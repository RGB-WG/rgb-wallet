// RGB standard library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashSet};

use amplify::confinement::{Confined, SmallOrdSet, TinyOrdMap, U16};
use amplify::{confinement, Wrapper};
use bp::seals::txout::CloseMethod;
use chrono::Utc;
use invoice::{Allocation, Amount};
use rgb::validation::Scripts;
use rgb::{
    validation, Assign, AssignmentType, Assignments, AttachState, ContractId, DataState,
    ExposedSeal, FungibleType, Genesis, GenesisSeal, GlobalState, GraphSeal, Identity, Input,
    Layer1, MetadataError, Opout, OwnedStateSchema, RevealedAttach, RevealedData, RevealedValue,
    Schema, Transition, TransitionType, TypedAssigns, XChain, XOutpoint,
};
use rgbcore::{GlobalStateSchema, GlobalStateType, MetaType, Metadata, ValencyType};
use strict_encoding::{FieldName, SerializeError, StrictSerialize};
use strict_types::{decode, SemId, TypeSystem};

use crate::containers::{BuilderSeal, ContainerVer, Contract, ValidConsignment};
use crate::interface::resolver::DumbResolver;
use crate::interface::{Iface, IfaceImpl, TransitionIface};
use crate::persistence::PersistedState;
use crate::Outpoint;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BuilderError {
    /// contract already has too many layers1.
    TooManyLayers1,

    /// metadata `{0}` are not known to the schema
    MetadataNotFound(FieldName),

    #[from]
    #[display(inner)]
    MetadataInvalid(MetadataError),

    /// global state `{0}` is not known to the schema.
    GlobalNotFound(FieldName),

    /// assignment `{0}` is not known to the schema.
    AssignmentNotFound(FieldName),

    /// transition `{0}` is not known to the schema.
    TransitionNotFound(FieldName),

    /// unknown owned state name `{0}`.
    InvalidStateField(FieldName),

    /// state `{0}` provided to the builder has invalid type.
    InvalidStateType(AssignmentType),

    /// interface doesn't specifies default operation name, thus an explicit
    /// operation type must be provided with `set_operation_type` method.
    NoOperationSubtype,

    /// interface doesn't have a default assignment type.
    NoDefaultAssignment,

    /// {0} is not supported by the contract genesis.
    InvalidLayer1(Layer1),

    /// the seal is committing to a layer 1 ({0}) different from the the contract one ({1})
    Layer1Mismatch(Layer1, Layer1),

    #[from]
    #[display(inner)]
    StrictEncode(SerializeError),

    #[from]
    #[display(inner)]
    Reify(decode::Error),

    #[from]
    #[display(inner)]
    Confinement(confinement::Error),

    #[from]
    #[display(inner)]
    ContractInconsistency(validation::Status),
}

mod private {
    pub trait Sealed {}
}

pub trait TxOutpoint: Copy + Eq + private::Sealed {
    fn is_liquid(&self) -> bool;
    fn is_bitcoin(&self) -> bool;
    fn map_to_xchain<U>(self, f: impl FnOnce(Outpoint) -> U) -> XChain<U>;
}

impl private::Sealed for Outpoint {}
impl private::Sealed for XOutpoint {}
impl TxOutpoint for Outpoint {
    fn is_liquid(&self) -> bool { false }
    fn is_bitcoin(&self) -> bool { true }
    fn map_to_xchain<U>(self, f: impl FnOnce(Outpoint) -> U) -> XChain<U> {
        XChain::Bitcoin(f(self))
    }
}
impl TxOutpoint for XOutpoint {
    fn is_liquid(&self) -> bool { XChain::is_liquid(self) }
    fn is_bitcoin(&self) -> bool { XChain::is_bitcoin(self) }
    fn map_to_xchain<U>(self, f: impl FnOnce(Outpoint) -> U) -> XChain<U> { self.map(f) }
}

#[derive(Clone, Debug)]
pub struct ContractBuilder {
    builder: OperationBuilder<GenesisSeal>,
    testnet: bool,
    close_method: CloseMethod,
    scripts: Scripts,
    issuer: Identity,
    layer1: Layer1,
}

impl ContractBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn with(
        close_method: CloseMethod,
        issuer: Identity,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
        scripts: Scripts,
        layer1: Layer1,
    ) -> Self {
        Self {
            builder: OperationBuilder::with(iface, schema, iimpl, types),
            testnet: true,
            close_method,
            scripts,
            issuer,
            layer1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        close_method: CloseMethod,
        issuer: Identity,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
        scripts: Scripts,
        layer1: Layer1,
    ) -> Self {
        Self {
            builder: OperationBuilder::deterministic(iface, schema, iimpl, types),
            testnet: true,
            close_method,
            scripts,
            issuer,
            layer1,
        }
    }

    pub fn type_system(&self) -> &TypeSystem { self.builder.type_system() }

    pub fn set_mainnet(mut self) -> Self {
        self.testnet = false;
        self
    }

    pub fn check_layer1(&self, layer1: Layer1) -> Result<(), BuilderError> {
        if self.layer1 != layer1 {
            return Err(BuilderError::Layer1Mismatch(layer1, self.layer1));
        }
        Ok(())
    }

    #[inline]
    pub fn global_type(&self, name: &FieldName) -> Option<GlobalStateType> {
        self.builder.global_type(name)
    }

    #[inline]
    pub fn valency_type(&self, name: &FieldName) -> Option<ValencyType> {
        self.builder.valency_type(name)
    }

    #[inline]
    pub fn valency_name(&self, type_id: ValencyType) -> &FieldName {
        self.builder.valency_name(type_id)
    }

    #[inline]
    pub fn meta_name(&self, type_id: MetaType) -> &FieldName { self.builder.meta_name(type_id) }

    #[inline]
    pub fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_global_state(name, value)?;
        Ok(self)
    }

    pub fn add_owned_state_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_owned_state_det(name, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_rights(name, seal)?;
        Ok(self)
    }

    pub fn add_fungible_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_fungible_state(name, seal, value)?;
        Ok(self)
    }

    pub fn add_data(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_data(name, seal, value)?;
        Ok(self)
    }

    pub fn add_data_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        data: RevealedData,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_data_det(name, seal, data)?;
        Ok(self)
    }

    pub fn add_attachment(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        attachment: AttachState,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_attachment(name, seal, attachment)?;
        Ok(self)
    }

    pub fn add_attachment_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        attachment: RevealedAttach,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_attachment_det(name, seal, attachment)?;
        Ok(self)
    }

    pub fn issue_contract(self) -> Result<ValidConsignment<false>, BuilderError> {
        debug_assert!(
            !self.builder.deterministic,
            "for issuing deterministic contracts please use issue_contract_det method"
        );
        self.issue_contract_raw(Utc::now().timestamp())
    }

    pub fn issue_contract_det(
        self,
        timestamp: i64,
    ) -> Result<ValidConsignment<false>, BuilderError> {
        debug_assert!(
            self.builder.deterministic,
            "for issuing deterministic contracts please use deterministic constructor"
        );
        self.issue_contract_raw(timestamp)
    }

    fn issue_contract_raw(self, timestamp: i64) -> Result<ValidConsignment<false>, BuilderError> {
        let (schema, iface, iimpl, global, assignments, types) = self.builder.complete();

        let genesis = Genesis {
            ffv: none!(),
            schema_id: schema.schema_id(),
            flags: none!(),
            timestamp,
            layer1: self.layer1,
            testnet: self.testnet,
            close_method: self.close_method,
            metadata: empty!(),
            globals: global,
            assignments,
            valencies: none!(),
            issuer: self.issuer,
            validator: none!(),
        };

        let ifaces = tiny_bmap! { iface => iimpl };
        let scripts = Confined::from_iter_checked(self.scripts.into_values());

        let contract = Contract {
            version: ContainerVer::V2,
            transfer: false,
            terminals: none!(),
            genesis,
            extensions: none!(),
            bundles: none!(),
            schema,
            ifaces,
            attachments: none!(), // TODO: Add support for attachment files

            types,
            scripts,

            supplements: none!(), // TODO: Add supplements
            signatures: none!(),  // TODO: Add signatures
        };

        let valid_contract = contract
            .validate(&DumbResolver, self.testnet)
            .map_err(|(status, _)| status)?;

        Ok(valid_contract)
    }
}

#[derive(Clone, Debug)]
pub struct TransitionBuilder {
    contract_id: ContractId,
    builder: OperationBuilder<GraphSeal>,
    nonce: u64,
    transition_type: TransitionType,
    inputs: TinyOrdMap<Input, PersistedState>,
}

impl TransitionBuilder {
    pub fn blank_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
    ) -> Self {
        Self::with(contract_id, iface, schema, iimpl, TransitionType::BLANK, types)
    }

    pub fn blank_transition_det(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
    ) -> Self {
        Self::deterministic(contract_id, iface, schema, iimpl, TransitionType::BLANK, types)
    }

    pub fn default_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
    ) -> Result<Self, BuilderError> {
        let transition_type = iface
            .default_operation
            .as_ref()
            .and_then(|name| iimpl.transition_type(name))
            .ok_or(BuilderError::NoOperationSubtype)?;
        Ok(Self::with(contract_id, iface, schema, iimpl, transition_type, types))
    }

    pub fn default_transition_det(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
    ) -> Result<Self, BuilderError> {
        let transition_type = iface
            .default_operation
            .as_ref()
            .and_then(|name| iimpl.transition_type(name))
            .ok_or(BuilderError::NoOperationSubtype)?;
        Ok(Self::deterministic(contract_id, iface, schema, iimpl, transition_type, types))
    }

    pub fn named_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_name: impl Into<FieldName>,
        types: TypeSystem,
    ) -> Result<Self, BuilderError> {
        let transition_name = transition_name.into();
        let transition_type = iimpl
            .transition_type(&transition_name)
            .ok_or(BuilderError::TransitionNotFound(transition_name))?;
        Ok(Self::with(contract_id, iface, schema, iimpl, transition_type, types))
    }

    pub fn named_transition_det(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_name: impl Into<FieldName>,
        types: TypeSystem,
    ) -> Result<Self, BuilderError> {
        let transition_name = transition_name.into();
        let transition_type = iimpl
            .transition_type(&transition_name)
            .ok_or(BuilderError::TransitionNotFound(transition_name))?;
        Ok(Self::deterministic(contract_id, iface, schema, iimpl, transition_type, types))
    }

    fn with(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_type: TransitionType,
        types: TypeSystem,
    ) -> Self {
        Self {
            contract_id,
            builder: OperationBuilder::with(iface, schema, iimpl, types),
            nonce: u64::MAX,
            transition_type,
            inputs: none!(),
        }
    }

    fn deterministic(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_type: TransitionType,
        types: TypeSystem,
    ) -> Self {
        Self {
            contract_id,
            builder: OperationBuilder::deterministic(iface, schema, iimpl, types),
            nonce: u64::MAX,
            transition_type,
            inputs: none!(),
        }
    }

    pub fn type_system(&self) -> &TypeSystem { self.builder.type_system() }

    pub fn transition_type(&self) -> TransitionType { self.transition_type }

    pub fn set_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    #[inline]
    pub fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_global_state(name, value)?;
        Ok(self)
    }

    pub fn add_input(mut self, opout: Opout, state: PersistedState) -> Result<Self, BuilderError> {
        self.inputs.insert(Input::with(opout), state)?;
        Ok(self)
    }

    pub fn default_assignment(&self) -> Result<&FieldName, BuilderError> {
        self.builder
            .transition_iface(self.transition_type)
            .default_assignment
            .as_ref()
            .ok_or(BuilderError::NoDefaultAssignment)
    }

    #[inline]
    pub fn assignments_type(&self, name: &FieldName) -> Option<AssignmentType> {
        self.builder.assignments_type(name)
    }

    #[inline]
    pub fn global_type(&self, name: &FieldName) -> Option<GlobalStateType> {
        self.builder.global_type(name)
    }

    #[inline]
    pub fn valency_type(&self, name: &FieldName) -> Option<ValencyType> {
        self.builder.valency_type(name)
    }

    pub fn valency_name(&self, type_id: ValencyType) -> &FieldName {
        self.builder.valency_name(type_id)
    }

    pub fn meta_name(&self, type_id: MetaType) -> &FieldName { self.builder.meta_name(type_id) }

    pub fn add_owned_state_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_owned_state_det(name, seal, state)?;
        Ok(self)
    }

    pub fn add_owned_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_owned_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_rights(name, seal)?;
        Ok(self)
    }

    pub fn add_fungible_default_state(
        self,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: u64,
    ) -> Result<Self, BuilderError> {
        let assignment_name = self.default_assignment()?.clone();
        self.add_fungible_state(assignment_name, seal.into(), value)
    }

    pub fn add_fungible_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_fungible_state(name.into(), seal, value)?;
        Ok(self)
    }

    pub fn add_fungible_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        let state = RevealedValue::new(value.into());
        self.builder = self.builder.add_fungible_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_data(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_data(name, seal, value)?;
        Ok(self)
    }

    pub fn add_data_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        data: RevealedData,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_data_det(name, seal, data)?;
        Ok(self)
    }

    pub fn add_data_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        allocation: impl Into<Allocation>,
        blinding: u64,
    ) -> Result<Self, BuilderError> {
        let revealed_state = RevealedData::with_salt(allocation.into(), blinding.into());
        self.builder = self.builder.add_data_raw(type_id, seal, revealed_state)?;
        Ok(self)
    }

    pub fn add_data_default(
        self,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let assignment_name = self.default_assignment()?.clone();
        self.add_data(assignment_name, seal.into(), value)
    }

    pub fn add_attachment(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        attachment: AttachState,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_attachment(name, seal, attachment)?;
        Ok(self)
    }

    pub fn add_attachment_det(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        attachment: RevealedAttach,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_attachment_det(name, seal, attachment)?;
        Ok(self)
    }

    pub fn has_inputs(&self) -> bool { !self.inputs.is_empty() }

    pub fn complete_transition(self) -> Result<Transition, BuilderError> {
        let (_, _, _, global, assignments, _) = self.builder.complete();

        let transition = Transition {
            ffv: none!(),
            contract_id: self.contract_id,
            nonce: self.nonce,
            transition_type: self.transition_type,
            metadata: empty!(),
            globals: global,
            inputs: SmallOrdSet::from_iter_checked(self.inputs.into_keys()).into(),
            assignments,
            valencies: none!(),
            witness: none!(),
            validator: none!(),
        };

        // TODO: Validate against schema

        Ok(transition)
    }
}

#[derive(Clone, Debug)]
pub struct OperationBuilder<Seal: ExposedSeal> {
    // TODO: use references instead of owned values
    schema: Schema,
    iface: Iface,
    iimpl: IfaceImpl,
    deterministic: bool,

    global: GlobalState,
    meta: Metadata,
    rights: TinyOrdMap<AssignmentType, Confined<HashSet<BuilderSeal<Seal>>, 1, U16>>,
    fungible:
        TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedValue>, 1, U16>>,
    data: TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedData>, 1, U16>>,
    attachments:
        TinyOrdMap<AssignmentType, Confined<BTreeMap<BuilderSeal<Seal>, RevealedAttach>, 1, U16>>,
    // TODO: add valencies
    types: TypeSystem,
}

impl<Seal: ExposedSeal> OperationBuilder<Seal> {
    fn with(iface: Iface, schema: Schema, iimpl: IfaceImpl, types: TypeSystem) -> Self {
        OperationBuilder {
            schema,
            iface,
            iimpl,
            deterministic: false,

            global: none!(),
            meta: none!(),
            rights: none!(),
            fungible: none!(),
            attachments: none!(),
            data: none!(),

            types,
        }
    }

    fn deterministic(iface: Iface, schema: Schema, iimpl: IfaceImpl, types: TypeSystem) -> Self {
        OperationBuilder {
            schema,
            iface,
            iimpl,
            deterministic: true,

            global: none!(),
            meta: none!(),
            rights: none!(),
            fungible: none!(),
            attachments: none!(),
            data: none!(),

            types,
        }
    }

    fn type_system(&self) -> &TypeSystem { &self.types }

    fn transition_iface(&self, ty: TransitionType) -> &TransitionIface {
        let transition_name = self.iimpl.transition_name(ty).expect("reverse type");
        self.iface
            .transitions
            .get(transition_name)
            .expect("internal inconsistency")
    }

    fn assignments_type(&self, name: &FieldName) -> Option<AssignmentType> {
        self.iimpl.assignments_type(name)
    }

    fn meta_type(&self, name: &FieldName) -> Option<MetaType> { self.iimpl.meta_type(name) }

    fn meta_name(&self, ty: MetaType) -> &FieldName {
        self.iimpl.meta_name(ty).expect("internal inconsistency")
    }

    fn global_type(&self, name: &FieldName) -> Option<GlobalStateType> {
        self.iimpl.global_type(name)
    }

    fn valency_type(&self, name: &FieldName) -> Option<ValencyType> {
        self.iimpl.valency_type(name)
    }

    fn valency_name(&self, ty: ValencyType) -> &FieldName {
        self.iimpl.valency_name(ty).expect("internal inconsistency")
    }

    #[inline]
    fn state_schema(&self, type_id: AssignmentType) -> &OwnedStateSchema {
        self.schema
            .owned_types
            .get(&type_id)
            .expect("schema should match interface: must be checked by the constructor")
    }

    #[inline]
    fn meta_schema(&self, type_id: MetaType) -> &SemId {
        self.schema
            .meta_types
            .get(&type_id)
            .expect("schema should match interface: must be checked by the constructor")
    }

    #[inline]
    fn global_schema(&self, type_id: GlobalStateType) -> &GlobalStateSchema {
        self.schema
            .global_types
            .get(&type_id)
            .expect("schema should match interface: must be checked by the constructor")
    }

    pub fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;

        let Some(type_id) = self.meta_type(&name) else {
            return Err(BuilderError::MetadataNotFound(name));
        };

        let sem_id = self.meta_schema(type_id);
        self.types.strict_deserialize_type(*sem_id, &serialized)?;
        self.meta.add_value(type_id, serialized.into())?;
        Ok(self)
    }

    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let name = name.into();
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;

        // Check value matches type requirements
        let Some(type_id) = self.global_type(&name) else {
            return Err(BuilderError::GlobalNotFound(name));
        };
        let sem_id = self.global_schema(type_id).sem_id;
        self.types.strict_deserialize_type(sem_id, &serialized)?;

        self.global.add_state(type_id, serialized.into())?;

        Ok(self)
    }

    fn add_owned_state_det(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        debug_assert!(
            self.deterministic,
            "to add owned state in deterministic way the builder has to be created using \
             deterministic constructor"
        );
        let name = name.into();
        let type_id = self
            .assignments_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name.clone()))?;
        self.add_owned_state_raw(type_id, seal, state)
    }

    fn add_owned_state_raw(
        self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: PersistedState,
    ) -> Result<Self, BuilderError> {
        match state {
            PersistedState::Void => self.add_rights_raw(type_id, seal),
            PersistedState::Amount(value) => {
                self.add_fungible_state_raw(type_id, seal, RevealedValue::new(value))
            }
            PersistedState::Data(data, salt) => {
                self.add_data_raw(type_id, seal, RevealedData::with_salt(data, salt))
            }
            PersistedState::Attachment(attach, salt) => self.add_attachment_raw(
                type_id,
                seal,
                RevealedAttach::with_salt(attach.id, attach.media_type, salt),
            ),
        }
    }

    fn add_rights(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();

        let type_id = self
            .assignments_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_rights_raw(type_id, seal)
    }

    fn add_rights_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if *state_schema != OwnedStateSchema::Declarative {
            return Err(BuilderError::InvalidStateType(type_id));
        }

        let seal = seal.into();
        match self.rights.get_mut(&type_id) {
            Some(assignments) => {
                assignments.push(seal)?;
            }
            None => {
                self.rights.insert(type_id, Confined::with(seal))?;
            }
        }

        Ok(self)
    }

    fn add_fungible_state(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: impl Into<Amount>,
    ) -> Result<Self, BuilderError> {
        let name = name.into();

        let type_id = self
            .assignments_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        let state = RevealedValue::new(value.into());
        self.add_fungible_state_raw(type_id, seal, state)
    }

    fn add_fungible_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedValue,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if *state_schema != OwnedStateSchema::Fungible(FungibleType::Unsigned64Bit) {
            return Err(BuilderError::InvalidStateType(type_id));
        }

        let seal = seal.into();
        match self.fungible.get_mut(&type_id) {
            Some(assignments) => {
                assignments.insert(seal, state)?;
            }
            None => {
                self.fungible
                    .insert(type_id, Confined::with((seal, state)))?;
            }
        }

        Ok(self)
    }

    fn add_data(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        debug_assert!(
            !self.deterministic,
            "for adding state to deterministic contracts you have to use add_*_det methods"
        );

        let name = name.into();
        let serialized = value.to_strict_serialized::<U16>()?;
        let state = DataState::from(serialized);

        let type_id = self
            .assignments_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_data_raw(type_id, seal, RevealedData::new_random_salt(state))
    }

    fn add_data_det(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedData,
    ) -> Result<Self, BuilderError> {
        debug_assert!(
            self.deterministic,
            "to add owned state in deterministic way the builder has to be created using \
             deterministic constructor"
        );

        let name = name.into();
        let type_id = self
            .assignments_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_data_raw(type_id, seal, state)
    }

    fn add_data_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedData,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if let OwnedStateSchema::Structured(_) = *state_schema {
            let seal = seal.into();
            match self.data.get_mut(&type_id) {
                Some(assignments) => {
                    assignments.insert(seal, state)?;
                }
                None => {
                    self.data.insert(type_id, Confined::with((seal, state)))?;
                }
            }
        } else {
            return Err(BuilderError::InvalidStateType(type_id));
        }
        Ok(self)
    }

    fn add_attachment(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        state: AttachState,
    ) -> Result<Self, BuilderError> {
        debug_assert!(
            !self.deterministic,
            "for adding state to deterministic contracts you have to use add_*_det methods"
        );

        let name = name.into();

        let type_id = self
            .assignments_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_attachment_raw(
            type_id,
            seal,
            RevealedAttach::new_random_salt(state.id, state.media_type),
        )
    }

    fn add_attachment_det(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedAttach,
    ) -> Result<Self, BuilderError> {
        debug_assert!(
            self.deterministic,
            "to add owned state in deterministic way the builder has to be created using \
             deterministic constructor"
        );

        let name = name.into();

        let type_id = self
            .assignments_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name))?;

        self.add_attachment_raw(type_id, seal, state)
    }

    fn add_attachment_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: RevealedAttach,
    ) -> Result<Self, BuilderError> {
        let state_schema = self.state_schema(type_id);
        if let OwnedStateSchema::Attachment(_) = *state_schema {
            let seal = seal.into();
            match self.attachments.get_mut(&type_id) {
                Some(assignments) => {
                    assignments.insert(seal, state)?;
                }
                None => {
                    self.attachments
                        .insert(type_id, Confined::with((seal, state)))?;
                }
            }
        } else {
            return Err(BuilderError::InvalidStateType(type_id));
        }
        Ok(self)
    }

    fn complete(self) -> (Schema, Iface, IfaceImpl, GlobalState, Assignments<Seal>, TypeSystem) {
        let owned_state = self.fungible.into_iter().map(|(id, vec)| {
            let vec = vec
                .into_iter()
                .map(|(seal, value)| match seal {
                    BuilderSeal::Revealed(seal) => Assign::Revealed {
                        seal,
                        state: value,
                        lock: none!(),
                    },
                    BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal {
                        seal,
                        state: value,
                        lock: none!(),
                    },
                })
                .collect::<Vec<_>>();
            let state = Confined::try_from_iter(vec).expect("at least one element");
            let state = TypedAssigns::Fungible(state);
            (id, state)
        });
        let owned_data = self.data.into_iter().map(|(id, vec)| {
            let vec_data = vec.into_iter().map(|(seal, value)| match seal {
                BuilderSeal::Revealed(seal) => Assign::Revealed {
                    seal,
                    state: value,
                    lock: none!(),
                },
                BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal {
                    seal,
                    state: value,
                    lock: none!(),
                },
            });
            let state_data = Confined::try_from_iter(vec_data).expect("at least one element");
            let state_data = TypedAssigns::Structured(state_data);
            (id, state_data)
        });
        let owned_rights = self.rights.into_iter().map(|(id, vec)| {
            let vec_data = vec.into_iter().map(|seal| match seal {
                BuilderSeal::Revealed(seal) => Assign::Revealed {
                    seal,
                    state: none!(),
                    lock: none!(),
                },
                BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal {
                    seal,
                    state: none!(),
                    lock: none!(),
                },
            });
            let state_data = Confined::try_from_iter(vec_data).expect("at least one element");
            let state_data = TypedAssigns::Declarative(state_data);
            (id, state_data)
        });
        let owned_attachments = self.attachments.into_iter().map(|(id, vec)| {
            let vec_data = vec.into_iter().map(|(seal, value)| match seal {
                BuilderSeal::Revealed(seal) => Assign::Revealed {
                    seal,
                    state: value,
                    lock: none!(),
                },
                BuilderSeal::Concealed(seal) => Assign::ConfidentialSeal {
                    seal,
                    state: value,
                    lock: none!(),
                },
            });
            let state_data = Confined::try_from_iter(vec_data).expect("at least one element");
            let state_data = TypedAssigns::Attachment(state_data);
            (id, state_data)
        });

        let owned_state = Confined::try_from_iter(owned_state).expect("same size");
        let owned_data = Confined::try_from_iter(owned_data).expect("same size");
        let owned_rights = Confined::try_from_iter(owned_rights).expect("same size");
        let owned_attachments = Confined::try_from_iter(owned_attachments).expect("same size");

        let mut assignments = Assignments::from_inner(owned_state);
        assignments
            .extend(Assignments::from_inner(owned_data).into_inner())
            .expect("too many assignments");
        assignments
            .extend(Assignments::from_inner(owned_rights).into_inner())
            .expect("too many assignments");
        assignments
            .extend(Assignments::from_inner(owned_attachments).into_inner())
            .expect("too many assignments");

        (self.schema, self.iface, self.iimpl, self.global, assignments, self.types)
    }
}
