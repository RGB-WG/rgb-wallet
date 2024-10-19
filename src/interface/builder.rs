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

use std::collections::btree_map::Entry;

use amplify::confinement::{self, Confined, SmallOrdSet, TinyOrdMap};
use chrono::Utc;
use rgb::validation::Scripts;
use rgb::{
    validation, AltLayer1, AltLayer1Set, AssignmentType, Assignments, AttachId, ContractId,
    ExposedSeal, Genesis, GenesisSeal, GlobalState, GlobalStateSchema, GlobalStateType, GraphSeal,
    Identity, Input, Layer1, MetaType, Metadata, MetadataError, Opout, Schema, State, StateData,
    Transition, TransitionType, TypedAssigns, ValencyType, XChain, XOutpoint, STATE_DATA_MAX_LEN,
};
use strict_encoding::{FieldName, SerializeError, StrictSerialize};
use strict_types::{decode, typify, SemId, StrictVal, TypeSystem};

use crate::containers::{BuilderSeal, ContainerVer, Contract, ValidConsignment};
use crate::interface::resolver::DumbResolver;
use crate::interface::{Iface, IfaceImpl, StateCalc, StateCalcError, TransitionIface};
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

    /// valency `{0}` is not known to the schema.
    ValencyNotFound(FieldName),

    /// transition `{0}` is not known to the schema.
    TransitionNotFound(FieldName),

    /// interface doesn't specify default operation name, thus an explicit
    /// operation type must be provided with `set_operation_type` method.
    NoOperationSubtype,

    /// interface doesn't have a default assignment type.
    NoDefaultAssignment,

    /// {0} is not supported by the contract genesis.
    InvalidLayer1(Layer1),

    #[from]
    #[display(inner)]
    Calc(StateCalcError),

    #[from]
    #[display(inner)]
    StrictEncode(SerializeError),

    #[from]
    #[display(inner)]
    Reify(decode::Error),

    #[from]
    #[display(inner)]
    Typify(typify::Error),

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
    alt_layers1: AltLayer1Set,
    scripts: Scripts,
    issuer: Identity,
}

impl ContractBuilder {
    pub fn with(
        issuer: Identity,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
        scripts: Scripts,
    ) -> Self {
        Self {
            builder: OperationBuilder::with(iface, schema, iimpl, types),
            testnet: true,
            alt_layers1: none!(),
            scripts,
            issuer,
        }
    }

    pub fn type_system(&self) -> &TypeSystem { self.builder.type_system() }

    pub fn set_mainnet(mut self) -> Self {
        self.testnet = false;
        self
    }

    pub fn has_layer1(&self, layer1: Layer1) -> bool {
        match layer1 {
            Layer1::Bitcoin => true,
            Layer1::Liquid => self.alt_layers1.contains(&AltLayer1::Liquid),
        }
    }
    pub fn check_layer1(&self, layer1: Layer1) -> Result<(), BuilderError> {
        if !self.has_layer1(layer1) {
            return Err(BuilderError::InvalidLayer1(layer1));
        }
        Ok(())
    }

    pub fn add_layer1(mut self, layer1: AltLayer1) -> Result<Self, BuilderError> {
        self.alt_layers1
            .push(layer1)
            .map_err(|_| BuilderError::TooManyLayers1)?;
        Ok(self)
    }

    #[inline]
    pub fn meta_type(&self, name: impl Into<FieldName>) -> Result<MetaType, BuilderError> {
        self.builder.meta_type(name)
    }

    #[inline]
    pub fn global_type(&self, name: impl Into<FieldName>) -> Result<GlobalStateType, BuilderError> {
        self.builder.global_type(name)
    }

    #[inline]
    pub fn valency_type(&self, name: impl Into<FieldName>) -> Result<ValencyType, BuilderError> {
        self.builder.valency_type(name)
    }

    #[inline]
    pub fn meta_name(&self, type_id: MetaType) -> &FieldName { self.builder.meta_name(type_id) }

    #[inline]
    pub fn valency_name(&self, type_id: ValencyType) -> &FieldName {
        self.builder.valency_name(type_id)
    }

    pub fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: StrictVal,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn serialize_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: &impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.serialize_metadata(name, value)?;
        Ok(self)
    }

    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: StrictVal,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_global_state(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn serialize_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: &impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.serialize_global_state(name, value)?;
        Ok(self)
    }

    pub fn add_owned_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        state: State,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_owned_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        attach: Option<AttachId>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_rights(name, seal, attach)?;
        Ok(self)
    }

    pub fn add_owned_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        state: StrictVal,
        attach: Option<AttachId>,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self.builder.add_owned_state(name, seal, state, attach)?;
        Ok(self)
    }

    pub fn serialize_owned_state(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GenesisSeal>>,
        value: &impl StrictSerialize,
        attach: Option<AttachId>,
    ) -> Result<Self, BuilderError> {
        let seal = seal.into();
        self.check_layer1(seal.layer1())?;
        self.builder = self
            .builder
            .serialize_owned_state(name, seal, value, attach)?;
        Ok(self)
    }

    pub fn issue_contract(self) -> Result<ValidConsignment<false>, BuilderError> {
        self.issue_contract_raw(Utc::now().timestamp())
    }

    pub fn issue_contract_det(
        self,
        timestamp: i64,
    ) -> Result<ValidConsignment<false>, BuilderError> {
        self.issue_contract_raw(timestamp)
    }

    fn issue_contract_raw(self, timestamp: i64) -> Result<ValidConsignment<false>, BuilderError> {
        let (schema, iface, iimpl, global, assignments, types) = self.builder.complete();

        let genesis = Genesis {
            ffv: none!(),
            schema_id: schema.schema_id(),
            flags: none!(),
            timestamp,
            testnet: self.testnet,
            alt_layers1: self.alt_layers1,
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

#[derive(Debug)]
pub struct TransitionBuilder {
    contract_id: ContractId,
    builder: OperationBuilder<GraphSeal>,
    nonce: u64,
    transition_type: TransitionType,
    inputs: TinyOrdMap<Input, State>,
    // TODO: Remove option once we have blank builder
    calc: Option<StateCalc>,
}

impl TransitionBuilder {
    pub fn blank_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
    ) -> Self {
        Self::with(contract_id, iface, schema, iimpl, TransitionType::BLANK, types, None)
    }

    pub fn default_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        types: TypeSystem,
        scripts: Scripts,
    ) -> Result<Self, BuilderError> {
        let transition_type = iface
            .default_operation
            .as_ref()
            .and_then(|name| iimpl.transition_type(name))
            .ok_or(BuilderError::NoOperationSubtype)?;
        let calc = StateCalc::new(scripts, iimpl.state_abi);
        Ok(Self::with(contract_id, iface, schema, iimpl, transition_type, types, Some(calc)))
    }

    pub fn named_transition(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_name: impl Into<FieldName>,
        types: TypeSystem,
        scripts: Scripts,
    ) -> Result<Self, BuilderError> {
        let transition_name = transition_name.into();
        let transition_type = iimpl
            .transition_type(&transition_name)
            .ok_or(BuilderError::TransitionNotFound(transition_name))?;
        let calc = StateCalc::new(scripts, iimpl.state_abi);
        Ok(Self::with(contract_id, iface, schema, iimpl, transition_type, types, Some(calc)))
    }

    fn with(
        contract_id: ContractId,
        iface: Iface,
        schema: Schema,
        iimpl: IfaceImpl,
        transition_type: TransitionType,
        types: TypeSystem,
        calc: Option<StateCalc>,
    ) -> Self {
        Self {
            contract_id,
            builder: OperationBuilder::with(iface, schema, iimpl, types),
            nonce: u64::MAX,
            transition_type,
            inputs: none!(),
            calc,
        }
    }

    pub fn type_system(&self) -> &TypeSystem { self.builder.type_system() }

    pub fn transition_type(&self) -> TransitionType { self.transition_type }

    #[inline]
    pub fn global_type(&self, name: impl Into<FieldName>) -> Result<GlobalStateType, BuilderError> {
        self.builder.global_type(name)
    }

    #[inline]
    pub fn assignments_type(
        &self,
        name: impl Into<FieldName>,
    ) -> Result<AssignmentType, BuilderError> {
        self.builder.assignments_type(name)
    }

    #[inline]
    pub fn valency_type(&self, name: impl Into<FieldName>) -> Result<ValencyType, BuilderError> {
        self.builder.valency_type(name)
    }

    #[inline]
    pub fn valency_name(&self, type_id: ValencyType) -> &FieldName {
        self.builder.valency_name(type_id)
    }

    pub fn meta_name(&self, type_id: MetaType) -> &FieldName { self.builder.meta_name(type_id) }

    pub fn default_assignment(&self) -> Result<&FieldName, BuilderError> {
        self.builder
            .transition_iface(self.transition_type)
            .default_assignment
            .as_ref()
            .ok_or(BuilderError::NoDefaultAssignment)
    }

    pub fn set_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn add_input(mut self, opout: Opout, state: State) -> Result<Self, BuilderError> {
        if let Some(calc) = &mut self.calc {
            calc.reg_input(opout.ty, &state)?;
        }
        self.inputs.insert(Input::with(opout), state)?;
        Ok(self)
    }

    pub fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: StrictVal,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_metadata(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn serialize_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: &impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.serialize_metadata(name, value)?;
        Ok(self)
    }

    pub fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: StrictVal,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_global_state(name, value)?;
        Ok(self)
    }

    #[inline]
    pub fn serialize_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: &impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.serialize_global_state(name, value)?;
        Ok(self)
    }

    // TODO: We won't need this once we will have Blank Transition builder
    /// NB: This does not process the state with VM
    pub fn add_owned_state_blank(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: State,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_owned_state_raw(type_id, seal, state)?;
        Ok(self)
    }

    pub fn add_rights(
        mut self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        attach: Option<AttachId>,
    ) -> Result<Self, BuilderError> {
        self.builder = self.builder.add_rights(name, seal, attach)?;
        Ok(self)
    }

    pub fn fulfill_owned_state(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
        state: State,
    ) -> Result<(Self, Option<State>), BuilderError> {
        let calc = self
            .calc
            .as_mut()
            .expect("you must not call fulfill_owned_state for the blank transition builder");
        let state = calc.calc_output(type_id, &state)?;
        self.builder = self
            .builder
            .add_owned_state_raw(type_id, seal, state.sufficient)?;
        Ok((self, state.insufficient))
    }

    pub fn add_owned_state_change(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<GraphSeal>>,
    ) -> Result<Self, BuilderError> {
        let calc = self
            .calc
            .as_mut()
            .expect("you must not call add_owned_state_change for the blank transition builder");
        if let Some(state) = calc.calc_change(type_id)? {
            self.builder = self.builder.add_owned_state_raw(type_id, seal, state)?;
        }
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

    global: GlobalState,
    meta: Metadata,
    assignments: Assignments<Seal>,
    // TODO: add valencies
    types: TypeSystem,
}

impl<Seal: ExposedSeal> OperationBuilder<Seal> {
    fn with(iface: Iface, schema: Schema, iimpl: IfaceImpl, types: TypeSystem) -> Self {
        OperationBuilder {
            schema,
            iface,
            iimpl,

            global: none!(),
            assignments: none!(),
            meta: none!(),
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

    fn assignments_type(&self, name: impl Into<FieldName>) -> Result<AssignmentType, BuilderError> {
        let name = name.into();
        self.iimpl
            .assignment_type(&name)
            .ok_or(BuilderError::AssignmentNotFound(name))
    }

    fn meta_type(&self, name: impl Into<FieldName>) -> Result<MetaType, BuilderError> {
        let name = name.into();
        self.iimpl
            .meta_type(&name)
            .ok_or(BuilderError::MetadataNotFound(name))
    }

    fn meta_name(&self, ty: MetaType) -> &FieldName {
        self.iimpl.meta_name(ty).expect("internal inconsistency")
    }

    fn global_type(&self, name: impl Into<FieldName>) -> Result<GlobalStateType, BuilderError> {
        let name = name.into();
        self.iimpl
            .global_type(&name)
            .ok_or(BuilderError::GlobalNotFound(name))
    }

    fn valency_type(&self, name: impl Into<FieldName>) -> Result<ValencyType, BuilderError> {
        let name = name.into();
        self.iimpl
            .valency_type(&name)
            .ok_or(BuilderError::ValencyNotFound(name))
    }

    fn valency_name(&self, ty: ValencyType) -> &FieldName {
        self.iimpl.valency_name(ty).expect("internal inconsistency")
    }

    #[inline]
    fn meta_schema(&self, type_id: MetaType) -> SemId {
        *self
            .schema
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

    fn add_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: StrictVal,
    ) -> Result<Self, BuilderError> {
        let type_id = self.meta_type(name)?;

        let types = self.type_system();
        let sem_id = *self
            .schema
            .meta_types
            .get(&type_id)
            .expect("schema-interface inconsistency");
        let value = types.typify(value, sem_id)?;
        let data = types.strict_serialize_value::<STATE_DATA_MAX_LEN>(&value)?;

        self.meta.add_value(type_id, data.into())?;
        Ok(self)
    }

    fn serialize_metadata(
        mut self,
        name: impl Into<FieldName>,
        value: &impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let type_id = self.meta_type(name)?;
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;
        let sem_id = self.meta_schema(type_id);

        #[cfg(debug_assertions)]
        self.types
            .strict_deserialize_type(sem_id, &serialized)
            .expect("failed deserialization");

        self.meta.add_value(type_id, serialized.into())?;
        Ok(self)
    }

    fn add_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: StrictVal,
    ) -> Result<Self, BuilderError> {
        let type_id = self.global_type(name)?;

        let types = self.type_system();
        let sem_id = self
            .schema
            .global_types
            .get(&type_id)
            .expect("schema-interface inconsistency")
            .sem_id;
        let value = types.typify(value, sem_id)?;
        let data = types.strict_serialize_value::<STATE_DATA_MAX_LEN>(&value)?;

        self.global.add_state(type_id, data.into())?;
        Ok(self)
    }

    fn serialize_global_state(
        mut self,
        name: impl Into<FieldName>,
        value: &impl StrictSerialize,
    ) -> Result<Self, BuilderError> {
        let type_id = self.global_type(name)?;
        let serialized = value.to_strict_serialized::<{ u16::MAX as usize }>()?;
        let sem_id = self.global_schema(type_id).sem_id;

        #[cfg(debug_assertions)]
        self.types
            .strict_deserialize_type(sem_id, &serialized)
            .expect("failed deserialization");

        self.global.add_state(type_id, serialized.into())?;

        Ok(self)
    }

    fn add_owned_state_raw(
        mut self,
        type_id: AssignmentType,
        seal: impl Into<BuilderSeal<Seal>>,
        state: State,
    ) -> Result<Self, BuilderError> {
        let assignment = seal.into().assignment(state);

        match self.assignments.entry(type_id)? {
            Entry::Vacant(entry) => {
                entry.insert(TypedAssigns::with(assignment));
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().push(assignment)?;
            }
        }
        Ok(self)
    }

    fn add_rights(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        attach: Option<AttachId>,
    ) -> Result<Self, BuilderError> {
        let type_id = self.assignments_type(name)?;
        let mut state = State::default();
        state.attach = attach;
        self.add_owned_state_raw(type_id, seal, state)
    }

    fn add_owned_state(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: StrictVal,
        attach: Option<AttachId>,
    ) -> Result<Self, BuilderError> {
        let type_id = self.assignments_type(name)?;

        let types = self.type_system();
        let sem_id = self
            .schema
            .owned_types
            .get(&type_id)
            .expect("schema-interface inconsistency")
            .sem_id;
        let value = types.typify(value, sem_id)?;
        let data = types.strict_serialize_value::<STATE_DATA_MAX_LEN>(&value)?;

        let mut state = State::from(StateData::from(data));
        state.attach = attach;
        self.add_owned_state_raw(type_id, seal, state)
    }

    fn serialize_owned_state(
        self,
        name: impl Into<FieldName>,
        seal: impl Into<BuilderSeal<Seal>>,
        value: &impl StrictSerialize,
        attach: Option<AttachId>,
    ) -> Result<Self, BuilderError> {
        let type_id = self.assignments_type(name)?;

        let mut state = State::from_serialized(value)?;
        state.attach = attach;
        self.add_owned_state_raw(type_id, seal, state)
    }

    fn complete(self) -> (Schema, Iface, IfaceImpl, GlobalState, Assignments<Seal>, TypeSystem) {
        (self.schema, self.iface, self.iimpl, self.global, self.assignments, self.types)
    }
}
