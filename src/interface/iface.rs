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

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use amplify::confinement::{TinyOrdMap, TinyOrdSet, TinyString, TinyVec};
use amplify::{ByteArray, Bytes32};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use chrono::{DateTime, TimeZone, Utc};
use commit_verify::{CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{ContractId, Identity, Occurrences, SchemaId, XWitnessId};
use strict_encoding::{
    FieldName, StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize,
    StrictType, TypeName, VariantName,
};
use strict_types::{SemId, SymbolicSys, TypeLib};

use crate::interface::{ContractIface, IfaceDisplay, IfaceImpl, VerNo};
use crate::persistence::{ContractStateRead, SchemaIfaces};
use crate::{WitnessInfo, LIB_NAME_RGB_STD};

/// Interface identifier.
///
/// Interface identifier commits to all the interface data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct IfaceId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for IfaceId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for IfaceId {
    const TAG: &'static str = "urn:lnp-bp:rgb:interface#2024-02-04";
}

impl DisplayBaid64 for IfaceId {
    const HRI: &'static str = "rgb:ifc";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = true;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for IfaceId {}
impl FromStr for IfaceId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for IfaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(IfaceId);

impl IfaceId {
    pub const fn from_array(id: [u8; 32]) -> Self { IfaceId(Bytes32::from_array(id)) }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum IfaceRef {
    #[from]
    #[from(&'static str)]
    Name(TypeName),
    #[from]
    Id(IfaceId),
}

impl Display for IfaceRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IfaceRef::Name(name) => f.write_str(name.as_str()),
            IfaceRef::Id(id) => {
                if f.alternate() {
                    write!(f, "{}", id.to_baid64_mnemonic())
                } else {
                    write!(f, "{}", id)
                }
            }
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum Req {
    Optional,
    Required,
    NoneOrMore,
    OneOrMore,
}

impl Req {
    pub fn is_required(self) -> bool { self == Req::Required || self == Req::OneOrMore }
    pub fn is_multiple(self) -> bool { self == Req::NoneOrMore || self == Req::OneOrMore }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ValencyIface {
    pub required: bool,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalIface {
    pub sem_id: Option<SemId>,
    pub required: bool,
    pub multiple: bool,
}

impl GlobalIface {
    pub fn any(req: Req) -> Self {
        GlobalIface {
            sem_id: None,
            required: req.is_required(),
            multiple: req.is_multiple(),
        }
    }
    pub fn optional(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: false,
            multiple: false,
        }
    }
    pub fn required(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: true,
            multiple: false,
        }
    }
    pub fn none_or_many(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: false,
            multiple: true,
        }
    }
    pub fn one_or_many(sem_id: SemId) -> Self {
        GlobalIface {
            sem_id: Some(sem_id),
            required: true,
            multiple: true,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AssignIface {
    pub state_ty: Option<SemId>,
    pub attach: Option<bool>,
    pub public: bool,
    pub required: bool,
    pub multiple: bool,
}

impl AssignIface {
    pub fn optional() -> Self {
        AssignIface {
            state_ty: None,
            attach: None,
            public: false,
            required: false,
            multiple: false,
        }
    }
    pub fn required() -> Self {
        AssignIface {
            state_ty: None,
            attach: None,
            public: false,
            required: true,
            multiple: false,
        }
    }
    pub fn none_or_many() -> Self {
        AssignIface {
            state_ty: None,
            attach: None,
            public: false,
            required: false,
            multiple: true,
        }
    }
    pub fn one_or_many() -> Self {
        AssignIface {
            state_ty: None,
            attach: None,
            public: false,
            required: true,
            multiple: true,
        }
    }
    pub fn public(mut self) -> Self {
        self.public = true;
        self
    }
    pub fn rights(mut self) -> Self {
        self.state_ty = Some(SemId::default());
        self
    }
    pub fn typed(mut self, sem_id: SemId) -> Self {
        self.state_ty = Some(sem_id);
        self
    }
    pub fn attachments(mut self, require: bool) -> Self {
        self.attach = Some(require);
        self
    }
}

pub type ArgMap = TinyOrdMap<FieldName, Occurrences>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, into_u8, try_from_u8, tags = repr)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
#[repr(u8)]
pub enum Modifier {
    Abstract = 0,
    Override = 1,
    #[default]
    Final = 0xFF,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GenesisIface {
    pub modifier: Modifier,
    pub metadata: TinyOrdSet<FieldName>,
    pub globals: ArgMap,
    pub assignments: ArgMap,
    pub valencies: TinyOrdSet<FieldName>,
    pub errors: TinyOrdSet<VariantName>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ExtensionIface {
    pub modifier: Modifier,
    /// Defines whence schema may omit providing this operation.
    pub optional: bool,
    pub metadata: TinyOrdSet<FieldName>,
    pub globals: ArgMap,
    pub assignments: ArgMap,
    pub redeems: TinyOrdSet<FieldName>,
    pub valencies: TinyOrdSet<FieldName>,
    pub errors: TinyOrdSet<VariantName>,
    pub default_assignment: Option<FieldName>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionIface {
    pub modifier: Modifier,
    /// Defines whence schema may omit providing this operation.
    pub optional: bool,
    pub metadata: TinyOrdSet<FieldName>,
    pub globals: ArgMap,
    pub inputs: ArgMap,
    pub assignments: ArgMap,
    pub valencies: TinyOrdSet<FieldName>,
    pub errors: TinyOrdSet<VariantName>,
    pub default_assignment: Option<FieldName>,
}

/// A class of interfaces: one or several interfaces inheriting from each other.
///
/// Interface standards like RGB20, RGB21 and RGB25 are actually interface
/// classes.
pub trait IfaceClass: Clone + Default {
    const IFACE_NAME: &'static str;
    const IFACE_IDS: &'static [IfaceId];

    type Wrapper<S: ContractStateRead>: IfaceWrapper<S>;

    fn stl(&self) -> TypeLib;
    fn iface(&self) -> Iface;
    fn iface_id(&self) -> IfaceId;
}

/// The instances implementing this trait are used as wrappers around
/// [`ContractIface`] object, allowing a simple API matching the interface class
/// requirements.
pub trait IfaceWrapper<S: ContractStateRead> {
    /// Object which represent concise summary about a contract;
    type Info: Clone + Eq + Debug;

    fn with(iface: ContractIface<S>) -> Self;

    /// Constructs information object describing a specific class in terms of
    /// the interface class.
    fn info(&self) -> Self::Info;

    /// Returns contract id.
    fn contract_id(&self) -> ContractId;

    /// Returns schema id of the contract.
    fn schema_id(&self) -> SchemaId;

    /// Returns information about a witness, if it is known to the contract state.
    fn witness_info(&self, witness_id: XWitnessId) -> Option<WitnessInfo>;
}

/// Interface definition.
#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = IfaceId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Iface {
    pub version: VerNo,
    pub name: TypeName,
    pub inherits: TinyVec<IfaceId>, // TODO: Replace with TinyIndexSet
    pub timestamp: i64,
    pub metadata: TinyOrdMap<FieldName, SemId>,
    pub global_state: TinyOrdMap<FieldName, GlobalIface>,
    pub assignments: TinyOrdMap<FieldName, AssignIface>,
    pub valencies: TinyOrdMap<FieldName, ValencyIface>,
    pub genesis: GenesisIface,
    pub transitions: TinyOrdMap<FieldName, TransitionIface>,
    pub extensions: TinyOrdMap<FieldName, ExtensionIface>,
    pub default_operation: Option<FieldName>,
    pub errors: TinyOrdMap<VariantName, TinyString>,
    pub developer: Identity,
}

impl PartialEq for Iface {
    fn eq(&self, other: &Self) -> bool { self.iface_id() == other.iface_id() }
}

impl Ord for Iface {
    fn cmp(&self, other: &Self) -> Ordering { self.iface_id().cmp(&other.iface_id()) }
}

impl PartialOrd for Iface {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Hash for Iface {
    fn hash<H: Hasher>(&self, state: &mut H) { state.write(self.iface_id().as_slice()) }
}

impl StrictSerialize for Iface {}
impl StrictDeserialize for Iface {}

impl Iface {
    #[inline]
    pub fn iface_id(&self) -> IfaceId { self.commit_id() }

    pub fn display<'a>(
        &'a self,
        externals: &'a HashMap<IfaceId, TypeName>,
        sys: &'a SymbolicSys,
    ) -> IfaceDisplay<'a> {
        IfaceDisplay::new(self, externals, sys)
    }

    pub fn types(&self) -> impl Iterator<Item = SemId> + '_ {
        self.metadata
            .values()
            .copied()
            .chain(self.global_state.values().filter_map(|i| i.sem_id))
            .chain(self.assignments.values().filter_map(|i| i.state_ty))
    }

    pub fn find_abstractable_impl<'a>(
        &self,
        schema_ifaces: &'a SchemaIfaces,
    ) -> Option<&'a IfaceImpl> {
        schema_ifaces.get(self.iface_id()).or_else(|| {
            self.inherits
                .iter()
                .rev()
                .find_map(move |parent| schema_ifaces.get(*parent))
        })
    }

    pub fn check(&self) -> Result<(), Vec<IfaceInconsistency>> {
        let proc_globals = |op_name: &OpName,
                            globals: &ArgMap,
                            errors: &mut Vec<IfaceInconsistency>| {
            for (name, occ) in globals {
                if let Some(g) = self.global_state.get(name) {
                    if occ.min_value() > 1 && !g.multiple {
                        errors.push(IfaceInconsistency::MultipleGlobal(
                            op_name.clone(),
                            name.clone(),
                        ));
                    }
                } else {
                    errors.push(IfaceInconsistency::UnknownGlobal(op_name.clone(), name.clone()));
                }
            }
        };
        let proc_assignments =
            |op_name: &OpName, assignments: &ArgMap, errors: &mut Vec<IfaceInconsistency>| {
                for (name, occ) in assignments {
                    if let Some(a) = self.assignments.get(name) {
                        if occ.min_value() > 1 && !a.multiple {
                            errors.push(IfaceInconsistency::MultipleAssignment(
                                op_name.clone(),
                                name.clone(),
                            ));
                        }
                    } else {
                        errors.push(IfaceInconsistency::UnknownAssignment(
                            op_name.clone(),
                            name.clone(),
                        ));
                    }
                }
            };
        let proc_valencies = |op_name: &OpName,
                              valencies: &TinyOrdSet<FieldName>,
                              errors: &mut Vec<IfaceInconsistency>| {
            for name in valencies {
                if self.valencies.get(name).is_none() {
                    errors.push(IfaceInconsistency::UnknownValency(op_name.clone(), name.clone()));
                }
            }
        };
        let proc_errors = |op_name: &OpName,
                           errs: &TinyOrdSet<VariantName>,
                           errors: &mut Vec<IfaceInconsistency>| {
            for name in errs {
                if !self.errors.contains_key(name) {
                    errors.push(IfaceInconsistency::UnknownError(op_name.clone(), name.clone()));
                }
            }
        };

        let mut errors = vec![];

        let now = Utc::now();
        match Utc.timestamp_opt(self.timestamp, 0).single() {
            Some(ts) if ts > now => errors.push(IfaceInconsistency::FutureTimestamp(ts)),
            None => errors.push(IfaceInconsistency::InvalidTimestamp(self.timestamp)),
            _ => {}
        }

        for name in &self.genesis.metadata {
            if !self.metadata.contains_key(name) {
                errors.push(IfaceInconsistency::UnknownMetadata(OpName::Genesis, name.clone()));
            }
        }
        proc_globals(&OpName::Genesis, &self.genesis.globals, &mut errors);
        proc_assignments(&OpName::Genesis, &self.genesis.assignments, &mut errors);
        proc_valencies(&OpName::Genesis, &self.genesis.valencies, &mut errors);
        proc_errors(&OpName::Genesis, &self.genesis.errors, &mut errors);

        for (name, t) in &self.transitions {
            let op_name = OpName::Transition(name.clone());

            for name in &t.metadata {
                if !self.metadata.contains_key(name) {
                    errors.push(IfaceInconsistency::UnknownMetadata(op_name.clone(), name.clone()));
                }
            }
            proc_globals(&op_name, &t.globals, &mut errors);
            proc_assignments(&op_name, &t.assignments, &mut errors);
            proc_valencies(&op_name, &t.valencies, &mut errors);
            proc_errors(&op_name, &t.errors, &mut errors);

            for (name, occ) in &t.inputs {
                if let Some(a) = self.assignments.get(name) {
                    if occ.min_value() > 1 && !a.multiple {
                        errors.push(IfaceInconsistency::MultipleInputs(
                            op_name.clone(),
                            name.clone(),
                        ));
                    }
                } else {
                    errors.push(IfaceInconsistency::UnknownInput(op_name.clone(), name.clone()));
                }
            }
            if let Some(ref name) = t.default_assignment {
                if t.assignments.get(name).is_none() {
                    errors
                        .push(IfaceInconsistency::UnknownDefaultAssignment(op_name, name.clone()));
                }
            }
        }

        for (name, e) in &self.extensions {
            let op_name = OpName::Extension(name.clone());

            for name in &e.metadata {
                if !self.metadata.contains_key(name) {
                    errors.push(IfaceInconsistency::UnknownMetadata(op_name.clone(), name.clone()));
                }
            }
            proc_globals(&op_name, &e.globals, &mut errors);
            proc_assignments(&op_name, &e.assignments, &mut errors);
            proc_valencies(&op_name, &e.valencies, &mut errors);
            proc_errors(&op_name, &e.errors, &mut errors);

            for name in &e.redeems {
                if self.valencies.get(name).is_none() {
                    errors.push(IfaceInconsistency::UnknownRedeem(op_name.clone(), name.clone()));
                }
            }
            if let Some(ref name) = e.default_assignment {
                if e.assignments.get(name).is_none() {
                    errors
                        .push(IfaceInconsistency::UnknownDefaultAssignment(op_name, name.clone()));
                }
            }
        }

        for name in self.transitions.keys() {
            if self.extensions.contains_key(name) {
                errors.push(IfaceInconsistency::RepeatedOperationName(name.clone()));
            }
        }

        if let Some(ref name) = self.default_operation {
            if self.transitions.get(name).is_none() && self.extensions.get(name).is_none() {
                errors.push(IfaceInconsistency::UnknownDefaultOp(name.clone()));
            }
        }

        for (name, g) in &self.global_state {
            if g.required && self.genesis.globals.get(name).is_none() {
                errors.push(IfaceInconsistency::RequiredGlobalAbsent(name.clone()));
            }
        }
        for (name, a) in &self.assignments {
            if a.required && self.genesis.assignments.get(name).is_none() {
                errors.push(IfaceInconsistency::RequiredAssignmentAbsent(name.clone()));
            }
        }
        for (name, v) in &self.valencies {
            if v.required && self.genesis.valencies.get(name).is_none() {
                errors.push(IfaceInconsistency::RequiredValencyAbsent(name.clone()));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    // TODO: Implement checking interface inheritance.
    /*
    pub fn check_inheritance<'a>(&self, ifaces: impl IntoIterator<Item = (&'a IfaceId, &'a Iface)>) -> Result<(), Vec<InheritanceError>> {
        // check for the depth
    }
     */

    // TODO: Implement checking types against presence in a type system.
    /*
    pub fn check_types(&self, sys: &TypeSystem) -> Result<(), Vec<IfaceTypeError>> {
        for g in self.global_state.values() {
            if let Some(id) = g.sem_id {

            }
        }
    }
     */
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
pub enum OpName {
    #[display("genesis")]
    Genesis,
    #[display("transition '{0}'")]
    Transition(FieldName),
    #[display("extension '{0}'")]
    Extension(FieldName),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum IfaceInconsistency {
    /// timestamp is invalid ({0}).
    InvalidTimestamp(i64),
    /// timestamp in the future ({0}).
    FutureTimestamp(DateTime<Utc>),
    /// unknown global state '{1}' referenced from {0}.
    UnknownGlobal(OpName, FieldName),
    /// unknown valency '{1}' referenced from {0}.
    UnknownValency(OpName, FieldName),
    /// unknown input '{1}' referenced from {0}.
    UnknownRedeem(OpName, FieldName),
    /// unknown assignment '{1}' referenced from {0}.
    UnknownAssignment(OpName, FieldName),
    /// unknown input '{1}' referenced from {0}.
    UnknownInput(OpName, FieldName),
    /// unknown error '{1}' referenced from {0}.
    UnknownError(OpName, VariantName),
    /// unknown default assignment '{1}' referenced from {0}.
    UnknownDefaultAssignment(OpName, FieldName),
    /// unknown default operation '{0}'.
    UnknownDefaultOp(FieldName),
    /// unknown metadata '{1}' in {0}.
    UnknownMetadata(OpName, FieldName),
    /// global state '{1}' must have a unique single value, but operation {0}
    /// defines multiple global state of this type.
    MultipleGlobal(OpName, FieldName),
    /// assignment '{1}' must be unique, but operation {0} defines multiple
    /// assignments of this type.
    MultipleAssignment(OpName, FieldName),
    /// assignment '{1}' is unique, but operation {0} defines multiple inputs of
    /// this type, which is not possible.
    MultipleInputs(OpName, FieldName),
    /// operation name '{0}' is used by both state transition and extension.
    RepeatedOperationName(FieldName),
    /// global state '{0}' is required, but genesis doesn't define it.
    RequiredGlobalAbsent(FieldName),
    /// assignment '{0}' is required, but genesis doesn't define it.
    RequiredAssignmentAbsent(FieldName),
    /// valency '{0}' is required, but genesis doesn't define it.
    RequiredValencyAbsent(FieldName),
}
