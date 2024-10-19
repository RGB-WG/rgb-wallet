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

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::confinement::TinyOrdSet;
use amplify::{ByteArray, Bytes32};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use chrono::{DateTime, TimeZone, Utc};
use commit_verify::{CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{
    impl_serde_baid64, AssignmentType, ExtensionType, GlobalStateType, Identity, MetaType, Schema,
    SchemaId, TransitionType, ValencyType,
};
use strict_encoding::{FieldName, StrictDumb, VariantName};
use strict_types::encoding::{StrictDecode, StrictEncode, StrictType};

use crate::interface::iface::IfaceId;
use crate::interface::{Iface, StateAbi, VerNo};
use crate::{ReservedBytes, LIB_NAME_RGB_STD};

pub trait SchemaTypeIndex:
    Copy + Eq + Ord + StrictType + StrictDumb + StrictEncode + StrictDecode
{
}
impl SchemaTypeIndex for u8 {} // Error types
impl SchemaTypeIndex for MetaType {}
impl SchemaTypeIndex for GlobalStateType {}
impl SchemaTypeIndex for AssignmentType {}
impl SchemaTypeIndex for ValencyType {}
impl SchemaTypeIndex for ExtensionType {}
impl SchemaTypeIndex for TransitionType {}

/// Interface identifier.
///
/// Interface identifier commits to all the interface data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct ImplId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for ImplId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ImplId {
    const TAG: &'static str = "urn:lnp-bp:rgb:iface-impl#2024-02-04";
}

impl DisplayBaid64 for ImplId {
    const HRI: &'static str = "rgb:imp";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = true;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for ImplId {}
impl FromStr for ImplId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for ImplId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(ImplId);

impl ImplId {
    pub const fn from_array(id: [u8; 32]) -> Self { ImplId(Bytes32::from_array(id)) }
}

/// Maps certain form of type id (global or owned state or a valency) to a
/// human-readable name.
///
/// Two distinct [`NamedField`] objects must always have both different state
/// ids and names.   
#[derive(Clone, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct NamedField<T: SchemaTypeIndex> {
    pub id: T,
    pub name: FieldName,
    /// Reserved bytes for storing information about value transformation
    /// procedures
    pub reserved: ReservedBytes<4usize>,
}

impl<T> PartialEq for NamedField<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedField<T> {
    pub fn with(id: T, name: FieldName) -> NamedField<T> {
        NamedField {
            id,
            name,
            reserved: default!(),
        }
    }
}

/// Maps certain form of type id (global or owned state or a valency) to a
/// human-readable name.
///
/// Two distinct [`crate::interface::NamedField`] objects must always have both
/// different state ids and names.
#[derive(Clone, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct NamedVariant<T: SchemaTypeIndex> {
    pub id: T,
    pub name: VariantName,
    /// Reserved bytes for storing information about value transformation
    /// procedures
    pub reserved: ReservedBytes<4usize>,
}

impl<T> PartialEq for NamedVariant<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedVariant<T> {
    pub fn with(id: T, name: VariantName) -> NamedVariant<T> {
        NamedVariant {
            id,
            name,
            reserved: default!(),
        }
    }
}

/// Maps operation numeric type id to a human-readable name.
///
/// Two distinct [`NamedType`] objects must always have both different state
/// ids and names.   
#[derive(Clone, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct NamedType<T: SchemaTypeIndex> {
    pub id: T,
    pub name: FieldName,
    /// Reserved bytes for storing information about adaptor procedures
    pub reserved: ReservedBytes<0, 4>,
}

impl<T> PartialEq for NamedType<T>
where T: SchemaTypeIndex
{
    fn eq(&self, other: &Self) -> bool { self.id == other.id || self.name == other.name }
}

impl<T: SchemaTypeIndex> NamedType<T> {
    pub fn with(id: T, name: impl Into<FieldName>) -> NamedType<T> {
        NamedType {
            id,
            name: name.into(),
            reserved: default!(),
        }
    }
}

/// Interface implementation for some specific schema.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = ImplId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfaceImpl {
    pub version: VerNo,
    pub schema_id: SchemaId,
    pub iface_id: IfaceId,
    pub timestamp: i64,
    pub metadata: TinyOrdSet<NamedField<MetaType>>,
    pub global_state: TinyOrdSet<NamedField<GlobalStateType>>,
    pub assignments: TinyOrdSet<NamedField<AssignmentType>>,
    pub valencies: TinyOrdSet<NamedField<ValencyType>>,
    pub transitions: TinyOrdSet<NamedField<TransitionType>>,
    pub extensions: TinyOrdSet<NamedField<ExtensionType>>,
    pub errors: TinyOrdSet<NamedVariant<u8>>,
    pub developer: Identity,
    pub state_abi: StateAbi,
}

impl IfaceImpl {
    #[inline]
    pub fn impl_id(&self) -> ImplId { self.commit_id() }

    pub fn meta_name(&self, id: MetaType) -> Option<&FieldName> {
        self.metadata
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn meta_type(&self, name: &FieldName) -> Option<MetaType> {
        self.metadata
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn global_type(&self, name: &FieldName) -> Option<GlobalStateType> {
        self.global_state
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn assignment_type(&self, name: &FieldName) -> Option<AssignmentType> {
        self.assignments
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn transition_type(&self, name: &FieldName) -> Option<TransitionType> {
        self.transitions
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn extension_name(&self, id: ExtensionType) -> Option<&FieldName> {
        self.extensions
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn extension_type(&self, name: &FieldName) -> Option<ExtensionType> {
        self.extensions
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn valency_type(&self, name: &FieldName) -> Option<ValencyType> {
        self.valencies
            .iter()
            .find(|nt| &nt.name == name)
            .map(|nt| nt.id)
    }

    pub fn valency_name(&self, id: ValencyType) -> Option<&FieldName> {
        self.valencies
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }
    pub fn global_name(&self, id: GlobalStateType) -> Option<&FieldName> {
        self.global_state
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn assignment_name(&self, id: AssignmentType) -> Option<&FieldName> {
        self.assignments
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn transition_name(&self, id: TransitionType) -> Option<&FieldName> {
        self.transitions
            .iter()
            .find(|nt| nt.id == id)
            .map(|nt| &nt.name)
    }

    pub fn error_name(&self, errno: u8) -> Option<&VariantName> {
        self.errors
            .iter()
            .find(|nt| nt.id == errno)
            .map(|nt| &nt.name)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ImplInconsistency {
    /// timestamp is invalid ({0}).
    InvalidTimestamp(i64),
    /// timestamp in the future ({0}).
    FutureTimestamp(DateTime<Utc>),

    /// interface metadata field '{0}' is not resolved by the implementation.
    IfaceMetaAbsent(FieldName),
    /// implementation metadata field '{0}' maps to an unknown schema metadata
    /// type {1}.
    SchemaMetaAbsent(FieldName, MetaType),

    /// interface global state field '{0}' is not resolved by the
    /// implementation.
    IfaceGlobalAbsent(FieldName),
    /// implementation global state field '{0}' maps to an unknown schema global
    /// state type {1}.
    SchemaGlobalAbsent(FieldName, GlobalStateType),

    /// interface owned state field '{0}' is not resolved by the
    /// implementation.
    IfaceAssignmentAbsent(FieldName),
    /// implementation owned state field '{0}' maps to an unknown schema owned
    /// state type {1}.
    SchemaAssignmentAbsent(FieldName, AssignmentType),

    /// interface valency field '{0}' is not resolved by the implementation.
    IfaceValencyAbsent(FieldName),
    /// implementation valency field '{0}' maps to an unknown schema valency
    /// {1}.
    SchemaValencyAbsent(FieldName, ValencyType),

    /// interface state transition name '{0}' is not resolved by the
    /// implementation.
    IfaceTransitionAbsent(FieldName),
    /// implementation state transition name '{0}' maps to an unknown schema
    /// state transition type {1}.
    SchemaTransitionAbsent(FieldName, TransitionType),

    /// interface state extension name '{0}' is not resolved by the
    /// implementation.
    IfaceExtensionAbsent(FieldName),
    /// implementation state extension name '{0}' maps to an unknown schema
    /// state extension type {1}.
    SchemaExtensionAbsent(FieldName, ExtensionType),

    /// implementation references unknown interface error '{0}'.
    IfaceErrorAbsent(VariantName),

    /// metadata field '{0}' is repeated {1} times
    RepeatedMetaData(FieldName, i32),

    /// global state field '{0}' is repeated {1} times
    RepeatedGlobalState(FieldName, i32),

    /// assignments field '{0}' is repeated {1} times
    RepeatedAssignments(FieldName, i32),

    /// valencies field '{0}' is repeated {1} times
    RepeatedValencies(FieldName, i32),

    /// transition field '{0}' is repeated {1} times
    RepeatedTransitions(FieldName, i32),

    /// extension field '{0}' is repeated {1} times
    RepeatedExtensions(FieldName, i32),
}

impl IfaceImpl {
    pub fn check(&self, iface: &Iface, schema: &Schema) -> Result<(), Vec<ImplInconsistency>> {
        let mut errors = vec![];
        let now = Utc::now();
        let mut dup_metadata = HashMap::new();
        let mut dup_global_state = HashMap::new();
        let mut dup_assignments = HashMap::new();
        let mut dup_valencies = HashMap::new();
        let mut dup_transitions = HashMap::new();
        let mut dup_extensions = HashMap::new();

        match Utc.timestamp_opt(self.timestamp, 0).single() {
            Some(ts) if ts > now => errors.push(ImplInconsistency::FutureTimestamp(ts)),
            None => errors.push(ImplInconsistency::InvalidTimestamp(self.timestamp)),
            _ => {}
        }

        for name in iface.metadata.keys() {
            if self.metadata.iter().all(|field| &field.name != name) {
                errors.push(ImplInconsistency::IfaceMetaAbsent(name.clone()));
            }
        }
        for field in &self.metadata {
            dup_metadata
                .entry(field.name.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(0);
            if !schema.meta_types.contains_key(&field.id) {
                errors.push(ImplInconsistency::SchemaMetaAbsent(field.name.clone(), field.id));
            }
        }

        dup_metadata
            .iter()
            .filter(|(_, &count)| count > 1)
            .for_each(|(field_name, &count)| {
                errors.push(ImplInconsistency::RepeatedMetaData(field_name.clone(), count));
            });

        for name in iface.global_state.keys() {
            if self.global_state.iter().all(|field| &field.name != name) {
                errors.push(ImplInconsistency::IfaceGlobalAbsent(name.clone()));
            }
        }
        for field in &self.global_state {
            dup_global_state
                .entry(field.name.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(0);
            if !schema.global_types.contains_key(&field.id) {
                errors.push(ImplInconsistency::SchemaGlobalAbsent(field.name.clone(), field.id));
            }
        }

        dup_global_state
            .iter()
            .filter(|(_, &count)| count > 1)
            .for_each(|(field_name, &count)| {
                errors.push(ImplInconsistency::RepeatedGlobalState(field_name.clone(), count));
            });

        for name in iface.assignments.keys() {
            if self.assignments.iter().all(|field| &field.name != name) {
                errors.push(ImplInconsistency::IfaceAssignmentAbsent(name.clone()));
            }
        }
        for field in &self.assignments {
            dup_assignments
                .entry(field.name.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(0);
            if !schema.owned_types.contains_key(&field.id) {
                errors
                    .push(ImplInconsistency::SchemaAssignmentAbsent(field.name.clone(), field.id));
            }
        }

        dup_assignments
            .iter()
            .filter(|(_, &count)| count > 1)
            .for_each(|(field_name, &count)| {
                errors.push(ImplInconsistency::RepeatedAssignments(field_name.clone(), count));
            });

        for name in iface.valencies.keys() {
            if self.valencies.iter().all(|field| &field.name != name) {
                errors.push(ImplInconsistency::IfaceValencyAbsent(name.clone()));
            }
        }
        for field in &self.valencies {
            dup_valencies
                .entry(field.name.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(0);

            if !schema.valency_types.contains(&field.id) {
                errors.push(ImplInconsistency::SchemaValencyAbsent(field.name.clone(), field.id));
            }
        }
        dup_valencies
            .iter()
            .filter(|(_, &count)| count > 1)
            .for_each(|(field_name, &count)| {
                errors.push(ImplInconsistency::RepeatedValencies(field_name.clone(), count));
            });

        for name in iface.transitions.keys() {
            if self.transitions.iter().all(|field| &field.name != name) {
                errors.push(ImplInconsistency::IfaceTransitionAbsent(name.clone()));
            }
        }
        for field in &self.transitions {
            dup_transitions
                .entry(field.name.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(0);

            if !schema.transitions.contains_key(&field.id) {
                errors
                    .push(ImplInconsistency::SchemaTransitionAbsent(field.name.clone(), field.id));
            }
        }

        dup_transitions
            .iter()
            .filter(|(_, &count)| count > 1)
            .for_each(|(field_name, &count)| {
                errors.push(ImplInconsistency::RepeatedTransitions(field_name.clone(), count));
            });

        for name in iface.extensions.keys() {
            if self.extensions.iter().all(|field| &field.name != name) {
                errors.push(ImplInconsistency::IfaceExtensionAbsent(name.clone()));
            }
        }
        for field in &self.extensions {
            dup_extensions
                .entry(field.name.clone())
                .and_modify(|counter| *counter += 1)
                .or_insert(0);

            if !schema.extensions.contains_key(&field.id) {
                errors.push(ImplInconsistency::SchemaExtensionAbsent(field.name.clone(), field.id));
            }
        }

        dup_extensions
            .iter()
            .filter(|(_, &count)| count > 1)
            .for_each(|(field_name, &count)| {
                errors.push(ImplInconsistency::RepeatedExtensions(field_name.clone(), count));
            });

        for var in &self.errors {
            if iface.errors.keys().all(|name| name != &var.name) {
                errors.push(ImplInconsistency::IfaceErrorAbsent(var.name.clone()));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
