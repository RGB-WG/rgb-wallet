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

use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use amplify::confinement::{SmallBlob, TinyOrdMap};
use amplify::{ByteArray, Bytes32};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use chrono::Utc;
use commit_verify::{CommitId, CommitmentId, DigestExt, Sha256};
use rgb::{AssignmentType, ContractId, GlobalStateType, Identity, SchemaId};
use strict_encoding::stl::{AlphaCaps, AlphaNumDash};
use strict_encoding::{
    DeserializeError, FieldName, RString, SerializeError, StrictDeserialize, StrictSerialize,
    TypeName, VariantName,
};
use strict_types::value;

use crate::interface::{IfaceId, ImplId};
use crate::LIB_NAME_RGB_STD;

pub const SUPPL_ANNOT_VELOCITY: &str = "Velocity";
pub const SUPPL_ANNOT_IFACE_CLASS: &str = "Standard";
pub const SUPPL_ANNOT_IFACE_FEATURES: &str = "Features";

/// Contract supplement identifier.
///
/// Contract supplement identifier commits to all of the supplement data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
pub struct SupplId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for SupplId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for SupplId {
    const TAG: &'static str = "urn:lnp-bp:rgb:suppl#2024-03-11";
}

impl DisplayBaid64 for SupplId {
    const HRI: &'static str = "rgb:sup";
    const CHUNKING: bool = false;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for SupplId {}
impl FromStr for SupplId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for SupplId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(SupplId);

impl SupplId {
    pub const fn from_array(id: [u8; 32]) -> Self { Self(Bytes32::from_array(id)) }
}

#[derive(Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From, Display)]
#[wrapper(Deref, FromStr)]
#[display(inner)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AnnotationName(RString<AlphaCaps, AlphaNumDash>);

impl From<&'static str> for AnnotationName {
    fn from(s: &'static str) -> Self { Self(RString::from(s)) }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From)]
#[display(inner)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = order, dumb = ContentRef::Schema(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum ContentRef {
    #[from]
    Schema(SchemaId),
    #[from]
    Genesis(ContractId),
    #[from]
    Iface(IfaceId),
    #[from]
    IfaceImpl(ImplId),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum SupplSub {
    #[default]
    Itself = 0,
    Meta = 1,
    Global,
    Owned,
    Valency,
    Assignment,
    Genesis,
    Transition,
    Extension,
    Exception,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum SupplItem {
    #[default]
    #[strict_type(tag = 0)]
    Default,
    #[strict_type(tag = 1)]
    TypeNo(u16),
    #[strict_type(tag = 0x11)]
    TypeName(TypeName),
    #[strict_type(tag = 0x12)]
    FieldName(FieldName),
    #[strict_type(tag = 0x13)]
    VariantName(VariantName),
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct SupplMap(TinyOrdMap<SupplItem, Annotations>);

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Annotations(TinyOrdMap<AnnotationName, SmallBlob>);

/// Contract supplement, providing non-consensus information about standard
/// way of working with the contract data. Each contract can have only a single
/// valid supplement; the supplement is attached to the contract via trusted
/// provider signature (providers are ordered by the priority).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = SupplId)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Supplement {
    pub content_id: ContentRef,
    pub timestamp: i64,
    pub creator: Identity,
    /// Strict-encoded custom fields.
    pub annotations: TinyOrdMap<SupplSub, SupplMap>,
}

impl StrictSerialize for Supplement {}
impl StrictDeserialize for Supplement {}

impl Supplement {
    pub fn suppl_id(&self) -> SupplId { self.commit_id() }

    pub fn new(content: impl Into<ContentRef>, creator: impl Into<Identity>) -> Self {
        Supplement {
            content_id: content.into(),
            timestamp: Utc::now().timestamp(),
            creator: creator.into(),
            annotations: none!(),
        }
    }

    pub fn with(
        content: impl Into<ContentRef>,
        creator: impl Into<Identity>,
        timestamp: i64,
    ) -> Self {
        Supplement {
            content_id: content.into(),
            timestamp,
            creator: creator.into(),
            annotations: none!(),
        }
    }

    pub fn get_default_opt<T: StrictDeserialize>(
        &self,
        sub: SupplSub,
        name: impl Into<AnnotationName>,
    ) -> Option<T> {
        self.get_default(sub, name).transpose().ok().flatten()
    }

    pub fn get_default<T: StrictDeserialize>(
        &self,
        sub: SupplSub,
        name: impl Into<AnnotationName>,
    ) -> Option<Result<T, DeserializeError>> {
        let annotation = self
            .annotations
            .get(&sub)?
            .get(&SupplItem::Default)?
            .get(&name.into())?;
        Some(T::from_strict_serialized(annotation.clone()))
    }

    pub fn get<T: StrictDeserialize>(
        &self,
        sub: SupplSub,
        item: SupplItem,
        name: impl Into<AnnotationName>,
    ) -> Option<Result<T, DeserializeError>> {
        let annotation = self.annotations.get(&sub)?.get(&item)?.get(&name.into())?;
        Some(T::from_strict_serialized(annotation.clone()))
    }

    pub fn annotate_itself(
        &mut self,
        name: impl Into<AnnotationName>,
        data: &impl StrictSerialize,
    ) -> Result<bool, SerializeError> {
        self.annotate_default(SupplSub::Itself, name, data)
    }

    pub fn annotate_default(
        &mut self,
        sub: SupplSub,
        name: impl Into<AnnotationName>,
        data: &impl StrictSerialize,
    ) -> Result<bool, SerializeError> {
        self.annotate(sub, SupplItem::Default, name, data)
    }

    pub fn annotate(
        &mut self,
        sub: SupplSub,
        item: SupplItem,
        name: impl Into<AnnotationName>,
        data: &impl StrictSerialize,
    ) -> Result<bool, SerializeError> {
        let mut a = self
            .annotations
            .remove(&sub)
            .expect("zero items allowed")
            .unwrap_or_default();
        let mut b = a
            .remove(&item)
            .expect("zero items allowed")
            .unwrap_or_default();
        let prev = b.insert(name.into(), data.to_strict_serialized()?)?;
        a.insert(item, b)?;
        self.annotations.insert(sub, a)?;
        Ok(prev.is_some())
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TickerSuppl {
    #[strict_type(tag = 0, dumb)]
    Absent,
    #[strict_type(tag = 1)]
    Global(GlobalStateType, value::Path),
    #[strict_type(tag = 2)]
    Owned(AssignmentType, value::Path),
}

impl StrictSerialize for TickerSuppl {}
impl StrictDeserialize for TickerSuppl {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = repr, try_from_u8, into_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
#[repr(u8)]
pub enum VelocityHint {
    #[default]
    Unspecified = 0,
    /// Should be used for thinks like secondary issuance for tokens which do
    /// not inflate very often.
    Seldom = 15,
    /// Should be used for digital identity revocations.
    Episodic = 31,
    /// Should be used for digital art, shares, bonds etc.
    Regular = 63,
    /// Should be used for fungible tokens.
    Frequent = 127,
    /// Should be used for stablecoins and money.
    HighFrequency = 255,
}

impl StrictSerialize for VelocityHint {}
impl StrictDeserialize for VelocityHint {}

impl VelocityHint {
    pub fn with_value(value: &u8) -> Self {
        match *value {
            0 => VelocityHint::Unspecified,
            1..=15 => VelocityHint::Seldom,
            16..=31 => VelocityHint::Episodic,
            32..=63 => VelocityHint::Regular,
            64..=127 => VelocityHint::Frequent,
            128..=255 => VelocityHint::HighFrequency,
        }
    }
}
