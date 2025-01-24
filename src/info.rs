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
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use amplify::confinement::TinyOrdSet;
use bp::seals::txout::CloseMethod;
use chrono::{DateTime, TimeZone, Utc};
use rgb::{ContractId, Genesis, Identity, Layer1, Operation, SchemaId};
use strict_encoding::stl::{AlphaCapsLodash, AlphaNumLodash};
use strict_encoding::{FieldName, RString, StrictDeserialize, StrictSerialize, TypeName};

use crate::containers::{
    SupplSub, Supplement, SUPPL_ANNOT_IFACE_CLASS, SUPPL_ANNOT_IFACE_FEATURES,
};
use crate::interface::{Iface, IfaceId, IfaceImpl, IfaceRef, ImplId, VerNo};
use crate::persistence::SchemaIfaces;
use crate::LIB_NAME_RGB_STD;

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, From)]
#[wrapper(Deref, Display, FromStr)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct IfaceClassName(RString<AlphaCapsLodash, AlphaNumLodash, 1, 64>);

impl_ident_type!(IfaceClassName);
impl_ident_subtype!(IfaceClassName);
impl_strict_newtype!(IfaceClassName, LIB_NAME_RGB_STD);

impl StrictSerialize for IfaceClassName {}
impl StrictDeserialize for IfaceClassName {}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct FeatureList(TinyOrdSet<FieldName>);

impl StrictSerialize for FeatureList {}
impl StrictDeserialize for FeatureList {}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfaceInfo {
    pub id: IfaceId,
    pub version: VerNo,
    pub name: TypeName,
    pub standard: Option<IfaceClassName>,
    pub features: FeatureList,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
    pub inherits: Vec<IfaceRef>,
    pub default_op: Option<FieldName>,
}

impl IfaceInfo {
    pub fn new(
        iface: &Iface,
        names: &HashMap<IfaceId, TypeName>,
        suppl: Option<&Supplement>,
    ) -> Self {
        let mut standard = None;
        let mut features = none!();
        if let Some(suppl) = suppl {
            standard =
                suppl.get_default_opt::<IfaceClassName>(SupplSub::Itself, SUPPL_ANNOT_IFACE_CLASS);
            if let Some(list) =
                suppl.get_default_opt::<FeatureList>(SupplSub::Itself, SUPPL_ANNOT_IFACE_FEATURES)
            {
                features = list
            };
        }
        Self::with(iface, standard, features, names)
    }

    pub fn with(
        iface: &Iface,
        standard: Option<IfaceClassName>,
        features: FeatureList,
        names: &HashMap<IfaceId, TypeName>,
    ) -> Self {
        IfaceInfo {
            id: iface.iface_id(),
            version: iface.version,
            name: iface.name.clone(),
            standard,
            features,
            developer: iface.developer.clone(),
            created_at: Utc
                .timestamp_opt(iface.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
            inherits: iface
                .inherits
                .iter()
                .map(|id| {
                    names
                        .get(id)
                        .cloned()
                        .map(IfaceRef::Name)
                        .unwrap_or(IfaceRef::Id(*id))
                })
                .collect(),
            default_op: iface.default_operation.clone(),
        }
    }
}

impl Display for IfaceInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t",
            self.standard
                .as_ref()
                .map(IfaceClassName::to_string)
                .unwrap_or_else(|| s!("~"))
        )?;
        write!(f, "{: <40}\t", self.name.to_string())?;
        write!(f, "{}\t", self.created_at.format("%Y-%m-%d"))?;
        write!(f, "{}\t", self.version)?;
        writeln!(f, "{}", self.id)?;

        writeln!(
            f,
            "  Features:    {}",
            self.features
                .iter()
                .map(FieldName::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )?;

        writeln!(
            f,
            "  Defaults to: {}",
            self.default_op
                .as_ref()
                .map(FieldName::to_string)
                .unwrap_or_else(|| s!("~"))
        )?;

        writeln!(f, "  Developer:   {}", self.developer)?;

        writeln!(
            f,
            "  Inherits:    {}",
            self.inherits
                .iter()
                .map(|f| format!("{:#}", f))
                .collect::<Vec<_>>()
                .chunks(5)
                .map(|chunk| chunk.join(", "))
                .collect::<Vec<_>>()
                .join("\n               ")
        )
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SchemaInfo {
    pub id: SchemaId,
    pub name: TypeName,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
    pub implements: Vec<ImplInfo>,
}

impl SchemaInfo {
    pub fn with(schema_ifaces: &SchemaIfaces) -> Self {
        let schema = &schema_ifaces.schema;
        SchemaInfo {
            id: schema.schema_id(),
            name: schema.name.clone(),
            developer: schema.developer.clone(),
            created_at: Utc
                .timestamp_opt(schema.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
            implements: schema_ifaces
                .iimpls
                .iter()
                .map(|(name, iimpl)| ImplInfo::with(name.clone(), iimpl))
                .collect(),
        }
    }
}

impl Display for SchemaInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{: <24}", self.name.to_string())?;
        write!(f, "\t{: <80}", self.id.to_string())?;
        write!(f, "\t{}", self.created_at.format("%Y-%m-%d"))?;
        writeln!(f, "\t{}", self.developer)?;
        for info in &self.implements {
            write!(f, "  {info}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ImplInfo {
    pub id: ImplId,
    pub iface_id: IfaceId,
    pub iface_name: TypeName,
    pub developer: Identity,
    pub created_at: DateTime<Utc>,
}

impl ImplInfo {
    pub fn with(iface_name: TypeName, iimpl: &IfaceImpl) -> Self {
        ImplInfo {
            id: iimpl.impl_id(),
            iface_id: iimpl.iface_id,
            iface_name,
            developer: iimpl.developer.clone(),
            created_at: Utc
                .timestamp_opt(iimpl.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
        }
    }
}

impl Display for ImplInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{: <24}", self.iface_name.to_string())?;
        write!(f, "\t{: <80}", self.id.to_string())?;
        write!(f, "\t{}", self.created_at.format("%Y-%m-%d"))?;
        writeln!(f, "\t{}", self.developer)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractInfo {
    pub id: ContractId,
    pub schema_id: SchemaId,
    pub issuer: Identity,
    pub issued_at: DateTime<Utc>,
    pub layer1: Layer1,
    pub testnet: bool,
    pub close_method: CloseMethod,
}

impl ContractInfo {
    pub fn with(genesis: &Genesis) -> Self {
        ContractInfo {
            id: genesis.contract_id(),
            schema_id: genesis.schema_id,
            issuer: genesis.issuer.clone(),
            issued_at: Utc
                .timestamp_opt(genesis.timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now),
            layer1: genesis.layer1,
            testnet: genesis.testnet,
            close_method: genesis.close_method,
        }
    }
}

impl Display for ContractInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)?;
        write!(f, "\t{} ({})", self.layer1, self.close_method)?;
        write!(f, "\t{}", self.issued_at.format("%Y-%m-%d"))?;
        writeln!(f, "\t{: <80}", self.schema_id.to_string())?;
        writeln!(f, "  Developer: {}", self.issuer)
    }
}
