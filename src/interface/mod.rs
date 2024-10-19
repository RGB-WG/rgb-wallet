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

//! RGB contract interface provides a mapping between identifiers of RGB schema-
//! defined contract state and operation types to a human-readable and
//! standardized wallet APIs.

mod iface;
mod iimpl;
mod contract;
mod builder;
mod filter;
pub(crate) mod resolver;
mod contractum;
mod inheritance;
mod calc;

pub use builder::{BuilderError, ContractBuilder, TransitionBuilder, TxOutpoint};
pub use calc::{AllocatedState, StateAbi, StateCalc, StateCalcError};
pub use contract::{ContractError, ContractIface, ContractOp, OpDirection, Output};
pub use contractum::IfaceDisplay;
pub use filter::{AssignmentsFilter, FilterExclude, FilterIncludeAll};
pub use iface::{
    ArgMap, AssignIface, ExtensionIface, GenesisIface, GlobalIface, Iface, IfaceClass, IfaceId,
    IfaceInconsistency, IfaceRef, IfaceWrapper, Modifier, OpName, Req, TransitionIface,
    ValencyIface,
};
pub use iimpl::{IfaceImpl, ImplId, NamedField, NamedType, NamedVariant, SchemaTypeIndex};
pub use inheritance::{CheckInheritance, ExtensionError, InheritanceFailure};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = crate::LIB_NAME_RGB_STD, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[non_exhaustive]
pub enum VerNo {
    #[display("v0", alt = "0")]
    V0 = 0,

    #[default]
    #[display("v1", alt = "1")]
    V1 = 1,
}
