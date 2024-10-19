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

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate core;
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;
#[macro_use]
extern crate rgbcore as rgb;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

/// Re-exporting all invoice data types (RGB and BP).
pub extern crate rgbinvoice as invoice;

pub mod stl;
pub mod interface;
pub mod containers;
pub mod persistence;
pub mod resolvers;
mod contract;
pub mod info;

pub use bp::{Outpoint, Txid};
pub use contract::{Allocation, MergeReveal, MergeRevealError, WitnessInfo};
pub use rgb::prelude::*;
pub use rgb::rgbasm;
pub use stl::{LIB_NAME_RGB_STD, LIB_NAME_RGB_STORAGE};

/// BIP32 derivation index for outputs which may contain assigned RGB state.
pub const RGB_NATIVE_DERIVATION_INDEX: u32 = 9;
/// BIP32 derivation index for outputs which are tweaked with Tapret commitment
/// and may also optionally contain assigned RGB state.
pub const RGB_TAPRET_DERIVATION_INDEX: u32 = 10;
