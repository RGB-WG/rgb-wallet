// RGB wallet library for smart contracts on Bitcoin & Lightning network
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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
extern crate rgbcore as rgb;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

/// Re-exporting BP invoice data types.
pub use ::invoice::*;

#[allow(clippy::module_inception)]
mod invoice;
mod parse;
mod builder;
mod amount;
mod data;

pub use amount::{Amount, AmountParseError, CoinAmount, Precision, PrecisionError};
pub use builder::RgbInvoiceBuilder;
pub use data::{Allocation, NonFungible, OwnedFraction, TokenIndex};
pub use parse::{InvoiceParseError, TransportParseError};

pub use crate::invoice::{
    Beneficiary, InvoiceState, Pay2Vout, Pay2VoutError, RgbInvoice, RgbTransport, XChainNet,
};

pub const LIB_NAME_RGB_CONTRACT: &str = "RGBContract";
