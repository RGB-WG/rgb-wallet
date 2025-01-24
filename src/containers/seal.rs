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

#![doc = include_str!("seals.md")]

use bp::seals::txout::{BlindSeal, CloseMethod, SealTxid};
use bp::secp256k1::rand::{thread_rng, RngCore};
use bp::Vout;
use rgb::{GraphSeal, Layer1, SecretSeal, TxoSeal, XChain};

use crate::LIB_NAME_RGB_STD;

/// Seal definition which re-uses witness transaction id of some other seal,
/// which is not known at the moment of seal construction. Thus, the definition
/// has only information about output number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct VoutSeal {
    /// Commitment to the specific seal close method [`CloseMethod`] which must
    /// be used to close this seal.
    pub method: CloseMethod,

    /// Tx output number, which should be always known.
    pub vout: Vout,

    /// Blinding factor providing confidentiality of the seal definition.
    /// Prevents rainbow table bruteforce attack based on the existing
    /// blockchain txid set.
    pub blinding: u64,
}

impl VoutSeal {
    /// Creates new seal definition for the provided output number and seal
    /// closing method. Uses `thread_rng` to initialize blinding factor.
    #[inline]
    pub fn new(method: CloseMethod, vout: impl Into<Vout>) -> Self {
        VoutSeal::with(method, vout, thread_rng().next_u64())
    }

    /// Creates new opret-seal seal definition for the provided output number
    /// and seal closing method. Uses `thread_rng` to initialize blinding
    /// factor.
    #[inline]
    pub fn new_opret(vout: impl Into<Vout>) -> Self { VoutSeal::new(CloseMethod::OpretFirst, vout) }

    /// Creates new tapret-seal seal definition for the provided output number
    /// and seal closing method. Uses `thread_rng` to initialize blinding
    /// factor.
    #[inline]
    pub fn new_tapret(vout: impl Into<Vout>) -> Self {
        VoutSeal::new(CloseMethod::TapretFirst, vout)
    }

    /// Reconstructs previously defined opret seal given an output number and a
    /// previously generated blinding factor.
    #[inline]
    pub fn with_opret(vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal::with(CloseMethod::OpretFirst, vout, blinding)
    }

    /// Reconstructs previously defined tapret seal given an output number and a
    /// previously generated blinding factor.
    #[inline]
    pub fn with_tapret(vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal::with(CloseMethod::TapretFirst, vout, blinding)
    }

    /// Reconstructs previously defined seal given method, an output number and
    /// a previously generated blinding factor.
    #[inline]
    pub fn with(method: CloseMethod, vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal {
            method,
            vout: vout.into(),
            blinding,
        }
    }
}

impl From<VoutSeal> for GraphSeal {
    fn from(seal: VoutSeal) -> Self { Self::with_blinded_vout(seal.vout, seal.blinding) }
}

/// Seal used by operation builder which can be either revealed or concealed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
pub enum BuilderSeal<Seal: TxoSeal + Ord> {
    Revealed(XChain<Seal>),
    #[from]
    Concealed(XChain<SecretSeal>),
}

impl<Id: SealTxid> From<XChain<BlindSeal<Id>>> for BuilderSeal<BlindSeal<Id>> {
    fn from(seal: XChain<BlindSeal<Id>>) -> Self { BuilderSeal::Revealed(seal) }
}

impl<Seal: TxoSeal + Ord> BuilderSeal<Seal> {
    pub fn layer1(&self) -> Layer1 {
        match self {
            BuilderSeal::Revealed(x) => x.layer1(),
            BuilderSeal::Concealed(x) => x.layer1(),
        }
    }
}
