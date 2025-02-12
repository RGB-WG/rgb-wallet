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
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

use amplify::confinement::{Confined, NonEmptyOrdMap, U24};
use bp::Outpoint;
use rgb::{ContractId, OpId, Operation, OutputSeal, Transition, TransitionBundle, Txid};
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, StrictType,
};

use crate::containers::{AnchorSet, PubWitness};
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionInfo {
    pub id: OpId,
    pub inputs: Confined<BTreeSet<Outpoint>, 1, U24>,
    pub transition: Transition,
}

impl StrictDumb for TransitionInfo {
    fn strict_dumb() -> Self { Self::new(strict_dumb!(), [strict_dumb!()]).unwrap() }
}

impl PartialEq for TransitionInfo {
    fn eq(&self, other: &Self) -> bool { self.id.eq(&other.id) }
}

impl Ord for TransitionInfo {
    fn cmp(&self, other: &Self) -> Ordering { self.id.cmp(&other.id) }
}

impl PartialOrd for TransitionInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Hash for TransitionInfo {
    fn hash<H: Hasher>(&self, state: &mut H) { state.write(self.id.as_slice()) }
}

impl TransitionInfo {
    /// # Panics
    ///
    /// If the number of provided seals is zero.
    pub fn new(
        transition: Transition,
        seals: impl AsRef<[OutputSeal]>,
    ) -> Result<Self, TransitionInfoError> {
        let id = transition.id();
        let seals = seals.as_ref();
        assert!(!seals.is_empty(), "empty seals provided to transition info constructor");
        let inputs = Confined::<BTreeSet<_>, 1, U24>::try_from_iter(
            seals.iter().copied().map(Outpoint::from),
        )
        .map_err(|_| TransitionInfoError::TooMany(id))?;
        Ok(TransitionInfo {
            id,
            inputs,
            transition,
        })
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum TransitionInfoError {
    /// the operation produces too many state transitions which can't fit the
    /// container requirements.
    TooMany(OpId),
}

/// A batch of state transitions under different contracts which are associated
/// with some specific transfer and will be anchored within a single layer 1
/// transaction.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Batch {
    pub main: TransitionInfo,
    pub blanks: Confined<Vec<TransitionInfo>, 0, { U24 - 1 }>,
}

impl StrictSerialize for Batch {}
impl StrictDeserialize for Batch {}

impl IntoIterator for Batch {
    type Item = TransitionInfo;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = self.blanks.release();
        vec.push(self.main);
        vec.into_iter()
    }
}

impl Batch {
    pub fn set_priority(&mut self, priority: u64) {
        self.main.transition.nonce = priority;
        for info in &mut self.blanks {
            info.transition.nonce = priority;
        }
    }
}

/// Structure exported from a PSBT for merging into the stash. It contains a set
/// of finalized state transitions (under multiple contracts), packed into
/// bundles, and anchored to a single layer 1 transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Fascia {
    pub witness: PubWitness,
    pub anchor: AnchorSet,
    pub bundles: NonEmptyOrdMap<ContractId, TransitionBundle, U24>,
}

impl StrictDumb for Fascia {
    fn strict_dumb() -> Self {
        Fascia {
            witness: strict_dumb!(),
            anchor: strict_dumb!(),
            bundles: NonEmptyOrdMap::with_key_value(strict_dumb!(), strict_dumb!()),
        }
    }
}
impl StrictSerialize for Fascia {}
impl StrictDeserialize for Fascia {}

impl Fascia {
    pub fn witness_id(&self) -> Txid { self.witness.txid() }

    pub fn into_bundles(self) -> impl IntoIterator<Item = (ContractId, TransitionBundle)> {
        self.bundles.into_iter()
    }
}
