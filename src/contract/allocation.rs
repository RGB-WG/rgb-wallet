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
use std::fmt::Debug;
use std::hash::Hash;

use rgb::vm::WitnessOrd;
use rgb::{AssignmentType, ExposedSeal, OpId, Opout, State, XChain, XOutputSeal, XWitnessId};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::LIB_NAME_RGB_STD;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WitnessInfo {
    pub id: XWitnessId,
    pub ord: WitnessOrd,
}

/// Allocation is an owned state assignment, equipped with information about the operation defining
/// the assignment and the witness id, containing the commitment to the operation.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Allocation {
    pub opout: Opout,
    pub seal: XOutputSeal,
    pub state: State,
    pub witness: Option<XWitnessId>,
}

impl PartialEq for Allocation {
    fn eq(&self, other: &Self) -> bool {
        // We ignore difference in witness transactions, state and seal definitions here
        // in order to support updates from the ephemeral state of the lightning
        // channels. See <https://github.com/RGB-WG/rgb-std/issues/238#issuecomment-2283822128>
        // for the details.
        let res = self.opout == other.opout && self.seal == other.seal;
        #[cfg(debug_assertions)]
        if res {
            debug_assert_eq!(self.state, other.state);
        }
        res
    }
}

impl PartialOrd for Allocation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for Allocation {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match self.opout.cmp(&other.opout) {
            Ordering::Equal => self.seal.cmp(&other.seal),
            ordering => ordering,
        }
    }
}

impl Allocation {
    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_witness<Seal: ExposedSeal>(
        seal: XChain<Seal>,
        witness_id: XWitnessId,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        Allocation {
            opout: Opout::new(opid, ty, no),
            seal: seal.try_to_output_seal(witness_id).expect(
                "processing contract from unverified/invalid stash: witness seal chain doesn't \
                 match anchor's chain",
            ),
            state,
            witness: witness_id.into(),
        }
    }

    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_no_witness<Seal: ExposedSeal>(
        seal: XChain<Seal>,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        Allocation {
            opout: Opout::new(opid, ty, no),
            seal: seal.to_output_seal().expect(
                "processing contract from unverified/invalid stash: seal must have txid \
                 information since it comes from genesis or extension",
            ),
            state,
            witness: None,
        }
    }

    pub fn check_witness(&self, filter: &HashMap<XWitnessId, WitnessOrd>) -> bool {
        match self.witness {
            None => true,
            Some(witness_id) => {
                !matches!(filter.get(&witness_id), None | Some(WitnessOrd::Archived))
            }
        }
    }
}
