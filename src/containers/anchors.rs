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

use amplify::ByteArray;
use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::dbc::{anchor, Anchor};
use bp::{dbc, Tx, Txid};
use commit_verify::mpc;
use rgb::validation::{DbcProof, EAnchor};
use rgb::{BundleId, DiscloseHash, GraphSeal, OpId, Operation, Transition, TransitionBundle};
use strict_encoding::StrictDumb;

use crate::{MergeReveal, MergeRevealError, TypedAssignsExt, LIB_NAME_RGB_STD};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("state transition {0} is not a part of the bundle.")]
pub struct UnrelatedTransition(OpId, Transition);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum AnchoredBundleMismatch {
    /// witness bundle for witness id {0} already has both opret and tapret information.
    AlreadyDouble(Txid),
    /// the combined anchored bundles for witness id {0} are of the same type.
    SameBundleType(Txid),
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SealWitness {
    pub public: PubWitness,
    pub anchor: AnchorSet,
}

impl SealWitness {
    pub fn new(witness: PubWitness, anchor: AnchorSet) -> Self {
        SealWitness {
            public: witness,
            anchor,
        }
    }

    pub fn witness_id(&self) -> Txid { self.public.to_witness_id() }
}

pub trait ToWitnessId {
    fn to_witness_id(&self) -> Txid;
}

impl ToWitnessId for PubWitness {
    fn to_witness_id(&self) -> Txid { self.txid() }
}

impl MergeReveal for PubWitness {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        self.merge_reveal(other)
    }
}

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom, dumb = Self::Txid(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum PubWitness {
    #[strict_type(tag = 0x00)]
    Txid(Txid),
    #[strict_type(tag = 0x01)]
    Tx(Tx), /* TODO: Consider using `UnsignedTx` here
             * TODO: Add SPV as an option here */
}

impl PartialEq for PubWitness {
    fn eq(&self, other: &Self) -> bool { self.txid() == other.txid() }
}

impl Ord for PubWitness {
    fn cmp(&self, other: &Self) -> Ordering { self.txid().cmp(&other.txid()) }
}

impl PartialOrd for PubWitness {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl PubWitness {
    pub fn new(txid: Txid) -> Self { Self::Txid(txid) }

    pub fn with(tx: Tx) -> Self { Self::Tx(tx) }

    pub fn txid(&self) -> Txid {
        match self {
            PubWitness::Txid(txid) => *txid,
            PubWitness::Tx(tx) => tx.txid(),
        }
    }

    pub fn tx(&self) -> Option<&Tx> {
        match self {
            PubWitness::Txid(_) => None,
            PubWitness::Tx(tx) => Some(tx),
        }
    }

    pub fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        match (self, other) {
            (Self::Txid(txid1), Self::Txid(txid2)) if txid1 == txid2 => Ok(Self::Txid(txid1)),
            (Self::Txid(txid), Self::Tx(tx)) | (Self::Txid(txid), Self::Tx(tx))
                if txid == tx.txid() =>
            {
                Ok(Self::Tx(tx))
            }
            // TODO: tx1 and tx2 may differ on their witness data; take the one having most of the
            // witness
            (Self::Tx(tx1), Self::Tx(tx2)) if tx1.txid() == tx2.txid() => Ok(Self::Tx(tx1)),
            (a, b) => Err(MergeRevealError::TxidMismatch(a.txid(), b.txid())),
        }
    }
}

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = DiscloseHash)]
pub struct WitnessBundle {
    pub pub_witness: PubWitness,
    pub anchored_bundle: AnchoredBundle,
}

impl PartialEq for WitnessBundle {
    fn eq(&self, other: &Self) -> bool { self.pub_witness == other.pub_witness }
}

impl Ord for WitnessBundle {
    fn cmp(&self, other: &Self) -> Ordering { self.pub_witness.cmp(&other.pub_witness) }
}

impl PartialOrd for WitnessBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl WitnessBundle {
    #[inline]
    pub fn with(pub_witness: PubWitness, anchored_bundle: ClientBundle) -> Self {
        Self {
            pub_witness,
            anchored_bundle: AnchoredBundle::from(anchored_bundle),
        }
    }

    pub fn witness_id(&self) -> Txid { self.pub_witness.to_witness_id() }

    pub fn reveal_seal(&mut self, bundle_id: BundleId, seal: GraphSeal) -> bool {
        let bundle = match &mut self.anchored_bundle {
            AnchoredBundle::Tapret(tapret) if tapret.bundle.bundle_id() == bundle_id => {
                Some(&mut tapret.bundle)
            }
            AnchoredBundle::Opret(opret) if opret.bundle.bundle_id() == bundle_id => {
                Some(&mut opret.bundle)
            }
            _ => None,
        };
        let Some(bundle) = bundle else {
            return false;
        };
        bundle
            .known_transitions
            .values_mut()
            .flat_map(|t| t.assignments.values_mut())
            .for_each(|a| a.reveal_seal(seal));

        true
    }

    pub fn anchored_bundle(&self) -> &AnchoredBundle { &self.anchored_bundle }

    pub fn bundle(&self) -> &TransitionBundle { self.anchored_bundle.bundle() }

    #[inline]
    pub fn known_transitions(&self) -> impl Iterator<Item = &Transition> {
        self.anchored_bundle.bundle().known_transitions.values()
    }
}

/// Keeps client-side data - a combination of client-side witness (anchor) and state (transition
/// bundle). Ensures that transition bundle uses the same DBC close method as used by the
/// client-side witness (anchor).
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ClientBundle<D: dbc::Proof = DbcProof> {
    mpc_proof: mpc::MerkleProof,
    dbc_proof: D,
    bundle: TransitionBundle,
}

impl<D: dbc::Proof> ClientBundle<D> {
    /// # Panics
    ///
    /// Panics if DBC proof and bundle have different closing methods
    pub fn new(mpc_proof: mpc::MerkleProof, dbc_proof: D, bundle: TransitionBundle) -> Self {
        Self {
            mpc_proof,
            dbc_proof,
            bundle,
        }
    }

    #[inline]
    pub fn bundle_id(&self) -> BundleId { self.bundle.bundle_id() }

    pub fn reveal_transition(
        &mut self,
        transition: Transition,
    ) -> Result<bool, UnrelatedTransition> {
        let opid = transition.id();
        if self.bundle.input_map.values().all(|id| *id != opid) {
            return Err(UnrelatedTransition(opid, transition));
        }
        if self.bundle.known_transitions.contains_key(&opid) {
            return Ok(false);
        }
        self.bundle
            .known_transitions
            .insert(opid, transition)
            .expect("same size as input map");
        Ok(true)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AnchoredBundle {
    #[strict_type(tag = 0x01)]
    Tapret(ClientBundle<TapretProof>),
    #[strict_type(tag = 0x02)]
    Opret(ClientBundle<OpretProof>),
}

impl StrictDumb for AnchoredBundle {
    fn strict_dumb() -> Self { Self::Opret(strict_dumb!()) }
}

impl From<ClientBundle> for AnchoredBundle {
    fn from(ab: ClientBundle) -> Self {
        match ab.dbc_proof {
            DbcProof::Opret(proof) => {
                Self::Opret(ClientBundle::<OpretProof>::new(ab.mpc_proof, proof, ab.bundle))
            }
            DbcProof::Tapret(proof) => {
                Self::Tapret(ClientBundle::<TapretProof>::new(ab.mpc_proof, proof, ab.bundle))
            }
        }
    }
}

impl AnchoredBundle {
    pub fn bundle(&self) -> &TransitionBundle {
        match self {
            AnchoredBundle::Tapret(tapret) => &tapret.bundle,
            AnchoredBundle::Opret(opret) => &opret.bundle,
        }
    }

    pub fn into_bundle(self) -> TransitionBundle {
        match self {
            AnchoredBundle::Tapret(tapret) => tapret.bundle,
            AnchoredBundle::Opret(opret) => opret.bundle,
        }
    }

    pub fn eanchor(&self) -> EAnchor {
        match self {
            AnchoredBundle::Tapret(tapret) => {
                EAnchor::new(tapret.mpc_proof.clone(), tapret.dbc_proof.clone().into())
            }
            AnchoredBundle::Opret(opret) => {
                EAnchor::new(opret.mpc_proof.clone(), opret.dbc_proof.into())
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AnchorSet {
    #[strict_type(tag = 0x01)]
    Tapret(Anchor<mpc::MerkleBlock, TapretProof>),
    #[strict_type(tag = 0x02)]
    Opret(Anchor<mpc::MerkleBlock, OpretProof>),
}

impl StrictDumb for AnchorSet {
    fn strict_dumb() -> Self { Self::Opret(strict_dumb!()) }
}

impl AnchorSet {
    pub fn known_bundle_ids(&self) -> impl Iterator<Item = BundleId> {
        let map = match self {
            AnchorSet::Tapret(tapret) => tapret.mpc_proof.to_known_message_map().release(),
            AnchorSet::Opret(opret) => opret.mpc_proof.to_known_message_map().release(),
        };
        map.into_values()
            .map(|msg| BundleId::from_byte_array(msg.to_byte_array()))
    }

    pub fn merge_reveal(self, other: Self) -> Result<Self, anchor::MergeError> {
        match (self, other) {
            (Self::Tapret(anchor), Self::Tapret(a)) => Ok(Self::Tapret(anchor.merge_reveal(a)?)),
            (Self::Opret(anchor), Self::Opret(a)) => Ok(Self::Opret(anchor.merge_reveal(a)?)),
            _ => Err(anchor::MergeError::DbcMismatch),
        }
    }
}
