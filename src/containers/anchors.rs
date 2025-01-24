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
use std::vec;

use amplify::ByteArray;
use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::dbc::{anchor, Anchor};
use bp::{dbc, Tx, Txid};
use commit_verify::mpc;
use rgb::validation::{DbcProof, EAnchor};
use rgb::{
    BundleId, DiscloseHash, OpId, Operation, Transition, TransitionBundle, XChain, XGraphSeal,
    XWitnessId,
};
use strict_encoding::StrictDumb;

use crate::containers::Dichotomy;
use crate::{MergeReveal, MergeRevealError, TypedAssignsExt, LIB_NAME_RGB_STD};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("state transition {0} is not a part of the bundle.")]
pub struct UnrelatedTransition(OpId, Transition);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum AnchoredBundleMismatch {
    /// witness bundle for witness id {0} already has both opret and tapret information.
    AlreadyDouble(XWitnessId),
    /// the combined anchored bundles for witness id {0} are of the same type.
    SameBundleType(XWitnessId),
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
    pub public: XPubWitness,
    pub anchors: AnchorSet,
}

impl SealWitness {
    pub fn new(witness: XPubWitness, anchors: AnchorSet) -> Self {
        SealWitness {
            public: witness,
            anchors,
        }
    }

    pub fn witness_id(&self) -> XWitnessId { self.public.to_witness_id() }
}

pub type XPubWitness = XChain<PubWitness>;

pub trait ToWitnessId {
    fn to_witness_id(&self) -> XWitnessId;
}

impl ToWitnessId for XPubWitness {
    fn to_witness_id(&self) -> XWitnessId { self.map_ref(|w| w.txid()) }
}

impl MergeReveal for XPubWitness {
    fn merge_reveal(self, other: Self) -> Result<Self, MergeRevealError> {
        match (self, other) {
            (XChain::Bitcoin(one), XChain::Bitcoin(two)) => {
                one.merge_reveal(two).map(XChain::Bitcoin)
            }
            (XChain::Liquid(one), XChain::Liquid(two)) => one.merge_reveal(two).map(XChain::Liquid),
            (XChain::Bitcoin(bitcoin), XChain::Liquid(liquid))
            | (XChain::Liquid(liquid), XChain::Bitcoin(bitcoin)) => {
                Err(MergeRevealError::ChainMismatch {
                    bitcoin: bitcoin.txid(),
                    liquid: liquid.txid(),
                })
            }
            _ => unreachable!(),
        }
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
    pub pub_witness: XPubWitness,
    pub anchored_bundles: AnchoredBundles,
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
    pub fn with(pub_witness: XPubWitness, anchored_bundle: ClientBundle) -> Self {
        Self {
            pub_witness,
            anchored_bundles: AnchoredBundles::from(anchored_bundle),
        }
    }

    pub fn into_double(mut self, other: ClientBundle) -> Result<Self, AnchoredBundleMismatch> {
        match (self.anchored_bundles, other.dbc_proof) {
            (AnchoredBundles::Double { .. }, _) => {
                return Err(AnchoredBundleMismatch::AlreadyDouble(
                    self.pub_witness.to_witness_id(),
                ));
            }
            (AnchoredBundles::Opret(opret), DbcProof::Tapret(tapret)) => {
                self.anchored_bundles = AnchoredBundles::Double {
                    tapret: ClientBundle::new(other.mpc_proof, tapret, other.bundle),
                    opret,
                }
            }
            (AnchoredBundles::Tapret(tapret), DbcProof::Opret(opret)) => {
                self.anchored_bundles = AnchoredBundles::Double {
                    opret: ClientBundle::new(other.mpc_proof, opret, other.bundle),
                    tapret,
                }
            }
            _ => {
                return Err(AnchoredBundleMismatch::SameBundleType(
                    self.pub_witness.to_witness_id(),
                ));
            }
        }
        Ok(self)
    }

    pub fn witness_id(&self) -> XWitnessId { self.pub_witness.to_witness_id() }

    pub fn reveal_seal(&mut self, bundle_id: BundleId, seal: XGraphSeal) -> bool {
        let bundle = match &mut self.anchored_bundles {
            AnchoredBundles::Tapret(tapret) | AnchoredBundles::Double { tapret, .. }
                if tapret.bundle.bundle_id() == bundle_id =>
            {
                Some(&mut tapret.bundle)
            }
            AnchoredBundles::Opret(opret) | AnchoredBundles::Double { opret, .. }
                if opret.bundle.bundle_id() == bundle_id =>
            {
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

    pub fn anchored_bundles(&self) -> impl Iterator<Item = (EAnchor, &TransitionBundle)> {
        self.anchored_bundles.iter()
    }

    pub fn bundles(&self) -> impl Iterator<Item = &TransitionBundle> {
        self.anchored_bundles.bundles()
    }

    #[inline]
    pub fn known_transitions(&self) -> impl Iterator<Item = &Transition> {
        self.anchored_bundles
            .bundles()
            .flat_map(|bundle| bundle.known_transitions.values())
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
        assert_eq!(dbc_proof.method(), bundle.close_method);
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
pub enum AnchoredBundles {
    #[strict_type(tag = 0x01)]
    Tapret(ClientBundle<TapretProof>),
    #[strict_type(tag = 0x02)]
    Opret(ClientBundle<OpretProof>),
    #[strict_type(tag = 0x03)]
    Double {
        tapret: ClientBundle<TapretProof>,
        opret: ClientBundle<OpretProof>,
    },
}

impl StrictDumb for AnchoredBundles {
    fn strict_dumb() -> Self { Self::Opret(strict_dumb!()) }
}

impl From<ClientBundle> for AnchoredBundles {
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

impl AnchoredBundles {
    pub fn bundles(&self) -> impl Iterator<Item = &TransitionBundle> {
        match self {
            AnchoredBundles::Tapret(tapret) => Dichotomy::single(&tapret.bundle),
            AnchoredBundles::Opret(opret) => Dichotomy::single(&opret.bundle),
            AnchoredBundles::Double { tapret, opret } => {
                Dichotomy::double(&tapret.bundle, &opret.bundle)
            }
        }
        .into_iter()
    }

    pub fn into_bundles(self) -> impl Iterator<Item = TransitionBundle> {
        match self {
            AnchoredBundles::Tapret(tapret) => Dichotomy::single(tapret.bundle),
            AnchoredBundles::Opret(opret) => Dichotomy::single(opret.bundle),
            AnchoredBundles::Double { tapret, opret } => {
                Dichotomy::double(tapret.bundle, opret.bundle)
            }
        }
        .into_iter()
    }

    pub fn iter(&self) -> impl Iterator<Item = (EAnchor, &TransitionBundle)> {
        match self {
            AnchoredBundles::Tapret(tapret) => {
                let anchor =
                    EAnchor::new(tapret.mpc_proof.clone(), tapret.dbc_proof.clone().into());
                Dichotomy::single((anchor, &tapret.bundle))
            }
            AnchoredBundles::Opret(opret) => {
                let anchor = EAnchor::new(opret.mpc_proof.clone(), opret.dbc_proof.into());
                Dichotomy::single((anchor, &opret.bundle))
            }
            AnchoredBundles::Double { tapret, opret } => {
                let tapret_anchor =
                    EAnchor::new(tapret.mpc_proof.clone(), tapret.dbc_proof.clone().into());
                let opret_anchor = EAnchor::new(opret.mpc_proof.clone(), opret.dbc_proof.into());
                Dichotomy::double((tapret_anchor, &tapret.bundle), (opret_anchor, &opret.bundle))
            }
        }
        .into_iter()
    }
}

impl IntoIterator for AnchoredBundles {
    type Item = (EAnchor, TransitionBundle);
    type IntoIter = vec::IntoIter<(EAnchor, TransitionBundle)>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AnchoredBundles::Tapret(tapret) => {
                let anchor = EAnchor::new(tapret.mpc_proof, tapret.dbc_proof.into());
                Dichotomy::single((anchor, tapret.bundle))
            }
            AnchoredBundles::Opret(opret) => {
                let anchor = EAnchor::new(opret.mpc_proof, opret.dbc_proof.into());
                Dichotomy::single((anchor, opret.bundle))
            }
            AnchoredBundles::Double { tapret, opret } => {
                let tapret_anchor = EAnchor::new(tapret.mpc_proof, tapret.dbc_proof.into());
                let opret_anchor = EAnchor::new(opret.mpc_proof, opret.dbc_proof.into());
                Dichotomy::double((tapret_anchor, tapret.bundle), (opret_anchor, opret.bundle))
            }
        }
        .into_iter()
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
    #[strict_type(tag = 0x03)]
    Double {
        tapret: Anchor<mpc::MerkleBlock, TapretProof>,
        opret: Anchor<mpc::MerkleBlock, OpretProof>,
    },
}

impl StrictDumb for AnchorSet {
    fn strict_dumb() -> Self { Self::Opret(strict_dumb!()) }
}

impl AnchorSet {
    pub fn known_bundle_ids(&self) -> impl Iterator<Item = BundleId> {
        let map = match self {
            AnchorSet::Tapret(tapret) => tapret.mpc_proof.to_known_message_map().release(),
            AnchorSet::Opret(opret) => opret.mpc_proof.to_known_message_map().release(),
            AnchorSet::Double { tapret, opret } => {
                let mut map = tapret.mpc_proof.to_known_message_map().release();
                map.extend(opret.mpc_proof.to_known_message_map().release());
                map
            }
        };
        map.into_values()
            .map(|msg| BundleId::from_byte_array(msg.to_byte_array()))
    }

    pub fn has_tapret(&self) -> bool { matches!(self, Self::Tapret(_) | Self::Double { .. }) }

    pub fn has_opret(&self) -> bool { matches!(self, Self::Opret(_) | Self::Double { .. }) }

    pub fn merge_reveal(self, other: Self) -> Result<Self, anchor::MergeError> {
        match (self, other) {
            (Self::Tapret(anchor), Self::Tapret(a)) => Ok(Self::Tapret(anchor.merge_reveal(a)?)),
            (Self::Opret(anchor), Self::Opret(a)) => Ok(Self::Opret(anchor.merge_reveal(a)?)),
            (Self::Tapret(tapret), Self::Opret(opret))
            | (Self::Opret(opret), Self::Tapret(tapret)) => Ok(Self::Double { tapret, opret }),

            (Self::Double { tapret, opret }, Self::Tapret(t))
            | (Self::Tapret(t), Self::Double { tapret, opret }) => Ok(Self::Double {
                tapret: tapret.merge_reveal(t)?,
                opret,
            }),

            (Self::Double { tapret, opret }, Self::Opret(o))
            | (Self::Opret(o), Self::Double { tapret, opret }) => Ok(Self::Double {
                tapret,
                opret: opret.merge_reveal(o)?,
            }),
            (
                Self::Double { tapret, opret },
                Self::Double {
                    tapret: t,
                    opret: o,
                },
            ) => Ok(Self::Double {
                tapret: tapret.merge_reveal(t)?,
                opret: opret.merge_reveal(o)?,
            }),
        }
    }
}
