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

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use rgb::validation::{ConsignmentApi, EAnchor, OpRef, Scripts};
use rgb::{
    BundleId, Extension, Genesis, OpId, Operation, Schema, Transition, TransitionBundle, XWitnessId,
};
use strict_types::TypeSystem;

use super::{Consignment, XPubWitness};
use crate::containers::anchors::ToWitnessId;

// TODO: Transform consignment into this type instead of composing over it
#[derive(Clone, Debug)]
pub struct IndexedConsignment<'c, const TRANSFER: bool> {
    consignment: &'c Consignment<TRANSFER>,
    scripts: Scripts,
    anchor_idx: BTreeMap<BundleId, (XWitnessId, EAnchor)>,
    bundle_idx: BTreeMap<BundleId, &'c TransitionBundle>,
    op_witness_idx: BTreeMap<OpId, XWitnessId>,
    op_bundle_idx: BTreeMap<OpId, BundleId>,
    extension_idx: BTreeMap<OpId, &'c Extension>,
    witness_idx: BTreeMap<XWitnessId, &'c XPubWitness>,
}

impl<const TRANSFER: bool> Deref for IndexedConsignment<'_, TRANSFER> {
    type Target = Consignment<TRANSFER>;

    fn deref(&self) -> &Self::Target { self.consignment }
}

impl<'c, const TRANSFER: bool> IndexedConsignment<'c, TRANSFER> {
    pub fn new(consignment: &'c Consignment<TRANSFER>) -> Self {
        let mut anchor_idx = BTreeMap::new();
        let mut bundle_idx = BTreeMap::new();
        let mut op_witness_idx = BTreeMap::new();
        let mut op_bundle_idx = BTreeMap::new();
        let mut extension_idx = BTreeMap::new();
        let mut witness_idx = BTreeMap::new();
        for witness_bundle in &consignment.bundles {
            witness_idx
                .insert(witness_bundle.pub_witness.to_witness_id(), &witness_bundle.pub_witness);
            let witness_id = witness_bundle.pub_witness.to_witness_id();
            for (anchor, bundle) in witness_bundle.anchored_bundles() {
                let bundle_id = bundle.bundle_id();
                bundle_idx.insert(bundle_id, bundle);
                anchor_idx.insert(bundle_id, (witness_id, anchor));
                for opid in bundle.known_transitions.keys() {
                    op_witness_idx.insert(*opid, witness_id);
                    op_bundle_idx.insert(*opid, bundle_id);
                }
            }
        }
        for extension in &consignment.extensions {
            extension_idx.insert(extension.id(), extension);
        }
        let scripts = Scripts::from_iter_checked(
            consignment
                .scripts
                .iter()
                .map(|lib| (lib.id(), lib.clone())),
        );
        Self {
            consignment,
            scripts,
            anchor_idx,
            bundle_idx,
            op_witness_idx,
            op_bundle_idx,
            extension_idx,
            witness_idx,
        }
    }

    fn extension(&self, opid: OpId) -> Option<&Extension> { self.extension_idx.get(&opid).copied() }

    fn transition(&self, opid: OpId) -> Option<&Transition> {
        self.op_bundle_idx
            .get(&opid)
            .and_then(|id| self.bundle_idx.get(id))
            .and_then(|bundle| bundle.known_transitions.get(&opid))
    }

    pub fn pub_witness(&self, id: XWitnessId) -> Option<&XPubWitness> {
        self.witness_idx.get(&id).copied()
    }
}

impl<const TRANSFER: bool> ConsignmentApi for IndexedConsignment<'_, TRANSFER> {
    fn schema(&self) -> &Schema { &self.schema }

    fn types(&self) -> &TypeSystem { &self.types }

    fn scripts(&self) -> &Scripts { &self.scripts }

    fn operation(&self, opid: OpId) -> Option<OpRef> {
        if opid == self.genesis.id() {
            return Some(OpRef::Genesis(&self.genesis));
        }
        self.transition(opid)
            .map(OpRef::Transition)
            .or_else(|| self.extension(opid).map(OpRef::Extension))
    }

    fn genesis(&self) -> &Genesis { &self.genesis }

    fn bundle_ids<'iter>(&self) -> impl Iterator<Item = BundleId> + 'iter {
        self.bundle_idx
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
    }

    fn bundle(&self, bundle_id: BundleId) -> Option<&TransitionBundle> {
        self.bundle_idx.get(&bundle_id).copied()
    }

    fn anchor(&self, bundle_id: BundleId) -> Option<(XWitnessId, &EAnchor)> {
        self.anchor_idx.get(&bundle_id).map(|(id, set)| (*id, set))
    }

    fn op_witness_id(&self, opid: OpId) -> Option<XWitnessId> {
        self.op_witness_idx.get(&opid).copied()
    }
}
