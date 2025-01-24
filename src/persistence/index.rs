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

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Debug;

use amplify::confinement::{self, TinyOrdSet};
use nonasync::persistence::{CloneNoPersistence, Persisting};
use rgb::{
    Assign, AssignmentType, BundleId, ContractId, ExposedState, Extension, Genesis, GenesisSeal,
    GraphSeal, OpId, Operation, Opout, TransitionBundle, TypedAssigns, XChain, XOutpoint,
    XWitnessId,
};

use crate::containers::{ConsignmentExt, ToWitnessId, WitnessBundle};
use crate::persistence::{MemError, StoreTransaction};
use crate::SecretSeal;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum IndexError<P: IndexProvider> {
    /// Connectivity errors which may be recoverable and temporary.
    ReadProvider(<P as IndexReadProvider>::Error),

    /// Connectivity errors which may be recoverable and temporary.
    WriteProvider(<P as IndexWriteProvider>::Error),

    /// {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised index storage.
    Inconsistency(IndexInconsistency),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum IndexReadError<E: Error> {
    #[from]
    Inconsistency(IndexInconsistency),
    Connectivity(E),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum IndexWriteError<E: Error> {
    #[from]
    Inconsistency(IndexInconsistency),
    Connectivity(E),
}

impl<P: IndexProvider> From<IndexReadError<<P as IndexReadProvider>::Error>> for IndexError<P> {
    fn from(err: IndexReadError<<P as IndexReadProvider>::Error>) -> Self {
        match err {
            IndexReadError::Inconsistency(e) => IndexError::Inconsistency(e),
            IndexReadError::Connectivity(e) => IndexError::ReadProvider(e),
        }
    }
}

impl<P: IndexProvider> From<IndexWriteError<<P as IndexWriteProvider>::Error>> for IndexError<P> {
    fn from(err: IndexWriteError<<P as IndexWriteProvider>::Error>) -> Self {
        match err {
            IndexWriteError::Inconsistency(e) => IndexError::Inconsistency(e),
            IndexWriteError::Connectivity(e) => IndexError::WriteProvider(e),
        }
    }
}

impl From<confinement::Error> for IndexWriteError<MemError> {
    fn from(err: confinement::Error) -> Self { IndexWriteError::Connectivity(err.into()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IndexInconsistency {
    /// contract {0} is unknown. Probably you haven't imported the contract yet.
    ContractAbsent(ContractId),

    /// bundle matching state transition {0} is absent in the index.
    BundleAbsent(OpId),

    /// outpoint {0} is not part of the contract {1}.
    OutpointUnknown(XOutpoint, ContractId),

    /// index already contains information about bundle {bundle_id} which
    /// specifies contract {present} instead of contract {expected}.
    DistinctBundleContract {
        bundle_id: BundleId,
        present: ContractId,
        expected: ContractId,
    },

    /// index already contains information about operation {opid} which
    /// specifies bundle {present} instead of bundle {expected}.
    DistinctBundleOp {
        opid: OpId,
        present: BundleId,
        expected: BundleId,
    },

    /// contract id for bundle {0} is not known.
    BundleContractUnknown(BundleId),

    /// absent information about witness for bundle {0}.
    BundleWitnessUnknown(BundleId),
}

#[derive(Debug)]
pub struct Index<P: IndexProvider> {
    provider: P,
}

impl<P: IndexProvider> CloneNoPersistence for Index<P> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            provider: self.provider.clone_no_persistence(),
        }
    }
}

impl<P: IndexProvider> Default for Index<P>
where P: Default
{
    fn default() -> Self {
        Self {
            provider: default!(),
        }
    }
}

impl<P: IndexProvider> Index<P> {
    pub(super) fn new(provider: P) -> Self { Self { provider } }

    #[doc(hidden)]
    pub fn as_provider(&self) -> &P { &self.provider }

    #[doc(hidden)]
    pub(super) fn as_provider_mut(&mut self) -> &mut P { &mut self.provider }

    pub(super) fn index_consignment(
        &mut self,
        consignment: impl ConsignmentExt,
    ) -> Result<(), IndexError<P>> {
        let contract_id = consignment.contract_id();

        self.provider
            .register_contract(contract_id)
            .map_err(IndexError::WriteProvider)?;
        self.index_genesis(contract_id, consignment.genesis())?;
        for extension in consignment.extensions() {
            self.index_extension(contract_id, extension)?;
        }
        for WitnessBundle {
            pub_witness,
            anchored_bundles,
        } in consignment.bundled_witnesses()
        {
            let witness_id = pub_witness.to_witness_id();
            for bundle in anchored_bundles.bundles() {
                self.index_bundle(contract_id, bundle, witness_id)?;
            }
        }

        Ok(())
    }

    fn index_genesis(&mut self, id: ContractId, genesis: &Genesis) -> Result<(), IndexError<P>> {
        let opid = genesis.id();
        for (type_id, assign) in genesis.assignments.iter() {
            match assign {
                TypedAssigns::Declarative(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Fungible(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Structured(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Attachment(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
            }
        }
        Ok(())
    }

    fn index_extension(
        &mut self,
        id: ContractId,
        extension: &Extension,
    ) -> Result<(), IndexError<P>> {
        let opid = extension.id();
        for (type_id, assign) in extension.assignments.iter() {
            match assign {
                TypedAssigns::Declarative(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Fungible(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Structured(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
                TypedAssigns::Attachment(vec) => {
                    self.provider
                        .index_genesis_assignments(id, vec, opid, *type_id)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn index_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: &TransitionBundle,
        witness_id: XWitnessId,
    ) -> Result<(), IndexError<P>> {
        let bundle_id = bundle.bundle_id();

        self.provider
            .register_bundle(bundle_id, witness_id, contract_id)?;

        for (opid, transition) in &bundle.known_transitions {
            self.provider.register_operation(*opid, bundle_id)?;
            for input in &transition.inputs {
                self.provider
                    .register_spending(input.prev_out.op, bundle_id)?;
            }
            for (type_id, assign) in transition.assignments.iter() {
                match assign {
                    TypedAssigns::Declarative(vec) => {
                        self.provider.index_transition_assignments(
                            contract_id,
                            vec,
                            *opid,
                            *type_id,
                            witness_id,
                        )?;
                    }
                    TypedAssigns::Fungible(vec) => {
                        self.provider.index_transition_assignments(
                            contract_id,
                            vec,
                            *opid,
                            *type_id,
                            witness_id,
                        )?;
                    }
                    TypedAssigns::Structured(vec) => {
                        self.provider.index_transition_assignments(
                            contract_id,
                            vec,
                            *opid,
                            *type_id,
                            witness_id,
                        )?;
                    }
                    TypedAssigns::Attachment(vec) => {
                        self.provider.index_transition_assignments(
                            contract_id,
                            vec,
                            *opid,
                            *type_id,
                            witness_id,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    pub(super) fn contracts_assigning(
        &self,
        outputs: BTreeSet<XOutpoint>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, IndexError<P>> {
        self.provider
            .contracts_assigning(outputs)
            .map_err(IndexError::ReadProvider)
    }

    pub(super) fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, IndexError<P>> {
        Ok(self.provider.public_opouts(contract_id)?)
    }

    pub(super) fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutpoint>>,
    ) -> Result<BTreeSet<Opout>, IndexError<P>> {
        Ok(self.provider.opouts_by_outputs(contract_id, outputs)?)
    }

    pub(super) fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, IndexError<P>> {
        self.provider
            .opouts_by_terminals(terminals)
            .map_err(IndexError::ReadProvider)
    }

    pub(super) fn bundle_id_for_op(&self, opid: OpId) -> Result<BundleId, IndexError<P>> {
        Ok(self.provider.bundle_id_for_op(opid)?)
    }

    pub(super) fn bundle_ids_children_of_op(
        &self,
        opid: OpId,
    ) -> Result<TinyOrdSet<BundleId>, IndexError<P>> {
        Ok(self.provider.bundle_ids_children_of_op(opid)?)
    }

    pub(super) fn bundle_info(
        &self,
        bundle_id: BundleId,
    ) -> Result<(impl Iterator<Item = XWitnessId> + '_, ContractId), IndexError<P>> {
        Ok(self.provider.bundle_info(bundle_id)?)
    }
}

impl<P: IndexProvider> StoreTransaction for Index<P> {
    type TransactionErr = IndexError<P>;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .begin_transaction()
            .map_err(IndexError::WriteProvider)
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .commit_transaction()
            .map_err(IndexError::WriteProvider)
    }

    fn rollback_transaction(&mut self) { self.provider.rollback_transaction() }
}

pub trait IndexProvider:
    Debug + CloneNoPersistence + Persisting + IndexReadProvider + IndexWriteProvider
{
}

pub trait IndexReadProvider {
    type Error: Clone + Eq + Error;

    fn contracts_assigning(
        &self,
        outputs: BTreeSet<XOutpoint>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, Self::Error>;

    fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>>;

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutpoint>>,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>>;

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, Self::Error>;

    fn bundle_id_for_op(&self, opid: OpId) -> Result<BundleId, IndexReadError<Self::Error>>;

    fn bundle_ids_children_of_op(
        &self,
        opid: OpId,
    ) -> Result<TinyOrdSet<BundleId>, IndexReadError<Self::Error>>;

    fn bundle_info(
        &self,
        bundle_id: BundleId,
    ) -> Result<(impl Iterator<Item = XWitnessId>, ContractId), IndexReadError<Self::Error>>;
}

pub trait IndexWriteProvider: StoreTransaction<TransactionErr = Self::Error> {
    type Error: Error;

    fn register_contract(&mut self, contract_id: ContractId) -> Result<bool, Self::Error>;

    fn register_bundle(
        &mut self,
        bundle_id: BundleId,
        witness_id: XWitnessId,
        contract_id: ContractId,
    ) -> Result<bool, IndexWriteError<Self::Error>>;

    fn register_operation(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>>;

    fn register_spending(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>>;

    fn index_genesis_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GenesisSeal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), IndexWriteError<Self::Error>>;

    fn index_transition_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GraphSeal>],
        opid: OpId,
        type_id: AssignmentType,
        witness_id: XWitnessId,
    ) -> Result<(), IndexWriteError<Self::Error>>;
}
