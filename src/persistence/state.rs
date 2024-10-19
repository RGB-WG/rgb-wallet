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

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;
use std::iter;

use nonasync::persistence::{CloneNoPersistence, Persisting};
use rgb::validation::{ResolveWitness, WitnessResolverError};
use rgb::vm::{ContractStateAccess, WitnessOrd};
use rgb::{
    ContractId, Extension, Genesis, Operation, Schema, SchemaId, Transition, TransitionBundle,
    XWitnessId,
};

use crate::containers::{ConsignmentExt, ToWitnessId};
use crate::contract::Allocation;
use crate::persistence::{StoreTransaction, UpdateRes};

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StateError<P: StateProvider> {
    /// Connectivity errors which may be recoverable and temporary.
    ReadProvider(<P as StateReadProvider>::Error),

    /// Connectivity errors which may be recoverable and temporary.
    WriteProvider(<P as StateWriteProvider>::Error),

    /// witness {0} can't be resolved: {1}
    #[display(doc_comments)]
    Resolver(XWitnessId, WitnessResolverError),

    /// valid (non-archived) witness is absent in the list of witnesses for a
    /// state transition bundle.
    AbsentValidWitness,

    /// {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    #[from]
    #[display(doc_comments)]
    Inconsistency(StateInconsistency),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum StateInconsistency {
    /// contract state {0} is not known.
    UnknownContract(ContractId),
    /// a witness {0} is absent from the state data.
    AbsentWitness(XWitnessId),
}

#[derive(Debug)]
pub struct State<P: StateProvider> {
    provider: P,
}

impl<P: StateProvider> CloneNoPersistence for State<P> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            provider: self.provider.clone_no_persistence(),
        }
    }
}

impl<P: StateProvider> Default for State<P>
where P: Default
{
    fn default() -> Self {
        Self {
            provider: default!(),
        }
    }
}

impl<P: StateProvider> State<P> {
    pub(super) fn new(provider: P) -> Self { Self { provider } }

    #[doc(hidden)]
    pub fn as_provider(&self) -> &P { &self.provider }

    #[doc(hidden)]
    pub(super) fn as_provider_mut(&mut self) -> &mut P { &mut self.provider }

    #[inline]
    pub fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<P::ContractRead<'_>, StateError<P>> {
        self.provider
            .contract_state(contract_id)
            .map_err(StateError::ReadProvider)
    }

    pub fn select_valid_witness(
        &self,
        witness_ids: impl IntoIterator<Item = impl Borrow<XWitnessId>>,
    ) -> Result<XWitnessId, StateError<P>> {
        for witness_id in witness_ids {
            let witness_id = *witness_id.borrow();
            if self
                .provider
                .is_valid_witness(witness_id)
                .map_err(StateError::ReadProvider)?
            {
                return Ok(witness_id);
            }
        }
        Err(StateError::AbsentValidWitness)
    }

    pub fn update_from_bundle<R: ResolveWitness>(
        &mut self,
        contract_id: ContractId,
        bundle: &TransitionBundle,
        witness_id: XWitnessId,
        resolver: R,
    ) -> Result<(), StateError<P>> {
        let mut updater = self
            .as_provider_mut()
            .update_contract(contract_id)
            .map_err(StateError::WriteProvider)?
            .ok_or(StateInconsistency::UnknownContract(contract_id))?;
        for transition in bundle.known_transitions.values() {
            let ord = resolver
                .resolve_pub_witness_ord(witness_id)
                .map_err(|e| StateError::Resolver(witness_id, e))?;
            updater
                .add_transition(transition, witness_id, ord)
                .map_err(StateError::WriteProvider)?;
        }
        Ok(())
    }

    pub fn update_from_consignment<R: ResolveWitness>(
        &mut self,
        consignment: impl ConsignmentExt,
        resolver: R,
    ) -> Result<(), StateError<P>> {
        let mut state = self
            .as_provider_mut()
            .register_contract(consignment.schema(), consignment.genesis())
            .map_err(StateError::WriteProvider)?;
        let mut extension_idx = consignment
            .extensions()
            .map(Extension::id)
            .zip(iter::repeat(false))
            .collect::<BTreeMap<_, _>>();
        let mut ordered_extensions = BTreeMap::new();
        for witness_bundle in consignment.bundled_witnesses() {
            for transition in witness_bundle.known_transitions() {
                let witness_id = witness_bundle.pub_witness.to_witness_id();
                let witness_ord = resolver
                    .resolve_pub_witness_ord(witness_id)
                    .map_err(|e| StateError::Resolver(witness_id, e))?;

                state
                    .add_transition(transition, witness_id, witness_ord)
                    .map_err(StateError::WriteProvider)?;
                for (id, used) in &mut extension_idx {
                    if *used {
                        continue;
                    }
                    for input in &transition.inputs {
                        if input.prev_out.op == *id {
                            *used = true;
                            if let Some((_, witness_ord2)) = ordered_extensions.get_mut(id) {
                                if *witness_ord2 < witness_ord {
                                    *witness_ord2 = witness_ord;
                                }
                            } else {
                                ordered_extensions.insert(*id, (witness_id, witness_ord));
                            }
                        }
                    }
                }
            }
        }
        for extension in consignment.extensions() {
            if let Some((witness_id, witness_ord)) = ordered_extensions.get(&extension.id()) {
                state
                    .add_extension(extension, *witness_id, *witness_ord)
                    .map_err(StateError::WriteProvider)?;
            }
            // Otherwise consignment includes state extensions which are not
            // used in transaction graph. This must not be the case for the
            // validated consignments.
        }

        Ok(())
    }

    pub fn update_witnesses(
        &mut self,
        resolver: impl ResolveWitness,
        after_height: u32,
    ) -> Result<UpdateRes, StateError<P>> {
        self.provider
            .update_witnesses(resolver, after_height)
            .map_err(StateError::WriteProvider)
    }
}

impl<P: StateProvider> StoreTransaction for State<P> {
    type TransactionErr = StateError<P>;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .begin_transaction()
            .map_err(StateError::WriteProvider)
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .commit_transaction()
            .map_err(StateError::WriteProvider)
    }

    fn rollback_transaction(&mut self) { self.provider.rollback_transaction() }
}

pub trait StateProvider:
    Debug + CloneNoPersistence + Persisting + StateReadProvider + StateWriteProvider
{
}

pub trait StateReadProvider {
    type ContractRead<'a>: ContractStateRead
    where Self: 'a;
    type Error: Clone + Eq + Error;

    fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<Self::ContractRead<'_>, Self::Error>;

    fn is_valid_witness(&self, witness_id: XWitnessId) -> Result<bool, Self::Error>;
}

pub trait StateWriteProvider: StoreTransaction<TransactionErr = Self::Error> {
    type ContractWrite<'a>: ContractStateWrite<Error = Self::Error>
    where Self: 'a;
    type Error: Error;

    fn register_contract(
        &mut self,
        schema: &Schema,
        genesis: &Genesis,
    ) -> Result<Self::ContractWrite<'_>, Self::Error>;

    fn update_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Option<Self::ContractWrite<'_>>, Self::Error>;

    fn update_witnesses(
        &mut self,
        resolver: impl ResolveWitness,
        after_height: u32,
    ) -> Result<UpdateRes, Self::Error>;
}

pub trait ContractStateRead: ContractStateAccess {
    fn contract_id(&self) -> ContractId;
    fn schema_id(&self) -> SchemaId;
    fn witness_ord(&self, witness_id: XWitnessId) -> Option<WitnessOrd>;
    fn assignments(&self) -> impl Iterator<Item = &Allocation>;
}

pub trait ContractStateWrite {
    type Error: Error;

    fn add_genesis(&mut self, genesis: &Genesis) -> Result<(), Self::Error>;

    fn add_transition(
        &mut self,
        transition: &Transition,
        witness_id: XWitnessId,
        witness_ord: WitnessOrd,
    ) -> Result<(), Self::Error>;

    fn add_extension(
        &mut self,
        extension: &Extension,
        witness_id: XWitnessId,
        witness_ord: WitnessOrd,
    ) -> Result<(), Self::Error>;
}
