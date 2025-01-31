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
use std::collections::{BTreeSet, HashMap, HashSet};

use bp::Outpoint;
use invoice::{Allocation, Amount};
use rgb::{
    AssignmentType, AttachState, ContractId, DataState, OpId, OutputSeal, RevealedAttach,
    RevealedData, RevealedValue, Schema, Txid, VoidState,
};
use strict_encoding::{FieldName, StrictDecode, StrictDumb, StrictEncode};
use strict_types::{StrictVal, TypeSystem};

use crate::contract::{KnownState, OutputAssignment, WitnessInfo};
use crate::info::ContractInfo;
use crate::interface::{AssignmentsFilter, IfaceImpl};
use crate::persistence::ContractStateRead;
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// field name {0} is unknown to the contract interface
    FieldNameUnknown(FieldName),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[display(inner)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AllocatedState {
    #[from(())]
    #[from(VoidState)]
    #[display("~")]
    #[strict_type(tag = 0, dumb)]
    Void,

    #[from]
    #[from(RevealedValue)]
    #[strict_type(tag = 1)]
    Amount(Amount),

    #[from]
    #[from(RevealedData)]
    #[from(Allocation)]
    #[strict_type(tag = 2)]
    Data(DataState),

    #[from]
    #[from(RevealedAttach)]
    #[strict_type(tag = 3)]
    Attachment(AttachState),
}

impl KnownState for AllocatedState {
    const IS_FUNGIBLE: bool = false;
}

impl AllocatedState {
    fn unwrap_fungible(&self) -> Amount {
        match self {
            AllocatedState::Amount(amount) => *amount,
            _ => panic!("unwrapping non-fungible state"),
        }
    }
}

pub type OwnedAllocation = OutputAssignment<AllocatedState>;
pub type RightsAllocation = OutputAssignment<VoidState>;
pub type FungibleAllocation = OutputAssignment<Amount>;
pub type DataAllocation = OutputAssignment<DataState>;
pub type AttachAllocation = OutputAssignment<AttachState>;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
pub enum OpDirection {
    Issued,
    Received,
    Sent,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub struct ContractOp {
    pub direction: OpDirection,
    pub ty: AssignmentType,
    pub opids: BTreeSet<OpId>,
    pub state: AllocatedState,
    pub to: BTreeSet<OutputSeal>,
    pub witness: Option<WitnessInfo>,
}

fn reduce_to_ty(allocations: impl IntoIterator<Item = OwnedAllocation>) -> AssignmentType {
    allocations
        .into_iter()
        .map(|a| a.opout.ty)
        .reduce(|ty1, ty2| {
            assert_eq!(ty1, ty2);
            ty1
        })
        .expect("empty list of allocations")
}

impl ContractOp {
    fn non_fungible_genesis(
        our_allocations: HashSet<OwnedAllocation>,
    ) -> impl ExactSizeIterator<Item = Self> {
        our_allocations.into_iter().map(|a| Self {
            direction: OpDirection::Issued,
            ty: a.opout.ty,
            opids: bset![a.opout.op],
            state: a.state,
            to: bset![a.seal],
            witness: None,
        })
    }

    fn non_fungible_sent(
        witness: WitnessInfo,
        ext_allocations: HashSet<OwnedAllocation>,
    ) -> impl ExactSizeIterator<Item = Self> {
        ext_allocations.into_iter().map(move |a| Self {
            direction: OpDirection::Sent,
            ty: a.opout.ty,
            opids: bset![a.opout.op],
            state: a.state,
            to: bset![a.seal],
            witness: Some(witness),
        })
    }

    fn non_fungible_received(
        witness: WitnessInfo,
        our_allocations: HashSet<OwnedAllocation>,
    ) -> impl ExactSizeIterator<Item = Self> {
        our_allocations.into_iter().map(move |a| Self {
            direction: OpDirection::Received,
            ty: a.opout.ty,
            opids: bset![a.opout.op],
            state: a.state,
            to: bset![a.seal],
            witness: Some(witness),
        })
    }

    fn fungible_genesis(our_allocations: HashSet<OwnedAllocation>) -> Self {
        let to = our_allocations.iter().map(|a| a.seal).collect();
        let opids = our_allocations.iter().map(|a| a.opout.op).collect();
        let issued = our_allocations
            .iter()
            .map(|a| a.state.unwrap_fungible())
            .sum();
        Self {
            direction: OpDirection::Issued,
            ty: reduce_to_ty(our_allocations),
            opids,
            state: AllocatedState::Amount(issued),
            to,
            witness: None,
        }
    }

    fn fungible_sent(witness: WitnessInfo, ext_allocations: HashSet<OwnedAllocation>) -> Self {
        let opids = ext_allocations.iter().map(|a| a.opout.op).collect();
        let to = ext_allocations.iter().map(|a| a.seal).collect();
        let amount = ext_allocations
            .iter()
            .map(|a| a.state.unwrap_fungible())
            .sum();
        Self {
            direction: OpDirection::Sent,
            ty: reduce_to_ty(ext_allocations),
            opids,
            state: AllocatedState::Amount(amount),
            to,
            witness: Some(witness),
        }
    }

    fn fungible_received(witness: WitnessInfo, our_allocations: HashSet<OwnedAllocation>) -> Self {
        let opids = our_allocations.iter().map(|a| a.opout.op).collect();
        let to = our_allocations.iter().map(|a| a.seal).collect();
        let amount = our_allocations
            .iter()
            .map(|a| a.state.unwrap_fungible())
            .sum();
        Self {
            direction: OpDirection::Received,
            ty: reduce_to_ty(our_allocations),
            opids,
            state: AllocatedState::Amount(amount),
            to,
            witness: Some(witness),
        }
    }
}

/// Contract state is an in-memory structure providing API to read structured
/// data from the [`rgb::ContractHistory`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ContractIface<S: ContractStateRead> {
    pub state: S,
    pub schema: Schema,
    pub iface: IfaceImpl,
    pub types: TypeSystem,
    pub info: ContractInfo,
}

impl<S: ContractStateRead> ContractIface<S> {
    pub fn contract_id(&self) -> ContractId { self.state.contract_id() }

    /// # Panics
    ///
    /// If data are corrupted and contract schema doesn't match interface
    /// implementations.
    pub fn global(
        &self,
        name: impl Into<FieldName>,
    ) -> Result<impl Iterator<Item = StrictVal> + '_, ContractError> {
        let name = name.into();
        let type_id = self
            .iface
            .global_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        let global_schema = self
            .schema
            .global_types
            .get(&type_id)
            .expect("schema doesn't match interface");
        Ok(self
            .state
            .global(type_id)
            .expect("schema doesn't match interface")
            .map(|data| {
                self.types
                    .strict_deserialize_type(global_schema.sem_id, data.borrow().as_slice())
                    .expect("unvalidated contract data in stash")
                    .unbox()
            }))
    }

    fn extract_state<'c, A, U>(
        &'c self,
        state: impl IntoIterator<Item = &'c OutputAssignment<A>> + 'c,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = OutputAssignment<U>> + 'c, ContractError>
    where
        A: Clone + KnownState + 'c,
        U: From<A> + KnownState + 'c,
    {
        Ok(self
            .extract_state_unfiltered(state, name)?
            .filter(move |outp| filter.should_include(outp.seal, outp.witness)))
    }

    fn extract_state_unfiltered<'c, A, U>(
        &'c self,
        state: impl IntoIterator<Item = &'c OutputAssignment<A>> + 'c,
        name: impl Into<FieldName>,
    ) -> Result<impl Iterator<Item = OutputAssignment<U>> + 'c, ContractError>
    where
        A: Clone + KnownState + 'c,
        U: From<A> + KnownState + 'c,
    {
        let name = name.into();
        let type_id = self
            .iface
            .assignments_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        Ok(state
            .into_iter()
            .filter(move |outp| outp.opout.ty == type_id)
            .cloned()
            .map(OutputAssignment::<A>::transmute))
    }

    pub fn rights<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = RightsAllocation> + 'c, ContractError> {
        self.extract_state(self.state.rights_all(), name, filter)
    }

    pub fn fungible<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = FungibleAllocation> + 'c, ContractError> {
        self.extract_state(self.state.fungible_all(), name, filter)
    }

    pub fn data<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = DataAllocation> + 'c, ContractError> {
        self.extract_state(self.state.data_all(), name, filter)
    }

    pub fn attachments<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = AttachAllocation> + 'c, ContractError> {
        self.extract_state(self.state.attach_all(), name, filter)
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl AssignmentsFilter + Copy + 'c,
    ) -> impl Iterator<Item = OwnedAllocation> + 'c {
        fn f<'a, S, U>(
            filter: impl AssignmentsFilter + 'a,
            state: impl IntoIterator<Item = &'a OutputAssignment<S>> + 'a,
        ) -> impl Iterator<Item = OutputAssignment<U>> + 'a
        where
            S: Clone + KnownState + 'a,
            U: From<S> + KnownState + 'a,
        {
            state
                .into_iter()
                .filter(move |outp| filter.should_include(outp.seal, outp.witness))
                .cloned()
                .map(OutputAssignment::<S>::transmute)
        }

        f(filter, self.state.rights_all())
            .map(OwnedAllocation::from)
            .chain(f(filter, self.state.fungible_all()).map(OwnedAllocation::from))
            .chain(f(filter, self.state.data_all()).map(OwnedAllocation::from))
            .chain(f(filter, self.state.attach_all()).map(OwnedAllocation::from))
    }

    pub fn outpoint_allocations(
        &self,
        outpoint: Outpoint,
    ) -> impl Iterator<Item = OwnedAllocation> + '_ {
        self.allocations(outpoint)
    }

    pub fn history(
        &self,
        filter_outpoints: impl AssignmentsFilter + Clone,
        filter_witnesses: impl AssignmentsFilter + Clone,
    ) -> Vec<ContractOp> {
        self.history_fungible(filter_outpoints.clone(), filter_witnesses.clone())
            .into_iter()
            .chain(self.history_rights(filter_outpoints.clone(), filter_witnesses.clone()))
            .chain(self.history_data(filter_outpoints.clone(), filter_witnesses.clone()))
            .chain(self.history_attach(filter_outpoints, filter_witnesses))
            .collect()
    }

    fn operations<'c, T: KnownState + 'c, I: Iterator<Item = &'c OutputAssignment<T>>>(
        &'c self,
        state: impl Fn(&'c S) -> I,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Vec<ContractOp>
    where
        AllocatedState: From<T>,
    {
        // get all allocations which ever belonged to this wallet and store them by witness id
        let mut allocations_our_outpoint = state(&self.state)
            .filter(move |outp| filter_outpoints.should_include(outp.seal, outp.witness))
            .fold(HashMap::<_, HashSet<_>>::new(), |mut map, a| {
                map.entry(a.witness)
                    .or_default()
                    .insert(a.clone().transmute::<AllocatedState>());
                map
            });
        // get all allocations which has a witness transaction belonging to this wallet
        let mut allocations_our_witness = state(&self.state)
            .filter(move |outp| filter_witnesses.should_include(outp.seal, outp.witness))
            .fold(HashMap::<_, HashSet<_>>::new(), |mut map, a| {
                let witness = a.witness.expect(
                    "all empty witnesses must be already filtered out by wallet.filter_witness()",
                );
                map.entry(witness)
                    .or_default()
                    .insert(a.clone().transmute::<AllocatedState>());
                map
            });

        // gather all witnesses from both sets
        let mut witness_ids = allocations_our_witness
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        witness_ids.extend(allocations_our_outpoint.keys().filter_map(|x| *x));

        // reconstruct contract history from the wallet perspective
        let mut ops = Vec::with_capacity(witness_ids.len() + 1);
        // add allocations with no witness to the beginning of the history
        if let Some(genesis_allocations) = allocations_our_outpoint.remove(&None) {
            if T::IS_FUNGIBLE {
                ops.push(ContractOp::fungible_genesis(genesis_allocations));
            } else {
                ops.extend(ContractOp::non_fungible_genesis(genesis_allocations));
            }
        }
        for witness_id in witness_ids {
            let our_outpoint = allocations_our_outpoint.remove(&Some(witness_id));
            let our_witness = allocations_our_witness.remove(&witness_id);
            let witness_info = self.witness_info(witness_id).expect(
                "witness id was returned from the contract state above, so it must be there",
            );
            match (our_outpoint, our_witness) {
                // we own both allocation and witness transaction: these allocations are changes and
                // outgoing payments. The difference between the change and the payments are whether
                // a specific allocation is listed in the first tuple pattern field.
                (Some(our_allocations), Some(all_allocations)) => {
                    // all_allocations - our_allocations = external payments
                    let ext_allocations = all_allocations
                        .difference(&our_allocations)
                        .cloned()
                        .collect::<HashSet<_>>();
                    // This was a blank state transition with no external payment
                    if ext_allocations.is_empty() {
                        continue;
                    }
                    if T::IS_FUNGIBLE {
                        ops.push(ContractOp::fungible_sent(witness_info, ext_allocations))
                    } else {
                        ops.extend(ContractOp::non_fungible_sent(witness_info, ext_allocations))
                    }
                }
                // the same as above, but the payment has no change
                (None, Some(ext_allocations)) => {
                    if T::IS_FUNGIBLE {
                        ops.push(ContractOp::fungible_sent(witness_info, ext_allocations))
                    } else {
                        ops.extend(ContractOp::non_fungible_sent(witness_info, ext_allocations))
                    }
                }
                // we own allocation but the witness transaction was made by other wallet:
                // this is an incoming payment to us.
                (Some(our_allocations), None) => {
                    if T::IS_FUNGIBLE {
                        ops.push(ContractOp::fungible_received(witness_info, our_allocations))
                    } else {
                        ops.extend(ContractOp::non_fungible_received(witness_info, our_allocations))
                    }
                }
                // these can't get into the `witness_ids` due to the used filters
                (None, None) => unreachable!("broken allocation filters"),
            };
        }

        ops
    }

    pub fn history_fungible(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Vec<ContractOp> {
        self.operations(|state| state.fungible_all(), filter_outpoints, filter_witnesses)
    }

    pub fn history_rights(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Vec<ContractOp> {
        self.operations(|state| state.rights_all(), filter_outpoints, filter_witnesses)
    }

    pub fn history_data(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Vec<ContractOp> {
        self.operations(|state| state.data_all(), filter_outpoints, filter_witnesses)
    }

    pub fn history_attach(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Vec<ContractOp> {
        self.operations(|state| state.attach_all(), filter_outpoints, filter_witnesses)
    }

    pub fn witness_info(&self, witness_id: Txid) -> Option<WitnessInfo> {
        let ord = self.state.witness_ord(witness_id)?;
        Some(WitnessInfo {
            id: witness_id,
            ord,
        })
    }
}
