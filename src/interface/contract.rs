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

use amplify::confinement::SmallBlob;
use amplify::Wrapper;
use rgb::validation::Scripts;
use rgb::{
    AssignmentType, AttachId, ContractId, OpId, Opout, Schema, State, StateData, XOutputSeal,
    XWitnessId, STATE_DATA_MAX_LEN,
};
use strict_encoding::{FieldName, SerializeError, StrictDeserialize};
use strict_types::{typify, SemId, StrictVal, TypeSystem};

use crate::contract::{Allocation, WitnessInfo};
use crate::info::ContractInfo;
use crate::interface::{AssignmentsFilter, IfaceImpl, StateCalc};
use crate::persistence::ContractStateRead;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// field name {0} is unknown to the contract interface
    FieldNameUnknown(FieldName),

    /// the provided state object is invalid; {0}
    #[from]
    Typify(typify::Error),

    /// the provided state exceeds maximum allowed length when serialized.
    #[from]
    Strict(SerializeError),
}

/// Allocation is an owned state assignment, equipped with information about the operation defining
/// the assignment and the witness id, containing the commitment to the operation.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Output<T = StrictVal> {
    pub opout: Opout,
    pub seal: XOutputSeal,
    pub state: T,
    pub attach_id: Option<AttachId>,
    pub witness: Option<XWitnessId>,
}

impl<T: StrictDeserialize> From<Allocation> for Output<T> {
    fn from(a: Allocation) -> Self {
        Output {
            opout: a.opout,
            seal: a.seal,
            state: T::from_strict_serialized(a.state.data.to_inner())
                .expect("data in stash are not valid"),
            attach_id: a.state.attach,
            witness: a.witness,
        }
    }
}

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

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractOp {
    pub direction: OpDirection,
    pub ty: AssignmentType,
    pub opids: BTreeSet<OpId>,
    pub state: StrictVal,
    pub attach_id: Option<AttachId>,
    pub to: BTreeSet<XOutputSeal>,
    pub witness: Option<WitnessInfo>,
}

impl ContractOp {
    fn new(
        direction: OpDirection,
        assignment: Allocation,
        value: StrictVal,
        witness: Option<WitnessInfo>,
    ) -> Self {
        Self {
            direction,
            ty: assignment.opout.ty,
            opids: bset![assignment.opout.op],
            state: value,
            attach_id: assignment.state.attach,
            to: bset![assignment.seal],
            witness,
        }
    }

    fn issued(assignment: Allocation, value: StrictVal) -> Self {
        Self::new(OpDirection::Issued, assignment, value, None)
    }

    fn received(assignment: Allocation, value: StrictVal, witness: WitnessInfo) -> Self {
        Self::new(OpDirection::Received, assignment, value, Some(witness))
    }

    fn sent(assignment: Allocation, value: StrictVal, witness: WitnessInfo) -> Self {
        Self::new(OpDirection::Sent, assignment, value, Some(witness))
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
    pub scripts: Scripts,
    pub info: ContractInfo,
}

impl<S: ContractStateRead> ContractIface<S> {
    fn assignment_type(&self, name: impl Into<FieldName>) -> Result<AssignmentType, ContractError> {
        let name = name.into();
        self.iface
            .assignment_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))
    }

    fn assignment_sem_id(&self, ty: AssignmentType) -> SemId {
        self.schema
            .owned_types
            .get(&ty)
            .expect("invalid contract state")
            .sem_id
    }

    fn allocation_to_output(&self, a: &Allocation) -> Output {
        Output {
            opout: a.opout,
            seal: a.seal,
            state: self.value_from_state_raw(a.opout.ty, &a.state),
            attach_id: a.state.attach,
            witness: a.witness,
        }
    }

    pub fn value_from_state_raw(&self, ty: AssignmentType, state: &State) -> StrictVal {
        self.types
            .strict_deserialize_type(self.assignment_sem_id(ty), state.data.as_slice())
            .expect("invalid contract state")
            .unbox()
    }

    pub fn value_from_state(
        &self,
        name: impl Into<FieldName>,
        state: &State,
    ) -> Result<StrictVal, ContractError> {
        let type_id = self.assignment_type(name)?;
        Ok(self.value_from_state_raw(type_id, state))
    }

    pub fn value_to_state_raw(
        &self,
        ty: AssignmentType,
        value: StrictVal,
    ) -> Result<StateData, ContractError> {
        let t = self.types.typify(value, self.assignment_sem_id(ty))?;
        let value = self
            .types
            .strict_serialize_value::<STATE_DATA_MAX_LEN>(&t)?;
        Ok(value.into())
    }

    pub fn value_to_state(
        &self,
        name: impl Into<FieldName>,
        value: StrictVal,
    ) -> Result<StateData, ContractError> {
        let type_id = self.assignment_type(name)?;
        self.value_to_state_raw(type_id, value)
    }

    pub fn contract_id(&self) -> ContractId { self.state.contract_id() }

    /// # Panics
    ///
    /// If data are corrupted and contract schema doesn't match interface implementations.
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
                    .strict_deserialize_type(global_schema.sem_id, data.borrow())
                    .expect("unvalidated contract data in stash")
                    .unbox()
            }))
    }

    /// # Panics
    ///
    /// If data are corrupted and contract schema doesn't match interface implementations.
    pub fn global_typed<T: StrictDeserialize>(
        &self,
        name: impl Into<FieldName>,
    ) -> Result<impl Iterator<Item = T> + '_, ContractError> {
        let name = name.into();
        let type_id = self
            .iface
            .global_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        Ok(self
            .state
            .global(type_id)
            .expect("schema doesn't match interface")
            .map(|data| {
                let data = SmallBlob::from_slice_checked(data.borrow());
                T::from_strict_serialized(data).expect("unvalidated contract data in stash")
            }))
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = &'c Allocation> + 'c {
        self.state
            .assignments()
            .filter(move |a| filter.should_include(a.seal, a.witness))
    }

    pub fn outputs<'c>(
        &'c self,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Output> + 'c {
        self.allocations(filter)
            .map(|a| self.allocation_to_output(a))
    }

    pub fn outputs_by_type<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = Output> + 'c, ContractError> {
        let type_id = self.assignment_type(name)?;
        Ok(self
            .outputs(filter)
            .filter(move |outp| outp.opout.ty == type_id))
    }

    pub fn output_selection<'c, K: Ord + 'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
        sorting: impl FnMut(&&Allocation) -> K,
        state: &'c State,
    ) -> Result<impl Iterator<Item = Output> + 'c, ContractError> {
        let type_id = self.assignment_type(name)?;
        let mut selected = self
            .allocations(filter)
            .filter(move |a| a.opout.ty == type_id)
            .collect::<Vec<_>>();
        selected.sort_by_key(sorting);
        let mut calc = StateCalc::new(self.scripts.clone(), self.iface.state_abi);
        Ok(selected
            .into_iter()
            .take_while(move |a| {
                if calc.reg_input(a.opout.ty, &a.state).is_err() {
                    return false;
                }
                calc.is_sufficient_for(a.opout.ty, state)
            })
            .map(|a| self.allocation_to_output(a)))
    }

    pub fn outputs_typed<'c, T: StrictDeserialize + 'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> Result<impl Iterator<Item = Output<T>> + 'c, ContractError> {
        let type_id = self.assignment_type(name)?;
        Ok(self
            .allocations(filter)
            .filter(move |a| a.opout.ty == type_id)
            .cloned()
            .map(Output::from))
    }

    pub fn history(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Vec<ContractOp> {
        // get all allocations which ever belonged to this wallet and store them by witness id
        let mut allocations_our_outpoint = self
            .state
            .assignments()
            .filter(move |outp| filter_outpoints.should_include(outp.seal, outp.witness))
            .fold(HashMap::<_, HashSet<_>>::new(), |mut map, a| {
                map.entry(a.witness).or_default().insert(a.clone());
                map
            });
        // get all allocations which has a witness transaction belonging to this wallet
        let mut allocations_our_witness = self
            .state
            .assignments()
            .filter(move |outp| filter_witnesses.should_include(outp.seal, outp.witness))
            .fold(HashMap::<_, HashSet<_>>::new(), |mut map, a| {
                let witness = a.witness.expect(
                    "all empty witnesses must be already filtered out by wallet.filter_witness()",
                );
                map.entry(witness).or_default().insert(a.clone());
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
        if let Some(genesis_state) = allocations_our_outpoint.remove(&None) {
            for assignment in genesis_state {
                let value = self.value_from_state_raw(assignment.opout.ty, &assignment.state);
                ops.push(ContractOp::issued(assignment, value))
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
                (Some(our_assignments), Some(all_assignments)) => {
                    // all_allocations - our_allocations = external payments
                    let ext_assignments = all_assignments
                        .difference(&our_assignments)
                        .cloned()
                        .collect::<HashSet<_>>();
                    // This was a blank state transition with no external payment
                    if ext_assignments.is_empty() {
                        continue;
                    }
                    for assignment in ext_assignments {
                        let value =
                            self.value_from_state_raw(assignment.opout.ty, &assignment.state);
                        ops.push(ContractOp::sent(assignment, value, witness_info))
                    }
                }
                // the same as above, but the payment has no change
                (None, Some(ext_assignments)) => {
                    for assignment in ext_assignments {
                        let value =
                            self.value_from_state_raw(assignment.opout.ty, &assignment.state);
                        ops.push(ContractOp::sent(assignment, value, witness_info))
                    }
                }
                // we own allocation but the witness transaction was made by other wallet:
                // this is an incoming payment to us.
                (Some(our_assignments), None) => {
                    for assignment in our_assignments {
                        let value =
                            self.value_from_state_raw(assignment.opout.ty, &assignment.state);
                        ops.push(ContractOp::received(assignment, value, witness_info))
                    }
                }
                // these can't get into the `witness_ids` due to the used filters
                (None, None) => unreachable!("broken allocation filters"),
            };
        }

        ops
    }

    pub fn witness_info(&self, witness_id: XWitnessId) -> Option<WitnessInfo> {
        let ord = self.state.witness_ord(witness_id)?;
        Some(WitnessInfo {
            id: witness_id,
            ord,
        })
    }
}
