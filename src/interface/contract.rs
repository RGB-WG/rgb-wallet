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

use amplify::confinement::{SmallOrdSet, SmallVec};
use invoice::{Allocation, Amount};
use rgb::{
    AssignmentWitness, AttachId, ContractId, ContractState, DataState, KnownState, MediaType, OpId,
    OutputAssignment, RevealedAttach, RevealedData, RevealedValue, VoidState, XOutpoint,
    XOutputSeal, XWitnessId,
};
use rgbinvoice::OwnedFraction;
use strict_encoding::{FieldName, StrictDecode, StrictDumb, StrictEncode};
use strict_types::typify::TypedVal;
use strict_types::{decode, StrictVal, TypeSystem};

use crate::info::ContractInfo;
use crate::interface::{IfaceImpl, OutpointFilter, WitnessFilter};
use crate::LIB_NAME_RGB_STD;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// field name {0} is unknown to the contract interface
    FieldNameUnknown(FieldName),

    #[from]
    #[display(inner)]
    Reify(decode::Error),
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
    Attachment(AttachedState),
}

impl KnownState for AllocatedState {}

pub type OwnedAllocation = OutputAssignment<AllocatedState>;
pub type RightsAllocation = OutputAssignment<VoidState>;
pub type FungibleAllocation = OutputAssignment<Amount>;
pub type DataAllocation = OutputAssignment<DataState>;
pub type AttachAllocation = OutputAssignment<AttachedState>;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[display("{id}:{media_type}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AttachedState {
    pub id: AttachId,
    pub media_type: MediaType,
}

impl KnownState for AttachedState {}

impl From<RevealedAttach> for AttachedState {
    fn from(attach: RevealedAttach) -> Self {
        AttachedState {
            id: attach.id,
            media_type: attach.media_type,
        }
    }
}

pub trait StateChange: Clone + Eq + StrictDumb + StrictEncode + StrictDecode {
    type State: KnownState;
    fn from_spent(state: Self::State) -> Self;
    fn from_received(state: Self::State) -> Self;
    fn merge_spent(&mut self, state: Self::State);
    fn merge_received(&mut self, state: Self::State);
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OwnedFractionChange {
    #[display("-{0}")]
    #[strict_type(tag = 0xFF)]
    Dec(OwnedFraction),

    #[display("0")]
    #[strict_type(tag = 0, dumb)]
    Zero,

    #[display("+{0}")]
    #[strict_type(tag = 0x01)]
    Inc(OwnedFraction),
}

impl StateChange for OwnedFractionChange {
    type State = OwnedFraction;

    fn from_spent(state: Self::State) -> Self { OwnedFractionChange::Dec(state) }

    fn from_received(state: Self::State) -> Self { OwnedFractionChange::Inc(state) }

    fn merge_spent(&mut self, sub: Self::State) {
        *self = match self {
            OwnedFractionChange::Dec(neg) => OwnedFractionChange::Dec(*neg + sub),
            OwnedFractionChange::Zero => OwnedFractionChange::Dec(sub),
            OwnedFractionChange::Inc(pos) => match sub.cmp(pos) {
                Ordering::Less => OwnedFractionChange::Inc(*pos - sub),
                Ordering::Equal => OwnedFractionChange::Zero,
                Ordering::Greater => OwnedFractionChange::Dec(sub - *pos),
            },
        };
    }

    fn merge_received(&mut self, add: Self::State) {
        *self = match self {
            OwnedFractionChange::Inc(pos) => OwnedFractionChange::Inc(*pos + add),
            OwnedFractionChange::Zero => OwnedFractionChange::Inc(add),
            OwnedFractionChange::Dec(neg) => match add.cmp(neg) {
                Ordering::Less => OwnedFractionChange::Dec(*neg - add),
                Ordering::Equal => OwnedFractionChange::Zero,
                Ordering::Greater => OwnedFractionChange::Inc(add - *neg),
            },
        };
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AmountChange {
    #[display("-{0}")]
    #[strict_type(tag = 0xFF)]
    Dec(Amount),

    #[display("0")]
    #[strict_type(tag = 0, dumb)]
    Zero,

    #[display("+{0}")]
    #[strict_type(tag = 0x01)]
    Inc(Amount),
}

impl StateChange for AmountChange {
    type State = Amount;

    fn from_spent(state: Self::State) -> Self { AmountChange::Dec(state) }

    fn from_received(state: Self::State) -> Self { AmountChange::Inc(state) }

    fn merge_spent(&mut self, sub: Self::State) {
        *self = match self {
            AmountChange::Dec(neg) => AmountChange::Dec(*neg + sub),
            AmountChange::Zero => AmountChange::Dec(sub),
            AmountChange::Inc(pos) => match sub.cmp(pos) {
                Ordering::Less => AmountChange::Inc(*pos - sub),
                Ordering::Equal => AmountChange::Zero,
                Ordering::Greater => AmountChange::Dec(sub - *pos),
            },
        };
    }

    fn merge_received(&mut self, add: Self::State) {
        *self = match self {
            AmountChange::Inc(pos) => AmountChange::Inc(*pos + add),
            AmountChange::Zero => AmountChange::Inc(add),
            AmountChange::Dec(neg) => match add.cmp(neg) {
                Ordering::Less => AmountChange::Dec(*neg - add),
                Ordering::Equal => AmountChange::Zero,
                Ordering::Greater => AmountChange::Inc(add - *neg),
            },
        };
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct IfaceOp<S: StateChange> {
    pub opids: SmallOrdSet<OpId>,  // may come from multiple bundles
    pub inputs: SmallOrdSet<OpId>, // may come from multiple bundles
    pub state_change: S,
    pub payers: SmallOrdSet<XOutputSeal>,
    pub beneficiaries: SmallOrdSet<XOutputSeal>,
}

impl<C: StateChange> IfaceOp<C> {
    fn from_spent(alloc: OutputAssignment<C::State>) -> Self {
        Self {
            opids: none!(),
            inputs: confined_bset![alloc.opout.op],
            state_change: C::from_spent(alloc.state),
            payers: none!(),
            // TODO: Do something with beneficiary info
            beneficiaries: none!(),
        }
    }
    fn from_received(alloc: OutputAssignment<C::State>) -> Self {
        Self {
            opids: confined_bset![alloc.opout.op],
            inputs: none!(),
            state_change: C::from_received(alloc.state),
            // TODO: Do something with payer info
            payers: none!(),
            beneficiaries: none!(),
        }
    }
    fn merge_spent(&mut self, alloc: OutputAssignment<C::State>) {
        self.inputs
            .push(alloc.opout.op)
            .expect("internal inconsistency of stash data");
        self.state_change.merge_spent(alloc.state);
        // TODO: Do something with beneficiary info
    }
    fn merge_received(&mut self, alloc: OutputAssignment<C::State>) {
        self.opids
            .push(alloc.opout.op)
            .expect("internal inconsistency of stash data");
        self.state_change.merge_received(alloc.state);
        // TODO: Do something with payer info
    }
}

/// Contract state is an in-memory structure providing API to read structured
/// data from the [`rgb::ContractHistory`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ContractIface {
    pub state: ContractState,
    pub iface: IfaceImpl,
    pub types: TypeSystem,
    pub info: ContractInfo,
}

// TODO: Introduce witness checker: additional filter returning only those data
//       which witnesses are mined
impl ContractIface {
    pub fn contract_id(&self) -> ContractId { self.state.contract_id() }

    /// # Panics
    ///
    /// If data are corrupted and contract schema doesn't match interface
    /// implementations.
    pub fn global(&self, name: impl Into<FieldName>) -> Result<SmallVec<StrictVal>, ContractError> {
        let name = name.into();
        let type_id = self
            .iface
            .global_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        let type_schema = self
            .state
            .schema
            .global_types
            .get(&type_id)
            .expect("schema doesn't match interface");
        let state = unsafe { self.state.global_unchecked(type_id) };
        let state = state
            .into_iter()
            .map(|data| {
                self.types
                    .strict_deserialize_type(type_schema.sem_id, data.as_ref())
                    .map(TypedVal::unbox)
            })
            .take(type_schema.max_items as usize)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SmallVec::try_from_iter(state).expect("same or smaller collection size"))
    }

    fn extract_state<'c, S, U>(
        &'c self,
        state: impl IntoIterator<Item = &'c OutputAssignment<S>> + 'c,
        name: impl Into<FieldName>,
        filter: impl OutpointFilter + 'c,
    ) -> Result<impl Iterator<Item = OutputAssignment<U>> + 'c, ContractError>
    where
        S: Clone + KnownState + 'c,
        U: From<S> + KnownState + 'c,
    {
        let name = name.into();
        let type_id = self
            .iface
            .assignments_type(&name)
            .ok_or(ContractError::FieldNameUnknown(name))?;
        Ok(state
            .into_iter()
            .filter(move |outp| outp.opout.ty == type_id)
            .filter(move |outp| filter.include_outpoint(outp.seal))
            .cloned()
            .map(OutputAssignment::<S>::transmute))
    }

    pub fn rights<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl OutpointFilter + 'c,
    ) -> Result<impl Iterator<Item = RightsAllocation> + 'c, ContractError> {
        self.extract_state(self.state.rights(), name, filter)
    }

    pub fn fungible<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl OutpointFilter + 'c,
    ) -> Result<impl Iterator<Item = FungibleAllocation> + 'c, ContractError> {
        self.extract_state(self.state.fungibles(), name, filter)
    }

    pub fn data<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl OutpointFilter + 'c,
    ) -> Result<impl Iterator<Item = DataAllocation> + 'c, ContractError> {
        self.extract_state(self.state.data(), name, filter)
    }

    pub fn attachments<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl OutpointFilter + 'c,
    ) -> Result<impl Iterator<Item = AttachAllocation> + 'c, ContractError> {
        self.extract_state(self.state.attach(), name, filter)
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl OutpointFilter + Copy + 'c,
    ) -> impl Iterator<Item = OwnedAllocation> + 'c {
        fn f<'a, S, U>(
            filter: impl OutpointFilter + 'a,
            state: impl IntoIterator<Item = &'a OutputAssignment<S>> + 'a,
        ) -> impl Iterator<Item = OutputAssignment<U>> + 'a
        where
            S: Clone + KnownState + 'a,
            U: From<S> + KnownState + 'a,
        {
            state
                .into_iter()
                .filter(move |outp| filter.include_outpoint(outp.seal))
                .cloned()
                .map(OutputAssignment::<S>::transmute)
        }

        f(filter, self.state.rights())
            .map(OwnedAllocation::from)
            .chain(f(filter, self.state.fungibles()).map(OwnedAllocation::from))
            .chain(f(filter, self.state.data()).map(OwnedAllocation::from))
            .chain(f(filter, self.state.attach()).map(OwnedAllocation::from))
    }

    pub fn outpoint_allocations(
        &self,
        outpoint: XOutpoint,
    ) -> impl Iterator<Item = OwnedAllocation> + '_ {
        self.allocations(outpoint)
    }

    // TODO: Ignore blank state transition
    fn operations<'c, C: StateChange>(
        &'c self,
        state: impl IntoIterator<Item = OutputAssignment<C::State>> + 'c,
        allocations: impl Iterator<Item = OutputAssignment<C::State>> + 'c,
        witness_filter: impl WitnessFilter + Copy,
        // resolver: impl WitnessCheck + 'c,
    ) -> HashMap<XWitnessId, IfaceOp<C>>
    where
        C::State: 'c,
    {
        fn f<'a, S, U>(
            filter: impl WitnessFilter + 'a,
            state: impl IntoIterator<Item = OutputAssignment<S>> + 'a,
        ) -> impl Iterator<Item = OutputAssignment<U>> + 'a
        where
            S: Clone + KnownState + 'a,
            U: From<S> + KnownState + 'a,
        {
            state
                .into_iter()
                .filter(move |outp| filter.include_witness(outp.witness))
                .map(OutputAssignment::<S>::transmute)
        }

        let spent = f::<_, C::State>(witness_filter, state).map(OutputAssignment::from);
        let mut ops = HashMap::<XWitnessId, IfaceOp<C>>::new();
        for alloc in spent {
            let AssignmentWitness::Present(witness_id) = alloc.witness else {
                continue;
            };
            if let Some(op) = ops.get_mut(&witness_id) {
                op.merge_spent(alloc);
            } else {
                ops.insert(witness_id, IfaceOp::from_spent(alloc));
            }
        }

        for alloc in allocations {
            let AssignmentWitness::Present(witness_id) = alloc.witness else {
                continue;
            };
            if let Some(op) = ops.get_mut(&witness_id) {
                op.merge_received(alloc);
            } else {
                ops.insert(witness_id, IfaceOp::from_received(alloc));
            }
        }

        ops
    }

    pub fn fungible_ops<C: StateChange<State = Amount>>(
        &self,
        name: impl Into<FieldName>,
        witness_filter: impl WitnessFilter + Copy,
        outpoint_filter: impl OutpointFilter + Copy,
    ) -> Result<HashMap<XWitnessId, IfaceOp<C>>, ContractError> {
        Ok(self.operations(
            self.state
                .fungibles()
                .iter()
                .cloned()
                .map(OutputAssignment::transmute),
            self.fungible(name, outpoint_filter)?,
            witness_filter,
        ))
    }

    pub fn data_ops<C: StateChange<State = DataState>>(
        &self,
        name: impl Into<FieldName>,
        witness_filter: impl WitnessFilter + Copy,
        outpoint_filter: impl OutpointFilter + Copy,
    ) -> Result<HashMap<XWitnessId, IfaceOp<C>>, ContractError> {
        Ok(self.operations(
            self.state
                .data()
                .iter()
                .cloned()
                .map(OutputAssignment::transmute),
            self.data(name, outpoint_filter)?,
            witness_filter,
        ))
    }

    pub fn rights_ops<C: StateChange<State = VoidState>>(
        &self,
        name: impl Into<FieldName>,
        witness_filter: impl WitnessFilter + Copy,
        outpoint_filter: impl OutpointFilter + Copy,
    ) -> Result<HashMap<XWitnessId, IfaceOp<C>>, ContractError> {
        Ok(self.operations(
            self.state
                .rights()
                .iter()
                .cloned()
                .map(OutputAssignment::transmute),
            self.rights(name, outpoint_filter)?,
            witness_filter,
        ))
    }

    pub fn attachment_ops<C: StateChange<State = AttachedState>>(
        &self,
        name: impl Into<FieldName>,
        witness_filter: impl WitnessFilter + Copy,
        outpoint_filter: impl OutpointFilter + Copy,
    ) -> Result<HashMap<XWitnessId, IfaceOp<C>>, ContractError> {
        Ok(self.operations(
            self.state
                .attach()
                .iter()
                .cloned()
                .map(OutputAssignment::transmute),
            self.attachments(name, outpoint_filter)?,
            witness_filter,
        ))
    }
}
