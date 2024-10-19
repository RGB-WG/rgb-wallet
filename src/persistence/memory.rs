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
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::num::NonZeroU32;
use std::{iter, mem};

use aluvm::library::{Lib, LibId};
use amplify::confinement::{
    self, Confined, LargeOrdMap, LargeOrdSet, MediumBlob, MediumOrdMap, MediumOrdSet, SmallOrdMap,
    TinyOrdMap, TinyOrdSet,
};
use amplify::num::u24;
use bp::dbc::tapret::TapretCommitment;
use commit_verify::{CommitId, Conceal};
use nonasync::persistence::{CloneNoPersistence, Persistence, PersistenceError, Persisting};
use rgb::validation::ResolveWitness;
use rgb::vm::{
    ContractStateAccess, ContractStateEvolve, GlobalContractState, GlobalOrd, GlobalStateIter,
    OrdOpRef, UnknownGlobalStateType, WitnessOrd,
};
use rgb::{
    Assign, AssignmentType, Assignments, AssignmentsRef, AttachId, BundleId, ContractId,
    ExposedSeal, Extension, Genesis, GenesisSeal, GlobalStateType, GraphSeal, Identity, OpId,
    Operation, Opout, Schema, SchemaId, SecretSeal, StateData, Transition, TransitionBundle,
    XChain, XOutpoint, XOutputSeal, XWitnessId,
};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::TypeSystem;

use super::{
    ContractIfaceError, ContractStateRead, ContractStateWrite, IndexInconsistency, IndexProvider,
    IndexReadError, IndexReadProvider, IndexWriteError, IndexWriteProvider, SchemaIfaces,
    StashInconsistency, StashProvider, StashProviderError, StashReadProvider, StashWriteProvider,
    StateInconsistency, StateProvider, StateReadProvider, StateWriteProvider, StoreTransaction,
    UpdateRes,
};
use crate::containers::{
    AnchorSet, ContentId, ContentRef, ContentSigs, SealWitness, SigBlob, Supplement, TrustLevel,
};
use crate::contract::{Allocation, GlobalOut, OpWitness};
use crate::interface::{Iface, IfaceClass, IfaceId, IfaceImpl, IfaceRef};
use crate::LIB_NAME_RGB_STORAGE;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum MemError {
    #[from]
    Persistence(PersistenceError),

    #[from]
    Confinement(confinement::Error),
}

//////////
// STASH
//////////

/// Hoard is an in-memory stash useful for WASM implementations.
#[derive(Getters, Debug)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemStash {
    #[getter(skip)]
    #[strict_type(skip)]
    persistence: Option<Persistence<Self>>,

    schemata: TinyOrdMap<SchemaId, SchemaIfaces>,
    ifaces: TinyOrdMap<IfaceId, Iface>,
    geneses: TinyOrdMap<ContractId, Genesis>,
    suppl: TinyOrdMap<ContentRef, TinyOrdSet<Supplement>>,
    bundles: LargeOrdMap<BundleId, TransitionBundle>,
    extensions: LargeOrdMap<OpId, Extension>,
    witnesses: LargeOrdMap<XWitnessId, SealWitness>,
    attachments: SmallOrdMap<AttachId, MediumBlob>,
    secret_seals: MediumOrdSet<XChain<GraphSeal>>,
    type_system: TypeSystem,
    identities: SmallOrdMap<Identity, TrustLevel>,
    libs: SmallOrdMap<LibId, Lib>,
    sigs: SmallOrdMap<ContentId, ContentSigs>,
}

impl StrictSerialize for MemStash {}
impl StrictDeserialize for MemStash {}

impl MemStash {
    pub fn in_memory() -> Self {
        Self {
            persistence: none!(),
            schemata: empty!(),
            ifaces: empty!(),
            geneses: empty!(),
            suppl: empty!(),
            bundles: empty!(),
            extensions: empty!(),
            witnesses: empty!(),
            attachments: empty!(),
            secret_seals: empty!(),
            type_system: none!(),
            identities: empty!(),
            libs: empty!(),
            sigs: empty!(),
        }
    }
}

impl CloneNoPersistence for MemStash {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            schemata: self.schemata.clone(),
            ifaces: self.ifaces.clone(),
            geneses: self.geneses.clone(),
            suppl: self.suppl.clone(),
            bundles: self.bundles.clone(),
            extensions: self.extensions.clone(),
            witnesses: self.witnesses.clone(),
            attachments: self.attachments.clone(),
            secret_seals: self.secret_seals.clone(),
            type_system: self.type_system.clone(),
            identities: self.identities.clone(),
            libs: self.libs.clone(),
            sigs: self.sigs.clone(),
        }
    }
}

impl Persisting for MemStash {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl StoreTransaction for MemStash {
    type TransactionErr = MemError;
    #[inline]
    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.mark_dirty();
        Ok(())
    }
    #[inline]
    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> { Ok(self.store()?) }
    #[inline]
    fn rollback_transaction(&mut self) { unreachable!() }
}

impl StashProvider for MemStash {}

impl StashReadProvider for MemStash {
    // With in-memory data we have no connectivity or I/O errors
    type Error = Infallible;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error> { Ok(&self.type_system) }

    fn lib(&self, id: LibId) -> Result<&Lib, StashProviderError<Self::Error>> {
        self.libs
            .get(&id)
            .ok_or_else(|| StashInconsistency::LibAbsent(id).into())
    }

    fn ifaces(&self) -> Result<impl Iterator<Item = &Iface>, Self::Error> {
        Ok(self.ifaces.values())
    }

    fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, StashProviderError<Self::Error>> {
        let iref = iface.into();
        match iref {
            IfaceRef::Name(ref name) => self.ifaces.values().find(|iface| &iface.name == name),
            IfaceRef::Id(ref id) => self.ifaces.get(id),
        }
        .ok_or_else(|| StashInconsistency::IfaceAbsent(iref).into())
    }

    fn schemata(&self) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error> {
        Ok(self.schemata.values())
    }
    fn schemata_by<C: IfaceClass>(
        &self,
    ) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error> {
        Ok(self
            .schemata
            .values()
            .filter(|schema_ifaces| self.impl_for::<C>(schema_ifaces).is_ok()))
    }

    fn impl_for<'a, C: IfaceClass + 'a>(
        &'a self,
        schema_ifaces: &'a SchemaIfaces,
    ) -> Result<&'a IfaceImpl, StashProviderError<Self::Error>> {
        schema_ifaces
            .iimpls
            .values()
            .find(|iimpl| C::IFACE_IDS.contains(&iimpl.iface_id))
            .or_else(|| {
                C::IFACE_IDS.iter().find_map(|id| {
                    let iface = self.iface(*id).ok()?;
                    iface.find_abstractable_impl(schema_ifaces)
                })
            })
            .ok_or_else(move || {
                ContractIfaceError::NoAbstractImpl(
                    C::IFACE_IDS[0],
                    schema_ifaces.schema.schema_id(),
                )
                .into()
            })
    }

    fn schema(
        &self,
        schema_id: SchemaId,
    ) -> Result<&SchemaIfaces, StashProviderError<Self::Error>> {
        self.schemata
            .get(&schema_id)
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn get_trust(&self, identity: &Identity) -> Result<TrustLevel, Self::Error> {
        Ok(self.identities.get(identity).copied().unwrap_or_default())
    }

    fn supplement(&self, content_ref: ContentRef) -> Result<Option<&Supplement>, Self::Error> {
        Ok(self.suppl.get(&content_ref).and_then(|s| s.first()))
    }

    fn supplements(
        &self,
        content_ref: ContentRef,
    ) -> Result<impl Iterator<Item = Supplement>, Self::Error> {
        Ok(self
            .suppl
            .get(&content_ref)
            .cloned()
            .unwrap_or_default()
            .into_iter())
    }

    fn sigs_for(&self, content_id: &ContentId) -> Result<Option<&ContentSigs>, Self::Error> {
        Ok(self.sigs.get(content_id))
    }

    fn geneses(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error> {
        Ok(self.geneses.values())
    }

    fn geneses_by<C: IfaceClass>(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error> {
        Ok(self.schemata_by::<C>()?.flat_map(|schema_ifaces| {
            self.geneses
                .values()
                .filter(|genesis| schema_ifaces.schema.schema_id() == genesis.schema_id)
        }))
    }

    fn genesis(
        &self,
        contract_id: ContractId,
    ) -> Result<&Genesis, StashProviderError<Self::Error>> {
        self.geneses
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn witness_ids(&self) -> Result<impl Iterator<Item = XWitnessId>, Self::Error> {
        Ok(self.witnesses.keys().copied())
    }

    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error> {
        Ok(self.bundles.keys().copied())
    }

    fn bundle(
        &self,
        bundle_id: BundleId,
    ) -> Result<&TransitionBundle, StashProviderError<Self::Error>> {
        self.bundles
            .get(&bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(bundle_id).into())
    }

    fn extension_ids(&self) -> Result<impl Iterator<Item = OpId>, Self::Error> {
        Ok(self.extensions.keys().copied())
    }

    fn extension(&self, op_id: OpId) -> Result<&Extension, StashProviderError<Self::Error>> {
        self.extensions
            .get(&op_id)
            .ok_or(StashInconsistency::OperationAbsent(op_id).into())
    }

    fn witness(
        &self,
        witness_id: XWitnessId,
    ) -> Result<&SealWitness, StashProviderError<Self::Error>> {
        self.witnesses
            .get(&witness_id)
            .ok_or(StashInconsistency::WitnessAbsent(witness_id).into())
    }

    fn taprets(&self) -> Result<impl Iterator<Item = (XWitnessId, TapretCommitment)>, Self::Error> {
        Ok(self
            .witnesses
            .iter()
            .filter_map(|(witness_id, witness)| match &witness.anchors {
                AnchorSet::Tapret(anchor)
                | AnchorSet::Double {
                    tapret: anchor,
                    opret: _,
                } => Some((*witness_id, TapretCommitment {
                    mpc: anchor.mpc_proof.commit_id(),
                    nonce: anchor.dbc_proof.path_proof.nonce(),
                })),
                _ => None,
            }))
    }

    fn seal_secret(
        &self,
        secret: XChain<SecretSeal>,
    ) -> Result<Option<XChain<GraphSeal>>, Self::Error> {
        Ok(self
            .secret_seals
            .iter()
            .find(|s| s.conceal() == secret)
            .copied())
    }

    fn secret_seals(&self) -> Result<impl Iterator<Item = XChain<GraphSeal>>, Self::Error> {
        Ok(self.secret_seals.iter().copied())
    }
}

impl StashWriteProvider for MemStash {
    type Error = MemError;

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, Self::Error> {
        let schema_id = schema.schema_id();
        if !self.schemata.contains_key(&schema_id) {
            self.schemata.insert(schema_id, SchemaIfaces::new(schema))?;
            return Ok(true);
        }
        Ok(false)
    }

    fn replace_iface(&mut self, iface: Iface) -> Result<bool, Self::Error> {
        let iface_id = iface.iface_id();
        if !self.ifaces.contains_key(&iface_id) {
            self.ifaces.insert(iface_id, iface)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn replace_iimpl(&mut self, iimpl: IfaceImpl) -> Result<bool, Self::Error> {
        let schema_ifaces = self
            .schemata
            .get_mut(&iimpl.schema_id)
            .expect("unknown schema");
        let iface = self.ifaces.get(&iimpl.iface_id).expect("unknown interface");
        let iface_name = iface.name.clone();
        let present = schema_ifaces.iimpls.contains_key(&iface_name);
        schema_ifaces.iimpls.insert(iface_name, iimpl)?;
        Ok(!present)
    }

    fn set_trust(
        &mut self,
        identity: Identity,
        trust: TrustLevel,
    ) -> Result<(), confinement::Error> {
        self.identities.insert(identity, trust)?;
        Ok(())
    }

    fn add_supplement(&mut self, suppl: Supplement) -> Result<(), Self::Error> {
        match self.suppl.get_mut(&suppl.content_id) {
            None => {
                self.suppl.insert(suppl.content_id, tiny_bset![suppl])?;
            }
            Some(suppls) => suppls.push(suppl)?,
        }
        Ok(())
    }

    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, Self::Error> {
        let contract_id = genesis.contract_id();
        let present = self.geneses.insert(contract_id, genesis)?.is_some();
        Ok(!present)
    }

    fn replace_extension(&mut self, extension: Extension) -> Result<bool, Self::Error> {
        let opid = extension.id();
        let present = self.extensions.insert(opid, extension)?.is_some();
        Ok(!present)
    }

    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error> {
        let bundle_id = bundle.bundle_id();
        let present = self.bundles.insert(bundle_id, bundle)?.is_some();
        Ok(!present)
    }

    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error> {
        let witness_id = witness.witness_id();
        let present = self.witnesses.insert(witness_id, witness)?.is_some();
        Ok(!present)
    }

    fn replace_attachment(
        &mut self,
        id: AttachId,
        attach: MediumBlob,
    ) -> Result<bool, Self::Error> {
        let present = self.attachments.insert(id, attach)?.is_some();
        Ok(!present)
    }

    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error> {
        Ok(self.type_system.extend(types)?)
    }

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, Self::Error> {
        let present = self.libs.insert(lib.id(), lib)?.is_some();
        Ok(!present)
    }

    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), Self::Error>
    where I: IntoIterator<Item = (Identity, SigBlob)> {
        let sigs = sigs.into_iter().filter(|(id, _)| {
            match self.identities.get(id) {
                Some(level) => *level,
                None => {
                    let level = TrustLevel::default();
                    // We ignore if the identities are full
                    self.identities.insert(id.clone(), level).ok();
                    level
                }
            }
            .should_accept()
        });
        if let Some(prev_sigs) = self.sigs.get_mut(&content_id) {
            prev_sigs.extend(sigs)?;
        } else {
            let sigs = Confined::try_from_iter(sigs)?;
            self.sigs.insert(content_id, ContentSigs::from(sigs)).ok();
        }
        Ok(())
    }

    fn add_secret_seal(&mut self, seal: XChain<GraphSeal>) -> Result<bool, Self::Error> {
        let present = self.secret_seals.contains(&seal);
        self.secret_seals.push(seal)?;
        Ok(!present)
    }
}

//////////
// STATE
//////////

#[derive(Getters, Debug)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemState {
    #[getter(skip)]
    #[strict_type(skip)]
    persistence: Option<Persistence<Self>>,

    witnesses: LargeOrdMap<XWitnessId, WitnessOrd>,
    contracts: TinyOrdMap<ContractId, MemContractState>,
}

impl StrictSerialize for MemState {}
impl StrictDeserialize for MemState {}

impl MemState {
    pub fn in_memory() -> Self {
        Self {
            persistence: none!(),
            witnesses: empty!(),
            contracts: empty!(),
        }
    }
}

impl CloneNoPersistence for MemState {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            witnesses: self.witnesses.clone(),
            contracts: self.contracts.clone(),
        }
    }
}

impl Persisting for MemState {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl StoreTransaction for MemState {
    type TransactionErr = MemError;
    #[inline]
    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.mark_dirty();
        Ok(())
    }
    #[inline]
    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> { Ok(self.store()?) }
    #[inline]
    fn rollback_transaction(&mut self) { unreachable!() }
}

impl StateProvider for MemState {}

impl StateReadProvider for MemState {
    type ContractRead<'a> = MemContract<&'a MemContractState>;
    type Error = StateInconsistency;

    fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<Self::ContractRead<'_>, Self::Error> {
        let unfiltered = self
            .contracts
            .get(&contract_id)
            .ok_or(StateInconsistency::UnknownContract(contract_id))?;
        let filter = self
            .witnesses
            .iter()
            .filter(|(id, _)| {
                let id = Some(**id);
                unfiltered
                    .global
                    .values()
                    .flat_map(|state| state.known.keys())
                    .any(|out| out.witness_id() == id)
                    || unfiltered.owned.iter().any(|a| a.witness == id)
            })
            .map(|(id, ord)| (*id, *ord))
            .collect();
        Ok(MemContract { filter, unfiltered })
    }

    fn is_valid_witness(&self, witness_id: XWitnessId) -> Result<bool, Self::Error> {
        let ord = self
            .witnesses
            .get(&witness_id)
            .ok_or(StateInconsistency::AbsentWitness(witness_id))?;
        Ok(ord.is_valid())
    }
}

impl StateWriteProvider for MemState {
    type ContractWrite<'a> = MemContractWriter<'a>;
    type Error = MemError;

    fn register_contract(
        &mut self,
        schema: &Schema,
        genesis: &Genesis,
    ) -> Result<Self::ContractWrite<'_>, Self::Error> {
        // TODO: Add begin/commit transaction
        let contract_id = genesis.contract_id();
        // This crazy construction is caused by a stupidity of rust borrow checker
        let contract = if self.contracts.contains_key(&contract_id) {
            if let Some(contract) = self.contracts.get_mut(&contract_id) {
                contract
            } else {
                unreachable!();
            }
        } else {
            self.contracts
                .insert(contract_id, MemContractState::new(schema, contract_id))?;
            self.contracts.get_mut(&contract_id).expect("just inserted")
        };
        let mut writer = MemContractWriter {
            writer: Box::new(
                |witness_id: XWitnessId, ord: WitnessOrd| -> Result<(), confinement::Error> {
                    // NB: We do not check the existence of the witness since we have a newer
                    // version anyway and even if it is known we have to replace it
                    self.witnesses.insert(witness_id, ord)?;
                    Ok(())
                },
            ),
            contract,
        };
        writer.add_genesis(genesis)?;
        Ok(writer)
    }

    fn update_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Option<Self::ContractWrite<'_>>, Self::Error> {
        // TODO: Add begin/commit transaction
        Ok(self
            .contracts
            .get_mut(&contract_id)
            .map(|contract| MemContractWriter {
                // We can't move this constructor to a dedicated method due to the rust borrower
                // checker
                writer: Box::new(
                    |witness_id: XWitnessId, ord: WitnessOrd| -> Result<(), confinement::Error> {
                        // NB: We do not check the existence of the witness since we have a newer
                        // version anyway and even if it is known we have to replace
                        // it
                        self.witnesses.insert(witness_id, ord)?;
                        Ok(())
                    },
                ),
                contract,
            }))
    }

    fn update_witnesses(
        &mut self,
        resolver: impl ResolveWitness,
        after_height: u32,
    ) -> Result<UpdateRes, Self::Error> {
        let after_height = NonZeroU32::new(after_height).unwrap_or(NonZeroU32::MIN);
        let mut succeeded = 0;
        let mut failed = map![];
        self.begin_transaction()?;
        let mut witnesses = LargeOrdMap::new();
        mem::swap(&mut self.witnesses, &mut witnesses);
        let mut witnesses = witnesses.release();
        for (id, ord) in &mut witnesses {
            if matches!(ord, WitnessOrd::Mined(pos) if pos.height() < after_height) {
                continue;
            }
            match resolver.resolve_pub_witness_ord(*id) {
                Ok(new) => *ord = new,
                Err(err) => {
                    failed.insert(*id, err.to_string());
                }
            }
            succeeded += 1;
        }
        let mut witnesses =
            LargeOrdMap::try_from(witnesses).inspect_err(|_| self.rollback_transaction())?;
        mem::swap(&mut self.witnesses, &mut witnesses);
        self.commit_transaction()?;
        Ok(UpdateRes { succeeded, failed })
    }
}

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MemGlobalState {
    known: LargeOrdMap<GlobalOut, StateData>,
    limit: u24,
}

impl MemGlobalState {
    pub fn new(limit: u24) -> Self {
        MemGlobalState {
            known: empty!(),
            limit,
        }
    }
}

/// Contract history accumulates raw data from the contract history, extracted
/// from a series of consignments over the time. It does consensus ordering of
/// the state data, but it doesn't interpret or validates the state against the
/// schema.
///
/// NB: MemContract provides an in-memory contract state used during contract
/// validation. It does not support filtering by witness transaction validity
/// and thus must not be used in any other cases in its explicit form. Pls see
/// [`MemContract`] instead.
#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct MemContractState {
    #[getter(as_copy)]
    schema_id: SchemaId,
    #[getter(as_copy)]
    contract_id: ContractId,
    #[getter(skip)]
    global: TinyOrdMap<GlobalStateType, MemGlobalState>,
    owned: LargeOrdSet<Allocation>,
}

impl MemContractState {
    pub fn new(schema: &Schema, contract_id: ContractId) -> Self {
        let global = TinyOrdMap::from_iter_checked(
            schema
                .global_types
                .iter()
                .map(|(ty, glob)| (*ty, MemGlobalState::new(glob.max_items))),
        );
        MemContractState {
            schema_id: schema.schema_id(),
            contract_id,
            global,
            owned: empty!(),
        }
    }

    fn add_operation(&mut self, op: OrdOpRef) {
        let opid = op.id();

        for (ty, state) in op.globals() {
            let map = self
                .global
                .get_mut(ty)
                .expect("global map must be initialized from the schema");
            for (idx, s) in state.iter().enumerate() {
                let out = GlobalOut {
                    opid,
                    nonce: op.nonce(),
                    index: idx as u16,
                    op_witness: OpWitness::from(op),
                };
                map.known
                    .insert(out, s.clone())
                    .expect("contract global state exceeded 2^32 items, which is unrealistic");
            }
        }

        // We skip removing of invalidated state for the cases of re-orgs or unmined
        // witness transactions committing to the new state.
        // TODO: Expose an API to prune historic state by witness txid
        /*
        // Remove invalidated state
        for input in &op.inputs() {
            if let Some(o) = self.rights.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone(); // need this b/c of borrow checker
                self.rights
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.fungibles.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone();
                self.fungibles
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.data.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone();
                self.data
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.attach.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone();
                self.attach
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
        }
         */

        let witness_id = op.witness_id();
        match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.add_assignments(witness_id, opid, assignments)
            }
            AssignmentsRef::Graph(assignments) => {
                self.add_assignments(witness_id, opid, assignments)
            }
        }
    }

    fn add_assignments<Seal: ExposedSeal>(
        &mut self,
        witness_id: Option<XWitnessId>,
        opid: OpId,
        assignments: &Assignments<Seal>,
    ) {
        for (ty, assignments) in assignments.iter() {
            for (no, seal, state) in assignments
                .iter()
                .enumerate()
                .filter_map(|(n, a)| a.revealed_seal().map(|seal| (n, seal, a.as_state())))
            {
                let assigned_state = match witness_id {
                    Some(witness_id) => Allocation::with_witness(
                        seal,
                        witness_id,
                        state.clone(),
                        opid,
                        *ty,
                        no as u16,
                    ),
                    None => Allocation::with_no_witness(seal, state.clone(), opid, *ty, no as u16),
                };
                self.owned
                    .push(assigned_state)
                    .expect("contract state exceeded 2^32 items, which is unrealistic");
            }
        }
    }
}

pub struct MemContract<M: Borrow<MemContractState> = MemContractState> {
    filter: HashMap<XWitnessId, WitnessOrd>,
    unfiltered: M,
}

impl<M: Borrow<MemContractState>> Debug for MemContract<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemContractFiltered { .. }")
    }
}

impl<M: Borrow<MemContractState>> ContractStateAccess for MemContract<M> {
    fn global(
        &self,
        ty: GlobalStateType,
    ) -> Result<GlobalContractState<impl GlobalStateIter>, UnknownGlobalStateType> {
        type Src<'a> = &'a BTreeMap<GlobalOut, StateData>;
        type FilteredIter<'a> = Box<dyn Iterator<Item = (GlobalOrd, &'a StateData)> + 'a>;
        struct Iter<'a> {
            src: Src<'a>,
            iter: FilteredIter<'a>,
            last: Option<(GlobalOrd, &'a StateData)>,
            depth: u24,
            constructor: Box<dyn Fn(Src<'a>) -> FilteredIter<'a> + 'a>,
        }
        impl<'a> Iter<'a> {
            fn swap(&mut self) -> FilteredIter<'a> {
                let mut iter = (self.constructor)(self.src);
                mem::swap(&mut iter, &mut self.iter);
                iter
            }
        }
        impl<'a> GlobalStateIter for Iter<'a> {
            type Data = &'a StateData;
            fn size(&mut self) -> u24 {
                let iter = self.swap();
                // TODO: Consuming iterator just to count items is highly inefficient, but I do
                //       not know any other way of computing this value
                let size = iter.count();
                u24::try_from(size as u32).expect("iterator size must fit u24 due to `take` limit")
            }
            fn prev(&mut self) -> Option<(GlobalOrd, Self::Data)> {
                self.last = self.iter.next();
                self.depth += u24::ONE;
                self.last()
            }
            fn last(&mut self) -> Option<(GlobalOrd, Self::Data)> { self.last }
            fn reset(&mut self, depth: u24) {
                match self.depth.cmp(&depth) {
                    Ordering::Less => {
                        let mut iter = Box::new(iter::empty()) as FilteredIter;
                        mem::swap(&mut self.iter, &mut iter);
                        self.iter = Box::new(iter.skip(depth.to_usize() - depth.to_usize()))
                    }
                    Ordering::Equal => {}
                    Ordering::Greater => {
                        let iter = self.swap();
                        self.iter = Box::new(iter.skip(depth.to_usize()));
                    }
                }
            }
        }
        // We need this due to the limitations of the rust compiler to enforce lifetimes
        // on closures
        fn constrained<'a, F: Fn(Src<'a>) -> FilteredIter<'a>>(f: F) -> F { f }

        let state = self
            .unfiltered
            .borrow()
            .global
            .get(&ty)
            .ok_or(UnknownGlobalStateType(ty))?;

        let constructor = constrained(move |src: Src<'_>| -> FilteredIter<'_> {
            Box::new(
                src.iter()
                    .rev()
                    .filter_map(|(out, data)| {
                        let ord = match out.op_witness {
                            OpWitness::Genesis => GlobalOrd::genesis(out.index),
                            OpWitness::Transition(id, ty) => {
                                let ord = self.filter.get(&id)?;
                                GlobalOrd::transition(out.opid, out.index, ty, out.nonce, *ord)
                            }
                            OpWitness::Extension(id, ty) => {
                                let ord = self.filter.get(&id)?;
                                GlobalOrd::extension(out.opid, out.index, ty, out.nonce, *ord)
                            }
                        };
                        Some((ord, data))
                    })
                    .take(state.limit.to_usize()),
            )
        });
        let iter = Iter {
            src: state.known.as_unconfined(),
            iter: constructor(state.known.as_unconfined()),
            depth: u24::ZERO,
            last: None,
            constructor: Box::new(constructor),
        };
        Ok(GlobalContractState::new(iter))
    }

    fn state(
        &self,
        outpoint: XOutpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<rgb::State>> {
        self.unfiltered
            .borrow()
            .owned
            .iter()
            .filter(move |assignment| {
                assignment.seal.to_outpoint() == outpoint && assignment.opout.ty == ty
            })
            .filter(|assignment| assignment.check_witness(&self.filter))
            .map(|assignment| &assignment.state)
    }
}

impl ContractStateEvolve for MemContract<MemContractState> {
    type Context<'ctx> = (&'ctx Schema, ContractId);

    fn init(context: Self::Context<'_>) -> Self {
        Self {
            filter: empty!(),
            unfiltered: MemContractState::new(context.0, context.1),
        }
    }

    fn evolve_state(&mut self, op: OrdOpRef) -> Result<(), confinement::Error> {
        fn writer(me: &mut MemContract<MemContractState>) -> MemContractWriter {
            MemContractWriter {
                writer: Box::new(
                    |witness_id: XWitnessId, ord: WitnessOrd| -> Result<(), confinement::Error> {
                        // NB: We do not check the existence of the witness since we have a
                        // newer version anyway and even if it is
                        // known we have to replace it
                        me.filter.insert(witness_id, ord);
                        Ok(())
                    },
                ),
                contract: &mut me.unfiltered,
            }
        }
        match op {
            OrdOpRef::Genesis(genesis) => {
                let mut writer = writer(self);
                writer.add_genesis(genesis)
            }
            OrdOpRef::Transition(transition, witness_id, ord) => {
                let mut writer = writer(self);
                writer.add_transition(transition, witness_id, ord)
            }
            OrdOpRef::Extension(extension, witness_id, ord) => {
                let mut writer = writer(self);
                writer.add_extension(extension, witness_id, ord)
            }
        }
        .map_err(|err| {
            // TODO: remove once evolve_state would accept arbitrary errors
            match err {
                MemError::Persistence(_) => unreachable!("only confinement errors are possible"),
                MemError::Confinement(e) => e,
            }
        })?;
        Ok(())
    }
}

impl<M: Borrow<MemContractState>> ContractStateRead for MemContract<M> {
    #[inline]
    fn contract_id(&self) -> ContractId { self.unfiltered.borrow().contract_id }

    #[inline]
    fn schema_id(&self) -> SchemaId { self.unfiltered.borrow().schema_id }

    #[inline]
    fn witness_ord(&self, witness_id: XWitnessId) -> Option<WitnessOrd> {
        self.filter.get(&witness_id).copied()
    }

    #[inline]
    fn assignments(&self) -> impl Iterator<Item = &Allocation> {
        self.unfiltered
            .borrow()
            .owned
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
    }
}

pub struct MemContractWriter<'mem> {
    writer: Box<dyn FnMut(XWitnessId, WitnessOrd) -> Result<(), confinement::Error> + 'mem>,
    contract: &'mem mut MemContractState,
}

impl<'mem> ContractStateWrite for MemContractWriter<'mem> {
    type Error = MemError;

    /// # Panics
    ///
    /// If genesis violates RGB consensus rules and wasn't checked against the
    /// schema before adding to the history.
    fn add_genesis(&mut self, genesis: &Genesis) -> Result<(), Self::Error> {
        self.contract.add_operation(OrdOpRef::Genesis(genesis));
        Ok(())
    }

    /// # Panics
    ///
    /// If state transition violates RGB consensus rules and wasn't checked
    /// against the schema before adding to the history.
    fn add_transition(
        &mut self,
        transition: &Transition,
        witness_id: XWitnessId,
        ord: WitnessOrd,
    ) -> Result<(), Self::Error> {
        (self.writer)(witness_id, ord)?;
        self.contract
            .add_operation(OrdOpRef::Transition(transition, witness_id, ord));
        Ok(())
    }

    /// # Panics
    ///
    /// If state extension violates RGB consensus rules and wasn't checked
    /// against the schema before adding to the history.
    fn add_extension(
        &mut self,
        extension: &Extension,
        witness_id: XWitnessId,
        ord: WitnessOrd,
    ) -> Result<(), Self::Error> {
        (self.writer)(witness_id, ord)?;
        self.contract
            .add_operation(OrdOpRef::Extension(extension, witness_id, ord));
        Ok(())
    }
}

//////////
// INDEX
//////////

impl From<confinement::Error> for IndexReadError<confinement::Error> {
    fn from(err: confinement::Error) -> Self { IndexReadError::Connectivity(err) }
}

impl From<confinement::Error> for IndexWriteError<confinement::Error> {
    fn from(err: confinement::Error) -> Self { IndexWriteError::Connectivity(err) }
}

#[derive(Clone, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractIndex {
    public_opouts: MediumOrdSet<Opout>,
    outpoint_opouts: MediumOrdMap<XOutputSeal, MediumOrdSet<Opout>>,
}

#[derive(Getters, Debug)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemIndex {
    #[getter(skip)]
    #[strict_type(skip)]
    persistence: Option<Persistence<Self>>,

    op_bundle_index: MediumOrdMap<OpId, BundleId>,
    bundle_contract_index: MediumOrdMap<BundleId, ContractId>,
    bundle_witness_index: MediumOrdMap<BundleId, TinyOrdSet<XWitnessId>>,
    contract_index: TinyOrdMap<ContractId, ContractIndex>,
    terminal_index: MediumOrdMap<XChain<SecretSeal>, TinyOrdSet<Opout>>,
}

impl StrictSerialize for MemIndex {}
impl StrictDeserialize for MemIndex {}

impl MemIndex {
    pub fn in_memory() -> Self {
        Self {
            persistence: None,
            op_bundle_index: empty!(),
            bundle_contract_index: empty!(),
            bundle_witness_index: empty!(),
            contract_index: empty!(),
            terminal_index: empty!(),
        }
    }
}

impl CloneNoPersistence for MemIndex {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            op_bundle_index: self.op_bundle_index.clone(),
            bundle_contract_index: self.bundle_contract_index.clone(),
            bundle_witness_index: self.bundle_witness_index.clone(),
            contract_index: self.contract_index.clone(),
            terminal_index: self.terminal_index.clone(),
        }
    }
}

impl Persisting for MemIndex {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl StoreTransaction for MemIndex {
    type TransactionErr = MemError;
    #[inline]
    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.mark_dirty();
        Ok(())
    }
    #[inline]
    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> { Ok(self.store()?) }
    #[inline]
    fn rollback_transaction(&mut self) { unreachable!() }
}

impl IndexProvider for MemIndex {}

impl IndexReadProvider for MemIndex {
    type Error = Infallible;

    fn contracts_assigning(
        &self,
        outputs: BTreeSet<XOutputSeal>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, Self::Error> {
        Ok(self
            .contract_index
            .iter()
            .flat_map(move |(contract_id, index)| {
                outputs.clone().into_iter().filter_map(|outpoint| {
                    if index.outpoint_opouts.contains_key(&outpoint) {
                        Some(*contract_id)
                    } else {
                        None
                    }
                })
            }))
    }

    fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;
        Ok(index.public_opouts.to_unconfined())
    }

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<XOutputSeal>>,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;
        let mut opouts = BTreeSet::new();
        for output in outputs.into_iter().map(|o| o.into()) {
            let set = index
                .outpoint_opouts
                .get(&output)
                .ok_or(IndexInconsistency::OutpointUnknown(output, contract_id))?;
            opouts.extend(set)
        }
        Ok(opouts)
    }

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = XChain<SecretSeal>>,
    ) -> Result<BTreeSet<Opout>, Self::Error> {
        let terminals = terminals.into_iter().collect::<BTreeSet<_>>();
        Ok(self
            .terminal_index
            .iter()
            .filter(|(seal, _)| terminals.contains(*seal))
            .flat_map(|(_, opout)| opout.iter())
            .copied()
            .collect())
    }

    fn bundle_id_for_op(&self, opid: OpId) -> Result<BundleId, IndexReadError<Self::Error>> {
        self.op_bundle_index
            .get(&opid)
            .copied()
            .ok_or(IndexInconsistency::BundleAbsent(opid).into())
    }

    fn bundle_info(
        &self,
        bundle_id: BundleId,
    ) -> Result<(impl Iterator<Item = XWitnessId>, ContractId), IndexReadError<Self::Error>> {
        let witness_id = self
            .bundle_witness_index
            .get(&bundle_id)
            .ok_or(IndexInconsistency::BundleWitnessUnknown(bundle_id))?;
        let contract_id = self
            .bundle_contract_index
            .get(&bundle_id)
            .ok_or(IndexInconsistency::BundleContractUnknown(bundle_id))?;
        Ok((witness_id.iter().cloned(), *contract_id))
    }
}

impl IndexWriteProvider for MemIndex {
    type Error = MemError;

    fn register_contract(&mut self, contract_id: ContractId) -> Result<bool, Self::Error> {
        if !self.contract_index.contains_key(&contract_id) {
            self.contract_index.insert(contract_id, empty!())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn register_bundle(
        &mut self,
        bundle_id: BundleId,
        witness_id: XWitnessId,
        contract_id: ContractId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        if let Some(alt) = self
            .bundle_contract_index
            .get(&bundle_id)
            .filter(|alt| *alt != &contract_id)
        {
            return Err(IndexInconsistency::DistinctBundleContract {
                bundle_id,
                present: *alt,
                expected: contract_id,
            }
            .into());
        }
        self.bundle_witness_index
            .entry(bundle_id)?
            .or_default()
            .push(witness_id)?;
        let present2 = self
            .bundle_contract_index
            .insert(bundle_id, contract_id)?
            .is_some();
        Ok(!present2)
    }

    fn register_operation(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        if let Some(alt) = self
            .op_bundle_index
            .get(&opid)
            .filter(|alt| *alt != &bundle_id)
        {
            return Err(IndexInconsistency::DistinctBundleOp {
                opid,
                present: *alt,
                expected: bundle_id,
            }
            .into());
        }
        let present = self.op_bundle_index.insert(opid, bundle_id)?.is_some();
        Ok(!present)
    }

    fn index_genesis_assignments(
        &mut self,
        contract_id: ContractId,
        assignments: &[Assign<GenesisSeal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;

        for (no, assign) in assignments.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::Revealed { seal, .. } = assign {
                let output = seal
                    .to_output_seal()
                    .expect("genesis seals always have outpoint");
                index
                    .outpoint_opouts
                    .entry(output)?
                    .or_default()
                    .push(opout)?;
            }
        }

        // We need two cycles due to the borrow checker
        self.extend_terminals(assignments, opid, type_id)
    }

    fn index_transition_assignments(
        &mut self,
        contract_id: ContractId,
        assignments: &[Assign<GraphSeal>],
        opid: OpId,
        type_id: AssignmentType,
        witness_id: XWitnessId,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;

        for (no, assign) in assignments.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::Revealed { seal, .. } = assign {
                let output = seal.try_to_output_seal(witness_id).unwrap_or_else(|_| {
                    panic!(
                        "chain mismatch between assignment vout seal {seal} and witness \
                         transaction {witness_id}",
                    )
                });
                index
                    .outpoint_opouts
                    .entry(output)?
                    .or_default()
                    .push(opout)?;
            }
        }

        // We need two cycles due to the borrow checker
        self.extend_terminals(assignments, opid, type_id)
    }
}

impl MemIndex {
    fn extend_terminals<Seal: ExposedSeal>(
        &mut self,
        vec: &[Assign<Seal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), IndexWriteError<MemError>> {
        for (no, assign) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::Confidential { seal, .. } = assign {
                self.add_terminal(*seal, opout)?;
            }
        }
        Ok(())
    }

    fn add_terminal(
        &mut self,
        seal: XChain<SecretSeal>,
        opout: Opout,
    ) -> Result<(), IndexWriteError<MemError>> {
        match self
            .terminal_index
            .remove(&seal)
            .expect("can have zero elements")
        {
            Some(mut existing_opouts) => {
                existing_opouts.push(opout)?;
                let _ = self.terminal_index.insert(seal, existing_opouts);
            }
            None => {
                self.terminal_index.insert(seal, tiny_bset![opout])?;
            }
        }
        Ok(())
    }
}
