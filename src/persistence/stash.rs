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
use std::error::Error;
use std::fmt::Debug;

use aluvm::library::{Lib, LibId};
use amplify::confinement::{Confined, MediumBlob, TinyOrdMap};
use amplify::{confinement, ByteArray};
use bp::dbc::anchor::MergeError;
use bp::dbc::tapret::TapretCommitment;
use bp::dbc::Anchor;
use bp::seals::txout::CloseMethod;
use commit_verify::mpc;
use commit_verify::mpc::MerkleBlock;
use nonasync::persistence::{CloneNoPersistence, Persisting};
use rgb::validation::{DbcProof, Scripts};
use rgb::{
    AttachId, BundleId, ContractId, Extension, Genesis, GraphSeal, Identity, OpId, Operation,
    Schema, SchemaId, TransitionBundle, XChain, XWitnessId,
};
use strict_encoding::{FieldName, TypeName};
use strict_types::typesys::UnknownType;
use strict_types::TypeSystem;

use crate::containers::{
    AnchorSet, Consignment, ConsignmentExt, ContentId, ContentRef, ContentSigs, Kit, SealWitness,
    SigBlob, Supplement, TrustLevel, WitnessBundle,
};
use crate::interface::{
    ContractBuilder, Iface, IfaceClass, IfaceId, IfaceImpl, IfaceRef, TransitionBuilder,
};
use crate::persistence::{ContractIfaceError, StoreTransaction};
use crate::{MergeReveal, MergeRevealError, SecretSeal, LIB_NAME_RGB_STD};

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StashError<P: StashProvider> {
    /// Connectivity errors which may be recoverable and temporary.
    ReadProvider(<P as StashReadProvider>::Error),

    /// Connectivity errors which may be recoverable and temporary.
    WriteProvider(<P as StashWriteProvider>::Error),

    /// {0}
    ///
    /// It may happen due to RGB standard library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    #[display(doc_comments)]
    Inconsistency(StashInconsistency),

    /// Errors caused by invalid input arguments.
    #[from]
    #[from(UnknownType)]
    #[from(MergeError)]
    #[from(MergeRevealError)]
    #[from(mpc::InvalidProof)]
    Data(StashDataError),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum ProviderError<E: Error> {
    #[from]
    Inconsistency(StashInconsistency),
    #[from]
    Iface(ContractIfaceError),
    Connectivity(E),
}

impl<P: StashProvider> From<ProviderError<<P as StashReadProvider>::Error>> for StashError<P> {
    fn from(err: ProviderError<<P as StashReadProvider>::Error>) -> Self {
        match err {
            ProviderError::Inconsistency(e) => StashError::Inconsistency(e),
            ProviderError::Connectivity(e) => StashError::ReadProvider(e),
            ProviderError::Iface(e) => StashError::Data(StashDataError::NoAbstractIface(e)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StashInconsistency {
    /// library {0} is unknown; perhaps you need to import it first.
    LibAbsent(LibId),

    /// interface {0} is unknown; perhaps you need to import it first.
    IfaceAbsent(IfaceRef),

    /// contract {0} is unknown. Probably you haven't imported the contract yet.
    ContractAbsent(ContractId),

    /// schema {0} is unknown.
    SchemaAbsent(SchemaId),

    /// interface {0::<0} is not implemented for the schema {1::<0}.
    IfaceImplAbsent(IfaceId, SchemaId),

    /// transition {0} is absent.
    OperationAbsent(OpId),

    /// information about witness {0} is absent.
    WitnessAbsent(XWitnessId),

    /// witness {0} for the bundle {1} misses contract {2} information in {3} anchor.
    WitnessMissesContract(XWitnessId, BundleId, ContractId, CloseMethod),

    /// bundle {0} is absent.
    BundleAbsent(BundleId),

    /// none of known anchors contain information on bundle {0} under contract
    /// {1}.
    BundleMissedInAnchors(BundleId, ContractId),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StashDataError {
    /// schema {0} and related interfaces use too many AluVM libraries.
    TooManyLibs(SchemaId),

    #[from]
    #[display(inner)]
    UnknownType(UnknownType),

    #[from]
    #[display(inner)]
    Anchor(mpc::InvalidProof),

    #[from]
    #[display(inner)]
    Merge(MergeError),

    #[from]
    #[display(inner)]
    MergeReveal(MergeRevealError),

    /// schema {0} doesn't implement interface {1}.
    NoIfaceImpl(SchemaId, IfaceId),

    #[from]
    #[display(inner)]
    NoAbstractIface(ContractIfaceError),
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SchemaIfaces {
    pub schema: Schema,
    pub iimpls: TinyOrdMap<TypeName, IfaceImpl>,
}

impl SchemaIfaces {
    pub fn new(schema: Schema) -> Self {
        SchemaIfaces {
            schema,
            iimpls: none!(),
        }
    }

    pub fn get(&self, id: IfaceId) -> Option<&IfaceImpl> {
        self.iimpls.values().find(|iimpl| iimpl.iface_id == id)
    }

    pub fn contains(&self, id: IfaceId) -> bool {
        self.iimpls.values().any(|iimpl| iimpl.iface_id == id)
    }
}

#[derive(Debug)]
pub struct Stash<P: StashProvider> {
    provider: P,
}

impl<P: StashProvider> CloneNoPersistence for Stash<P> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            provider: self.provider.clone_no_persistence(),
        }
    }
}

impl<P: StashProvider> Default for Stash<P>
where P: Default
{
    fn default() -> Self {
        Self {
            provider: default!(),
        }
    }
}

impl<P: StashProvider> Stash<P> {
    pub(super) fn new(provider: P) -> Self { Self { provider } }

    #[doc(hidden)]
    pub fn as_provider(&self) -> &P { &self.provider }

    #[doc(hidden)]
    pub(super) fn as_provider_mut(&mut self) -> &mut P { &mut self.provider }

    pub(super) fn ifaces(&self) -> Result<impl Iterator<Item = &Iface> + '_, StashError<P>> {
        self.provider.ifaces().map_err(StashError::ReadProvider)
    }
    pub(super) fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, StashError<P>> {
        Ok(self.provider.iface(iface)?)
    }
    pub(super) fn schemata(
        &self,
    ) -> Result<impl Iterator<Item = &SchemaIfaces> + '_, StashError<P>> {
        self.provider.schemata().map_err(StashError::ReadProvider)
    }
    pub(super) fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, StashError<P>> {
        Ok(self.provider.schema(schema_id)?)
    }
    pub(super) fn impl_for<'a, C: IfaceClass + 'a>(
        &'a self,
        schema_ifaces: &'a SchemaIfaces,
    ) -> Result<&'a IfaceImpl, StashError<P>> {
        Ok(self.provider.impl_for::<C>(schema_ifaces)?)
    }

    pub(super) fn geneses(&self) -> Result<impl Iterator<Item = &Genesis> + '_, StashError<P>> {
        self.provider.geneses().map_err(StashError::ReadProvider)
    }
    pub(super) fn geneses_by<'a, C: IfaceClass + 'a>(
        &'a self,
    ) -> Result<impl Iterator<Item = &'a Genesis> + 'a, StashError<P>> {
        self.provider
            .geneses_by::<C>()
            .map_err(StashError::ReadProvider)
    }
    pub(super) fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, StashError<P>> {
        Ok(self.provider.genesis(contract_id)?)
    }
    pub(super) fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, StashError<P>> {
        Ok(self.provider.bundle(bundle_id)?)
    }
    pub(super) fn witness(&self, witness_id: XWitnessId) -> Result<&SealWitness, StashError<P>> {
        Ok(self.provider.witness(witness_id)?)
    }

    pub(super) fn supplements(
        &self,
        content_ref: ContentRef,
    ) -> Result<impl Iterator<Item = Supplement> + '_, StashError<P>> {
        self.provider
            .supplements(content_ref)
            .map_err(StashError::ReadProvider)
    }

    pub(super) fn sigs_for(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<&ContentSigs>, StashError<P>> {
        self.provider
            .sigs_for(content_id)
            .map_err(StashError::ReadProvider)
    }

    pub(super) fn supplement(
        &self,
        content_ref: ContentRef,
    ) -> Result<Option<&Supplement>, StashError<P>> {
        self.provider
            .supplement(content_ref)
            .map_err(StashError::ReadProvider)
    }

    pub(super) fn scripts<'a>(
        &self,
        lib_ids: impl IntoIterator<Item = LibId>,
    ) -> Result<Scripts, StashError<P>> {
        let mut scripts = BTreeMap::new();
        for id in lib_ids {
            let lib = self.provider.lib(id)?;
            scripts.insert(id, lib.clone());
        }
        Ok(Scripts::from_checked(scripts))
    }

    pub(super) fn type_system(&self, iface: &Iface) -> Result<TypeSystem, StashError<P>> {
        Ok(self
            .provider
            .type_system()
            .map_err(StashError::ReadProvider)?
            .extract(iface.types())?)
    }

    pub(super) fn types_scripts<'a>(
        &self,
        schema: &Schema,
        ifaces: impl IntoIterator<Item = &'a Iface>,
    ) -> Result<(TypeSystem, Scripts), StashError<P>> {
        let type_iter = schema
            .types()
            .into_iter()
            .chain(ifaces.into_iter().flat_map(Iface::types));
        let types = self
            .provider
            .type_system()
            .map_err(StashError::ReadProvider)?
            .extract(type_iter)?;

        let mut scripts = BTreeMap::new();
        for id in schema.libs() {
            let lib = self.provider.lib(id)?;
            scripts.insert(id, lib.clone());
        }
        // TODO: Make sure we have all the libs including their dependencies
        let scripts = Scripts::try_from(scripts)
            .map_err(|_| StashDataError::TooManyLibs(schema.schema_id()))?;

        Ok((types, scripts))
    }

    pub(super) fn contract_builder(
        &self,
        issuer: Identity,
        schema_id: SchemaId,
        iface: impl Into<IfaceRef>,
    ) -> Result<ContractBuilder, StashError<P>> {
        let schema_ifaces = self.schema(schema_id)?;
        let iface = self.iface(iface)?;
        let iface_id = iface.iface_id();
        let iimpl = schema_ifaces
            .get(iface_id)
            .ok_or(StashDataError::NoIfaceImpl(schema_id, iface_id))?;

        let (types, scripts) = self.types_scripts(&schema_ifaces.schema, [iface])?;

        let builder = ContractBuilder::with(
            issuer,
            iface.clone(),
            schema_ifaces.schema.clone(),
            iimpl.clone(),
            types,
            scripts,
        );
        Ok(builder)
    }

    pub(super) fn transition_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
        transition_name: Option<impl Into<FieldName>>,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema_ifaces = self.provider.contract_schema(contract_id)?;
        let iface = self.iface(iface)?;
        let schema = &schema_ifaces.schema;
        let iimpl = schema_ifaces
            .get(iface.iface_id())
            .ok_or(StashDataError::NoIfaceImpl(schema.schema_id(), iface.iface_id()))?;

        let types = self.type_system(iface)?;
        let scripts = self.scripts(iimpl.state_abi.lib_ids())?;

        let builder = if let Some(transition_name) = transition_name {
            TransitionBuilder::named_transition(
                contract_id,
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                transition_name.into(),
                types,
                scripts,
            )
        } else {
            TransitionBuilder::default_transition(
                contract_id,
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                types,
                scripts,
            )
        }
        .expect("internal inconsistency");

        Ok(builder)
    }

    pub(super) fn blank_builder(
        &self,
        contract_id: ContractId,
        iface: impl Into<IfaceRef>,
    ) -> Result<TransitionBuilder, StashError<P>> {
        let schema_ifaces = self.provider.contract_schema(contract_id)?;
        let iface = self.iface(iface)?;
        let schema = &schema_ifaces.schema;
        if schema_ifaces.iimpls.is_empty() {
            return Err(StashDataError::NoIfaceImpl(schema.schema_id(), iface.iface_id()).into());
        }
        let types = self.type_system(iface)?;

        let builder = if let Some(iimpl) = schema_ifaces.get(iface.iface_id()) {
            TransitionBuilder::blank_transition(
                contract_id,
                iface.clone(),
                schema.clone(),
                iimpl.clone(),
                types,
            )
        } else {
            let (default_iface_name, default_iimpl) =
                schema_ifaces.iimpls.first_key_value().unwrap();
            let default_iface = self.iface(default_iface_name.clone())?;

            TransitionBuilder::blank_transition(
                contract_id,
                default_iface.clone(),
                schema.clone(),
                default_iimpl.clone(),
                types,
            )
        };

        Ok(builder)
    }

    pub(super) fn consume_kit(&mut self, kit: Kit) -> Result<(), StashError<P>> {
        self.provider
            .consume_types(kit.types)
            .map_err(StashError::WriteProvider)?;
        for lib in kit.scripts {
            self.provider
                .replace_lib(lib)
                .map_err(StashError::WriteProvider)?;
        }

        // TODO: filter most trusted signers
        for schema in kit.schemata {
            self.provider
                .replace_schema(schema)
                .map_err(StashError::WriteProvider)?;
        }
        for iface in kit.ifaces {
            self.provider
                .replace_iface(iface)
                .map_err(StashError::WriteProvider)?;
        }
        for iimpl in kit.iimpls {
            self.provider
                .replace_iimpl(iimpl)
                .map_err(StashError::WriteProvider)?;
        }

        // TODO: filter out non-trusted signers
        for suppl in kit.supplements {
            self.provider
                .add_supplement(suppl)
                .map_err(StashError::WriteProvider)?;
        }

        for (content_id, sigs) in kit.signatures {
            // TODO: Filter sigs by trust level
            // Do not bother if we can't import all the sigs
            self.provider.import_sigs(content_id, sigs).ok();
        }

        Ok(())
    }

    pub(super) fn resolve_secrets<const TRANSFER: bool>(
        &self,
        mut consignment: Consignment<TRANSFER>,
    ) -> Result<Consignment<TRANSFER>, StashError<P>> {
        consignment = consignment.reveal_terminal_seals(|secret| {
            self.provider
                .seal_secret(secret)
                .map_err(StashError::ReadProvider)
        })?;
        Ok(consignment)
    }

    pub(super) fn consume_consignment<const TRANSFER: bool>(
        &mut self,
        consignment: Consignment<TRANSFER>,
    ) -> Result<(), StashError<P>> {
        let contract_id = consignment.contract_id();

        let genesis = match self.genesis(contract_id) {
            Ok(g) => g.clone().merge_reveal(consignment.genesis)?,
            Err(_) => consignment.genesis,
        };
        self.provider
            .replace_genesis(genesis)
            .map_err(StashError::WriteProvider)?;

        for extension in consignment.extensions {
            let opid = extension.id();
            let extension = match self.provider.extension(opid) {
                Ok(e) => e.clone().merge_reveal(extension)?,
                Err(_) => extension,
            };
            self.provider
                .replace_extension(extension)
                .map_err(StashError::WriteProvider)?;
        }

        for witness_bundles in consignment.bundles {
            self.consume_witness_bundle(contract_id, witness_bundles)?;
        }

        for (id, attach) in consignment.attachments {
            self.provider
                .replace_attachment(id, attach)
                .map_err(StashError::WriteProvider)?;
        }

        let (ifaces, iimpls): (BTreeSet<_>, BTreeSet<_>) = consignment
            .ifaces
            .release()
            .into_iter()
            .fold((bset!(), bset!()), |(mut keys, mut values), (k, v)| {
                keys.insert(k);
                values.insert(v);
                (keys, values)
            });

        self.consume_kit(Kit {
            version: consignment.version,
            ifaces: Confined::from_checked(ifaces),
            schemata: tiny_bset![consignment.schema],
            iimpls: Confined::from_checked(iimpls),
            supplements: consignment.supplements,
            types: consignment.types,
            scripts: Confined::from_checked(consignment.scripts.release()),
            signatures: consignment.signatures,
        })
    }

    fn consume_witness_bundle(
        &mut self,
        contract_id: ContractId,
        witness_bundle: WitnessBundle,
    ) -> Result<(), StashError<P>> {
        let WitnessBundle {
            pub_witness,
            anchored_bundles,
        } = witness_bundle;

        // TODO: Save pub witness transaction SPVs

        let mut anchors = Vec::with_capacity(2);
        for (anchor, bundle) in anchored_bundles.into_iter() {
            let bundle_id = bundle.bundle_id();
            self.consume_bundle(bundle)?;

            let proto = mpc::ProtocolId::from_byte_array(contract_id.to_byte_array());
            let msg = mpc::Message::from_byte_array(bundle_id.to_byte_array());
            let merkle_block = MerkleBlock::with(&anchor.mpc_proof, proto, msg)?;
            anchors.push(Anchor::new(merkle_block, anchor.dbc_proof));
        }

        let anchors = match (anchors.pop().unwrap(), anchors.pop()) {
            (
                Anchor {
                    dbc_proof: DbcProof::Opret(opret),
                    mpc_proof,
                    ..
                },
                None,
            ) => AnchorSet::Opret(Anchor::new(mpc_proof, opret)),
            (
                Anchor {
                    dbc_proof: DbcProof::Tapret(tapret),
                    mpc_proof,
                    ..
                },
                None,
            ) => AnchorSet::Tapret(Anchor::new(mpc_proof, tapret)),
            (
                Anchor {
                    dbc_proof: DbcProof::Tapret(tapret),
                    mpc_proof: mpc_proof_tapret,
                    ..
                },
                Some(Anchor {
                    dbc_proof: DbcProof::Opret(opret),
                    mpc_proof: mpc_proof_opret,
                    ..
                }),
            )
            | (
                Anchor {
                    dbc_proof: DbcProof::Opret(opret),
                    mpc_proof: mpc_proof_opret,
                    ..
                },
                Some(Anchor {
                    dbc_proof: DbcProof::Tapret(tapret),
                    mpc_proof: mpc_proof_tapret,
                    ..
                }),
            ) => AnchorSet::Double {
                tapret: Anchor::new(mpc_proof_tapret, tapret),
                opret: Anchor::new(mpc_proof_opret, opret),
            },
            (
                Anchor {
                    dbc_proof: DbcProof::Opret(_),
                    ..
                },
                Some(Anchor {
                    dbc_proof: DbcProof::Opret(_),
                    ..
                }),
            )
            | (
                Anchor {
                    dbc_proof: DbcProof::Tapret(_),
                    ..
                },
                Some(Anchor {
                    dbc_proof: DbcProof::Tapret(_),
                    ..
                }),
            ) => unreachable!(
                "these combinations must be prevented at the `AnchoredBundles` structure level"
            ),
        };
        let witness = SealWitness {
            public: pub_witness.clone(),
            anchors,
        };
        self.consume_witness(witness)?;

        Ok(())
    }

    pub(crate) fn consume_witness(&mut self, witness: SealWitness) -> Result<bool, StashError<P>> {
        let witness = match self.provider.witness(witness.witness_id()).cloned() {
            Ok(mut w) => {
                w.public = w.public.clone().merge_reveal(witness.public)?;
                w.anchors = w.anchors.clone().merge_reveal(witness.anchors)?;
                w
            }
            Err(_) => witness,
        };

        self.provider
            .replace_witness(witness)
            .map_err(StashError::WriteProvider)
    }

    pub(crate) fn consume_bundle(
        &mut self,
        bundle: TransitionBundle,
    ) -> Result<bool, StashError<P>> {
        let bundle = match self.provider.bundle(bundle.bundle_id()).cloned() {
            Ok(b) => b.merge_reveal(bundle)?,
            Err(_) => bundle,
        };
        self.provider
            .replace_bundle(bundle)
            .map_err(StashError::WriteProvider)
    }

    pub(crate) fn store_secret_seal(
        &mut self,
        seal: XChain<GraphSeal>,
    ) -> Result<bool, StashError<P>> {
        self.begin_transaction()?;
        let seal = self
            .provider
            .add_secret_seal(seal)
            .inspect_err(|_| self.rollback_transaction())
            .map_err(StashError::WriteProvider)?;
        self.commit_transaction()?;
        Ok(seal)
    }
}

impl<P: StashProvider> StoreTransaction for Stash<P> {
    type TransactionErr = StashError<P>;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .begin_transaction()
            .map_err(StashError::WriteProvider)
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .commit_transaction()
            .map_err(StashError::WriteProvider)
    }

    fn rollback_transaction(&mut self) { self.provider.rollback_transaction() }
}

pub trait StashProvider:
    Debug + CloneNoPersistence + Persisting + StashReadProvider + StashWriteProvider
{
}

pub trait StashReadProvider {
    /// Error type which must indicate problems on data retrieval.
    type Error: Clone + Eq + Error;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error>;
    fn lib(&self, id: LibId) -> Result<&Lib, ProviderError<Self::Error>>;

    fn ifaces(&self) -> Result<impl Iterator<Item = &Iface>, Self::Error>;
    fn iface(&self, iface: impl Into<IfaceRef>) -> Result<&Iface, ProviderError<Self::Error>>;
    fn schemata(&self) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error>;
    fn schema(&self, schema_id: SchemaId) -> Result<&SchemaIfaces, ProviderError<Self::Error>>;
    fn schemata_by<C: IfaceClass>(
        &self,
    ) -> Result<impl Iterator<Item = &SchemaIfaces>, Self::Error>;
    fn impl_for<'a, C: IfaceClass + 'a>(
        &'a self,
        schema_ifaces: &'a SchemaIfaces,
    ) -> Result<&'a IfaceImpl, ProviderError<Self::Error>>;
    fn geneses(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error>;
    fn geneses_by<C: IfaceClass>(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error>;
    fn genesis(&self, contract_id: ContractId) -> Result<&Genesis, ProviderError<Self::Error>>;

    fn contract_schema(
        &self,
        contract_id: ContractId,
    ) -> Result<&SchemaIfaces, ProviderError<Self::Error>> {
        let genesis = self.genesis(contract_id)?;
        self.schema(genesis.schema_id)
    }

    fn get_trust(&self, identity: &Identity) -> Result<TrustLevel, Self::Error>;
    fn supplement(&self, content_ref: ContentRef) -> Result<Option<&Supplement>, Self::Error>;
    fn supplements(
        &self,
        content_ref: ContentRef,
    ) -> Result<impl Iterator<Item = Supplement>, Self::Error>;

    fn sigs_for(&self, content_id: &ContentId) -> Result<Option<&ContentSigs>, Self::Error>;
    fn witness_ids(&self) -> Result<impl Iterator<Item = XWitnessId>, Self::Error>;
    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error>;
    fn bundle(&self, bundle_id: BundleId) -> Result<&TransitionBundle, ProviderError<Self::Error>>;
    fn extension_ids(&self) -> Result<impl Iterator<Item = OpId>, Self::Error>;
    fn extension(&self, op_id: OpId) -> Result<&Extension, ProviderError<Self::Error>>;
    fn witness(&self, witness_id: XWitnessId) -> Result<&SealWitness, ProviderError<Self::Error>>;

    fn taprets(&self) -> Result<impl Iterator<Item = (XWitnessId, TapretCommitment)>, Self::Error>;
    fn seal_secret(
        &self,
        secret: XChain<SecretSeal>,
    ) -> Result<Option<XChain<GraphSeal>>, Self::Error>;
    fn secret_seals(&self) -> Result<impl Iterator<Item = XChain<GraphSeal>>, Self::Error>;
}

pub trait StashWriteProvider: StoreTransaction<TransactionErr = Self::Error> {
    type Error: Error;

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, Self::Error>;
    fn replace_iface(&mut self, iface: Iface) -> Result<bool, Self::Error>;
    fn replace_iimpl(&mut self, iimpl: IfaceImpl) -> Result<bool, Self::Error>;
    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, Self::Error>;
    fn replace_extension(&mut self, extension: Extension) -> Result<bool, Self::Error>;
    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error>;
    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error>;
    fn replace_attachment(&mut self, id: AttachId, attach: MediumBlob)
        -> Result<bool, Self::Error>;

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, Self::Error>;
    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error>;
    fn set_trust(
        &mut self,
        identity: Identity,
        trust: TrustLevel,
    ) -> Result<(), confinement::Error>;
    fn add_supplement(&mut self, suppl: Supplement) -> Result<(), Self::Error>;
    fn import_sigs<I>(&mut self, content_id: ContentId, sigs: I) -> Result<(), Self::Error>
    where I: IntoIterator<Item = (Identity, SigBlob)>;

    fn add_secret_seal(&mut self, seal: XChain<GraphSeal>) -> Result<bool, Self::Error>;
}
