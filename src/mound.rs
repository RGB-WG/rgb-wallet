// Standard Library for RGB smart contracts
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use alloc::collections::BTreeMap;
use core::borrow::Borrow;
use std::io;

use amplify::hex::ToHex;
use amplify::Bytes16;
use commit_verify::ReservedBytes;
use hypersonic::{AuthToken, CellAddr, CodexId, ContractId, ContractName, Opid, Schema, Supply};
use rgb::RgbSealDef;
use single_use_seals::{PublishedWitness, SingleUseSeal};
use strict_encoding::{
    DecodeError, ReadRaw, StrictDecode, StrictDumb, StrictEncode, StrictReader, StrictWriter,
    WriteRaw,
};

use crate::{
    Consensus, ConsumeError, ContractInfo, ContractRef, CreateParams, Operation, Pile, Stockpile,
};

pub const MAGIC_BYTES_CONSIGNMENT: [u8; 16] = *b"RGB CONSIGNMENT\0";

pub trait Excavate<S: Supply, P: Pile> {
    fn schemata(&mut self) -> impl Iterator<Item = (CodexId, Schema)>;
    fn contracts(&mut self) -> impl Iterator<Item = (ContractId, Stockpile<S, P>)>;
}

/// Mound is a collection of smart contracts which have homogenous capabilities.
pub struct Mound<S: Supply, P: Pile, X: Excavate<S, P>> {
    consensus: Consensus,
    testnet: bool,
    schemata: BTreeMap<CodexId, Schema>,
    contracts: BTreeMap<ContractId, Stockpile<S, P>>,
    /// Persistence does loading of a stockpiles and their storage when a new contract is added.
    persistence: X,
}

impl<S: Supply, P: Pile, X: Excavate<S, P> + Default> Mound<S, P, X> {
    pub fn bitcoin_testnet() -> Self {
        Self {
            testnet: true,
            consensus: Consensus::Bitcoin,
            schemata: BTreeMap::new(),
            contracts: BTreeMap::new(),
            persistence: default!(),
        }
    }
}

impl<S: Supply, P: Pile, X: Excavate<S, P>> Mound<S, P, X> {
    pub fn with_testnet(consensus: Consensus, persistence: X) -> Self {
        Self {
            testnet: true,
            consensus,
            schemata: BTreeMap::new(),
            contracts: BTreeMap::new(),
            persistence,
        }
    }

    pub fn open_testnet(consensus: Consensus, mut persistance: X) -> Self {
        Self {
            testnet: true,
            consensus,
            schemata: persistance.schemata().collect(),
            contracts: persistance.contracts().collect(),
            persistence: persistance,
        }
    }

    pub fn issue(
        &mut self,
        params: CreateParams<P::SealDef>,
        supply: S,
        pile: P,
    ) -> Result<ContractId, IssueError> {
        if params.consensus != self.consensus {
            return Err(IssueError::ConsensusMismatch);
        }
        if params.testnet != self.testnet {
            return Err(if params.testnet {
                IssueError::TestnetMismatch
            } else {
                IssueError::MainnetMismatch
            });
        }
        let schema = self
            .schema(params.codex_id)
            .ok_or(IssueError::UnknownCodex(params.codex_id))?;
        let stockpile = Stockpile::issue(schema.clone(), params, supply, pile);
        let id = stockpile.contract_id();
        self.contracts.insert(id, stockpile);
        Ok(id)
    }

    pub fn codex_ids(&self) -> impl Iterator<Item = CodexId> + use<'_, S, P, X> {
        self.schemata.keys().copied()
    }

    pub fn schemata(&self) -> impl Iterator<Item = (CodexId, &Schema)> {
        self.schemata.iter().map(|(id, schema)| (*id, schema))
    }

    pub fn schema(&self, codex_id: CodexId) -> Option<&Schema> { self.schemata.get(&codex_id) }

    pub fn contract_ids(&self) -> impl Iterator<Item = ContractId> + use<'_, S, P, X> {
        self.contracts.keys().copied()
    }

    pub fn contracts(&self) -> impl Iterator<Item = (ContractId, &Stockpile<S, P>)> {
        self.contracts.iter().map(|(id, stock)| (*id, stock))
    }

    pub fn contracts_info(&self) -> impl Iterator<Item = ContractInfo> + use<'_, S, P, X> {
        self.contracts
            .iter()
            .map(|(id, stockpile)| ContractInfo::new(*id, stockpile.stock().articles()))
    }

    pub fn contracts_mut(&mut self) -> impl Iterator<Item = (ContractId, &mut Stockpile<S, P>)> {
        self.contracts.iter_mut().map(|(id, stock)| (*id, stock))
    }

    pub fn has_contract(&self, id: ContractId) -> bool { self.contracts.contains_key(&id) }

    pub fn find_contract_id(&self, r: impl Into<ContractRef>) -> Option<ContractId> {
        match r.into() {
            ContractRef::Id(id) if self.has_contract(id) => Some(id),
            ContractRef::Id(_) => None,
            ContractRef::Name(name) => {
                let name = ContractName::Named(name);
                self.contracts
                    .iter()
                    .find(|(_, stockpile)| stockpile.stock().articles().contract.meta.name == name)
                    .map(|(id, _)| *id)
            }
        }
    }

    pub fn contract(&self, id: ContractId) -> &Stockpile<S, P> {
        self.contracts
            .get(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn contract_mut(&mut self, id: ContractId) -> &mut Stockpile<S, P> {
        self.contracts
            .get_mut(&id)
            .unwrap_or_else(|| panic!("unknown contract {id}"))
    }

    pub fn select<'seal>(
        &self,
        seal: &'seal P::SealDef,
    ) -> impl Iterator<Item = (ContractId, CellAddr)> + use<'_, 'seal, S, P, X> {
        self.contracts
            .iter()
            .filter_map(|(id, stockpile)| stockpile.seal(seal).map(|addr| (*id, addr)))
    }

    pub fn include(
        &mut self,
        contract_id: ContractId,
        opid: Opid,
        pub_witness: &<P::SealSrc as SingleUseSeal>::PubWitness,
        anchor: <P::SealSrc as SingleUseSeal>::CliWitness,
    ) {
        self.contract_mut(contract_id)
            .include(opid, anchor, pub_witness)
    }

    pub fn consign(
        &mut self,
        contract_id: ContractId,
        terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
        mut writer: StrictWriter<impl WriteRaw>,
    ) -> io::Result<()>
    where
        <P::SealSrc as SingleUseSeal>::CliWitness: StrictDumb + StrictEncode,
        <P::SealSrc as SingleUseSeal>::PubWitness: StrictDumb + StrictEncode,
        <<P::SealSrc as SingleUseSeal>::PubWitness as PublishedWitness<P::SealSrc>>::PubId:
            StrictEncode,
    {
        writer = MAGIC_BYTES_CONSIGNMENT.strict_encode(writer)?;
        // Version
        writer = 0x00u16.strict_encode(writer)?;
        writer = contract_id.strict_encode(writer)?;
        self.contract_mut(contract_id).consign(terminals, writer)
    }

    pub fn consume(
        &mut self,
        reader: &mut StrictReader<impl ReadRaw>,
        seal_resolver: impl FnMut(&Operation) -> BTreeMap<u16, P::SealDef>,
    ) -> Result<(), MoundConsumeError<P::SealDef>>
    where
        <P::SealSrc as SingleUseSeal>::CliWitness: StrictDecode,
        <P::SealSrc as SingleUseSeal>::PubWitness: StrictDecode,
        <<P::SealSrc as SingleUseSeal>::PubWitness as PublishedWitness<P::SealSrc>>::PubId:
            StrictDecode,
    {
        let magic_bytes = Bytes16::strict_decode(reader)?;
        if magic_bytes.to_byte_array() != MAGIC_BYTES_CONSIGNMENT {
            return Err(MoundConsumeError::UnrecognizedMagic(magic_bytes.to_hex()));
        }
        // Version
        ReservedBytes::<2>::strict_decode(reader)?;
        let contract_id = ContractId::strict_decode(reader)?;
        let contract = if self.has_contract(contract_id) {
            self.contract_mut(contract_id)
        } else {
            return Err(MoundConsumeError::UnknownContract(contract_id));
        };
        contract
            .consume(reader, seal_resolver)
            .map_err(MoundConsumeError::Inner)
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum IssueError {
    /// proof of publication layer mismatch.
    ConsensusMismatch,
    /// unable to consume a testnet contract for mainnet.
    TestnetMismatch,
    /// unable to consume a mainnet contract for testnet.
    MainnetMismatch,
    /// unknown codex for contract issue {0}.
    UnknownCodex(CodexId),
}

#[derive(Display, From)]
#[display(doc_comments)]
pub enum MoundConsumeError<Seal: RgbSealDef> {
    /// unrecognized magic bytes in consignment stream ({0})
    UnrecognizedMagic(String),

    /// unknown {0} can't be consumed; please import contract articles first.
    UnknownContract(ContractId),

    #[display(inner)]
    #[from(DecodeError)]
    Inner(ConsumeError<Seal>),
}

#[cfg(feature = "fs")]
pub mod file {
    use std::ffi::OsStr;
    use std::fs;
    use std::fs::{File, FileType};
    use std::marker::PhantomData;
    use std::path::{Path, PathBuf};

    use hypersonic::expect::Expect;
    use hypersonic::{FileSupply, Stock};
    use rgb::RgbSealDef;
    use single_use_seals::PublishedWitness;
    use strict_encoding::{
        DeserializeError, StreamWriter, StrictDecode, StrictEncode,
    };

    use super::*;
    use crate::FilePile;

    pub struct DirExcavator<SealDef: RgbSealDef> {
        dir: PathBuf,
        consensus: Consensus,
        testnet: bool,
        no_prefix: bool,
        _phantom: PhantomData<SealDef>,
    }

    impl<SealDef: RgbSealDef> DirExcavator<SealDef> {
        pub fn new(consensus: Consensus, testnet: bool, dir: PathBuf, no_prefix: bool) -> Self {
            Self { dir, consensus, testnet, no_prefix, _phantom: PhantomData }
        }

        fn consensus_dir(&self) -> PathBuf {
            if self.no_prefix {
                return self.dir.to_owned();
            }
            let mut dir = self.dir.join(self.consensus.to_string());
            if self.testnet {
                dir.set_extension("testnet");
            }
            dir
        }

        fn contents(&mut self, top: bool) -> impl Iterator<Item = (FileType, PathBuf)> {
            let dir =
                if top { fs::read_dir(&self.dir) } else { fs::read_dir(self.consensus_dir()) };
            dir.expect_or_else(|| format!("unable to read directory `{}`", self.dir.display()))
                .map(|entry| {
                    let entry = entry.expect("unable to read directory");
                    let ty = entry.file_type().expect("unable to read file type");
                    (ty, entry.path())
                })
        }
    }

    impl<SealDef: RgbSealDef> Excavate<FileSupply, FilePile<SealDef>> for DirExcavator<SealDef>
    where
        <SealDef::Src as SingleUseSeal>::CliWitness: StrictEncode + StrictDecode,
        <SealDef::Src as SingleUseSeal>::PubWitness: Eq + StrictEncode + StrictDecode,
        <<SealDef::Src as SingleUseSeal>::PubWitness as PublishedWitness<SealDef::Src>>::PubId:
            Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        fn schemata(&mut self) -> impl Iterator<Item = (CodexId, Schema)> {
            self.contents(true).filter_map(|(ty, path)| {
                if ty.is_file() && path.extension().and_then(OsStr::to_str) == Some("issuer") {
                    Schema::load(path)
                        .ok()
                        .map(|schema| (schema.codex.codex_id(), schema))
                } else {
                    None
                }
            })
        }

        fn contracts(
            &mut self,
        ) -> impl Iterator<Item = (ContractId, Stockpile<FileSupply, FilePile<SealDef>>)> {
            self.contents(false).filter_map(|(ty, path)| {
                if ty.is_dir() && path.extension().and_then(OsStr::to_str) == Some("contract") {
                    let contract = Stockpile::load(path);
                    let meta = &contract.stock().articles().contract.meta;
                    if meta.consensus == self.consensus && meta.testnet == self.testnet {
                        return Some((contract.contract_id(), contract));
                    }
                }
                None
            })
        }
    }

    pub type DirMound<SealDef> = Mound<FileSupply, FilePile<SealDef>, DirExcavator<SealDef>>;

    impl<SealDef: RgbSealDef> DirMound<SealDef>
    where
        <SealDef::Src as SingleUseSeal>::CliWitness: StrictEncode + StrictDecode,
        <SealDef::Src as SingleUseSeal>::PubWitness: Eq + StrictEncode + StrictDecode,
        <<SealDef::Src as SingleUseSeal>::PubWitness as PublishedWitness<SealDef::Src>>::PubId:
            Ord + From<[u8; 32]> + Into<[u8; 32]>,
    {
        pub fn load_testnet(consensus: Consensus, path: impl AsRef<Path>, no_prefix: bool) -> Self {
            let path = path.as_ref();
            let excavator = DirExcavator::new(consensus, true, path.to_owned(), no_prefix);
            Self::open_testnet(consensus, excavator)
        }

        pub fn load_issuer(
            &mut self,
            issuer: impl AsRef<Path>,
        ) -> Result<CodexId, DeserializeError> {
            let schema = Schema::load(issuer)?;
            let codex_id = schema.codex.codex_id();
            self.schemata.insert(codex_id, schema);
            Ok(codex_id)
        }

        pub fn issue_to_file(
            &mut self,
            params: CreateParams<SealDef>,
        ) -> Result<ContractId, IssueError> {
            let dir = self.persistence.consensus_dir();
            let supply = FileSupply::new(params.name.as_str(), &dir);
            let pile = FilePile::<SealDef>::new(params.name.as_str(), &dir);
            self.issue(params, supply, pile)
        }

        pub fn path(&self) -> PathBuf { self.persistence.consensus_dir() }

        pub fn consign_to_file(
            &mut self,
            contract_id: ContractId,
            terminals: impl IntoIterator<Item = impl Borrow<AuthToken>>,
            path: impl AsRef<Path>,
        ) -> io::Result<()>
        where
            <SealDef::Src as SingleUseSeal>::CliWitness: StrictDumb,
            <SealDef::Src as SingleUseSeal>::PubWitness: StrictDumb,
            <<SealDef::Src as SingleUseSeal>::PubWitness as PublishedWitness<SealDef::Src>>::PubId:
                StrictEncode,
        {
            let file = File::create_new(path)?;
            let writer = StrictWriter::with(StreamWriter::new::<{ usize::MAX }>(file));
            self.consign(contract_id, terminals, writer)
        }

        pub fn import_articles(&mut self, source_dir: impl AsRef<Path>) -> io::Result<()>
        where
            <SealDef::Src as SingleUseSeal>::CliWitness: StrictDecode,
            <SealDef::Src as SingleUseSeal>::PubWitness: StrictDecode,
            <<SealDef::Src as SingleUseSeal>::PubWitness as PublishedWitness<SealDef::Src>>::PubId:
                StrictDecode,
        {
            let stock = Stock::<FileSupply>::load(source_dir.as_ref());
            let articles = stock.articles().clone();

            // Prevent duplicate contract IDs
            if self.has_contract(articles.contract.contract_id()) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("contract {} already exists", articles.contract.contract_id()),
                ));
            }

            let contract_id = articles.contract.contract_id();
            let name = articles.contract.meta.name.to_string();
            let target_dir = self.persistence.consensus_dir();

            // Persist articles to target directory
            let _new_supply = FileSupply::new(&name, &target_dir);
            let _new_pile = FilePile::<SealDef>::new(&name, &target_dir);
            let _new_stock = Stock::create(articles, _new_supply);

            // Load from persisted location
            let mut contract_dir = target_dir.join(&name);
            contract_dir.set_extension("contract");

            let stockpile = Stockpile::load(&contract_dir);

            // Verify contract ID matches loaded articles and insert into mound
            assert_eq!(contract_id, stockpile.contract_id());
            self.contracts.insert(contract_id, stockpile);
            Ok(())
        }
    }
}
