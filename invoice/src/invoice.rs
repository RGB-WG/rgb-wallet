// RGB wallet library for smart contracts on Bitcoin & Lightning network
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

use std::ops::Deref;
use std::str::FromStr;

use amplify::{ByteArray, Bytes32};
use bp::{InvalidPubkey, OutputPk, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
use indexmap::IndexMap;
use invoice::{AddressNetwork, AddressPayload, Network};
use rgb::{AttachId, ChainNet, ContractId, Layer1, SecretSeal};
use strict_encoding::{FieldName, TypeName};

use crate::{Amount, NonFungible};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum RgbTransport {
    JsonRpc { tls: bool, host: String },
    RestHttp { tls: bool, host: String },
    WebSockets { tls: bool, host: String },
    Storm {/* todo */},
    UnspecifiedMeans,
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum InvoiceStateError {
    #[display(doc_comments)]
    /// could not parse as amount, data, or attach: {0}.
    ParseError(String),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
pub enum InvoiceState {
    #[display("")]
    Void,
    #[display("{0}")]
    Amount(Amount),
    #[display(inner)]
    Data(NonFungible),
    #[display(inner)]
    Attach(AttachId),
}

impl FromStr for InvoiceState {
    type Err = InvoiceStateError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(InvoiceState::Void)
        } else if let Ok(amount) = Amount::from_str(s) {
            Ok(InvoiceState::Amount(amount))
        } else if let Ok(data) = NonFungible::from_str(s) {
            Ok(InvoiceState::Data(data))
        } else if let Ok(attach) = AttachId::from_str(s) {
            Ok(InvoiceState::Attach(attach))
        } else {
            Err(InvoiceStateError::ParseError(s.to_owned()))
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum XChainNet<T> {
    BitcoinMainnet(T),
    BitcoinTestnet3(T),
    BitcoinTestnet4(T),
    BitcoinSignet(T),
    BitcoinRegtest(T),
    LiquidMainnet(T),
    LiquidTestnet(T),
}

impl<T> XChainNet<T> {
    pub fn with(cn: ChainNet, data: T) -> Self {
        match cn {
            ChainNet::BitcoinMainnet => XChainNet::BitcoinMainnet(data),
            ChainNet::BitcoinTestnet3 => XChainNet::BitcoinTestnet3(data),
            ChainNet::BitcoinTestnet4 => XChainNet::BitcoinTestnet4(data),
            ChainNet::BitcoinSignet => XChainNet::BitcoinSignet(data),
            ChainNet::BitcoinRegtest => XChainNet::BitcoinRegtest(data),
            ChainNet::LiquidMainnet => XChainNet::LiquidMainnet(data),
            ChainNet::LiquidTestnet => XChainNet::LiquidTestnet(data),
        }
    }

    pub fn bitcoin(network: Network, data: T) -> Self {
        match network {
            Network::Mainnet => Self::BitcoinMainnet(data),
            Network::Testnet3 => Self::BitcoinTestnet3(data),
            Network::Testnet4 => Self::BitcoinTestnet4(data),
            Network::Signet => Self::BitcoinSignet(data),
            Network::Regtest => Self::BitcoinRegtest(data),
        }
    }

    pub fn chain_network(&self) -> ChainNet {
        match self {
            XChainNet::BitcoinMainnet(_) => ChainNet::BitcoinMainnet,
            XChainNet::BitcoinTestnet3(_) => ChainNet::BitcoinTestnet3,
            XChainNet::BitcoinTestnet4(_) => ChainNet::BitcoinTestnet4,
            XChainNet::BitcoinSignet(_) => ChainNet::BitcoinSignet,
            XChainNet::BitcoinRegtest(_) => ChainNet::BitcoinRegtest,
            XChainNet::LiquidMainnet(_) => ChainNet::LiquidMainnet,
            XChainNet::LiquidTestnet(_) => ChainNet::LiquidTestnet,
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            XChainNet::BitcoinMainnet(inner)
            | XChainNet::BitcoinTestnet3(inner)
            | XChainNet::BitcoinTestnet4(inner)
            | XChainNet::BitcoinSignet(inner)
            | XChainNet::BitcoinRegtest(inner)
            | XChainNet::LiquidMainnet(inner)
            | XChainNet::LiquidTestnet(inner) => inner,
        }
    }

    pub fn layer1(&self) -> Layer1 { self.chain_network().layer1() }

    pub fn address_network(&self) -> AddressNetwork {
        match self.chain_network() {
            ChainNet::BitcoinMainnet => AddressNetwork::Mainnet,
            ChainNet::BitcoinTestnet3 | ChainNet::BitcoinTestnet4 | ChainNet::BitcoinSignet => {
                AddressNetwork::Testnet
            }
            ChainNet::BitcoinRegtest => AddressNetwork::Regtest,
            ChainNet::LiquidMainnet => AddressNetwork::Mainnet,
            ChainNet::LiquidTestnet => AddressNetwork::Testnet,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum Pay2VoutError {
    /// unexpected address type byte {0:#04x}.
    InvalidAddressType(u8),
    /// invalid taproot output key; specifically {0}.
    InvalidTapkey(InvalidPubkey<32>),
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct Pay2Vout(AddressPayload);

impl Pay2Vout {
    pub fn new(address_payload: AddressPayload) -> Self { Pay2Vout(address_payload) }
}

impl Deref for Pay2Vout {
    type Target = AddressPayload;

    fn deref(&self) -> &'_ Self::Target { &self.0 }
}

impl Pay2Vout {
    pub(crate) const P2PKH: u8 = 1;
    pub(crate) const P2SH: u8 = 2;
    pub(crate) const P2WPKH: u8 = 3;
    pub(crate) const P2WSH: u8 = 4;
    pub(crate) const P2TR: u8 = 5;
}

impl TryFrom<[u8; 33]> for Pay2Vout {
    type Error = Pay2VoutError;

    fn try_from(data: [u8; 33]) -> Result<Self, Self::Error> {
        let address = match data[0] {
            Self::P2PKH => AddressPayload::Pkh(PubkeyHash::from_slice_unsafe(&data[1..21])),
            Self::P2SH => AddressPayload::Sh(ScriptHash::from_slice_unsafe(&data[1..21])),
            Self::P2WPKH => AddressPayload::Wpkh(WPubkeyHash::from_slice_unsafe(&data[1..21])),
            Self::P2WSH => AddressPayload::Wsh(WScriptHash::from_slice_unsafe(&data[1..])),
            Self::P2TR => AddressPayload::Tr(
                OutputPk::from_byte_array(Bytes32::from_slice_unsafe(&data[1..33]).to_byte_array())
                    .map_err(Pay2VoutError::InvalidTapkey)?,
            ),
            wrong => return Err(Pay2VoutError::InvalidAddressType(wrong)),
        };
        Ok(Pay2Vout(address))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
pub enum Beneficiary {
    #[from]
    BlindedSeal(SecretSeal),
    #[from]
    WitnessVout(Pay2Vout),
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub struct RgbInvoice {
    pub transports: Vec<RgbTransport>,
    pub contract: Option<ContractId>,
    pub iface: Option<TypeName>,
    pub operation: Option<FieldName>,
    pub assignment: Option<FieldName>,
    pub beneficiary: XChainNet<Beneficiary>,
    pub owned_state: InvoiceState,
    /// UTC unix timestamp
    pub expiry: Option<i64>,
    pub unknown_query: IndexMap<String, String>,
}

impl RgbInvoice {
    pub fn chain_network(&self) -> ChainNet { self.beneficiary.chain_network() }
    pub fn address_network(&self) -> AddressNetwork { self.beneficiary.address_network() }
    pub fn layer1(&self) -> Layer1 { self.beneficiary.layer1() }
}
