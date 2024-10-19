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

use amplify::{ByteArray, Bytes32};
use bp::seals::txout::CloseMethod;
use bp::{InvalidPubkey, OutputPk, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
use indexmap::IndexMap;
use invoice::{AddressNetwork, AddressPayload, Network};
use rgb::{ContractId, Layer1, SecretSeal, StateData};
use strict_encoding::{FieldName, TypeName};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum RgbTransport {
    JsonRpc { tls: bool, host: String },
    RestHttp { tls: bool, host: String },
    WebSockets { tls: bool, host: String },
    Storm {/* todo */},
    UnspecifiedMeans,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[non_exhaustive]
pub enum ChainNet {
    #[display("bc")]
    BitcoinMainnet,
    #[display("tb")]
    BitcoinTestnet,
    #[display("sb")]
    BitcoinSignet,
    #[display("bcrt")]
    BitcoinRegtest,
    #[display("lq")]
    LiquidMainnet,
    #[display("tl")]
    LiquidTestnet,
}

impl ChainNet {
    pub fn layer1(&self) -> Layer1 {
        match self {
            ChainNet::BitcoinMainnet
            | ChainNet::BitcoinTestnet
            | ChainNet::BitcoinSignet
            | ChainNet::BitcoinRegtest => Layer1::Bitcoin,
            ChainNet::LiquidMainnet | ChainNet::LiquidTestnet => Layer1::Liquid,
        }
    }

    pub fn is_prod(&self) -> bool {
        match self {
            ChainNet::BitcoinMainnet | ChainNet::LiquidMainnet => true,

            ChainNet::BitcoinTestnet
            | ChainNet::BitcoinSignet
            | ChainNet::BitcoinRegtest
            | ChainNet::LiquidTestnet => false,
        }
    }

    pub fn address_network(&self) -> AddressNetwork {
        match self {
            ChainNet::BitcoinMainnet => AddressNetwork::Mainnet,
            ChainNet::BitcoinTestnet | ChainNet::BitcoinSignet => AddressNetwork::Testnet,
            ChainNet::BitcoinRegtest => AddressNetwork::Regtest,
            ChainNet::LiquidMainnet => AddressNetwork::Mainnet,
            ChainNet::LiquidTestnet => AddressNetwork::Testnet,
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum XChainNet<T> {
    BitcoinMainnet(T),
    BitcoinTestnet(T),
    BitcoinSignet(T),
    BitcoinRegtest(T),
    LiquidMainnet(T),
    LiquidTestnet(T),
}

impl<T> XChainNet<T> {
    pub fn with(cn: ChainNet, data: T) -> Self {
        match cn {
            ChainNet::BitcoinMainnet => XChainNet::BitcoinMainnet(data),
            ChainNet::BitcoinTestnet => XChainNet::BitcoinTestnet(data),
            ChainNet::BitcoinSignet => XChainNet::BitcoinSignet(data),
            ChainNet::BitcoinRegtest => XChainNet::BitcoinRegtest(data),
            ChainNet::LiquidMainnet => XChainNet::LiquidMainnet(data),
            ChainNet::LiquidTestnet => XChainNet::LiquidTestnet(data),
        }
    }

    pub fn bitcoin(network: Network, data: T) -> Self {
        match network {
            Network::Mainnet => Self::BitcoinMainnet(data),
            Network::Testnet3 => Self::BitcoinTestnet(data),
            Network::Testnet4 => Self::BitcoinTestnet(data),
            Network::Signet => Self::BitcoinSignet(data),
            Network::Regtest => Self::BitcoinRegtest(data),
        }
    }

    pub fn chain_network(&self) -> ChainNet {
        match self {
            XChainNet::BitcoinMainnet(_) => ChainNet::BitcoinMainnet,
            XChainNet::BitcoinTestnet(_) => ChainNet::BitcoinTestnet,
            XChainNet::BitcoinSignet(_) => ChainNet::BitcoinSignet,
            XChainNet::BitcoinRegtest(_) => ChainNet::BitcoinRegtest,
            XChainNet::LiquidMainnet(_) => ChainNet::LiquidMainnet,
            XChainNet::LiquidTestnet(_) => ChainNet::LiquidTestnet,
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            XChainNet::BitcoinMainnet(inner)
            | XChainNet::BitcoinTestnet(inner)
            | XChainNet::BitcoinSignet(inner)
            | XChainNet::BitcoinRegtest(inner)
            | XChainNet::LiquidMainnet(inner)
            | XChainNet::LiquidTestnet(inner) => inner,
        }
    }

    pub fn layer1(&self) -> Layer1 { self.chain_network().layer1() }
    pub fn address_network(&self) -> AddressNetwork { self.chain_network().address_network() }
    pub fn is_prod(&self) -> bool { self.chain_network().is_prod() }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum Pay2VoutError {
    /// invalid close method byte {0:#04x}.
    InvalidMethod(u8),
    /// unexpected address type byte {0:#04x}.
    InvalidAddressType(u8),
    /// invalid taproot output key; specifically {0}.
    InvalidTapkey(InvalidPubkey<32>),
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct Pay2Vout {
    pub method: CloseMethod,
    pub address: AddressPayload,
}

impl Pay2Vout {
    pub(crate) const P2PKH: u8 = 1;
    pub(crate) const P2SH: u8 = 2;
    pub(crate) const P2WPKH: u8 = 3;
    pub(crate) const P2WSH: u8 = 4;
    pub(crate) const P2TR: u8 = 5;
}

impl TryFrom<[u8; 34]> for Pay2Vout {
    type Error = Pay2VoutError;

    fn try_from(data: [u8; 34]) -> Result<Self, Self::Error> {
        let method =
            CloseMethod::try_from(data[0]).map_err(|e| Pay2VoutError::InvalidMethod(e.1))?;
        let address = match data[1] {
            Self::P2PKH => AddressPayload::Pkh(PubkeyHash::from_slice_unsafe(&data[2..22])),
            Self::P2SH => AddressPayload::Sh(ScriptHash::from_slice_unsafe(&data[2..22])),
            Self::P2WPKH => AddressPayload::Wpkh(WPubkeyHash::from_slice_unsafe(&data[2..22])),
            Self::P2WSH => AddressPayload::Wsh(WScriptHash::from_slice_unsafe(&data[2..])),
            Self::P2TR => AddressPayload::Tr(
                OutputPk::from_byte_array(Bytes32::from_slice_unsafe(&data[2..34]).to_byte_array())
                    .map_err(Pay2VoutError::InvalidTapkey)?,
            ),
            wrong => return Err(Pay2VoutError::InvalidAddressType(wrong)),
        };
        Ok(Self { method, address })
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
    pub state: Option<StateData>,
    /// UTC unix timestamp
    pub expiry: Option<i64>,
    // Attachment requirements should go here
    pub unknown_query: IndexMap<String, String>,
}

impl RgbInvoice {
    pub fn chain_network(&self) -> ChainNet { self.beneficiary.chain_network() }
    pub fn address_network(&self) -> AddressNetwork { self.beneficiary.address_network() }
    pub fn layer1(&self) -> Layer1 { self.beneficiary.layer1() }
    pub fn is_prod(&self) -> bool { self.beneficiary.is_prod() }
}
