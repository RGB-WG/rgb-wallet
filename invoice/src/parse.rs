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

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Cursor, Write};
use std::num::ParseIntError;
use std::str::FromStr;

use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use fluent_uri::enc::EStr;
use fluent_uri::Uri;
use indexmap::IndexMap;
use invoice::{AddressPayload, UnknownNetwork};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rgb::{ContractId, SecretSeal, StateData, StateParseError};
use strict_encoding::{InvalidRString, TypeName};

use crate::invoice::{Beneficiary, ChainNet, Pay2Vout, RgbInvoice, RgbTransport, XChainNet};

const OMITTED: &str = "~";
const EXPIRY: &str = "expiry";
const ENDPOINTS: &str = "endpoints";
const TRANSPORT_SEP: char = ',';
const TRANSPORT_HOST_SEP: &str = "://";
const QUERY_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b']')
    .add(b'&')
    .add(b'=');

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum TransportParseError {
    #[display(doc_comments)]
    /// invalid transport {0}.
    InvalidTransport(String),

    #[display(doc_comments)]
    /// invalid transport host {0}.
    InvalidTransportHost(String),
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum InvoiceParseError {
    #[from]
    #[display(inner)]
    Uri(fluent_uri::ParseError),

    /// absent invoice URI scheme name.
    AbsentScheme,

    /// invalid invoice scheme {0}.
    InvalidScheme(String),

    /// RGB invoice must not contain any URI authority data, including empty
    /// one.
    Authority,

    /// contract id is missed from the invoice.
    ContractMissed,

    /// interface information is missed from the invoice.
    IfaceMissed,

    /// assignment data is missed from the invoice.
    AssignmentMissed,

    #[from]
    #[display(inner)]
    InvalidState(StateParseError),

    /// no invoice transport has been provided.
    NoTransport,

    /// invalid invoice: contract ID present but no contract interface provided.
    ContractIdNoIface,

    /// invalid contract ID.
    InvalidContractId(String),

    /// invalid interface {0}.
    InvalidIface(String),

    /// invalid expiration timestamp {0}.
    InvalidExpiration(String),

    #[display(inner)]
    #[from]
    InvalidNetwork(UnknownNetwork),

    /// invalid query parameter {0}.
    InvalidQueryParam(String),

    #[from]
    #[display(inner)]
    Id(Baid64ParseError),

    /// can't recognize beneficiary "{0}": it should be either a bitcoin address
    /// or a blinded UTXO seal.
    Beneficiary(String),

    #[from]
    #[display(inner)]
    Num(ParseIntError),

    #[from]
    /// invalid interface name.
    IfaceName(InvalidRString),
}

impl RgbInvoice {
    fn has_params(&self) -> bool {
        self.expiry.is_some()
            || self.transports != vec![RgbTransport::UnspecifiedMeans]
            || !self.unknown_query.is_empty()
    }

    fn query_params(&self) -> IndexMap<String, String> {
        let mut query_params: IndexMap<String, String> = IndexMap::new();
        if let Some(expiry) = self.expiry {
            query_params.insert(EXPIRY.to_string(), expiry.to_string());
        }
        if self.transports != vec![RgbTransport::UnspecifiedMeans] {
            let mut transports: Vec<String> = vec![];
            for transport in self.transports.clone() {
                transports.push(transport.to_string());
            }
            query_params.insert(ENDPOINTS.to_string(), transports.join(&TRANSPORT_SEP.to_string()));
        }
        query_params.extend(self.unknown_query.clone());
        query_params
    }
}

impl Display for RgbTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RgbTransport::JsonRpc { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "rpc{s}{TRANSPORT_HOST_SEP}{}", host)?;
            }
            RgbTransport::RestHttp { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "http{s}{TRANSPORT_HOST_SEP}{}", host)?;
            }
            RgbTransport::WebSockets { tls, host } => {
                let s = if *tls { "s" } else { "" };
                write!(f, "ws{s}{TRANSPORT_HOST_SEP}{}", host)?;
            }
            RgbTransport::Storm {} => {
                write!(f, "storm{TRANSPORT_HOST_SEP}_/")?;
            }
            RgbTransport::UnspecifiedMeans => {}
        };
        Ok(())
    }
}

impl FromStr for RgbTransport {
    type Err = TransportParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tokens = s.split_once(TRANSPORT_HOST_SEP);
        if tokens.is_none() {
            return Err(TransportParseError::InvalidTransport(s.to_string()));
        }
        let (trans_type, host) = tokens.unwrap();
        if host.is_empty() {
            return Err(TransportParseError::InvalidTransportHost(host.to_string()));
        }
        let host = host.to_string();
        let transport = match trans_type {
            "rpc" => RgbTransport::JsonRpc { tls: false, host },
            "rpcs" => RgbTransport::JsonRpc { tls: true, host },
            "http" => RgbTransport::RestHttp { tls: false, host },
            "https" => RgbTransport::RestHttp { tls: true, host },
            "ws" => RgbTransport::WebSockets { tls: false, host },
            "wss" => RgbTransport::WebSockets { tls: true, host },
            "storm" => RgbTransport::Storm {},
            _ => return Err(TransportParseError::InvalidTransport(s.to_string())),
        };
        Ok(transport)
    }
}

impl Display for XChainNet<Beneficiary> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.chain_network())?;
        match self.into_inner() {
            Beneficiary::BlindedSeal(seal) => Display::fmt(&seal, f),
            Beneficiary::WitnessVout(payload) => payload.fmt_baid64(f),
        }
    }
}

impl FromStr for ChainNet {
    type Err = InvoiceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase() {
            x if ChainNet::BitcoinMainnet.to_string() == x => Ok(ChainNet::BitcoinMainnet),
            x if ChainNet::BitcoinTestnet.to_string() == x => Ok(ChainNet::BitcoinTestnet),
            x if ChainNet::BitcoinSignet.to_string() == x => Ok(ChainNet::BitcoinSignet),
            x if ChainNet::BitcoinRegtest.to_string() == x => Ok(ChainNet::BitcoinRegtest),
            x if ChainNet::LiquidMainnet.to_string() == x => Ok(ChainNet::BitcoinMainnet),
            x if ChainNet::LiquidTestnet.to_string() == x => Ok(ChainNet::LiquidTestnet),
            _ => Err(InvoiceParseError::Beneficiary(s.to_owned())),
        }
    }
}

impl DisplayBaid64<34> for Pay2Vout {
    const HRI: &'static str = "wvout";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = true;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 34] {
        let mut payload = [0u8; 34];
        // tmp stack array to store the tr payload to resolve lifetime issue
        let schnorr_pk: [u8; 32];
        payload[0] = self.method as u8;
        let (addr_type, spk) = match &self.address {
            AddressPayload::Pkh(pkh) => (Self::P2PKH, pkh.as_ref()),
            AddressPayload::Sh(sh) => (Self::P2SH, sh.as_ref()),
            AddressPayload::Wpkh(wpkh) => (Self::P2WPKH, wpkh.as_ref()),
            AddressPayload::Wsh(wsh) => (Self::P2WSH, wsh.as_ref()),
            AddressPayload::Tr(tr) => {
                schnorr_pk = tr.to_byte_array();
                (Self::P2TR, &schnorr_pk[..])
            }
        };
        payload[1] = addr_type;
        Cursor::new(&mut payload[2..])
            .write_all(spk)
            .expect("address payload always less than 32 bytes");
        payload
    }
}

impl Display for Pay2Vout {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}
impl FromBaid64Str<34> for Pay2Vout {}
impl FromStr for Pay2Vout {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

impl FromStr for XChainNet<Beneficiary> {
    type Err = InvoiceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((cn, beneficiary)) = s.split_once(':') else {
            return Err(InvoiceParseError::Beneficiary(s.to_owned()));
        };
        let cn = ChainNet::from_str(cn)?;
        if let Ok(seal) = SecretSeal::from_str(beneficiary) {
            return Ok(XChainNet::with(cn, Beneficiary::BlindedSeal(seal)));
        }

        let payload = Pay2Vout::from_str(beneficiary)?;
        Ok(XChainNet::with(cn, Beneficiary::WitnessVout(payload)))
    }
}

impl Display for RgbInvoice {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO: Support attachment through invoice params
        if let Some(contract) = self.contract {
            let id = if f.alternate() {
                contract.to_string().replace('-', "")
            } else {
                contract.to_string()
            };
            write!(f, "{id}/")?;
        } else {
            write!(f, "rgb:{OMITTED}/")?;
        }
        if let Some(iface) = self.iface.clone() {
            write!(f, "{iface}/")?;
        } else {
            write!(f, "{OMITTED}/")?;
        }
        if let Some(ref op) = self.operation {
            write!(f, "{op}/")?;
        }
        if let Some(ref assignment_name) = self.assignment {
            write!(f, "{assignment_name}/")?;
        }
        if let Some(state) = self.state.as_ref() {
            write!(f, "{state}+")?;
        }
        let beneficiary = if f.alternate() {
            self.beneficiary.to_string().replace('-', "")
        } else {
            self.beneficiary.to_string()
        };
        f.write_str(&beneficiary)?;
        if self.has_params() {
            f.write_str("?")?;
        }
        let query_params = self.query_params();
        for (key, val) in query_params.iter().take(1) {
            write!(
                f,
                "{}={}",
                utf8_percent_encode(key, QUERY_ENCODE),
                utf8_percent_encode(val, QUERY_ENCODE)
            )?;
        }
        for (key, val) in query_params.iter().skip(1) {
            write!(
                f,
                "&{}={}",
                utf8_percent_encode(key, QUERY_ENCODE),
                utf8_percent_encode(val, QUERY_ENCODE)
            )?;
        }
        Ok(())
    }
}

impl FromStr for RgbInvoice {
    type Err = InvoiceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Support attachment through invoice params
        let uri = Uri::parse(s)?;

        let scheme = uri.scheme().ok_or(InvoiceParseError::AbsentScheme)?;
        if scheme.as_str() != "rgb" {
            return Err(InvoiceParseError::InvalidScheme(scheme.to_string()));
        }

        let path = uri.path();
        if path.is_absolute() || uri.authority().is_some() {
            return Err(InvoiceParseError::Authority);
        }

        let mut path = path.segments();

        let Some(contract_id_str) = path.next() else {
            return Err(InvoiceParseError::ContractMissed);
        };
        let contract = match ContractId::from_str(contract_id_str.as_str()) {
            Ok(cid) => Some(cid),
            Err(_) if contract_id_str.as_str() == OMITTED => None,
            Err(_) => {
                return Err(InvoiceParseError::InvalidContractId(contract_id_str.to_string()));
            }
        };

        let Some(iface_str) = path.next() else {
            return Err(InvoiceParseError::IfaceMissed);
        };
        let iface = match TypeName::try_from(iface_str.to_string()) {
            Ok(i) => Some(i),
            Err(_) if iface_str.as_str() == OMITTED => None,
            Err(_) => return Err(InvoiceParseError::InvalidIface(iface_str.to_string())),
        };
        if contract.is_some() && iface.is_none() {
            return Err(InvoiceParseError::ContractIdNoIface);
        }

        let Some(assignment) = path.next() else {
            return Err(InvoiceParseError::AssignmentMissed);
        };
        let (state, beneficiary) = assignment
            .as_str()
            .split_once('+')
            .map(|(a, b)| (Some(a), Some(b)))
            .unwrap_or((Some(assignment.as_str()), None));
        let (beneficiary_str, state) = match (beneficiary, state) {
            (Some(b), Some(a)) => (b, Some(StateData::from_str(a)?)),
            (None, Some(b)) => (b, None),
            _ => unreachable!(),
        };

        let beneficiary = XChainNet::<Beneficiary>::from_str(beneficiary_str)?;
        let mut query_params = map_query_params(&uri)?;

        let transports = if let Some(endpoints) = query_params.shift_remove(ENDPOINTS) {
            let tokens = endpoints.split(TRANSPORT_SEP);
            let mut transport_vec: Vec<RgbTransport> = vec![];
            for token in tokens {
                transport_vec.push(
                    RgbTransport::from_str(token)
                        .map_err(|e| InvoiceParseError::InvalidQueryParam(e.to_string()))?,
                );
            }
            transport_vec
        } else {
            vec![RgbTransport::UnspecifiedMeans]
        };

        let mut expiry = None;
        if let Some(exp) = query_params.shift_remove(EXPIRY) {
            let timestamp = exp
                .parse::<i64>()
                .map_err(|e| InvoiceParseError::InvalidExpiration(e.to_string()))?;
            expiry = Some(timestamp);
        }

        Ok(RgbInvoice {
            transports,
            contract,
            iface,
            operation: None,
            assignment: None,
            beneficiary,
            state,
            expiry,
            unknown_query: query_params,
        })
    }
}

fn percent_decode(estr: &EStr) -> Result<String, InvoiceParseError> {
    Ok(estr
        .decode()
        .into_string()
        .map_err(|e| InvoiceParseError::InvalidQueryParam(e.to_string()))?
        .to_string())
}

fn map_query_params(uri: &Uri<&str>) -> Result<IndexMap<String, String>, InvoiceParseError> {
    let mut map: IndexMap<String, String> = IndexMap::new();
    if let Some(q) = uri.query() {
        let params = q.split('&');
        for p in params {
            if let Some((k, v)) = p.split_once('=') {
                map.insert(percent_decode(k)?, percent_decode(v)?);
            } else {
                return Err(InvoiceParseError::InvalidQueryParam(p.to_string()));
            }
        }
    }
    Ok(map)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        // rgb20/rgb25 parameters
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.state, Some(StateData::from_checked(vec![100, 0, 0, 0, 0, 0, 0, 0])));
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb21 parameters
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB21/\
                           -p----p---------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(
            invoice.state,
            Some(StateData::from_checked(vec![1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]))
        );
        assert_eq!(invoice.to_string(), invoice_str);

        // no amount
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no allocation
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB21/bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no contract ID
        let invoice_str =
            "rgb:~/RGB20/bc:utxob:zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // no contract ID nor iface
        let invoice_str = "rgb:~/~/bc:utxob:zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // contract ID provided but no iface
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/~/bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::ContractIdNoIface)));

        // invalid contract ID
        let invalid_contract_id = "invalid";
        let invoice_str = format!(
            "rgb:{invalid_contract_id}/RGB20/bc:utxob:\
             zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F"
        );
        let result = RgbInvoice::from_str(&invoice_str);
        assert!(matches!(result,
                Err(InvoiceParseError::InvalidContractId(c)) if c == invalid_contract_id));

        // with expiration
        let invoice_str =
            "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/y----------+bc:utxob:\
             zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?expiry=1682086371";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // bad expiration
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?expiry=six";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidExpiration(_))));

        // with bad query parameter
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?expiry";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // with an unknown query parameter
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?unknown=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with two unknown query parameters
        let invoice_str =
            "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/y----------+bc:utxob:\
             zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?unknown=new&another=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with expiration and an unknown query parameter
        let invoice_str =
            "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/y----------+bc:utxob:\
             zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?expiry=1682086371&unknown=new";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.to_string(), invoice_str);

        // with an unknown query parameter containing percent-encoded text
        let invoice_base = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                            y----------+bc:utxob:\
                            zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?";
        let query_key_encoded = ":@-%20%23";
        let query_key_decoded = ":@- #";
        let query_val_encoded = "?/.%26%3D";
        let query_val_decoded = "?/.&=";
        let invoice =
            RgbInvoice::from_str(&format!("{invoice_base}{query_key_encoded}={query_val_encoded}"))
                .unwrap();
        let query_params = invoice.query_params();
        assert_eq!(query_params[query_key_decoded], query_val_decoded);
        assert_eq!(
            invoice.to_string(),
            format!("{invoice_base}{query_key_encoded}={query_val_encoded}")
        );

        // no scheme
        let invoice_str = "2WBcas9-yjzEvGufY-9GEgnyMj7-beMNMWA8r-sPHtV1nPU-TMsGMQX/~/bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::AbsentScheme)));

        // invalid scheme
        let invoice_str = "bad:2WBcas9-yjzEvGufY-9GEgnyMj7-beMNMWA8r-sPHtV1nPU-TMsGMQX/~/bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidScheme(_))));

        // empty transport endpoint specification
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // invalid transport endpoint specification
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=bad";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // invalid transport variant
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpca:/\
                           /host.example.com";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpc://\
                           host.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: false,
            host: "host.example.com".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant, host containing authentication, "-" characters and port
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpcs:/\
                           /user:pass@host-1.ex-ample.com:1234";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: true,
            host: "user:pass@host-1.ex-ample.com:1234".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant, IPv6 host
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpcs:/\
                           /%5B2001:db8::1%5D:1234";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        assert_eq!(invoice.transports, vec![RgbTransport::JsonRpc {
            tls: true,
            host: "[2001:db8::1]:1234".to_string()
        }]);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb-rpc variant with missing host
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpc://";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant with invalid separator
        let invoice_str =
            "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/y----------+bc:utxob:\
             zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpc/host.example.com";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::InvalidQueryParam(_))));

        // rgb-rpc variant with invalid transport host specification
        let invoice_str =
            "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/y----------+bc:utxob:\
             zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpc://ho]t";
        let result = RgbInvoice::from_str(invoice_str);
        assert!(matches!(result, Err(InvoiceParseError::Uri(_))));

        // rgb+http variant
        let invoice_str = "rgb:\
                           11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=https://\
                           host.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![RgbTransport::RestHttp {
            tls: true,
            host: "host.example.com".to_string(),
        }];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // rgb+ws variant
        let invoice_str = "rgb:11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:\
                           zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=wss://\
                           host.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![RgbTransport::WebSockets {
            tls: true,
            host: "host.example.com".to_string(),
        }];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // TODO: rgb+storm variant

        // multiple transports
        let invoice_str = "rgb:\
                           11Fa!$Dk-rUWXhy8-7H35qXm-pLGGLOo-txBWUgj-tbOaSbI/RGB20/\
                           y----------+bc:utxob:zlVS28Rb-amM5lih-ONXGACC-IUWD0Y$-0JXcnWZ-MQn8VEI-B39!F?endpoints=rpcs://\
                           host1.example.com,http://host2.example.com,ws://host3.example.com";
        let invoice = RgbInvoice::from_str(invoice_str).unwrap();
        let transports = vec![
            RgbTransport::JsonRpc {
                tls: true,
                host: "host1.example.com".to_string(),
            },
            RgbTransport::RestHttp {
                tls: false,
                host: "host2.example.com".to_string(),
            },
            RgbTransport::WebSockets {
                tls: false,
                host: "host3.example.com".to_string(),
            },
        ];
        assert_eq!(invoice.transports, transports);
        assert_eq!(invoice.to_string(), invoice_str);

        // empty transport parse error
        let result = RgbTransport::from_str("");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));

        // invalid transport parse error
        let result = RgbTransport::from_str("bad");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));

        // invalid transport variant parse error
        let result = RgbTransport::from_str("rpca://host.example.com");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));

        // rgb-rpc variant with missing host parse error
        let result = RgbTransport::from_str("rpc://");
        assert!(matches!(result, Err(TransportParseError::InvalidTransportHost(_))));

        // rgb-rpc variant with invalid separator parse error
        let result = RgbTransport::from_str("rpc/host.example.com");
        assert!(matches!(result, Err(TransportParseError::InvalidTransport(_))));
    }

    #[test]
    fn pay2vout_parse() {
        let p = Pay2Vout {
            method: bp::dbc::Method::OpretFirst,
            address: AddressPayload::Pkh([0xff; 20].into()),
        };
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout {
            method: bp::dbc::Method::OpretFirst,
            address: AddressPayload::Sh([0xff; 20].into()),
        };
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout {
            method: bp::dbc::Method::OpretFirst,
            address: AddressPayload::Wpkh([0xff; 20].into()),
        };
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout {
            method: bp::dbc::Method::OpretFirst,
            address: AddressPayload::Wsh([0xff; 32].into()),
        };
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);

        let p = Pay2Vout {
            method: bp::dbc::Method::OpretFirst,
            address: AddressPayload::Tr(
                bp::OutputPk::from_byte_array([
                    0x85, 0xa6, 0x42, 0x59, 0x8b, 0xfe, 0x2e, 0x42, 0xa3, 0x78, 0xcb, 0xb5, 0x3b,
                    0xf1, 0x4a, 0xbe, 0x77, 0xf8, 0x1a, 0xef, 0xed, 0xf7, 0x3b, 0x66, 0x7b, 0x42,
                    0x85, 0xaf, 0x7c, 0xf1, 0xc8, 0xa3,
                ])
                .unwrap(),
            ),
        };
        assert_eq!(Pay2Vout::from_str(&p.to_string()).unwrap(), p);
    }
}
