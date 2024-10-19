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

use std::str::FromStr;

use rgb::{ContractId, StateData};
use strict_encoding::{FieldName, SerializeError, StrictSerialize, TypeName};

use crate::{Beneficiary, RgbInvoice, RgbTransport, TransportParseError, XChainNet};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RgbInvoiceBuilder(RgbInvoice);

#[allow(clippy::result_large_err)]
impl RgbInvoiceBuilder {
    pub fn new(beneficiary: impl Into<XChainNet<Beneficiary>>) -> Self {
        Self(RgbInvoice {
            transports: vec![RgbTransport::UnspecifiedMeans],
            contract: None,
            iface: None,
            operation: None,
            assignment: None,
            beneficiary: beneficiary.into(),
            state: None,
            expiry: None,
            unknown_query: none!(),
        })
    }

    pub fn with(contract_id: ContractId, beneficiary: impl Into<XChainNet<Beneficiary>>) -> Self {
        Self::new(beneficiary).set_contract(contract_id)
    }

    pub fn set_contract(mut self, contract_id: ContractId) -> Self {
        self.0.contract = Some(contract_id);
        self
    }

    /// Sets interface for the invoice. Interface can be a concrete interface (name or id), or a
    /// name of an interface standard, like `RGB20`, `RGB21` etc.
    pub fn set_interface(mut self, name: impl Into<TypeName>) -> Self {
        self.0.iface = Some(name.into());
        self
    }

    pub fn set_operation(mut self, name: impl Into<FieldName>) -> Self {
        self.0.operation = Some(name.into());
        self
    }

    pub fn set_assignment(mut self, name: impl Into<FieldName>) -> Self {
        self.0.assignment = Some(name.into());
        self
    }

    /// Add state data to the invoice.
    ///
    /// See also [`Self::serialize_state_data`], which adds state data by serializing them from a
    /// state object.
    pub fn set_state(mut self, data: StateData) -> Self {
        self.0.state = Some(data);
        self
    }

    /// Add state data to the invoice by strict-serializing the provided object.
    ///
    /// Use the function carefully, since the common pitfall here is to perform double serialization
    /// of an already serialized data type, like `SmallBlob`. This produces an invalid state object
    /// which can't be properly parsed later. See also [`Self::set_state`], which sets state data
    /// directly with no serialization.
    pub fn serialize_state_data(
        mut self,
        data: &impl StrictSerialize,
    ) -> Result<Self, SerializeError> {
        self.0.state = Some(StateData::from_serialized(data)?);
        Ok(self)
    }

    pub fn set_expiry_timestamp(mut self, expiry: i64) -> Self {
        self.0.expiry = Some(expiry);
        self
    }

    fn drop_unspecified_transport(&mut self) {
        if self.0.transports.len() == 1 && self.0.transports[0] == RgbTransport::UnspecifiedMeans {
            self.0.transports = vec![];
        }
    }

    pub fn add_transport(self, transport: &str) -> Result<Self, (Self, TransportParseError)> {
        let transport = match RgbTransport::from_str(transport) {
            Err(err) => return Err((self, err)),
            Ok(transport) => transport,
        };
        Ok(self.add_transport_raw(transport))
    }

    pub fn add_transport_raw(mut self, transport: RgbTransport) -> Self {
        self.drop_unspecified_transport();
        self.0.transports.push(transport);
        self
    }

    pub fn add_transports<'a>(
        self,
        transports: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, (Self, TransportParseError)> {
        let res = transports
            .into_iter()
            .map(RgbTransport::from_str)
            .collect::<Result<Vec<_>, TransportParseError>>();
        let transports = match res {
            Err(err) => return Err((self, err)),
            Ok(transports) => transports,
        };
        Ok(self.add_transports_raw(transports))
    }

    pub fn add_transports_raw(
        mut self,
        transports: impl IntoIterator<Item = RgbTransport>,
    ) -> Self {
        self.drop_unspecified_transport();
        self.0.transports.extend(transports);
        self
    }

    pub fn finish(self) -> RgbInvoice { self.0 }
}
