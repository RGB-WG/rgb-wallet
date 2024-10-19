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

//! Module defines API used by providers of persistent data for RGB contracts.
//!
//! These data include:
//! 1. Stash: a consensus-critical data for client-side-validation which must be preserved and
//!    backed up.
//! 2. Contract state, updated with each enclosed consignment and disclosure.
//! 3. Index over stash, which simplifies construction of new consignments.
//!
//! Contract state and index data can be re-computed from the stash in case of
//! loss or corruption, while stash can't be recovered unless it was backed up.

mod stock;
mod stash;
mod state;
mod index;

mod memory;
#[cfg(feature = "fs")]
pub mod fs;

pub use index::{
    Index, IndexError, IndexInconsistency, IndexProvider, IndexReadError, IndexReadProvider,
    IndexWriteError, IndexWriteProvider,
};
pub use memory::{
    MemContract, MemContractState, MemError, MemGlobalState, MemIndex, MemStash, MemState,
};
pub use stash::{
    ProviderError as StashProviderError, SchemaIfaces, Stash, StashDataError, StashError,
    StashInconsistency, StashProvider, StashReadProvider, StashWriteProvider,
};
pub use state::{
    ContractStateRead, ContractStateWrite, State, StateError, StateInconsistency, StateProvider,
    StateReadProvider, StateWriteProvider,
};
pub use stock::{
    ComposeError, ConsignError, ContractIfaceError, FasciaError, InputError as StockInputError,
    Stock, StockError, StockErrorAll, StockErrorMem, UpdateRes,
};

pub trait StoreTransaction {
    type TransactionErr: std::error::Error;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr>;

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr>;

    fn rollback_transaction(&mut self);
}
