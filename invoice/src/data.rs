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

use rgb::{DataState, KnownState, RevealedData};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::StrictVal;

use crate::LIB_NAME_RGB_CONTRACT;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum NonFungible {
    #[display(inner)]
    RGB21(Allocation),
}

impl FromStr for NonFungible {
    type Err = AllocationParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let allocation = Allocation::from_str(s)?;
        Ok(NonFungible::RGB21(allocation))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum AllocationParseError {
    #[display(doc_comments)]
    /// invalid token index {0}.
    InvalidIndex(String),

    #[display(doc_comments)]
    /// invalid fraction {0}.
    InvalidFraction(String),

    #[display(doc_comments)]
    /// allocation must have format <fraction>@<token_index>.
    WrongFormat,
}

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Display, FromStr, Add, Sub, Mul, Div, Rem)]
#[wrapper_mut(AddAssign, SubAssign, MulAssign, DivAssign, RemAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct TokenIndex(u32);

#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Display, FromStr, Add, Sub, Mul, Div, Rem)]
#[wrapper_mut(AddAssign, SubAssign, MulAssign, DivAssign, RemAssign)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct OwnedFraction(u64);

impl OwnedFraction {
    pub const ZERO: Self = OwnedFraction(0);

    pub fn from_strict_val_unchecked(value: &StrictVal) -> Self {
        value.unwrap_uint::<u64>().into()
    }

    pub fn value(self) -> u64 { self.0 }

    pub fn saturating_add(&self, other: impl Into<Self>) -> Self {
        self.0.saturating_add(other.into().0).into()
    }
    pub fn saturating_sub(&self, other: impl Into<Self>) -> Self {
        self.0.saturating_sub(other.into().0).into()
    }

    pub fn saturating_add_assign(&mut self, other: impl Into<Self>) {
        *self = self.0.saturating_add(other.into().0).into();
    }
    pub fn saturating_sub_assign(&mut self, other: impl Into<Self>) {
        *self = self.0.saturating_sub(other.into().0).into();
    }

    #[must_use]
    pub fn checked_add(&self, other: impl Into<Self>) -> Option<Self> {
        self.0.checked_add(other.into().0).map(Self)
    }
    #[must_use]
    pub fn checked_sub(&self, other: impl Into<Self>) -> Option<Self> {
        self.0.checked_sub(other.into().0).map(Self)
    }

    #[must_use]
    pub fn checked_add_assign(&mut self, other: impl Into<Self>) -> Option<()> {
        *self = self.0.checked_add(other.into().0).map(Self)?;
        Some(())
    }
    #[must_use]
    pub fn checked_sub_assign(&mut self, other: impl Into<Self>) -> Option<()> {
        *self = self.0.checked_sub(other.into().0).map(Self)?;
        Some(())
    }
}

impl KnownState for OwnedFraction {}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default, Display)]
#[display("{1}@{0}")]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CONTRACT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Allocation(TokenIndex, OwnedFraction);

impl Allocation {
    pub fn with(index: impl Into<TokenIndex>, fraction: impl Into<OwnedFraction>) -> Allocation {
        Allocation(index.into(), fraction.into())
    }

    pub fn token_index(self) -> TokenIndex { self.0 }

    pub fn fraction(self) -> OwnedFraction { self.1 }
}

impl StrictSerialize for Allocation {}
impl StrictDeserialize for Allocation {}

impl KnownState for Allocation {}

impl From<RevealedData> for Allocation {
    fn from(data: RevealedData) -> Self {
        Allocation::from_strict_serialized(data.value.into()).expect("invalid allocation data")
    }
}

impl From<DataState> for Allocation {
    fn from(state: DataState) -> Self {
        Allocation::from_strict_serialized(state.into()).expect("invalid allocation data")
    }
}

impl From<Allocation> for DataState {
    fn from(allocation: Allocation) -> Self {
        DataState::from(
            allocation
                .to_strict_serialized()
                .expect("invalid allocation data"),
        )
    }
}

impl FromStr for Allocation {
    type Err = AllocationParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains('@') {
            return Err(AllocationParseError::WrongFormat);
        }

        match s.split_once('@') {
            Some((fraction, token_index)) => Ok(Allocation(
                token_index
                    .parse()
                    .map_err(|_| AllocationParseError::InvalidIndex(token_index.to_owned()))?,
                fraction
                    .parse()
                    .map_err(|_| AllocationParseError::InvalidFraction(fraction.to_lowercase()))?,
            )),
            None => Err(AllocationParseError::WrongFormat),
        }
    }
}

#[cfg(test)]
mod test {
    use strict_types::value::StrictNum;

    use super::*;

    #[test]
    fn owned_fraction_from_str() {
        let owned_fraction = match OwnedFraction::from_str("1") {
            Ok(value) => value,
            Err(_) => OwnedFraction::ZERO,
        };

        assert_eq!(owned_fraction.value(), 1);
        assert_eq!(format!("{owned_fraction}"), "1");
    }

    #[test]
    fn owned_fraction_from_strict_val() {
        // note that the strict number is u128 but not u64
        let owned_fraction =
            OwnedFraction::from_strict_val_unchecked(&StrictVal::Number(StrictNum::Uint(1)));

        assert_eq!(owned_fraction.value(), 1);
        assert_eq!(format!("{owned_fraction}"), "1");
    }

    #[test]
    fn owned_fraction_add_assign() {
        let mut owned_fraction = match OwnedFraction::from_str("1") {
            Ok(value) => value,
            Err(_) => OwnedFraction::ZERO,
        };

        let _ = owned_fraction.checked_add_assign(OwnedFraction::ZERO);
        assert_eq!(owned_fraction.value(), 1);
        assert_eq!(format!("{owned_fraction}"), "1");
    }

    #[test]
    fn owned_fraction_add() {
        let owned_fraction = match OwnedFraction::from_str("1") {
            Ok(value) => value,
            Err(_) => OwnedFraction::ZERO,
        };

        let owned = match owned_fraction.checked_add(OwnedFraction::ZERO) {
            Some(value) => value,
            None => OwnedFraction::ZERO,
        };
        assert_eq!(owned.value(), 1);
        assert_eq!(format!("{owned}"), "1");
    }

    #[test]
    fn owned_fraction_sub() {
        let owned_fraction = match OwnedFraction::from_str("1") {
            Ok(value) => value,
            Err(_) => OwnedFraction::ZERO,
        };

        let other_fraction = match OwnedFraction::from_str("1") {
            Ok(value) => value,
            Err(_) => OwnedFraction::ZERO,
        };

        let owned = match owned_fraction.checked_sub(other_fraction) {
            Some(value) => value,
            None => OwnedFraction::ZERO,
        };
        assert_eq!(owned.value(), 0);
        assert_eq!(format!("{owned}"), "0");
    }

    #[test]
    fn owned_fraction_sub_assign() {
        let mut owned_fraction = match OwnedFraction::from_str("1") {
            Ok(value) => value,
            Err(_) => OwnedFraction::ZERO,
        };

        let other_fraction = match OwnedFraction::from_str("1") {
            Ok(value) => value,
            Err(_) => OwnedFraction::ZERO,
        };

        let _ = owned_fraction.checked_sub_assign(other_fraction);
        assert_eq!(owned_fraction.value(), 0);
        assert_eq!(format!("{owned_fraction}"), "0");
    }
}
