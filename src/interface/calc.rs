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

use aluvm::data::ByteStr;
use aluvm::library::{LibId, LibSite};
use aluvm::reg::{Reg16, Reg32, RegA, RegR};
use amplify::num::{u256, u4};
use amplify::{ByteArray, Wrapper};
use rgb::validation::Scripts;
use rgb::{AssignmentType, AttachId, StateData};

use crate::LIB_NAME_RGB_STD;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum StateCalcError {
    /// reserved byte value {0} is not 0x00 for assignment type {1}.
    InvalidReserved(AssignmentType, u8),
    /// error registering input state of type {0} - {1}.
    InputReg(AssignmentType, String),
    /// error registering output state of type {0} - {1}.
    OutputReg(AssignmentType, String),
    /// error computing output state of type {0} - {1}.
    OutputCalc(AssignmentType, String),
    /// error computing change state of type {0} - {1}.
    ChangeCalc(AssignmentType, String),
    /// failed script for calculating output state of type {0}; please update interface
    /// implementation for the schema
    InsufficientState(AssignmentType),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STD)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct StateAbi {
    pub reg_input: LibSite,
    pub reg_output: LibSite,
    pub calc_output: LibSite,
    pub calc_change: LibSite,
}

impl StateAbi {
    pub fn lib_ids(&self) -> impl Iterator<Item = LibId> {
        [self.reg_input, self.reg_output, self.calc_output, self.calc_change]
            .into_iter()
            .map(|site| site.lib)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AllocatedState {
    pub sufficient: rgb::State,
    pub insufficient: Option<rgb::State>,
}

#[derive(Clone, Debug)]
pub struct StateCalc {
    vm: aluvm::Vm,
    abi: StateAbi,
    scripts: Scripts,
}

impl StateCalc {
    pub fn new(scripts: Scripts, abi: StateAbi) -> Self {
        let vm = aluvm::Vm::new();
        Self { vm, abi, scripts }
    }

    fn run(&mut self, site: LibSite) -> Result<(), String> {
        if !self.vm.exec(site, |id| self.scripts.get(&id), &()) {
            if let Some(err) = self.vm.registers.s16(15).cloned() {
                return Err(err.to_string());
            }
        }
        Ok(())
    }

    fn put_state(&mut self, ty: AssignmentType, state: &rgb::State) {
        self.vm
            .registers
            .set_n(RegA::A16, Reg32::Reg0, Some(ty.to_inner()));
        assert_eq!(state.reserved, none!());
        self.vm.registers.set_n(RegA::A8, Reg32::Reg0, Some(0u8));
        self.vm.registers.set_s16(0, ByteStr::with(&state.data));
        self.vm.registers.set_n(
            RegR::R256,
            Reg32::Reg0,
            state.attach.map(|a| u256::from_le_bytes(a.to_byte_array())),
        );
    }

    fn fetch_state(
        &self,
        ty: AssignmentType,
        idx: Reg16,
    ) -> Result<Option<rgb::State>, StateCalcError> {
        let Some(data) = self.vm.registers.s16(u4::from(idx)) else {
            return Ok(None);
        };
        let reserved = self
            .vm
            .registers
            .get_n(RegA::A8, idx)
            .map(|n| u8::from(n))
            .unwrap_or_default();
        let attach = self
            .vm
            .registers
            .get_n(RegR::R256, idx)
            .map(|n| AttachId::from_byte_array(u256::from(n).to_le_bytes()));
        if reserved != 0x00 {
            return Err(StateCalcError::InvalidReserved(ty, reserved));
        }
        Ok(Some(rgb::State {
            reserved: none!(),
            data: StateData::from_checked(data.to_vec()),
            attach,
        }))
    }

    pub fn reg_input(
        &mut self,
        ty: AssignmentType,
        state: &rgb::State,
    ) -> Result<(), StateCalcError> {
        self.put_state(ty, state);
        self.run(self.abi.reg_input)
            .map_err(|err| StateCalcError::InputReg(ty, err))
    }

    pub fn reg_output(
        &mut self,
        ty: AssignmentType,
        state: &rgb::State,
    ) -> Result<(), StateCalcError> {
        self.put_state(ty, state);
        self.run(self.abi.reg_output)
            .map_err(|err| StateCalcError::OutputReg(ty, err))
    }

    pub fn calc_output(
        &mut self,
        ty: AssignmentType,
        state: &rgb::State,
    ) -> Result<AllocatedState, StateCalcError> {
        self.put_state(ty, state);
        self.run(self.abi.calc_output)
            .map_err(|err| StateCalcError::OutputCalc(ty, err))?;
        let Some(sufficient) = self.fetch_state(ty, Reg16::Reg0)? else {
            return Err(StateCalcError::InsufficientState(ty));
        };
        let insufficient = self.fetch_state(ty, Reg16::Reg1)?;
        Ok(AllocatedState {
            sufficient,
            insufficient,
        })
    }

    pub fn calc_change(
        &mut self,
        ty: AssignmentType,
    ) -> Result<Option<rgb::State>, StateCalcError> {
        self.run(self.abi.calc_change)
            .map_err(|err| StateCalcError::ChangeCalc(ty, err))?;
        self.fetch_state(ty, Reg16::Reg0)
    }

    pub fn is_sufficient_for(&self, ty: AssignmentType, state: &rgb::State) -> bool {
        self.clone().calc_output(ty, state).is_ok()
    }
}
