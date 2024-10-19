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

use amplify::IoError;
use baid64::Baid64ParseError;
pub use bp::bc::stl::bp_tx_stl;
pub use bp::stl::bp_core_stl;
pub use commit_verify::stl::{commit_verify_stl, LIB_ID_COMMIT_VERIFY};
pub use rgb::stl::{aluvm_stl, rgb_commit_stl, rgb_logic_stl, LIB_ID_RGB_COMMIT, LIB_ID_RGB_LOGIC};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::{typesys, CompileError, LibBuilder, TypeLib};

use crate::containers::{Contract, Kit, Transfer};
use crate::persistence::{MemIndex, MemStash, MemState};

pub const LIB_NAME_RGB_STD: &str = "RGBStd";
pub const LIB_NAME_RGB_STORAGE: &str = "RGBStorage";

/// Strict types id for the library providing standard data types which may be
/// used in RGB smart contracts.
pub const LIB_ID_RGB_STORAGE: &str =
    "stl:dYzM3Ct9-SJ8PljY-C!6hB6y-VlWvDE7-DAtNg3y-zanf6hE#media-fresh-cadet";

/// Strict types id for the library representing of RGB StdLib data types.
pub const LIB_ID_RGB_STD: &str =
    "stl:3QsSNDHr-YPIKTR9-5O!fLuv-xhcxKT2-0LWrO9b-pG15Nvw#mango-inside-shelf";

#[allow(dead_code)]
#[derive(Debug, From)]
pub enum Error {
    #[from(std::io::Error)]
    Io(IoError),
    #[from]
    Baid64(Baid64ParseError),
    #[from]
    Compile(CompileError),
    #[from]
    Link1(typesys::Error),
    #[from]
    Link2(Vec<typesys::Error>),
}

fn _rgb_std_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_STD), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_commit_stl().to_dependency(),
        rgb_logic_stl().to_dependency(),
    })
    .transpile::<Transfer>()
    .transpile::<Contract>()
    .transpile::<Kit>()
    .compile()
}

fn _rgb_storage_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_STORAGE), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_commit_stl().to_dependency(),
        rgb_logic_stl().to_dependency(),
        rgb_std_stl().to_dependency()
    })
    .transpile::<MemIndex>()
    .transpile::<MemState>()
    .transpile::<MemStash>()
    .compile()
}

/// Generates strict type library representation of RGB StdLib data types.
pub fn rgb_std_stl() -> TypeLib { _rgb_std_stl().expect("invalid strict type RGBStd library") }

/// Generates strict type library providing standard storage for state, contract
/// state and index.
pub fn rgb_storage_stl() -> TypeLib {
    _rgb_storage_stl().expect("invalid strict type RGBStorage library")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn std_lib_id() {
        let lib = rgb_std_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_STD);
    }

    #[test]
    fn storage_lib_id() {
        let lib = rgb_storage_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_STORAGE);
    }
}
