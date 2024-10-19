// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
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

use std::fs;
use std::io::Write;

use commit_verify::CommitmentLayout;
use rgbstd::containers::Transfer;
use rgbstd::stl::{
    aluvm_stl, bp_core_stl, bp_tx_stl, commit_verify_stl, rgb_commit_stl, rgb_logic_stl,
    rgb_std_stl, rgb_storage_stl,
};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::{parse_args, StlFormat, SystemBuilder};

fn main() {
    let (_, dir) = parse_args();
    let dir = dir.unwrap_or_else(|| "./stl".to_owned());

    let rgb_std = rgb_std_stl();
    rgb_std
        .serialize(StlFormat::Binary, Some(&dir), "0.11.0", None)
        .expect("unable to write to the file");
    rgb_std
        .serialize(StlFormat::Armored, Some(&dir), "0.11.0", None)
        .expect("unable to write to the file");
    rgb_std
        .serialize(
            StlFormat::Source,
            Some(&dir),
            "0.11.0",
            Some(
                "
  Description: RGB standard library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let rgb_storage = rgb_storage_stl();
    rgb_storage
        .serialize(StlFormat::Binary, Some(&dir), "0.11.0", None)
        .expect("unable to write to the file");
    rgb_storage
        .serialize(StlFormat::Armored, Some(&dir), "0.11.0", None)
        .expect("unable to write to the file");
    rgb_storage
        .serialize(
            StlFormat::Source,
            Some(&dir),
            "0.11.0",
            Some(
                "
  Description: RGB storage library
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let std = std_stl();
    let rgb = rgb_std_stl();
    let rgb_commit = rgb_commit_stl();
    let rgb_logic = rgb_logic_stl();
    let tx = bp_tx_stl();
    let bp = bp_core_stl();
    let cv = commit_verify_stl();
    let st = strict_types_stl();
    let vm = aluvm_stl();

    let sys = SystemBuilder::new()
        .import(rgb)
        .unwrap()
        .import(rgb_logic)
        .unwrap()
        .import(rgb_commit)
        .unwrap()
        .import(vm)
        .unwrap()
        .import(bp)
        .unwrap()
        .import(tx)
        .unwrap()
        .import(cv)
        .unwrap()
        .import(st)
        .unwrap()
        .import(std)
        .unwrap()
        .finalize()
        .expect("not all libraries present");

    let mut file = fs::File::create(format!("{dir}/Transfer.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: RGB Transfer
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Seals vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = Transfer::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGBStd.Consignmenttrue").unwrap();
    writeln!(file, "{tt}").unwrap();
}
