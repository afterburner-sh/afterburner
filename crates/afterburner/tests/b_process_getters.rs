// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `process.getBuiltinModule(id)` (Node 22+) and
//! `process.getActiveResourcesInfo()` (Node 18+).

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed. stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

#[test]
fn process_get_builtin_module_returns_module_for_known_id() {
    let out = run_inline(
        r#"
        const fs = process.getBuiltinModule('fs');
        if (fs && typeof fs.readFileSync === 'function') console.log('GBM-OK');
        else console.log('FAIL', typeof fs);
        "#,
    );
    assert_marker(&out, "GBM-OK");
}

#[test]
fn process_get_builtin_module_strips_node_prefix() {
    let out = run_inline(
        r#"
        const a = process.getBuiltinModule('path');
        const b = process.getBuiltinModule('node:path');
        if (a && b && a.join === b.join) console.log('PREFIX-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "PREFIX-OK");
}

#[test]
fn process_get_builtin_module_unknown_returns_undefined() {
    let out = run_inline(
        r#"
        const r = process.getBuiltinModule('definitely-not-a-builtin');
        if (r === undefined) console.log('UNKNOWN-OK');
        else console.log('FAIL', typeof r);
        "#,
    );
    assert_marker(&out, "UNKNOWN-OK");
}

#[test]
fn process_get_active_resources_info_returns_an_array() {
    let out = run_inline(
        r#"
        const r = process.getActiveResourcesInfo();
        if (Array.isArray(r)) console.log('GAI-OK');
        else console.log('FAIL', typeof r);
        "#,
    );
    assert_marker(&out, "GAI-OK");
}
