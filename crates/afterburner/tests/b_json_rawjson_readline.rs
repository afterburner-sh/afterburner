// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `JSON.rawJSON` / `JSON.isRawJSON` (Stage 4, Node 21+) and
//! `readline.promises` namespace.

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
fn json_raw_json_round_trips_through_stringify() {
    let out = run_inline(
        r#"
        const wrapped = JSON.rawJSON('[1,2,3]');
        const s = JSON.stringify({ a: wrapped, b: 'plain' });
        if (s === '{"a":[1,2,3],"b":"plain"}') console.log('RAWJSON-OK');
        else console.log('FAIL', s);
        "#,
    );
    assert_marker(&out, "RAWJSON-OK");
}

#[test]
fn json_is_raw_json_distinguishes_wrapped_from_object() {
    let out = run_inline(
        r#"
        const w = JSON.rawJSON('42');
        if (JSON.isRawJSON(w) && !JSON.isRawJSON({}) && !JSON.isRawJSON(null) &&
            !JSON.isRawJSON('a string')) console.log('IS-RAW-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "IS-RAW-OK");
}

#[test]
fn json_raw_json_validates_input() {
    let out = run_inline(
        r#"
        try {
            JSON.rawJSON('this is not json');
            console.log('FAIL no-throw');
        } catch (e) {
            if (e instanceof SyntaxError) console.log('VALIDATE-OK');
            else console.log('FAIL wrong-error', e.constructor.name);
        }
        "#,
    );
    assert_marker(&out, "VALIDATE-OK");
}

#[test]
fn readline_promises_namespace_exposes_create_interface() {
    let out = run_inline(
        r#"
        const rl = require('readline');
        if (typeof rl.promises === 'object' &&
            typeof rl.promises.createInterface === 'function' &&
            typeof rl.promises.Interface === 'function') console.log('RLP-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "RLP-OK");
}
