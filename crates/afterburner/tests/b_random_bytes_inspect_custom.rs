// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `crypto.randomBytes` returning a Buffer (not a hex string) and
//! `util.inspect.custom` symbol hook (Node 6.6+).

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
fn crypto_random_bytes_returns_buffer() {
    let out = run_inline(
        r#"
        const crypto = require('crypto');
        const buf = crypto.randomBytes(16);
        if (Buffer.isBuffer(buf) && buf.length === 16) console.log('RB-OK');
        else console.log('FAIL', typeof buf, buf && buf.length);
        "#,
    );
    assert_marker(&out, "RB-OK");
}

#[test]
fn crypto_random_bytes_callback_form() {
    let out = run_inline(
        r#"
        const crypto = require('crypto');
        crypto.randomBytes(8, (err, buf) => {
            if (!err && Buffer.isBuffer(buf) && buf.length === 8) console.log('RB-CB-OK');
            else console.log('FAIL', err, buf && buf.length);
        });
        "#,
    );
    assert_marker(&out, "RB-CB-OK");
}

#[test]
fn util_inspect_custom_symbol_present() {
    let out = run_inline(
        r#"
        const util = require('util');
        if (typeof util.inspect.custom === 'symbol' &&
            util.inspect.custom === Symbol.for('nodejs.util.inspect.custom'))
            console.log('IC-SYM-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "IC-SYM-OK");
}

#[test]
fn util_inspect_calls_custom_hook() {
    let out = run_inline(
        r#"
        const util = require('util');
        const obj = {
            [util.inspect.custom]: function(depth, opts) { return 'CUSTOM-' + depth; },
        };
        const s = util.inspect(obj);
        if (s.indexOf('CUSTOM-') === 0) console.log('IC-HOOK-OK');
        else console.log('FAIL', s);
        "#,
    );
    assert_marker(&out, "IC-HOOK-OK");
}

#[test]
fn util_inspect_default_options_present() {
    let out = run_inline(
        r#"
        const util = require('util');
        const o = util.inspect.defaultOptions;
        if (o && o.depth === 2 && o.maxArrayLength === 100) console.log('DEF-OPTS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "DEF-OPTS-OK");
}
