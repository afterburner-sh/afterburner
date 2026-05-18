// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `crypto.randomInt` (sync + callback), `crypto.randomFill`,
//! `crypto.randomFillSync`, `crypto.webcrypto` alias.

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
fn crypto_random_int_sync_within_range() {
    let out = run_inline(
        r#"
        const c = require('crypto');
        for (let i = 0; i < 100; i++) {
            const v = c.randomInt(0, 10);
            if (!Number.isInteger(v) || v < 0 || v >= 10) {
                console.log('FAIL', v);
                process.exit(1);
            }
        }
        console.log('RI-SYNC-OK');
        "#,
    );
    assert_marker(&out, "RI-SYNC-OK");
}

#[test]
fn crypto_random_int_max_only() {
    let out = run_inline(
        r#"
        const c = require('crypto');
        const v = c.randomInt(50);
        if (Number.isInteger(v) && v >= 0 && v < 50) console.log('RI-MAX-OK');
        else console.log('FAIL', v);
        "#,
    );
    assert_marker(&out, "RI-MAX-OK");
}

#[test]
fn crypto_random_int_callback_form() {
    let out = run_inline(
        r#"
        const c = require('crypto');
        c.randomInt(100, 200, (err, v) => {
            if (!err && v >= 100 && v < 200) console.log('RI-CB-OK');
            else console.log('FAIL', err, v);
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 1000);
        "#,
    );
    assert_marker(&out, "RI-CB-OK");
}

#[test]
fn crypto_random_int_rejects_negative_min() {
    let out = run_inline(
        r#"
        const c = require('crypto');
        try {
            c.randomInt(-5, 10);
            console.log('FAIL no-throw');
        } catch (_) { console.log('RI-NEG-OK'); }
        "#,
    );
    assert_marker(&out, "RI-NEG-OK");
}

#[test]
fn crypto_random_fill_sync_fills_buffer() {
    let out = run_inline(
        r#"
        const c = require('crypto');
        const b = Buffer.alloc(32);
        c.randomFillSync(b);
        // Probability of all-zero is 2^-256 — negligible.
        if (b.some(x => x !== 0)) console.log('FILL-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "FILL-OK");
}

#[test]
fn crypto_random_fill_async_invokes_callback_with_buffer() {
    let out = run_inline(
        r#"
        const c = require('crypto');
        const b = Buffer.alloc(16);
        c.randomFill(b, (err, returned) => {
            if (!err && returned === b && returned.some(x => x !== 0)) console.log('FILL-CB-OK');
            else console.log('FAIL', err && err.message);
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 1000);
        "#,
    );
    assert_marker(&out, "FILL-CB-OK");
}

#[test]
fn crypto_webcrypto_aliases_global_crypto() {
    let out = run_inline(
        r#"
        const c = require('crypto');
        if (c.webcrypto && typeof c.webcrypto.subtle === 'object' &&
            typeof c.webcrypto.subtle.digest === 'function') console.log('WEBCRYPTO-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "WEBCRYPTO-OK");
}
