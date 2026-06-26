// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Stage-3 / Node 22+ Uint8Array base64 + hex methods:
//! `toBase64({alphabet, omitPadding})` / `toHex()` /
//! `Uint8Array.fromBase64(input, opts)` / `fromHex(input)`.

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
fn uint8_to_hex_lowercase_padded() {
    let out = run_inline(
        r#"
        const u = new Uint8Array([0x0a, 0x0f, 0xff, 0x00]);
        if (u.toHex() === '0a0fff00') console.log('HEX-OK');
        else console.log('FAIL', u.toHex());
        "#,
    );
    assert_marker(&out, "HEX-OK");
}

#[test]
fn uint8_to_base64_default_padded() {
    let out = run_inline(
        r#"
        const u = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        if (u.toBase64() === '3q2+7w==') console.log('B64-OK');
        else console.log('FAIL', u.toBase64());
        "#,
    );
    assert_marker(&out, "B64-OK");
}

#[test]
fn uint8_to_base64_url_alphabet_and_omit_padding() {
    let out = run_inline(
        r#"
        const u = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const s = u.toBase64({ alphabet: 'base64url', omitPadding: true });
        if (s === '3q2-7w') console.log('B64URL-OK');
        else console.log('FAIL', s);
        "#,
    );
    assert_marker(&out, "B64URL-OK");
}

#[test]
fn uint8_from_hex_round_trips() {
    let out = run_inline(
        r#"
        const u = Uint8Array.fromHex('cafebabe');
        if (u.length === 4 && u[0] === 0xca && u[3] === 0xbe) console.log('FROM-HEX-OK');
        else console.log('FAIL', Array.from(u));
        "#,
    );
    assert_marker(&out, "FROM-HEX-OK");
}

#[test]
fn uint8_from_hex_rejects_odd_length() {
    let out = run_inline(
        r#"
        try {
            Uint8Array.fromHex('abc');
            console.log('FAIL no-throw');
        } catch (_) { console.log('ODD-OK'); }
        "#,
    );
    assert_marker(&out, "ODD-OK");
}

#[test]
fn uint8_from_base64_url_round_trips() {
    let out = run_inline(
        r#"
        const u = Uint8Array.fromBase64('3q2-7w', { alphabet: 'base64url' });
        if (u.length === 4 && u[0] === 0xde && u[3] === 0xef) console.log('FROM-B64-OK');
        else console.log('FAIL', Array.from(u));
        "#,
    );
    assert_marker(&out, "FROM-B64-OK");
}
