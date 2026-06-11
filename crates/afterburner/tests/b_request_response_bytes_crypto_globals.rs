// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Request/Response.bytes() (Node 22+), Request body methods (Node 18+),
//! and CryptoKey / SubtleCrypto / Crypto class globals (Node 17+).

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
fn response_bytes_returns_uint8array() {
    let out = run_inline(
        r#"
        const r = new Response('hello');
        r.bytes().then(u => {
            if (u instanceof Uint8Array && u.length === 5 && u[0] === 0x68)
                console.log('RESP-BYTES-OK');
            else console.log('FAIL', u);
        });
        "#,
    );
    assert_marker(&out, "RESP-BYTES-OK");
}

#[test]
fn request_bytes_returns_uint8array() {
    let out = run_inline(
        r#"
        const r = new Request('http://x/y', { method: 'POST', body: 'abc' });
        r.bytes().then(u => {
            if (u instanceof Uint8Array && u.length === 3) console.log('REQ-BYTES-OK');
            else console.log('FAIL', u && u.length);
        });
        "#,
    );
    assert_marker(&out, "REQ-BYTES-OK");
}

#[test]
fn request_text_and_json_round_trip() {
    let out = run_inline(
        r#"
        const r = new Request('http://x/y', { method: 'POST', body: '{"a":1}' });
        r.json().then(o => {
            if (o && o.a === 1) console.log('REQ-JSON-OK');
            else console.log('FAIL');
        });
        "#,
    );
    assert_marker(&out, "REQ-JSON-OK");
}

#[test]
fn crypto_key_global_is_class_like() {
    let out = run_inline(
        r#"
        if (typeof CryptoKey === 'function') {
            try { new CryptoKey(); console.log('FAIL no-throw'); }
            catch (e) { console.log('CK-CTOR-OK'); }
        } else console.log('FAIL', typeof CryptoKey);
        "#,
    );
    assert_marker(&out, "CK-CTOR-OK");
}

#[test]
fn subtle_crypto_and_crypto_globals_present() {
    let out = run_inline(
        r#"
        if (typeof SubtleCrypto === 'function' && typeof Crypto === 'function')
            console.log('SC-CRYPTO-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SC-CRYPTO-OK");
}

#[test]
fn response_blob_returns_blob_with_content_type() {
    let out = run_inline(
        r#"
        const r = new Response('hello', { headers: { 'content-type': 'text/plain' } });
        r.blob().then(b => {
            if (b instanceof Blob && b.size === 5 && b.type === 'text/plain')
                console.log('RESP-BLOB-OK');
            else console.log('FAIL', b);
        });
        "#,
    );
    assert_marker(&out, "RESP-BLOB-OK");
}
