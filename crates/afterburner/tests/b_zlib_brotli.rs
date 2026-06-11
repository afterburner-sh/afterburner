// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Brotli compression via real pure-Rust codec.
//!
//! Sync round-trip via `zlib.brotliCompressSync` / `brotliDecompressSync`;
//! async round-trip via `zlib.brotliCompress` / `brotliDecompress`;
//! header sniff (brotli stream starts with a window-size + magic byte
//! pattern — we just confirm the bytes aren't the input verbatim and
//! that decompress returns them).

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", src])
        .output()
        .expect("spawn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains(marker),
        "missing `{marker}`\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn brotli_sync_roundtrip() {
    let src = r#"
        const zlib = require('zlib');
        const input = Buffer.from('the quick brown fox jumps over the lazy dog'.repeat(10));
        const compressed = zlib.brotliCompressSync(input);
        if (!Buffer.isBuffer(compressed) && !(compressed instanceof Uint8Array)) {
            console.error('not buffer:', compressed); process.exit(2);
        }
        if (compressed.length >= input.length) {
            console.error('no compression: comp=' + compressed.length + ' in=' + input.length);
            process.exit(3);
        }
        const dec = zlib.brotliDecompressSync(compressed);
        if (Buffer.from(dec).toString('utf8') !== input.toString('utf8')) {
            console.error('roundtrip mismatch'); process.exit(4);
        }
        console.log('BROTLI_SYNC_OK ratio=' + (compressed.length / input.length).toFixed(2));
    "#;
    assert_marker(&run_inline(src), "BROTLI_SYNC_OK");
}

#[test]
#[serial]
fn brotli_async_roundtrip() {
    let src = r#"
        const zlib = require('zlib');
        const input = Buffer.from('async-payload-' + 'x'.repeat(500));
        zlib.brotliCompress(input, (err, comp) => {
            if (err) { console.error('comp err:', err); process.exit(2); }
            zlib.brotliDecompress(comp, (err2, dec) => {
                if (err2) { console.error('dec err:', err2); process.exit(3); }
                if (Buffer.from(dec).toString('utf8') !== input.toString('utf8')) {
                    console.error('mismatch'); process.exit(4);
                }
                console.log('BROTLI_ASYNC_OK');
                process.exit(0);
            });
        });
        setTimeout(() => process.exit(99), 30000);
    "#;
    assert_marker(&run_inline(src), "BROTLI_ASYNC_OK");
}

#[test]
#[serial]
fn brotli_decompress_rejects_garbage() {
    let src = r#"
        const zlib = require('zlib');
        let threw = false;
        try {
            zlib.brotliDecompressSync(Buffer.from('this is not valid brotli'));
        } catch (e) {
            threw = true;
        }
        if (!threw) { console.error('expected throw'); process.exit(2); }
        console.log('BROTLI_REJECT_OK');
    "#;
    assert_marker(&run_inline(src), "BROTLI_REJECT_OK");
}
