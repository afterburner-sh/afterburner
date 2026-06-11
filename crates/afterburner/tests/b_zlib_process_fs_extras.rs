// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `zlib.crc32` (Node 22.2+), `zlib.brotli{Compress,Decompress}` async
//! wrappers, `process.uptime` / `kill` / `dlopen` /
//! `allowedNodeEnvironmentFlags` / `features` / `config` / `release`,
//! and `fs.realpathSync.native` / `fs.promises.statfs`.

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
fn zlib_crc32_known_vectors() {
    // Test against known IEEE CRC32 values:
    //   "" -> 0
    //   "a" -> 0xe8b7be43
    //   "123456789" -> 0xcbf43926
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        if (zlib.crc32('') === 0 &&
            zlib.crc32('a') === 0xe8b7be43 &&
            zlib.crc32('123456789') === 0xcbf43926)
            console.log('CRC32-OK');
        else console.log('FAIL', zlib.crc32(''), zlib.crc32('a').toString(16), zlib.crc32('123456789').toString(16));
        "#,
    );
    assert_marker(&out, "CRC32-OK");
}

#[test]
fn zlib_crc32_chains_with_seed() {
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        // CRC32('foobar') should equal CRC32('bar', CRC32('foo'))
        const a = zlib.crc32('foobar');
        const b = zlib.crc32('bar', zlib.crc32('foo'));
        if (a === b) console.log('CRC32-CHAIN-OK');
        else console.log('FAIL', a.toString(16), b.toString(16));
        "#,
    );
    assert_marker(&out, "CRC32-CHAIN-OK");
}

#[test]
fn zlib_brotli_compress_async_round_trips() {
    // `zlib.brotliCompress` + `brotliDecompress` are real now -
    // earlier rounds returned `ERR_BROTLI_INVALID_PARAM` as a stub.
    // Pin the working contract: compressed bytes decompress to input.
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        zlib.brotliCompress('hello world', (err, compressed) => {
            if (err) { console.log('FAIL compress:', err.message); return; }
            zlib.brotliDecompress(compressed, (e2, plain) => {
                if (e2) { console.log('FAIL decompress:', e2.message); return; }
                const s = Buffer.isBuffer(plain) ? plain.toString('utf8') : String(plain);
                if (s === 'hello world') console.log('BR-OK');
                else console.log('FAIL roundtrip:', JSON.stringify(s));
            });
        });
        "#,
    );
    assert_marker(&out, "BR-OK");
}

#[test]
fn process_uptime_returns_positive_number() {
    let out = run_inline(
        r#"
        if (typeof process.uptime === 'function' && process.uptime() >= 0)
            console.log('UP-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "UP-OK");
}

#[test]
fn process_kill_with_self_pid_succeeds() {
    let out = run_inline(
        r#"
        const r = process.kill(process.pid, 0);
        if (r === true) console.log('KILL-OK');
        else console.log('FAIL', r);
        "#,
    );
    assert_marker(&out, "KILL-OK");
}

#[test]
fn process_dlopen_throws_disabled_in_sandbox() {
    let out = run_inline(
        r#"
        try { process.dlopen({}, 'fake.node', 0); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_DLOPEN_DISABLED') console.log('DL-OK'); else console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "DL-OK");
}

#[test]
fn process_allowed_node_environment_flags_is_set() {
    let out = run_inline(
        r#"
        const f = process.allowedNodeEnvironmentFlags;
        if (f instanceof Set && f.has('--enable-source-maps')) console.log('FLAGS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "FLAGS-OK");
}

#[test]
fn process_features_and_release_present() {
    let out = run_inline(
        r#"
        if (process.features && process.features.tls === true &&
            process.release && process.release.name === 'node')
            console.log('FEAT-REL-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "FEAT-REL-OK");
}

#[test]
fn process_config_has_target_and_variables() {
    let out = run_inline(
        r#"
        const c = process.config;
        if (c && c.target_defaults && c.variables && c.variables.target_arch)
            console.log('CONF-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CONF-OK");
}

#[test]
fn fs_realpath_sync_native_alias_works() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        const a = fs.realpathSync('.');
        const b = fs.realpathSync.native('.');
        if (a === b && typeof a === 'string') console.log('RPN-OK');
        else console.log('FAIL', a, b);
        "#,
    );
    assert_marker(&out, "RPN-OK");
}

#[test]
fn fs_promises_statfs_resolves() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        fs.promises.statfs('.').then(s => {
            if (s && typeof s.bsize === 'number') console.log('STATFS-OK');
            else console.log('FAIL', s);
        }).catch(e => console.log('FAIL err', e.message));
        "#,
    );
    assert_marker(&out, "STATFS-OK");
}
