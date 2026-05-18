// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Streaming zlib classes — `Gzip` / `Gunzip` / `Deflate` / `Inflate`.
//!
//! Pacote / minizlib / tar all wrap one of these and call
//! `.write(chunk)` + `.end()` then collect the `data` chunks. Without
//! the streaming class shape every `npm install` tarball extraction
//! crashes at module-init with `zlib: not a function`. The class
//! sits on top of the existing sync codecs (one host call per
//! buffered input); for our async-HTTP body which arrives as one
//! chunk that's identical to the streaming case anyway.

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
fn gunzip_class_round_trips_via_event_emitter() {
    // The minimum shape minizlib / pacote / tar reach for: an
    // EventEmitter-style streaming codec. write(chunk) queues input,
    // end() runs the codec and emits 'data' + 'end'.
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        const data = Buffer.from('Hello, World! '.repeat(100));
        const compressed = zlib.gzipSync(data);
        const g = zlib.createGunzip();
        let collected = Buffer.alloc(0);
        g.on('data', chunk => { collected = Buffer.concat([collected, chunk]); });
        g.on('end', () => {
            if (collected.toString('utf8') === data.toString('utf8')) console.log('GUNZIP-OK');
            else console.log('MISMATCH:', collected.length, 'vs', data.length);
            process.exit(0);
        });
        g.on('error', e => { console.log('ERR:', e.message); process.exit(1); });
        g.end(compressed);
        "#,
    );
    assert_marker(&out, "GUNZIP-OK");
}

#[test]
fn gzip_then_gunzip_roundtrip() {
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        const original = Buffer.from('the quick brown fox '.repeat(50));
        // Pipe through Gzip, then Gunzip
        const gz = zlib.createGzip();
        let compressed = Buffer.alloc(0);
        gz.on('data', c => { compressed = Buffer.concat([compressed, c]); });
        gz.on('end', () => {
            const gu = zlib.createGunzip();
            let final_ = Buffer.alloc(0);
            gu.on('data', c => { final_ = Buffer.concat([final_, c]); });
            gu.on('end', () => {
                if (final_.toString('utf8') === original.toString('utf8')) console.log('ROUNDTRIP-OK');
                else console.log('FAIL: ' + final_.length + ' vs ' + original.length);
                process.exit(0);
            });
            gu.end(compressed);
        });
        gz.on('error', e => { console.log('ERR:', e.message); process.exit(1); });
        gz.end(original);
        "#,
    );
    assert_marker(&out, "ROUNDTRIP-OK");
}

#[test]
fn gunzip_process_chunk_handles_empty_finalize() {
    // minizlib's flow calls _processChunk with the data chunk first
    // then with an empty buffer (Z_FINISH flush). Our zlib host
    // would synchronously throw "unexpected end of file" on the
    // empty input — the polyfill short-circuits empty → empty.
    // Without this, every npm install tarball extraction crashed
    // immediately after the first chunk.
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        const data = Buffer.from('hello empty-finalize');
        const compressed = zlib.gzipSync(data);
        const inst = new zlib.Gunzip({});
        const decoded = inst._processChunk(compressed, 4 /* Z_FINISH */);
        if (decoded.toString('utf8') !== 'hello empty-finalize') {
            console.log('FAIL decoded:', decoded.toString('utf8'));
            process.exit(1);
        }
        // Now the canary call — empty buffer must not throw.
        const empty = inst._processChunk(Buffer.alloc(0), 4);
        if (empty.length !== 0) {
            console.log('FAIL empty len:', empty.length);
            process.exit(1);
        }
        console.log('FINALIZE-OK');
        "#,
    );
    assert_marker(&out, "FINALIZE-OK");
}

#[test]
fn url_resolves_relative_against_base() {
    // Reference resolution per RFC 3986 §5.3. Without this, every
    // Location-header redirect (which npm's registry follows for
    // tarball downloads) ends up with an empty host and the
    // upstream HTTP client synthesises a malformed `https:///path`
    // URL.
    let out = run_inline(
        r#"
        const cases = [
            ['/a/b', 'https://h.com/x', 'https://h.com/a/b'],
            ['p', 'https://h.com/dir/page', 'https://h.com/dir/p'],
            ['https://o.com/x', 'https://h.com/y', 'https://o.com/x'],
            ['?q=1', 'https://h.com/x', 'https://h.com/x?q=1'],
        ];
        for (const [href, base, expected] of cases) {
            const got = new URL(href, base).href;
            if (got !== expected) {
                console.log('MISMATCH', JSON.stringify({href, base, expected, got}));
                process.exit(1);
            }
        }
        console.log('URL-RESOLVE-OK');
        "#,
    );
    assert_marker(&out, "URL-RESOLVE-OK");
}

#[test]
fn url_normalizes_dot_segments() {
    // `..` and `.` segments must collapse — RFC 3986 §5.2.4. Without
    // it, redirect chains that include `..` (uncommon but valid)
    // produce paths the upstream rejects.
    let out = run_inline(
        r#"
        const cases = [
            ['../x', 'https://h.com/a/b/c', 'https://h.com/a/x'],
            ['./x', 'https://h.com/a/b/', 'https://h.com/a/b/x'],
            ['../../', 'https://h.com/a/b/c', 'https://h.com/'],
        ];
        for (const [href, base, expected] of cases) {
            const got = new URL(href, base).href;
            if (got !== expected) {
                console.log('MISMATCH', JSON.stringify({href, base, expected, got}));
                process.exit(1);
            }
        }
        console.log('URL-DOTS-OK');
        "#,
    );
    assert_marker(&out, "URL-DOTS-OK");
}
