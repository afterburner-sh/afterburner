// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `events.once` / `on` / `getEventListeners` / `setMaxListeners` /
//! `captureRejectionSymbol` / `errorMonitor`. `buffer.constants` /
//! `transcode` / `atob` / `btoa` / `SlowBuffer`. `stream.duplexPair`
//! / `stream.promises`. All Node-module-level fills.

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

// ---- events --------------------------------------------------------

#[test]
fn events_once_resolves_to_emitted_args() {
    let out = run_inline(
        r#"
        async function main() {
            const EE = require('events');
            const ee = new EE();
            setTimeout(() => ee.emit('hi', 1, 'x'), 10);
            const args = await EE.once(ee, 'hi');
            if (args.length === 2 && args[0] === 1 && args[1] === 'x') console.log('ONCE-OK');
            else console.log('FAIL', JSON.stringify(args));
        }
        main();
        "#,
    );
    assert_marker(&out, "ONCE-OK");
}

#[test]
fn events_once_rejects_on_emitted_error() {
    let out = run_inline(
        r#"
        async function main() {
            const EE = require('events');
            const ee = new EE();
            setTimeout(() => ee.emit('error', new Error('bang')), 10);
            try {
                await EE.once(ee, 'tick');
                console.log('FAIL no-throw');
            } catch (e) {
                if (e.message === 'bang') console.log('ONCE-ERR-OK');
                else console.log('FAIL', e.message);
            }
        }
        main();
        "#,
    );
    assert_marker(&out, "ONCE-ERR-OK");
}

#[test]
fn events_on_async_iter_yields_emitted_args() {
    let out = run_inline(
        r#"
        async function main() {
            const EE = require('events');
            const ee = new EE();
            setTimeout(() => { ee.emit('tick', 1); ee.emit('tick', 2); ee.emit('tick', 3); }, 10);
            const ac = new AbortController();
            setTimeout(() => ac.abort(), 80);
            const collected = [];
            try {
                for await (const args of EE.on(ee, 'tick', { signal: ac.signal })) {
                    collected.push(args[0]);
                    if (collected.length === 3) break;
                }
            } catch (_) {}
            if (collected.join(',') === '1,2,3') console.log('ON-ITER-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "ON-ITER-OK");
}

#[test]
fn events_capture_rejection_symbol_is_a_well_known_symbol() {
    let out = run_inline(
        r#"
        const EE = require('events');
        if (typeof EE.captureRejectionSymbol === 'symbol' &&
            typeof EE.errorMonitor === 'symbol' &&
            EE.captureRejectionSymbol === Symbol.for('nodejs.rejection')) {
            console.log('SYM-OK');
        } else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SYM-OK");
}

// ---- buffer ---------------------------------------------------------

#[test]
fn buffer_module_constants_match_k_max_length() {
    let out = run_inline(
        r#"
        const buf = require('buffer');
        if (buf.constants && buf.constants.MAX_LENGTH === 0x7fffffff &&
            typeof buf.constants.MAX_STRING_LENGTH === 'number')
            console.log('CONST-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CONST-OK");
}

#[test]
fn buffer_module_atob_and_btoa_round_trip() {
    let out = run_inline(
        r#"
        const buf = require('buffer');
        const enc = buf.btoa('Hello World');
        const dec = buf.atob(enc);
        if (dec === 'Hello World') console.log('AB-OK');
        else console.log('FAIL', enc, dec);
        "#,
    );
    assert_marker(&out, "AB-OK");
}

#[test]
fn buffer_transcode_utf8_to_latin1() {
    let out = run_inline(
        r#"
        const buf = require('buffer');
        const utf8 = Buffer.from('Hello', 'utf8');
        const latin = buf.transcode(utf8, 'utf-8', 'latin1');
        if (latin.toString('latin1') === 'Hello') console.log('TRANSCODE-OK');
        else console.log('FAIL', latin.toString('latin1'));
        "#,
    );
    assert_marker(&out, "TRANSCODE-OK");
}

#[test]
fn buffer_slow_buffer_returns_buffer() {
    let out = run_inline(
        r#"
        const buf = require('buffer');
        const sb = buf.SlowBuffer(32);
        if (Buffer.isBuffer(sb) && sb.length === 32) console.log('SLOW-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SLOW-OK");
}

// ---- stream --------------------------------------------------------

#[test]
fn stream_duplex_pair_returns_two_connected_streams() {
    let out = run_inline(
        r#"
        const stream = require('stream');
        const pair = stream.duplexPair();
        if (Array.isArray(pair) && pair.length === 2 &&
            typeof pair[0].pipe === 'function' && typeof pair[1].pipe === 'function')
            console.log('PAIR-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "PAIR-OK");
}

#[test]
fn stream_promises_pipeline_resolves_promise() {
    let out = run_inline(
        r#"
        async function main() {
            const stream = require('stream');
            const collected = [];
            await stream.promises.pipeline(
                stream.Readable.from(['a', 'b', 'c']),
                new stream.Writable({
                    write(chunk, _enc, cb) { collected.push(chunk.toString()); cb(); },
                }),
            );
            if (collected.join(',') === 'a,b,c') console.log('PROM-PIPELINE-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "PROM-PIPELINE-OK");
}
