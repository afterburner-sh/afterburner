// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Round-5 crypto fills:
//! - `crypto.createHash('shake128'|'shake256')` real XOF output
//! - `crypto.checkPrime` / `checkPrimeSync` Miller-Rabin
//! - `crypto.generatePrime` / `generatePrimeSync`
//! - `events.EventEmitterAsyncResource`
//! - `tty.WriteStream.hasColors` honouring `FORCE_COLOR` / `NO_COLOR`

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn run_with_env(src: &str, env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(BURN);
    cmd.env("BURN_QUIET", "1").arg("-A").arg("-e").arg(src);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed.\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

// ---- SHAKE ----------------------------------------------------------

#[test]
fn shake256_default_output_is_32_bytes_64_hex() {
    let out = run(r#"
        const c = require('crypto');
        const h = c.createHash('shake256');
        h.update('abc');
        const d = h.digest('hex');
        if (d.length === 64) console.log('SHAKE256-LEN-OK');
        else console.log('FAIL ' + d.length);
    "#);
    assert_marker(&out, "SHAKE256-LEN-OK");
}

#[test]
fn shake128_default_output_is_16_bytes_32_hex() {
    let out = run(r#"
        const c = require('crypto');
        const h = c.createHash('shake128');
        h.update('abc');
        const d = h.digest('hex');
        if (d.length === 32) console.log('SHAKE128-LEN-OK');
        else console.log('FAIL ' + d.length);
    "#);
    assert_marker(&out, "SHAKE128-LEN-OK");
}

#[test]
fn shake256_chunked_input_matches_one_shot() {
    let out = run(r#"
        const c = require('crypto');
        const a = c.createHash('shake256');
        a.update('the quick brown fox jumps over the lazy dog');
        const oneshot = a.digest('hex');
        const b = c.createHash('shake256');
        b.update('the quick ');
        b.update('brown fox jumps ');
        b.update('over the lazy dog');
        if (b.digest('hex') === oneshot) console.log('SHAKE256-STREAM-OK');
        else console.log('FAIL streamed-vs-oneshot');
    "#);
    assert_marker(&out, "SHAKE256-STREAM-OK");
}

#[test]
fn shake256_listed_in_get_hashes() {
    let out = run(r#"
        const c = require('crypto');
        const list = c.getHashes();
        if (list.indexOf('shake128') >= 0 && list.indexOf('shake256') >= 0)
            console.log('SHAKE-IN-LIST-OK');
    "#);
    assert_marker(&out, "SHAKE-IN-LIST-OK");
}

// ---- checkPrime -----------------------------------------------------

#[test]
fn check_prime_recognises_small_known_primes() {
    let out = run(r#"
        const { checkPrimeSync } = require('crypto');
        const primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 97, 1009, 7919];
        const fails = primes.filter(p => !checkPrimeSync(BigInt(p)));
        if (fails.length === 0) console.log('CHECK-PRIME-OK');
        else console.log('FAIL', fails);
    "#);
    assert_marker(&out, "CHECK-PRIME-OK");
}

#[test]
fn check_prime_recognises_carmichael_561_as_composite() {
    let out = run(r#"
        const { checkPrimeSync } = require('crypto');
        if (checkPrimeSync(561n) === false) console.log('CARMICHAEL-OK');
    "#);
    assert_marker(&out, "CARMICHAEL-OK");
}

#[test]
fn check_prime_async_callback_form_returns_result() {
    let out = run(r#"
        const { checkPrime } = require('crypto');
        checkPrime(7n, (err, ok) => {
            if (err) { console.log('FAIL', err.message); return; }
            if (ok === true) console.log('CHECK-PRIME-ASYNC-OK');
        });
    "#);
    assert_marker(&out, "CHECK-PRIME-ASYNC-OK");
}

#[test]
fn check_prime_accepts_buffer_be_bytes() {
    let out = run(r#"
        const { checkPrimeSync } = require('crypto');
        // 0x07 is 7, prime
        if (checkPrimeSync(Buffer.from([7]))) console.log('CHECK-PRIME-BUFFER-OK');
    "#);
    assert_marker(&out, "CHECK-PRIME-BUFFER-OK");
}

// ---- generatePrime --------------------------------------------------

#[test]
fn generate_prime_returns_bigint_at_target_size() {
    let out = run(r#"
        const c = require('crypto');
        const p = c.generatePrimeSync(64);
        if (typeof p === 'bigint' && c.checkPrimeSync(p) === true)
            console.log('GEN-PRIME-OK');
        else console.log('FAIL', typeof p, p);
    "#);
    assert_marker(&out, "GEN-PRIME-OK");
}

#[test]
fn generate_prime_buffer_form_returns_be_bytes() {
    let out = run(r#"
        const c = require('crypto');
        const buf = c.generatePrimeSync(64, { bigint: false });
        if (Buffer.isBuffer(buf) && buf.length > 0) console.log('GEN-PRIME-BUF-OK');
        else console.log('FAIL', buf);
    "#);
    assert_marker(&out, "GEN-PRIME-BUF-OK");
}

#[test]
fn generate_safe_prime_has_safe_property() {
    let out = run(r#"
        const c = require('crypto');
        const p = c.generatePrimeSync(32, { safe: true });
        if (typeof p !== 'bigint') { console.log('FAIL not bigint'); return; }
        const half = (p - 1n) / 2n;
        // For 32-bit primes both should pass with high probability via Miller-Rabin.
        if (c.checkPrimeSync(p) && c.checkPrimeSync(half)) console.log('SAFE-PRIME-OK');
        else console.log('FAIL safe property');
    "#);
    assert_marker(&out, "SAFE-PRIME-OK");
}

#[test]
fn generate_prime_async_callback_form() {
    let out = run(r#"
        const c = require('crypto');
        c.generatePrime(64, (err, p) => {
            if (err) { console.log('FAIL', err.message); return; }
            if (typeof p === 'bigint' && c.checkPrimeSync(p)) console.log('GEN-PRIME-ASYNC-OK');
        });
    "#);
    assert_marker(&out, "GEN-PRIME-ASYNC-OK");
}

// ---- EventEmitterAsyncResource --------------------------------------

#[test]
fn event_emitter_async_resource_is_a_class_with_emit_proxy() {
    let out = run(r#"
        const { EventEmitterAsyncResource } = require('events');
        const e = new EventEmitterAsyncResource({ name: 'TEST' });
        let got = null;
        e.on('msg', (m) => { got = m; });
        e.emit('msg', 'hello');
        if (got === 'hello' && typeof e.asyncId === 'number'
            && typeof e.triggerAsyncId === 'number'
            && e.asyncResource && typeof e.asyncResource.runInAsyncScope === 'function')
            console.log('EE-ASYNC-RES-OK');
        else console.log('FAIL', got, typeof e.asyncId);
    "#);
    assert_marker(&out, "EE-ASYNC-RES-OK");
}

#[test]
fn event_emitter_async_resource_accepts_no_options() {
    let out = run(r#"
        const { EventEmitterAsyncResource } = require('events');
        const e = new EventEmitterAsyncResource();
        let fired = false;
        e.on('x', () => { fired = true; });
        e.emit('x');
        if (fired) console.log('EE-ASYNC-NOOPTS-OK');
    "#);
    assert_marker(&out, "EE-ASYNC-NOOPTS-OK");
}

#[test]
fn event_emitter_async_resource_inherits_event_emitter_methods() {
    let out = run(r#"
        const { EventEmitterAsyncResource, EventEmitter } = require('events');
        const e = new EventEmitterAsyncResource({ name: 'X' });
        if (e instanceof EventEmitter && typeof e.once === 'function'
            && typeof e.removeListener === 'function')
            console.log('EE-ASYNC-INHERIT-OK');
    "#);
    assert_marker(&out, "EE-ASYNC-INHERIT-OK");
}

// ---- tty.hasColors honours env --------------------------------------

#[test]
fn tty_has_colors_returns_true_with_force_color_3() {
    let out = run_with_env(
        r#"
        const tty = require('tty');
        const ws = new tty.WriteStream(1);
        if (ws.hasColors() === true && ws.hasColors(16) === true
            && ws.hasColors(256) === true && ws.hasColors(16777216) === true)
            console.log('FORCE3-OK');
        else console.log('FAIL', ws.getColorDepth());
    "#,
        &[("FORCE_COLOR", "3")],
    );
    assert_marker(&out, "FORCE3-OK");
}

#[test]
fn tty_has_colors_no_color_overrides_force_color() {
    let out = run_with_env(
        r#"
        const tty = require('tty');
        const ws = new tty.WriteStream(1);
        if (ws.hasColors() === false && ws.getColorDepth() === 1) console.log('NO-COLOR-OK');
    "#,
        &[("NO_COLOR", "1"), ("FORCE_COLOR", "3")],
    );
    assert_marker(&out, "NO-COLOR-OK");
}

#[test]
fn tty_has_colors_truecolor_via_colorterm() {
    let out = run_with_env(
        r#"
        const tty = require('tty');
        const ws = new tty.WriteStream(1);
        if (ws.getColorDepth() === 24) console.log('TRUECOLOR-OK');
    "#,
        &[("COLORTERM", "truecolor")],
    );
    assert_marker(&out, "TRUECOLOR-OK");
}

#[test]
fn tty_has_colors_dumb_term_returns_one_bit() {
    let out = run_with_env(
        r#"
        const tty = require('tty');
        const ws = new tty.WriteStream(1);
        if (ws.getColorDepth() === 1 && ws.hasColors() === false)
            console.log('DUMB-OK');
    "#,
        &[("TERM", "dumb")],
    );
    assert_marker(&out, "DUMB-OK");
}

#[test]
fn tty_has_colors_xterm_256color() {
    let out = run_with_env(
        r#"
        const tty = require('tty');
        const ws = new tty.WriteStream(1);
        if (ws.getColorDepth() === 8 && ws.hasColors(256) === true) console.log('256-OK');
    "#,
        &[("TERM", "xterm-256color")],
    );
    assert_marker(&out, "256-OK");
}

#[test]
fn process_stdout_has_colors_proxies_to_tty() {
    let out = run_with_env(
        r#"
        if (process.stdout.hasColors() === true && process.stdout.getColorDepth() >= 4)
            console.log('STDOUT-OK');
    "#,
        &[("FORCE_COLOR", "1")],
    );
    assert_marker(&out, "STDOUT-OK");
}
