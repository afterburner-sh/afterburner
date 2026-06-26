// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Phase 0 / Gap A regression: `require('stream')` returns a callable
//! `Stream` constructor with `Readable`/`Writable`/etc. attached as own
//! properties - matching Node's dual-shape contract.
//!
//! Real npm packages depend on this. `send/index.js` (transitively
//! required by `express` → `serve-static`) does
//! `util.inherits(SendStream, Stream)`. Our `util.inherits` rejects a
//! non-callable `superCtor` with a `TypeError` (polyfills/util.js:73),
//! so a plain-object `module.exports` would crash module init.
//!
//! Coverage:
//!   * `typeof require('stream') === 'function'` - the callable contract.
//!   * `Stream.Readable`, `Stream.Writable`, `Stream.Duplex`,
//!     `Stream.Transform`, `Stream.PassThrough`, `Stream.pipeline`,
//!     `Stream.finished`, `Stream.compose`, `Stream.addAbortSignal`,
//!     `Stream.Stream` are all reachable as own properties.
//!   * `util.inherits(Sub, require('stream'))` does not throw.
//!   * Stream-derived instances mix in `EventEmitter` (`.on`, `.emit`).
//!   * Existing consumers - `Readable.from([...])`, `pipeline(...)`,
//!     `addAbortSignal(...)`, `stream/promises.pipeline` - keep working
//!     (the `exports` namespace is still populated).
//!   * `tty.ReadStream` (which calls `stream.Readable.call(this, ...)`)
//!     still constructs cleanly - proves we didn't break the
//!     `Readable.call(this)` callable-from-prototype pattern.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_burn(source: &str) -> std::process::Output {
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

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} FAILED\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn stream_module_is_callable() {
    let out = run_burn(
        r#"
        const Stream = require('stream');
        if (typeof Stream !== 'function') {
            throw new Error('require("stream") must be a function, got ' + typeof Stream);
        }
        console.log('ok callable');
        "#,
    );
    assert_ok(&out, "require('stream') callable");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok callable"), "stdout = {stdout:?}");
}

#[test]
fn stream_carries_all_subexports() {
    let out = run_burn(
        r#"
        const Stream = require('stream');
        const expected = [
            'Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough',
            'pipeline', 'finished', 'compose', 'addAbortSignal', 'Stream',
        ];
        for (const name of expected) {
            if (Stream[name] === undefined) {
                throw new Error('Stream.' + name + ' is undefined');
            }
        }
        // Self-reference matches Node's behavior.
        if (Stream.Stream !== Stream) throw new Error('Stream.Stream !== Stream');
        console.log('ok subexports');
        "#,
    );
    assert_ok(&out, "Stream sub-exports");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok subexports"), "stdout = {stdout:?}");
}

#[test]
fn stream_round_trips_via_node_prefix_and_bare() {
    let out = run_burn(
        r#"
        const a = require('stream');
        const b = require('node:stream');
        if (a !== b) throw new Error('node:stream and stream resolve to different exports');
        if (a.Readable !== b.Readable) throw new Error('Stream.Readable mismatch');
        console.log('ok parity');
        "#,
    );
    assert_ok(&out, "node:stream parity");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok parity"), "stdout = {stdout:?}");
}

#[test]
fn util_inherits_with_stream_as_super_works() {
    // The exact pattern `send/index.js:173` uses.
    let out = run_burn(
        r#"
        const Stream = require('stream');
        const util = require('util');
        function Sub() { Stream.call(this); }
        util.inherits(Sub, Stream);
        const s = new Sub();
        if (typeof s.on !== 'function')    throw new Error('Sub instance missing .on');
        if (typeof s.emit !== 'function')  throw new Error('Sub instance missing .emit');
        if (typeof s.pipe !== 'function')  throw new Error('Sub instance missing .pipe');
        if (Sub.super_ !== Stream)         throw new Error('Sub.super_ !== Stream');
        console.log('ok inherits');
        "#,
    );
    assert_ok(&out, "util.inherits(Sub, Stream)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok inherits"), "stdout = {stdout:?}");
}

#[test]
fn stream_emits_events_after_inherits() {
    // EventEmitter mix-in must be live: a consumer that does
    // Stream.call(this) then .on(...).emit(...) round-trips an event.
    let out = run_burn(
        r#"
        const Stream = require('stream');
        const util = require('util');
        function Tap() { Stream.call(this); }
        util.inherits(Tap, Stream);
        const t = new Tap();
        let saw = null;
        t.on('boop', (n) => { saw = n; });
        t.emit('boop', 42);
        if (saw !== 42) throw new Error('event roundtrip failed; saw=' + saw);
        console.log('ok events');
        "#,
    );
    assert_ok(&out, "Stream EventEmitter mix-in");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok events"), "stdout = {stdout:?}");
}

#[test]
fn readable_from_iterable_still_works() {
    // Regression: `Readable.from([...])` was the pre-change canonical
    // entry point. Must keep working - the `exports.Readable` slot is
    // still populated and `Stream.Readable` aliases it.
    let out = run_burn(
        r#"
        const { Readable } = require('stream');
        const r = Readable.from([1, 2, 3]);
        const out = [];
        r.on('data', (c) => out.push(c));
        r.on('end', () => console.log('sum=' + out.reduce((a, b) => a + b, 0)));
        "#,
    );
    assert_ok(&out, "Readable.from regression");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sum=6"), "stdout = {stdout:?}");
}

#[test]
fn stream_promises_subpath_unaffected() {
    // `node:stream/promises` was registered as its own factory and
    // re-exports `pipeline` / `finished` from the base module. Our
    // change must not regress that subpath.
    let out = run_burn(
        r#"
        const sp = require('stream/promises');
        if (typeof sp.pipeline !== 'function') throw new Error('sp.pipeline missing');
        if (typeof sp.finished !== 'function') throw new Error('sp.finished missing');
        console.log('ok subpath');
        "#,
    );
    assert_ok(&out, "stream/promises regression");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok subpath"), "stdout = {stdout:?}");
}

#[test]
fn tty_readstream_construction_unaffected() {
    // Regression - `polyfills/tty.js` does
    // `if (typeof stream.Readable === 'function') stream.Readable.call(this, options);`
    // followed by `Object.create(stream.Readable.prototype)`. The
    // dual-shape change leaves `stream.Readable` populated, so this
    // path must still construct without error.
    let out = run_burn(
        r#"
        const tty = require('tty');
        const r = new tty.ReadStream(0);
        if (r.fd !== 0) throw new Error('fd not set: ' + r.fd);
        if (r.isTTY !== false) throw new Error('isTTY should be false in sandbox');
        if (typeof r.setRawMode !== 'function') throw new Error('setRawMode missing');
        console.log('ok tty');
        "#,
    );
    assert_ok(&out, "tty.ReadStream regression");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok tty"), "stdout = {stdout:?}");
}
