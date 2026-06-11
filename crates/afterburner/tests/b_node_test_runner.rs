// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `node:test` + `node:sqlite` real-runner tests.
//!
//! `node:test` collects describe/it/before/after blocks, runs them
//! synchronously through their async bodies, and emits TAP-shaped
//! output. Tests verify ordering, skip / todo handling, async pass,
//! sub-suite indentation, and exit-code-1 on failure.
//!
//! `node:sqlite` is the Node 22+ built-in (distinct from the L3
//! `sqlite3` shadow npm package). DatabaseSync.exec / prepare /
//! statement.run / get / all round-trip through the same rusqlite
//! host fns the L3 shadow uses.

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

// ---- node:test ------------------------------------------------------

#[test]
fn node_test_describe_it_emits_tap_pass_lines() {
    let out = run_inline(
        r#"
        const { describe, it } = require('node:test');
        const assert = require('assert');
        describe('arithmetic', () => {
            it('two plus two', () => assert.strictEqual(2 + 2, 4));
            it('three by three', () => assert.strictEqual(3 * 3, 9));
        });
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(stdout.contains("# Subtest: arithmetic"));
    assert!(stdout.contains("ok 1 - two plus two"));
    assert!(stdout.contains("ok 2 - three by three"));
    assert!(stdout.contains("# pass: 2"));
    assert!(stdout.contains("# fail: 0"));
}

#[test]
fn node_test_skipped_test_marked_skip_in_summary() {
    let out = run_inline(
        r#"
        const { it } = require('node:test');
        it('runs', () => {});
        it('skipped', { skip: true }, () => { throw new Error('should not run'); });
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok 2 - skipped # SKIP"), "{stdout}");
    assert!(stdout.contains("# skip: 1"), "{stdout}");
}

#[test]
fn node_test_failing_test_emits_not_ok_and_exits_1() {
    let out = run_inline(
        r#"
        const { it } = require('node:test');
        const assert = require('assert');
        it('passing', () => {});
        it('failing', () => assert.strictEqual(1, 2));
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let code = out.status.code().unwrap_or(0);
    assert_eq!(code, 1, "expected exit 1 on test failure: {stdout}");
    assert!(stdout.contains("not ok 2 - failing"), "{stdout}");
    assert!(stdout.contains("# fail: 1"), "{stdout}");
}

#[test]
fn node_test_async_test_awaited_before_pass_recorded() {
    let out = run_inline(
        r#"
        const { it } = require('node:test');
        it('async pass', async () => {
            await Promise.resolve();
            await new Promise(r => setTimeout(r, 1));
        });
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(stdout.contains("ok 1 - async pass"), "{stdout}");
    assert!(stdout.contains("# pass: 1"), "{stdout}");
}

#[test]
fn node_test_before_each_runs_before_each_test() {
    let out = run_inline(
        r#"
        const { describe, it, beforeEach } = require('node:test');
        const assert = require('assert');
        let counter = 0;
        describe('hooks', () => {
            beforeEach(() => { counter++; });
            it('first', () => assert.strictEqual(counter, 1));
            it('second', () => assert.strictEqual(counter, 2));
            it('third', () => assert.strictEqual(counter, 3));
        });
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(stdout.contains("# pass: 3"), "{stdout}");
    assert!(stdout.contains("# fail: 0"), "{stdout}");
}

#[test]
fn node_test_test_default_export_is_callable_and_namespaced() {
    let out = run_inline(
        r#"
        const test = require('node:test');
        test('top-level', () => {});
        test.describe('inner', () => {
            test.it('nested', () => {});
        });
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(stdout.contains("# pass: 2"), "{stdout}");
}

// ---- node:sqlite ----------------------------------------------------

#[cfg(feature = "shadow-sqlite3")]
#[test]
fn node_sqlite_database_sync_round_trips_rows() {
    let out = run_inline(
        r#"
        const { DatabaseSync } = require('node:sqlite');
        const db = new DatabaseSync(':memory:');
        db.exec('CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)');
        const ins = db.prepare('INSERT INTO t(name) VALUES (?)');
        const r1 = ins.run('alpha');
        const r2 = ins.run('beta');
        if (r1.lastInsertRowid !== 1 || r2.lastInsertRowid !== 2) {
            console.log('FAIL rowid', r1.lastInsertRowid, r2.lastInsertRowid);
            process.exit(1);
        }
        const all = db.prepare('SELECT * FROM t ORDER BY id').all();
        if (all.length !== 2 || all[0].name !== 'alpha' || all[1].name !== 'beta') {
            console.log('FAIL all', JSON.stringify(all));
            process.exit(1);
        }
        const one = db.prepare('SELECT * FROM t WHERE name=?').get('beta');
        if (one.id !== 2) {
            console.log('FAIL one', JSON.stringify(one));
            process.exit(1);
        }
        db.close();
        if (db.isOpen()) { console.log('FAIL still open'); process.exit(1); }
        console.log('SQLITE-OK');
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(stdout.contains("SQLITE-OK"), "{stdout}");
}

#[cfg(feature = "shadow-sqlite3")]
#[test]
fn node_sqlite_statement_iterate_yields_rows() {
    let out = run_inline(
        r#"
        const { DatabaseSync } = require('node:sqlite');
        const db = new DatabaseSync(':memory:');
        db.exec('CREATE TABLE n(x INTEGER)');
        db.exec('INSERT INTO n VALUES (1),(2),(3)');
        const stmt = db.prepare('SELECT x FROM n ORDER BY x');
        const xs = [];
        for (const r of stmt.iterate()) xs.push(r.x);
        if (xs.join(',') === '1,2,3') console.log('ITER-OK');
        else console.log('ITER-FAIL', xs);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ITER-OK"), "{stdout}");
}

// ---- node:diagnostics_channel ---------------------------------------

#[test]
fn diagnostics_channel_publish_and_subscribe() {
    let out = run_inline(
        r#"
        const dc = require('node:diagnostics_channel');
        const ch = dc.channel('burn:test');
        let received = null;
        const onMessage = (msg, name) => { received = { msg: msg, name: name }; };
        dc.subscribe('burn:test', onMessage);
        if (!ch.hasSubscribers) { console.log('FAIL no-subs'); process.exit(1); }
        ch.publish({ k: 1 });
        if (received && received.msg.k === 1 && received.name === 'burn:test') {
            console.log('DC-OK');
        } else {
            console.log('FAIL received', JSON.stringify(received));
        }
        dc.unsubscribe('burn:test', onMessage);
        if (ch.hasSubscribers) { console.log('FAIL still-subs'); process.exit(1); }
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DC-OK"), "{stdout}");
}

#[test]
fn diagnostics_channel_tracing_channel_emits_lifecycle() {
    let out = run_inline(
        r#"
        const dc = require('node:diagnostics_channel');
        const tc = dc.tracingChannel('burn:tx');
        const events = [];
        dc.subscribe('burn:tx:start', () => events.push('start'));
        dc.subscribe('burn:tx:end',   () => events.push('end'));
        const result = tc.traceSync(() => 42, {});
        if (result === 42 && events.join(',') === 'start,end') console.log('TRACE-OK');
        else console.log('FAIL', result, events.join(','));
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TRACE-OK"), "{stdout}");
}
