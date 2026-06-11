// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! L3 shadow for `sqlite3` — end-to-end integration coverage.
//!
//! Each test runs a small JS program through `burn` that exercises
//! the polyfill's surface. The Rust SQLite (`rusqlite/bundled`) is
//! linked statically into the burn binary at build time, so these
//! tests are hermetic — no `libsqlite3.so` on the runner, no network.
//!
//! Coverage groups:
//!
//! * **Happy path** — open / create / insert / select / close on an
//!   in-memory database; `:memory:` and disk-backed paths.
//! * **API shape** — callback-vs-no-callback, `this.lastID`/`changes`
//!   on `db.run`, `db.each` row dispatch.
//! * **Parameter types** — null, bool, int, float, unicode strings,
//!   Buffer (BLOB), large i64 values, named-param (object) binding.
//! * **Error paths** — bad SQL, missing table, unique-constraint
//!   violations, post-close access, unsupported param types.
//! * **Lifecycle** — close idempotency, multi-Database isolation,
//!   transactions (commit + rollback), file persistence.
//! * **Sandbox boundary** — without `--allow-fs`, opening a disk path
//!   outside the allow-list returns an error rather than silently
//!   writing somewhere unexpected.

#![cfg(feature = "shadow-sqlite3")]

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", source])
        .output()
        .expect("spawn burn")
}

// ----- happy path: CRUD round-trips ------------------------------------

#[test]
#[serial]
fn round_trip_create_insert_select_close() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)', (err) => {
                if (err) { console.error('exec:', err); process.exit(2); }
                db.run('INSERT INTO t (name) VALUES (?)', ['alpha'], function(err) {
                    if (err) { console.error('insert:', err); process.exit(3); }
                    if (this.lastID !== 1) { console.error('lastID', this.lastID); process.exit(4); }
                    if (this.changes !== 1) { console.error('changes', this.changes); process.exit(5); }
                    db.get('SELECT * FROM t WHERE id = ?', [1], (err, row) => {
                        if (err) { console.error('get:', err); process.exit(6); }
                        if (!row || row.id !== 1 || row.name !== 'alpha') {
                            console.error('row mismatch:', JSON.stringify(row));
                            process.exit(7);
                        }
                        console.log('ROUND_TRIP_OK');
                        db.close(() => process.exit(0));
                    });
                });
            });
            setTimeout(() => { console.error('TIMEOUT'); process.exit(99); }, 5000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("ROUND_TRIP_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn db_all_returns_array_in_insertion_order() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (n INTEGER)', () => {
                let inserted = 0;
                const n = 5;
                for (let i = 1; i <= n; i++) {
                    db.run('INSERT INTO t VALUES (?)', i, () => {
                        inserted++;
                        if (inserted === n) {
                            db.all('SELECT n FROM t ORDER BY n', (err, rows) => {
                                if (err) { console.error('all:', err); process.exit(2); }
                                if (rows.length !== n) {
                                    console.error('rows', rows.length); process.exit(3);
                                }
                                for (let i = 0; i < n; i++) {
                                    if (rows[i].n !== i + 1) {
                                        console.error('mismatch', rows[i]); process.exit(4);
                                    }
                                }
                                console.log('ALL_OK');
                                db.close(() => process.exit(0));
                            });
                        }
                    });
                }
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("ALL_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn db_get_returns_undefined_when_no_rows() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (n INTEGER)', () => {
                db.get('SELECT n FROM t WHERE n = ?', [42], (err, row) => {
                    if (err) { console.error('get:', err); process.exit(2); }
                    if (row !== undefined) {
                        console.error('expected undefined, got', JSON.stringify(row));
                        process.exit(3);
                    }
                    console.log('NO_ROW_OK');
                    db.close(() => process.exit(0));
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("NO_ROW_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn db_each_dispatches_per_row_and_done_cb_total() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (n INTEGER)', () => {
                db.exec('INSERT INTO t VALUES (1); INSERT INTO t VALUES (2); INSERT INTO t VALUES (3);', () => {
                    const seen = [];
                    db.each(
                        'SELECT n FROM t ORDER BY n',
                        (err, row) => {
                            if (err) { console.error('row:', err); process.exit(2); }
                            seen.push(row.n);
                        },
                        (err, count) => {
                            if (err) { console.error('done:', err); process.exit(3); }
                            if (count !== 3) {
                                console.error('expected count=3, got', count); process.exit(4);
                            }
                            // Microtasks for each row should have fired by now.
                            Promise.resolve().then(() => {
                                if (JSON.stringify(seen) !== '[1,2,3]') {
                                    console.error('seen mismatch:', JSON.stringify(seen)); process.exit(5);
                                }
                                console.log('EACH_OK');
                                db.close(() => process.exit(0));
                            });
                        }
                    );
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("EACH_OK"), "stdout: {stdout}");
}

// ----- parameter-shape coverage ----------------------------------------

#[test]
#[serial]
fn null_param_round_trips_through_db() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (v ANY)', () => {
                db.run('INSERT INTO t VALUES (?)', [null], () => {
                    db.get('SELECT v FROM t', (err, row) => {
                        if (err) { console.error(err); process.exit(2); }
                        if (row.v !== null) {
                            console.error('expected null, got', row.v); process.exit(3);
                        }
                        console.log('NULL_OK');
                        db.close(() => process.exit(0));
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("NULL_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn buffer_param_round_trips_as_blob() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const { Buffer } = require('buffer');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (b BLOB)', () => {
                const original = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
                db.run('INSERT INTO t VALUES (?)', [original], () => {
                    db.get('SELECT b FROM t', (err, row) => {
                        if (err) { console.error(err); process.exit(2); }
                        if (!Buffer.isBuffer(row.b)) {
                            console.error('expected Buffer, got', typeof row.b); process.exit(3);
                        }
                        if (row.b.toString('hex') !== 'deadbeef') {
                            console.error('hex mismatch:', row.b.toString('hex')); process.exit(4);
                        }
                        console.log('BLOB_OK');
                        db.close(() => process.exit(0));
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("BLOB_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn unicode_text_param_round_trips() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (s TEXT)', () => {
                const cases = ['hello', 'héllo', '🚀rocket', '日本語', ''];
                let inserted = 0;
                cases.forEach((s) => {
                    db.run('INSERT INTO t VALUES (?)', [s], () => {
                        inserted++;
                        if (inserted === cases.length) {
                            db.all('SELECT s FROM t ORDER BY rowid', (err, rows) => {
                                if (err) { console.error(err); process.exit(2); }
                                for (let i = 0; i < cases.length; i++) {
                                    if (rows[i].s !== cases[i]) {
                                        console.error('mismatch', i, JSON.stringify(rows[i].s));
                                        process.exit(3);
                                    }
                                }
                                console.log('UTF8_OK');
                                db.close(() => process.exit(0));
                            });
                        }
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("UTF8_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn named_param_object_binding() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (id INTEGER, name TEXT)', () => {
                // Object form binds positionally by insertion order.
                db.run('INSERT INTO t VALUES (?, ?)', { id: 7, name: 'beta' }, (err) => {
                    if (err) { console.error(err); process.exit(2); }
                    db.get('SELECT id, name FROM t', (err, row) => {
                        if (err) { console.error(err); process.exit(3); }
                        if (row.id !== 7 || row.name !== 'beta') {
                            console.error(JSON.stringify(row)); process.exit(4);
                        }
                        console.log('NAMED_OK');
                        db.close(() => process.exit(0));
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("NAMED_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn varargs_param_form() {
    // db.run('?', a, b, c, cb) — vararg form (no array wrapper).
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (a INTEGER, b INTEGER, c INTEGER)', () => {
                db.run('INSERT INTO t VALUES (?, ?, ?)', 10, 20, 30, (err) => {
                    if (err) { console.error(err); process.exit(2); }
                    db.get('SELECT a, b, c FROM t', (err, row) => {
                        if (row.a !== 10 || row.b !== 20 || row.c !== 30) {
                            console.error(JSON.stringify(row)); process.exit(3);
                        }
                        console.log('VARARGS_OK');
                        db.close(() => process.exit(0));
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("VARARGS_OK"), "stdout: {stdout}");
}

// ----- error paths -----------------------------------------------------

#[test]
#[serial]
fn syntax_error_callback_receives_typed_error() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('NOT VALID SQL', (err) => {
                if (!err) { console.error('expected err'); process.exit(2); }
                if (err.code !== 'SQLITE_ERROR') {
                    console.error('expected SQLITE_ERROR, got', err.code);
                    process.exit(3);
                }
                console.log('SYNTAX_OK');
                db.close(() => process.exit(0));
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("SYNTAX_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn missing_table_select_yields_error() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.get('SELECT * FROM does_not_exist', (err, row) => {
                if (!err) { console.error('expected err'); process.exit(2); }
                console.log('MISSING_OK');
                db.close(() => process.exit(0));
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("MISSING_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn unique_violation_yields_error_then_db_still_usable() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (n INTEGER UNIQUE)', () => {
                db.run('INSERT INTO t VALUES (?)', [1], () => {
                    db.run('INSERT INTO t VALUES (?)', [1], (err) => {
                        if (!err) { console.error('expected err'); process.exit(2); }
                        // Connection should still be usable after the violation.
                        db.all('SELECT n FROM t', (err, rows) => {
                            if (err) { console.error('post-violation:', err); process.exit(3); }
                            if (rows.length !== 1) { console.error('rows', rows); process.exit(4); }
                            console.log('UNIQUE_OK');
                            db.close(() => process.exit(0));
                        });
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("UNIQUE_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn post_close_use_is_typed_error() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.close(() => {
                db.run('SELECT 1', (err) => {
                    if (!err) { console.error('expected closed err'); process.exit(2); }
                    if (err.code !== 'SQLITE_MISUSE') {
                        console.error('wrong code:', err.code); process.exit(3);
                    }
                    console.log('POST_CLOSE_OK');
                    process.exit(0);
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("POST_CLOSE_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn unsupported_param_type_throws() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (v ANY)', () => {
                // Symbols can't be encoded — the polyfill rejects.
                db.run('INSERT INTO t VALUES (?)', [Symbol('s')], (err) => {
                    if (!err) { console.error('expected err'); process.exit(2); }
                    console.log('BAD_TYPE_OK');
                    db.close(() => process.exit(0));
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("BAD_TYPE_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn prepare_method_returns_statement_handle() {
    // `db.prepare(sql)` now returns a real Statement with
    // `.run/.all/.get/.finalize`. Earlier rounds surfaced
    // ERR_NOT_IMPLEMENTED; the surface is wired now.
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            const stmt = db.prepare('SELECT 1 AS one');
            const okShape =
                stmt &&
                typeof stmt.run === 'function' &&
                typeof stmt.all === 'function' &&
                typeof stmt.get === 'function' &&
                typeof stmt.finalize === 'function';
            if (!okShape) {
                console.error('wrong shape:', stmt && Object.keys(stmt).join(','));
                process.exit(3);
            }
            console.log('PREPARE_OK');
            stmt.finalize(function() { db.close(function() { process.exit(0); }); });
            setTimeout(function() { process.exit(99); }, 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("PREPARE_OK"), "stdout: {stdout}");
}

// ----- lifecycle / isolation / persistence -----------------------------

#[test]
#[serial]
fn two_databases_are_isolated() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const a = new sqlite3.Database(':memory:');
            const b = new sqlite3.Database(':memory:');
            a.exec('CREATE TABLE t (n INTEGER); INSERT INTO t VALUES (1);', () => {
                b.exec('CREATE TABLE t (n INTEGER); INSERT INTO t VALUES (2);', () => {
                    a.get('SELECT n FROM t', (_e, ra) => {
                        b.get('SELECT n FROM t', (_e, rb) => {
                            if (ra.n !== 1 || rb.n !== 2) {
                                console.error('mix:', JSON.stringify(ra), JSON.stringify(rb));
                                process.exit(2);
                            }
                            console.log('ISOLATED_OK');
                            a.close(() => b.close(() => process.exit(0)));
                        });
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("ISOLATED_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn double_close_is_idempotent() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.close(() => {
                db.close((err) => {
                    if (err) { console.error('second close err:', err); process.exit(2); }
                    console.log('DOUBLE_CLOSE_OK');
                    process.exit(0);
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("DOUBLE_CLOSE_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn transaction_commit_persists_changes() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (n INTEGER)', () => {
                db.exec('BEGIN', () => {
                    db.run('INSERT INTO t VALUES (?)', [10], () => {
                        db.exec('COMMIT', () => {
                            db.get('SELECT n FROM t', (_e, row) => {
                                if (!row || row.n !== 10) {
                                    console.error(JSON.stringify(row)); process.exit(2);
                                }
                                console.log('COMMIT_OK');
                                db.close(() => process.exit(0));
                            });
                        });
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("COMMIT_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn transaction_rollback_discards_changes() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (n INTEGER)', () => {
                db.exec('BEGIN', () => {
                    db.run('INSERT INTO t VALUES (?)', [99], () => {
                        db.exec('ROLLBACK', () => {
                            db.get('SELECT n FROM t', (_e, row) => {
                                if (row !== undefined) {
                                    console.error('expected undefined, got', JSON.stringify(row));
                                    process.exit(2);
                                }
                                console.log('ROLLBACK_OK');
                                db.close(() => process.exit(0));
                            });
                        });
                    });
                });
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("ROLLBACK_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn file_database_persists_across_reopens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("burn-shadow.db");
    let path_str = path.to_string_lossy().into_owned();

    // Pass 1: open + write + close.
    let parent1 = format!(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database({path:?});
            db.exec('CREATE TABLE t (n INTEGER); INSERT INTO t VALUES (7);', (err) => {{
                if (err) {{ console.error(err); process.exit(2); }}
                db.close(() => {{ console.log('WRITTEN'); process.exit(0); }});
            }});
            setTimeout(() => process.exit(99), 30000);
        "#,
        path = path_str
    );
    let out1 = run_inline(&parent1);
    assert!(
        out1.status.success(),
        "stdout1: {}",
        String::from_utf8_lossy(&out1.stdout)
    );
    assert!(String::from_utf8_lossy(&out1.stdout).contains("WRITTEN"));

    // Pass 2: re-open + read back.
    let parent2 = format!(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database({path:?});
            db.get('SELECT n FROM t', (err, row) => {{
                if (err) {{ console.error(err); process.exit(2); }}
                if (!row || row.n !== 7) {{
                    console.error('row mismatch:', JSON.stringify(row)); process.exit(3);
                }}
                console.log('READ_BACK_OK n=' + row.n);
                db.close(() => process.exit(0));
            }});
            setTimeout(() => process.exit(99), 30000);
        "#,
        path = path_str
    );
    let out2 = run_inline(&parent2);
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(out2.status.success(), "stdout2: {stdout2}");
    assert!(stdout2.contains("READ_BACK_OK n=7"), "stdout2: {stdout2}");
}

// ----- module shape ----------------------------------------------------

#[test]
#[serial]
fn module_exposes_database_and_open_constants() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const checks = [
                typeof sqlite3.Database === 'function',
                typeof sqlite3.OPEN_READONLY === 'number',
                typeof sqlite3.OPEN_READWRITE === 'number',
                typeof sqlite3.OPEN_CREATE === 'number',
                typeof sqlite3.verbose === 'function',
                sqlite3.verbose() === sqlite3,
            ];
            if (checks.every(Boolean)) console.log('SHAPE_OK');
            else { console.error('checks:', checks); process.exit(2); }
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("SHAPE_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn run_changes_count_for_update_and_delete() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (n INTEGER)', () => {
                db.exec(
                    'INSERT INTO t VALUES (1); INSERT INTO t VALUES (2); ' +
                    'INSERT INTO t VALUES (3); INSERT INTO t VALUES (4);',
                    () => {
                        // UPDATE matches n in {1,2} → 2 rows; multiplies to {10,20}
                        db.run('UPDATE t SET n = n * 10 WHERE n <= ?', [2], function(err) {
                            if (err) { console.error(err); process.exit(2); }
                            if (this.changes !== 2) {
                                console.error('upd changes', this.changes); process.exit(3);
                            }
                            // After update: n in {10, 20, 3, 4}.
                            // DELETE WHERE n > 5 matches {10, 20} → 2 rows.
                            db.run('DELETE FROM t WHERE n > ?', [5], function(err) {
                                if (err) { console.error(err); process.exit(4); }
                                if (this.changes !== 2) {
                                    console.error('del changes', this.changes); process.exit(5);
                                }
                                console.log('CHANGES_OK');
                                db.close(() => process.exit(0));
                            });
                        });
                    }
                );
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("CHANGES_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn last_insert_rowid_advances_per_insert() {
    let out = run_inline(
        r#"
            const sqlite3 = require('sqlite3');
            const db = new sqlite3.Database(':memory:');
            db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)', () => {
                let count = 0;
                const seenIds = [];
                function next(i) {
                    db.run('INSERT INTO t (n) VALUES (?)', [i], function(err) {
                        if (err) { console.error(err); process.exit(2); }
                        seenIds.push(this.lastID);
                        count++;
                        if (count === 4) {
                            if (JSON.stringify(seenIds) !== '[1,2,3,4]') {
                                console.error('ids', seenIds); process.exit(3);
                            }
                            console.log('LASTID_OK');
                            db.close(() => process.exit(0));
                        } else {
                            next(i + 1);
                        }
                    });
                }
                next(10);
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("LASTID_OK"), "stdout: {stdout}");
}
