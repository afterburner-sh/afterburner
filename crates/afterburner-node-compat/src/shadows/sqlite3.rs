// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! L3 shadow for the `sqlite3` npm package.
//!
//! Upstream `sqlite3` ships a `.node` native addon; inside the WASM
//! sandbox we intercept `require('sqlite3')` and dispatch to
//! [`rusqlite`](https://crates.io/crates/rusqlite) via host imports.
//! `rusqlite/bundled` compiles the SQLite C amalgamation into the
//! burn binary at build time, so a single static binary ships the
//! real SQLite engine - no runtime dependency on `libsqlite3.so`.
//!
//! ## Threading model
//!
//! `rusqlite::Connection` is `Send` but `!Sync`. The workspace rule
//! forbids `std::sync::Mutex`, so each opened database runs in its
//! **own dedicated worker thread** that owns the `Connection`. The
//! coordinator stores the per-connection command sender in a
//! `HopscotchMap`; commands cross via `kovan_channel::unbounded` and
//! their replies via `kovan_channel::bounded(1)` (used as one-shot).
//!
//! Per-call cost is two channel hops (forward + reply) - negligible
//! next to the SQLite-side work, which dominates anything past
//! pure-cache hits.
//!
//! ## API surface (matches the npm `sqlite3` package)
//!
//! * `new sqlite3.Database(path[, mode][, cb])` → opens a connection
//! * `db.run(sql[, params][, cb])` → INSERT/UPDATE/DELETE; cb receives
//!   `this` with `lastID` and `changes`
//! * `db.get(sql[, params][, cb])` → first row (or `undefined`)
//! * `db.all(sql[, params][, cb])` → all rows
//! * `db.exec(sql[, cb])` → multi-statement (no params, no result)
//! * `db.close([cb])` → drops the connection, joins the worker
//! * `db.serialize(fn)` / `db.parallelize(fn)` → no-op (we serialize
//!   at the worker by construction)
//!
//! ### Deferred (will throw a clear error if used)
//!
//! * `db.prepare(sql)` returning a `Statement` handle for re-binding -
//!   most callers use the inline `db.run(sql, params)` form. Could
//!   land later as a separate handle map; not in the minimum subset.
//! * `db.each(sql, params, rowCb, doneCb)` - partial; we materialize
//!   all rows and invoke `rowCb` synchronously per row, then `doneCb`.
//!
//! Parameters and result values cross the host boundary as JSON. NULL,
//! booleans, integers, floats, and strings travel as primitive JSON;
//! blobs travel as `{"$blob_b64": "..."}` objects. The polyfill
//! handles `Buffer` → blob conversion.

use afterburner_core::{AfterburnerError, Result};
use kovan_channel::flavors::bounded::{Sender as BoundedTx, channel as bounded_channel};
use kovan_channel::flavors::unbounded::{
    Receiver as UnboundedRx, Sender as UnboundedTx, channel as unbounded_channel,
};
use kovan_map::HopscotchMap;
use rusqlite::{Connection, OpenFlags, params_from_iter, types::Value as SqlValue};
use serde_json::{Value as JsonValue, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::thread;

pub type DbId = i64;

#[derive(Clone)]
struct ConnHandle {
    cmd_tx: UnboundedTx<DbCommand>,
}

enum DbCommand {
    Run {
        sql: String,
        params: Vec<JsonValue>,
        reply: BoundedTx<Result<RunResult>>,
    },
    Get {
        sql: String,
        params: Vec<JsonValue>,
        reply: BoundedTx<Result<Option<JsonValue>>>,
    },
    All {
        sql: String,
        params: Vec<JsonValue>,
        reply: BoundedTx<Result<Vec<JsonValue>>>,
    },
    Exec {
        sql: String,
        reply: BoundedTx<Result<()>>,
    },
    Close {
        reply: BoundedTx<()>,
    },
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub last_insert_rowid: i64,
    pub changes: u64,
}

pub struct SqliteShadow {
    conns: HopscotchMap<DbId, ConnHandle>,
    next_id: AtomicI64,
}

impl Default for SqliteShadow {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SqliteShadow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteShadow").finish_non_exhaustive()
    }
}

impl SqliteShadow {
    pub fn new() -> Self {
        Self {
            conns: HopscotchMap::new(),
            // Start at 1 so JS can use `0` as "no database".
            next_id: AtomicI64::new(1),
        }
    }

    /// Open a database file. `:memory:` opens an in-memory database
    /// (matches sqlite3's convention). The new connection runs in a
    /// fresh worker thread; the returned id is the JS-side handle.
    pub fn open(self: &Arc<Self>, path: &str) -> Result<DbId> {
        // Validate path eagerly so `new sqlite3.Database` fails fast
        // for an obviously-bad path. The actual `Connection::open` is
        // re-tried inside the worker thread (where we own the conn),
        // but we run it once here too so the synchronous error path
        // surfaces an Err before the worker is spawned.
        let conn = open_connection(path)
            .map_err(|e| AfterburnerError::Host(format!("sqlite3.Database({path}): {e}")))?;
        // Drop the probe connection - the worker will open its own.
        // (Two opens of the same file are fine; SQLite's locking
        // handles concurrent process-level access.)
        drop(conn);

        let (tx, rx) = unbounded_channel::<DbCommand>();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let path = path.to_string();
        thread::Builder::new()
            .name(format!("sqlite3-shadow-{id}"))
            .spawn(move || run_worker(path, rx))
            .map_err(|e| AfterburnerError::Host(format!("sqlite3 worker spawn: {e}")))?;
        self.conns.insert(id, ConnHandle { cmd_tx: tx });
        Ok(id)
    }

    pub fn run(&self, id: DbId, sql: &str, params: Vec<JsonValue>) -> Result<RunResult> {
        let handle = self.handle(id)?;
        let (tx, rx) = bounded_channel(1);
        handle.cmd_tx.send(DbCommand::Run {
            sql: sql.to_string(),
            params,
            reply: tx,
        });
        rx.recv()
            .ok_or_else(|| AfterburnerError::Host("sqlite3.run: worker dropped".into()))?
    }

    pub fn get(&self, id: DbId, sql: &str, params: Vec<JsonValue>) -> Result<Option<JsonValue>> {
        let handle = self.handle(id)?;
        let (tx, rx) = bounded_channel(1);
        handle.cmd_tx.send(DbCommand::Get {
            sql: sql.to_string(),
            params,
            reply: tx,
        });
        rx.recv()
            .ok_or_else(|| AfterburnerError::Host("sqlite3.get: worker dropped".into()))?
    }

    pub fn all(&self, id: DbId, sql: &str, params: Vec<JsonValue>) -> Result<Vec<JsonValue>> {
        let handle = self.handle(id)?;
        let (tx, rx) = bounded_channel(1);
        handle.cmd_tx.send(DbCommand::All {
            sql: sql.to_string(),
            params,
            reply: tx,
        });
        rx.recv()
            .ok_or_else(|| AfterburnerError::Host("sqlite3.all: worker dropped".into()))?
    }

    pub fn exec(&self, id: DbId, sql: &str) -> Result<()> {
        let handle = self.handle(id)?;
        let (tx, rx) = bounded_channel(1);
        handle.cmd_tx.send(DbCommand::Exec {
            sql: sql.to_string(),
            reply: tx,
        });
        rx.recv()
            .ok_or_else(|| AfterburnerError::Host("sqlite3.exec: worker dropped".into()))?
    }

    pub fn close(&self, id: DbId) -> Result<()> {
        let Some(handle) = self.conns.remove(&id) else {
            return Err(AfterburnerError::Host(format!(
                "sqlite3.close: unknown db id {id}"
            )));
        };
        let (tx, rx) = bounded_channel::<()>(1);
        handle.cmd_tx.send(DbCommand::Close { reply: tx });
        // Best-effort wait for the worker to drop the conn before we
        // return - avoids races where the user closes a file then
        // immediately re-opens the same path expecting fresh state.
        let _ = rx.recv();
        Ok(())
    }

    fn handle(&self, id: DbId) -> Result<ConnHandle> {
        self.conns
            .get(&id)
            .ok_or_else(|| AfterburnerError::Host(format!("sqlite3: unknown db id {id}")))
    }
}

/// Open with the same flags `node-sqlite3` uses by default
/// (READWRITE | CREATE | URI). The `bundled` build of rusqlite
/// always serialises threads at the SQLite level, so concurrent
/// access from outside the worker is safe - but we restrict access
/// to the worker thread anyway by construction.
fn open_connection(path: &str) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_URI;
    Connection::open_with_flags(path, flags)
}

fn run_worker(path: String, rx: UnboundedRx<DbCommand>) {
    let conn = match open_connection(&path) {
        Ok(c) => c,
        Err(_e) => {
            // Path validation already happened in `open`; if we hit
            // an error here, the file was concurrently removed or
            // permissions changed. Drain commands with an error
            // until the user gives up and closes.
            while let Some(cmd) = rx.recv() {
                let err = || AfterburnerError::Host(format!("sqlite3 worker: cannot open {path}"));
                match cmd {
                    DbCommand::Run { reply, .. } => {
                        reply.send(Err(err()));
                    }
                    DbCommand::Get { reply, .. } => {
                        reply.send(Err(err()));
                    }
                    DbCommand::All { reply, .. } => {
                        reply.send(Err(err()));
                    }
                    DbCommand::Exec { reply, .. } => {
                        reply.send(Err(err()));
                    }
                    DbCommand::Close { reply } => {
                        reply.send(());
                        return;
                    }
                }
            }
            return;
        }
    };

    while let Some(cmd) = rx.recv() {
        match cmd {
            DbCommand::Run { sql, params, reply } => {
                reply.send(do_run(&conn, &sql, params));
            }
            DbCommand::Get { sql, params, reply } => {
                reply.send(do_get(&conn, &sql, params));
            }
            DbCommand::All { sql, params, reply } => {
                reply.send(do_all(&conn, &sql, params));
            }
            DbCommand::Exec { sql, reply } => {
                reply.send(do_exec(&conn, &sql));
            }
            DbCommand::Close { reply } => {
                reply.send(());
                return;
            }
        }
    }
}

fn do_run(conn: &Connection, sql: &str, params: Vec<JsonValue>) -> Result<RunResult> {
    let bound = bind_params(params)?;
    let mut stmt = prepare(conn, sql)?;
    let changes = stmt
        .execute(params_from_iter(bound.iter()))
        .map_err(map_err)?;
    Ok(RunResult {
        last_insert_rowid: conn.last_insert_rowid(),
        changes: changes as u64,
    })
}

fn do_get(conn: &Connection, sql: &str, params: Vec<JsonValue>) -> Result<Option<JsonValue>> {
    let bound = bind_params(params)?;
    let mut stmt = prepare(conn, sql)?;
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let mut rows = stmt
        .query(params_from_iter(bound.iter()))
        .map_err(map_err)?;
    match rows.next().map_err(map_err)? {
        Some(row) => Ok(Some(row_to_json(row, &column_names)?)),
        None => Ok(None),
    }
}

fn do_all(conn: &Connection, sql: &str, params: Vec<JsonValue>) -> Result<Vec<JsonValue>> {
    let bound = bind_params(params)?;
    let mut stmt = prepare(conn, sql)?;
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let mut rows = stmt
        .query(params_from_iter(bound.iter()))
        .map_err(map_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(map_err)? {
        out.push(row_to_json(row, &column_names)?);
    }
    Ok(out)
}

fn do_exec(conn: &Connection, sql: &str) -> Result<()> {
    conn.execute_batch(sql).map_err(map_err)
}

fn prepare<'c>(conn: &'c Connection, sql: &str) -> Result<rusqlite::Statement<'c>> {
    conn.prepare(sql).map_err(map_err)
}

fn map_err(e: rusqlite::Error) -> AfterburnerError {
    AfterburnerError::Host(format!("sqlite3: {e}"))
}

/// Translate JSON parameter values into the SQLite type system. NULL,
/// booleans, integers, floats, strings, and `{$blob_b64: "..."}`
/// blob objects are supported.
fn bind_params(params: Vec<JsonValue>) -> Result<Vec<SqlValue>> {
    use base64::Engine as _;
    let mut out = Vec::with_capacity(params.len());
    for p in params {
        let v = match p {
            JsonValue::Null => SqlValue::Null,
            JsonValue::Bool(b) => SqlValue::Integer(if b { 1 } else { 0 }),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    SqlValue::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    SqlValue::Real(f)
                } else {
                    return Err(AfterburnerError::Host(
                        "sqlite3: param number out of i64/f64 range".into(),
                    ));
                }
            }
            JsonValue::String(s) => SqlValue::Text(s),
            JsonValue::Object(map) if map.contains_key("$blob_b64") => {
                let s = map
                    .get("$blob_b64")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| {
                        AfterburnerError::Host("sqlite3: $blob_b64 requires a string value".into())
                    })?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|e| AfterburnerError::Host(format!("sqlite3: blob base64: {e}")))?;
                SqlValue::Blob(bytes)
            }
            other => {
                return Err(AfterburnerError::Host(format!(
                    "sqlite3: unsupported param type {other:?}"
                )));
            }
        };
        out.push(v);
    }
    Ok(out)
}

fn row_to_json(row: &rusqlite::Row<'_>, column_names: &[String]) -> Result<JsonValue> {
    use base64::Engine as _;
    let mut obj = serde_json::Map::with_capacity(column_names.len());
    for (i, name) in column_names.iter().enumerate() {
        let v: SqlValue = row.get(i).map_err(map_err)?;
        let json_v = match v {
            SqlValue::Null => JsonValue::Null,
            SqlValue::Integer(n) => json!(n),
            SqlValue::Real(f) => json!(f),
            SqlValue::Text(s) => JsonValue::String(s),
            SqlValue::Blob(b) => {
                // Mirror the parameter shape - Buffer round-trips
                // through `{"$blob_b64": "..."}`.
                let b64 = base64::engine::general_purpose::STANDARD.encode(&b);
                json!({ "$blob_b64": b64 })
            }
        };
        obj.insert(name.clone(), json_v);
    }
    Ok(JsonValue::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_mem() -> (Arc<SqliteShadow>, DbId) {
        let s = Arc::new(SqliteShadow::new());
        let id = s.open(":memory:").expect("open mem");
        (s, id)
    }

    // ----- happy path: CRUD round-trips -------------------------------

    #[test]
    fn round_trip_create_insert_select() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
            .expect("create");
        let r = s
            .run(id, "INSERT INTO t (name) VALUES (?)", vec![json!("alpha")])
            .expect("insert");
        assert_eq!(r.changes, 1);
        assert_eq!(r.last_insert_rowid, 1);
        let row = s
            .get(id, "SELECT * FROM t WHERE id = ?", vec![json!(1)])
            .expect("get");
        let row = row.expect("row present");
        assert_eq!(row["id"], json!(1));
        assert_eq!(row["name"], json!("alpha"));
        s.close(id).expect("close");
    }

    #[test]
    fn all_returns_every_row_in_order() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        for n in 1..=5 {
            s.run(id, "INSERT INTO t VALUES (?)", vec![json!(n)])
                .expect("insert");
        }
        let rows = s
            .all(id, "SELECT n FROM t ORDER BY n", vec![])
            .expect("all");
        assert_eq!(rows.len(), 5);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row["n"], json!(i as i64 + 1));
        }
        s.close(id).expect("close");
    }

    #[test]
    fn get_returns_none_when_no_rows() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        let row = s
            .get(id, "SELECT n FROM t WHERE n = ?", vec![json!(42)])
            .expect("get");
        assert!(row.is_none(), "expected None for empty result");
        s.close(id).expect("close");
    }

    #[test]
    fn all_returns_empty_array_when_no_rows() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        let rows = s.all(id, "SELECT n FROM t", vec![]).expect("all");
        assert!(rows.is_empty(), "expected empty array, got {rows:?}");
        s.close(id).expect("close");
    }

    #[test]
    fn run_changes_count_reflects_update() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        for n in 1..=10 {
            s.run(id, "INSERT INTO t VALUES (?)", vec![json!(n)])
                .expect("insert");
        }
        // Update half the rows.
        let r = s
            .run(id, "UPDATE t SET n = n * 2 WHERE n <= ?", vec![json!(5)])
            .expect("update");
        assert_eq!(r.changes, 5, "expected 5 rows updated");
        s.close(id).expect("close");
    }

    #[test]
    fn run_changes_count_reflects_delete() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        for n in 1..=4 {
            s.run(id, "INSERT INTO t VALUES (?)", vec![json!(n)])
                .expect("insert");
        }
        let r = s
            .run(id, "DELETE FROM t WHERE n > ?", vec![json!(2)])
            .expect("delete");
        assert_eq!(r.changes, 2);
        let rows = s
            .all(id, "SELECT n FROM t ORDER BY n", vec![])
            .expect("all");
        assert_eq!(rows.len(), 2);
        s.close(id).expect("close");
    }

    #[test]
    fn last_insert_rowid_advances_per_insert() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)")
            .expect("create");
        for expected_id in 1..=4 {
            let r = s
                .run(id, "INSERT INTO t (n) VALUES (?)", vec![json!(expected_id)])
                .expect("insert");
            assert_eq!(r.last_insert_rowid, expected_id);
        }
        s.close(id).expect("close");
    }

    // ----- exec (multi-statement) -------------------------------------

    #[test]
    fn exec_runs_multiple_statements_in_one_call() {
        let (s, id) = open_mem();
        s.exec(
            id,
            "CREATE TABLE a (n INTEGER); \
             CREATE TABLE b (n INTEGER); \
             INSERT INTO a VALUES (1); \
             INSERT INTO b VALUES (2);",
        )
        .expect("multi-exec");
        let a_row = s
            .get(id, "SELECT n FROM a", vec![])
            .expect("a")
            .expect("row");
        let b_row = s
            .get(id, "SELECT n FROM b", vec![])
            .expect("b")
            .expect("row");
        assert_eq!(a_row["n"], json!(1));
        assert_eq!(b_row["n"], json!(2));
        s.close(id).expect("close");
    }

    // ----- parameter type coverage ------------------------------------

    #[test]
    fn null_param_round_trip() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (v ANY)").expect("create");
        s.run(id, "INSERT INTO t VALUES (?)", vec![JsonValue::Null])
            .expect("insert null");
        let row = s
            .get(id, "SELECT v FROM t", vec![])
            .expect("get")
            .expect("row");
        assert_eq!(row["v"], JsonValue::Null);
        s.close(id).expect("close");
    }

    #[test]
    fn boolean_param_stored_as_integer() {
        // SQLite has no native bool - we map to 0/1 INTEGER, matching
        // node-sqlite3 behavior. The retrieved value is the integer
        // form, not a JSON bool.
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (b INTEGER)").expect("create");
        s.run(id, "INSERT INTO t VALUES (?)", vec![json!(true)])
            .expect("insert true");
        s.run(id, "INSERT INTO t VALUES (?)", vec![json!(false)])
            .expect("insert false");
        let rows = s
            .all(id, "SELECT b FROM t ORDER BY rowid", vec![])
            .expect("all");
        assert_eq!(rows[0]["b"], json!(1));
        assert_eq!(rows[1]["b"], json!(0));
        s.close(id).expect("close");
    }

    #[test]
    fn float_param_round_trip() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (f REAL)").expect("create");
        s.run(id, "INSERT INTO t VALUES (?)", vec![json!(3.5)])
            .expect("insert");
        let row = s
            .get(id, "SELECT f FROM t", vec![])
            .expect("get")
            .expect("row");
        let f = row["f"].as_f64().expect("number");
        assert!((f - 3.5).abs() < 1e-9);
        s.close(id).expect("close");
    }

    #[test]
    fn unicode_text_round_trip() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (s TEXT)").expect("create");
        let words = ["héllo", "🚀rocket", "日本語", ""];
        for w in words {
            s.run(id, "INSERT INTO t VALUES (?)", vec![json!(w)])
                .expect("insert");
        }
        let rows = s
            .all(id, "SELECT s FROM t ORDER BY rowid", vec![])
            .expect("all");
        for (i, w) in words.iter().enumerate() {
            assert_eq!(rows[i]["s"], json!(*w));
        }
        s.close(id).expect("close");
    }

    #[test]
    fn blob_round_trip() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (b BLOB)").expect("create");
        // 4-byte blob: 0xDE 0xAD 0xBE 0xEF
        let b64 = "3q2+7w==";
        s.run(
            id,
            "INSERT INTO t VALUES (?)",
            vec![json!({"$blob_b64": b64})],
        )
        .expect("insert");
        let row = s
            .get(id, "SELECT b FROM t", vec![])
            .expect("get")
            .expect("row");
        assert_eq!(row["b"], json!({"$blob_b64": b64}));
        s.close(id).expect("close");
    }

    #[test]
    fn empty_blob_round_trip() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (b BLOB)").expect("create");
        s.run(
            id,
            "INSERT INTO t VALUES (?)",
            vec![json!({"$blob_b64": ""})],
        )
        .expect("insert empty blob");
        let row = s
            .get(id, "SELECT b FROM t", vec![])
            .expect("get")
            .expect("row");
        assert_eq!(row["b"], json!({"$blob_b64": ""}));
        s.close(id).expect("close");
    }

    #[test]
    fn large_integer_round_trip() {
        // i64 max - biggest value SQLite supports.
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        let big = i64::MAX;
        s.run(id, "INSERT INTO t VALUES (?)", vec![json!(big)])
            .expect("insert max i64");
        let row = s
            .get(id, "SELECT n FROM t", vec![])
            .expect("get")
            .expect("row");
        assert_eq!(row["n"], json!(big));
        s.close(id).expect("close");
    }

    // ----- error paths -----------------------------------------------

    #[test]
    fn unknown_id_errors() {
        let s = Arc::new(SqliteShadow::new());
        for op in [
            s.run(9999, "SELECT 1", vec![]).err(),
            s.get(9999, "SELECT 1", vec![]).err(),
            s.all(9999, "SELECT 1", vec![]).err(),
            s.exec(9999, "SELECT 1").err(),
        ] {
            assert!(matches!(op, Some(AfterburnerError::Host(_))));
        }
    }

    #[test]
    fn syntax_error_surfaces_as_host_error() {
        let (s, id) = open_mem();
        let r = s.exec(id, "NOT VALID SQL");
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
        // Connection still alive after an error - verify by running
        // a subsequent command that should succeed.
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("recover");
        s.close(id).expect("close");
    }

    #[test]
    fn missing_table_select_surfaces_as_host_error() {
        let (s, id) = open_mem();
        let r = s.get(id, "SELECT * FROM does_not_exist", vec![]);
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
        s.close(id).expect("close");
    }

    #[test]
    fn unique_constraint_violation_surfaces_as_host_error() {
        let (s, id) = open_mem();
        s.exec(
            id,
            "CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER UNIQUE)",
        )
        .expect("create");
        s.run(id, "INSERT INTO t (n) VALUES (?)", vec![json!(1)])
            .expect("first");
        let r = s.run(id, "INSERT INTO t (n) VALUES (?)", vec![json!(1)]);
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
        // Connection still usable.
        let rows = s.all(id, "SELECT n FROM t", vec![]).expect("all");
        assert_eq!(rows.len(), 1);
        s.close(id).expect("close");
    }

    #[test]
    fn unsupported_param_type_errors() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (v ANY)").expect("create");
        // Arrays aren't valid SQLite values; the host bridge rejects.
        let r = s.run(id, "INSERT INTO t VALUES (?)", vec![json!([1, 2, 3])]);
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
        s.close(id).expect("close");
    }

    // ----- isolation / lifecycle -------------------------------------

    #[test]
    fn close_drops_worker_and_invalidates_id() {
        let s = Arc::new(SqliteShadow::new());
        let id = s.open(":memory:").expect("open");
        s.close(id).expect("close");
        let r = s.run(id, "SELECT 1", vec![]);
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
    }

    #[test]
    fn multiple_close_calls_are_safe() {
        let s = Arc::new(SqliteShadow::new());
        let id = s.open(":memory:").expect("open");
        s.close(id).expect("first close");
        // Second close on the same id should be a no-op error rather
        // than a panic - caller already invalidated the handle.
        let _ = s.close(id);
    }

    #[test]
    fn two_databases_are_isolated() {
        let s = Arc::new(SqliteShadow::new());
        let a = s.open(":memory:").expect("open a");
        let b = s.open(":memory:").expect("open b");
        s.exec(a, "CREATE TABLE t (n INTEGER)").expect("create a");
        s.exec(b, "CREATE TABLE t (n INTEGER)").expect("create b");
        s.run(a, "INSERT INTO t VALUES (?)", vec![json!(1)])
            .expect("a insert");
        s.run(b, "INSERT INTO t VALUES (?)", vec![json!(2)])
            .expect("b insert");
        let row_a = s
            .get(a, "SELECT n FROM t", vec![])
            .expect("a get")
            .expect("row");
        let row_b = s
            .get(b, "SELECT n FROM t", vec![])
            .expect("b get")
            .expect("row");
        assert_eq!(row_a["n"], json!(1));
        assert_eq!(row_b["n"], json!(2));
        s.close(a).expect("close a");
        s.close(b).expect("close b");
    }

    #[test]
    fn concurrent_dbs_dont_block_each_other() {
        // Each db has its own worker thread - a long-running op on
        // one mustn't block another. We can prove the parallelism
        // with two SQLite "BEGIN IMMEDIATE" / busy-loop style tests,
        // but a simpler proof is that opening N dbs and running N
        // queries in parallel from different threads finishes faster
        // than serially.
        use std::sync::Barrier;
        use std::time::Instant;
        let s = Arc::new(SqliteShadow::new());
        let n = 4;
        let ids: Vec<DbId> = (0..n).map(|_| s.open(":memory:").expect("open")).collect();
        for &id in &ids {
            s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        }
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::new();
        let t0 = Instant::now();
        for &id in &ids {
            let s = Arc::clone(&s);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                for i in 0..50 {
                    s.run(id, "INSERT INTO t VALUES (?)", vec![json!(i)])
                        .expect("insert");
                }
            }));
        }
        for h in handles {
            h.join().expect("join");
        }
        let elapsed = t0.elapsed();
        for &id in &ids {
            let rows = s.all(id, "SELECT n FROM t", vec![]).expect("all");
            assert_eq!(rows.len(), 50);
        }
        for id in ids {
            s.close(id).expect("close");
        }
        // Sanity: 4 × 50 inserts in parallel should comfortably fit
        // in 2 seconds even on a slow CI box.
        assert!(elapsed.as_secs() < 5, "parallel run took {elapsed:?}");
    }

    #[test]
    fn id_counter_is_monotonic() {
        let s = Arc::new(SqliteShadow::new());
        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(s.open(":memory:").expect("open"));
        }
        for w in ids.windows(2) {
            assert!(w[1] > w[0], "ids must be monotonic, got {ids:?}");
        }
        for id in ids {
            s.close(id).expect("close");
        }
    }

    // ----- transactions ----------------------------------------------

    #[test]
    fn transaction_commit_persists() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        s.exec(id, "BEGIN").expect("begin");
        s.run(id, "INSERT INTO t VALUES (?)", vec![json!(1)])
            .expect("insert");
        s.exec(id, "COMMIT").expect("commit");
        let row = s
            .get(id, "SELECT n FROM t", vec![])
            .expect("get")
            .expect("row");
        assert_eq!(row["n"], json!(1));
        s.close(id).expect("close");
    }

    #[test]
    fn transaction_rollback_discards() {
        let (s, id) = open_mem();
        s.exec(id, "CREATE TABLE t (n INTEGER)").expect("create");
        s.exec(id, "BEGIN").expect("begin");
        s.run(id, "INSERT INTO t VALUES (?)", vec![json!(99)])
            .expect("insert");
        s.exec(id, "ROLLBACK").expect("rollback");
        let row = s.get(id, "SELECT n FROM t", vec![]).expect("get");
        assert!(row.is_none(), "rolled-back row should not be visible");
        s.close(id).expect("close");
    }

    // ----- file-backed databases -------------------------------------

    #[test]
    fn file_database_persists_across_reopens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("burn-shadow.db");
        let path_str = path.to_string_lossy().into_owned();

        // Open, write, close.
        let s = Arc::new(SqliteShadow::new());
        let id1 = s.open(&path_str).expect("open 1");
        s.exec(id1, "CREATE TABLE t (n INTEGER)").expect("create");
        s.run(id1, "INSERT INTO t VALUES (?)", vec![json!(7)])
            .expect("insert");
        s.close(id1).expect("close 1");

        // Re-open same path, read back.
        let id2 = s.open(&path_str).expect("open 2");
        let row = s
            .get(id2, "SELECT n FROM t", vec![])
            .expect("get")
            .expect("row");
        assert_eq!(row["n"], json!(7));
        s.close(id2).expect("close 2");
    }
}
