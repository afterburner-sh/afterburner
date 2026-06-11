// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! R10 - `cluster` real per-CPU multi-process integration.
//!
//! Validates that:
//! 1. `cluster.fork()` spawns a real subprocess.
//! 2. Multiple workers can co-bind the same port via `SO_REUSEPORT`.
//! 3. `Worker.process.pid` reports a real OS pid (not the cluster id).
//! 4. IPC: `worker.send(msg)` and `cluster.worker.send(reply)` round-trip.
//! 5. `cluster.on('listening', ...)` fires when a worker calls
//!    `server.listen(...)`.
//! 6. `cluster.on('exit', ...)` fires when a worker terminates.

mod common;

use common::pick_port as pick_free_port;
use serial_test::serial;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn write_temp(dir: &TempDir, name: &str, source: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(source.as_bytes()).expect("write");
    path
}

/// `cluster.fork()` returns a real worker; `Worker.process.pid` is non-zero
/// and distinct from the parent pid; IPC round-trips.
#[test]
#[serial]
fn cluster_fork_spawns_real_subprocess_with_pid_and_ipc() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "entry.js",
        r#"
            const cluster = require('cluster');
            if (cluster.isPrimary) {
                const parentPid = process.pid;
                console.log('PRIMARY_PID=' + parentPid);
                const w = cluster.fork();
                console.log('WORKER_ID=' + w.id);
                console.log('WORKER_PID=' + w.process.pid);
                if (!w.process.pid || w.process.pid === parentPid) {
                    console.error('worker pid invalid:', w.process.pid);
                    process.exit(2);
                }
                w.on('message', (m) => {
                    if (m && m.echo === 'ping') {
                        console.log('IPC_OK');
                        w.disconnect();
                    } else {
                        console.error('unexpected:', JSON.stringify(m));
                        process.exit(3);
                    }
                });
                w.on('exit', (code) => {
                    console.log('EXIT=' + code);
                    process.exit(0);
                });
                w.on('online', () => {
                    w.send({ greet: 'ping' });
                });
                setTimeout(() => process.exit(99), 30000);
            } else {
                const worker = cluster.worker;
                worker.on('message', (m) => {
                    if (m && m.greet === 'ping') {
                        worker.send({ echo: 'ping' });
                    }
                });
            }
        "#,
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected success; status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("IPC_OK"),
        "missing IPC_OK marker.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        stdout.contains("EXIT="),
        "missing EXIT marker.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

/// `cluster.isPrimary` and `cluster.isWorker` reflect role correctly on
/// both sides.
#[test]
#[serial]
fn cluster_isPrimary_isWorker_split() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "split.js",
        r#"
            const cluster = require('cluster');
            console.log('SIDE_isPrimary=' + cluster.isPrimary);
            console.log('SIDE_isWorker=' + cluster.isWorker);
            if (cluster.isPrimary) {
                const w = cluster.fork();
                w.on('message', (m) => {
                    if (m && m.tag === 'WORKER_REPORT') {
                        console.log('WORKER_isPrimary=' + m.isPrimary);
                        console.log('WORKER_isWorker=' + m.isWorker);
                        w.disconnect();
                    }
                });
                w.on('exit', () => process.exit(0));
                setTimeout(() => process.exit(99), 30000);
            } else {
                cluster.worker.send({
                    tag: 'WORKER_REPORT',
                    isPrimary: cluster.isPrimary,
                    isWorker: cluster.isWorker,
                });
            }
        "#,
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(stdout.contains("WORKER_isPrimary=false"));
    assert!(stdout.contains("WORKER_isWorker=true"));
}

/// `cluster.on('listening', ...)` fires when a worker calls
/// `server.listen(port)`.
#[test]
#[serial]
fn cluster_listening_event() {
    let dir = TempDir::new().expect("tempdir");
    let port = pick_free_port();
    let entry = write_temp(
        &dir,
        "listen.js",
        &format!(
            r#"
            const cluster = require('cluster');
            const http = require('http');
            if (cluster.isPrimary) {{
                const w = cluster.fork();
                cluster.on('listening', (worker, addr) => {{
                    console.log('LISTENING port=' + addr.port);
                    w.disconnect();
                }});
                w.on('exit', () => process.exit(0));
                setTimeout(() => process.exit(99), 30000);
            }} else {{
                const srv = http.createServer((req, res) => res.end('hi'));
                srv.listen({port});
            }}
        "#,
        ),
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("LISTENING port="),
        "missing LISTENING marker.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

/// Two workers co-bind the same port via SO_REUSEPORT - the kernel
/// 4-tuple-balances accept(). On Linux/macOS we can confirm both
/// workers report a successful listen on the same port. On Windows
/// SO_REUSEADDR allows the bind even if balance is OS-version-gated.
#[test]
#[serial]
fn cluster_two_workers_co_bind_same_port() {
    let dir = TempDir::new().expect("tempdir");
    let port = pick_free_port();
    let entry = write_temp(
        &dir,
        "cobind.js",
        &format!(
            r#"
            const cluster = require('cluster');
            const http = require('http');
            if (cluster.isPrimary) {{
                let onlineCount = 0;
                let listeningCount = 0;
                const workers = [cluster.fork(), cluster.fork()];
                cluster.on('listening', (w, addr) => {{
                    listeningCount++;
                    if (listeningCount === 2) {{
                        console.log('BOTH_LISTENING port=' + addr.port);
                        workers.forEach(x => x.disconnect());
                    }}
                }});
                let exits = 0;
                cluster.on('exit', () => {{
                    exits++;
                    if (exits === 2) process.exit(0);
                }});
                // 60s safety - cold CI cold-spawn + 2-worker fork
                // + dual listen can take 40s+ on a 4-vCPU GH runner.
                setTimeout(() => process.exit(99), 60000);
            }} else {{
                const srv = http.createServer((req, res) => res.end('hi'));
                srv.on('error', (e) => {{
                    console.error('LISTEN_FAIL=' + e.code + ' rc=' + (e.errno || ''));
                    process.exit(2);
                }});
                srv.listen({port});
            }}
        "#,
        ),
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    let expected = format!("BOTH_LISTENING port={port}");
    assert!(
        stdout.contains(&expected),
        "expected both workers to bind {port} via SO_REUSEPORT.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

/// `cluster.workers` map tracks all live workers; `disconnect()` removes
/// from the map; `cluster.disconnect(cb)` waits for everyone.
#[test]
#[serial]
fn cluster_workers_map_and_disconnect_all() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "many.js",
        r#"
            const cluster = require('cluster');
            if (cluster.isPrimary) {
                const ws = [cluster.fork(), cluster.fork(), cluster.fork()];
                console.log('MAP_COUNT=' + Object.keys(cluster.workers).length);
                let onlineSeen = 0;
                ws.forEach(w => w.on('online', () => {
                    onlineSeen++;
                    if (onlineSeen === 3) {
                        cluster.disconnect(() => {
                            console.log('ALL_DISCONNECTED count=' + Object.keys(cluster.workers).length);
                            process.exit(0);
                        });
                    }
                }));
                setTimeout(() => process.exit(99), 60000);
            } else {
                cluster.worker.on('disconnect', () => {
                    setTimeout(() => process.exit(0), 50);
                });
            }
        "#,
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("MAP_COUNT=3"),
        "missing MAP_COUNT=3.\nSTDOUT:\n{stdout}"
    );
    assert!(
        stdout.contains("ALL_DISCONNECTED count=0"),
        "missing ALL_DISCONNECTED.\nSTDOUT:\n{stdout}"
    );
}
