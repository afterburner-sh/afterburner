// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! B10 — `worker_threads` round-trip integration.
//!
//! Spawns `burn` with an inline parent script that creates a `Worker`
//! pointing at a temp `child.js`, posts a message, and asserts the
//! child's reply makes it back. Validates the full IPC pipeline:
//! parent JS → __host_worker_spawn → child process → init frame →
//! parentPort → __host_worker_post_to_parent → parent stdout pipe →
//! daemon-event dispatcher → worker.on('message') → emit.
//!
//! These tests require the plugin `.wasm` to be Wizer-rebuilt with the
//! current plenum bundle (which embeds `polyfills/worker_threads.js`).
//! Run `bash afterburner-plugin/build.sh` once before this suite.

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

/// Quote a path string as a JS string literal.
fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// Minimum-viable: parent posts a message; child echoes it back.
#[test]
#[serial]
fn worker_round_trip_message() {
    let dir = TempDir::new().expect("tempdir");
    let child_js = write_temp(
        &dir,
        "child.js",
        r#"
            const { parentPort, workerData } = require('worker_threads');
            parentPort.on('message', (msg) => {
                parentPort.postMessage({ echo: msg, data: workerData });
            });
        "#,
    );

    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            const w = new Worker({path}, {{ workerData: {{ tag: 'hello' }} }});
            let exitCode = 1;
            w.on('message', (msg) => {{
                if (msg.echo === 'ping' && msg.data && msg.data.tag === 'hello') {{
                    exitCode = 0;
                    console.log('ROUNDTRIP_OK');
                }} else {{
                    console.error('unexpected reply:', JSON.stringify(msg));
                }}
                w.terminate().then(() => process.exit(exitCode));
            }});
            w.on('error', (e) => {{
                console.error('worker error:', (e && e.stack) || String(e));
                process.exit(2);
            }});
            w.on('online', () => {{
                w.postMessage('ping');
            }});
            // 60s safety timer — cold CI runners (4-vCPU) need >10s
            // to walk burn-init + plugin + worker-child cold-spawn +
            // first message round-trip. Local boxes finish in <5s; the
            // ceiling only matters when the round-trip is actually
            // broken (then we still get a deterministic 42 exit and
            // a clean test failure).
            setTimeout(() => {{ process.exit(42); }}, 60000);
        "#,
        path = js_str(child_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
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
        stdout.contains("ROUNDTRIP_OK"),
        "missing ROUNDTRIP_OK marker.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

/// `isMainThread` reflects role correctly on both sides; `threadId` is
/// 0 in parent and a monotonic positive in child.
#[test]
#[serial]
#[allow(non_snake_case)]
fn isMainThread_and_threadId() {
    let dir = TempDir::new().expect("tempdir");
    let child_js = write_temp(
        &dir,
        "isMain.js",
        r#"
            const wt = require('worker_threads');
            wt.parentPort.postMessage({
                isMain: wt.isMainThread,
                tid: wt.threadId,
            });
        "#,
    );

    let parent = format!(
        r#"
            const wt = require('worker_threads');
            console.log('PARENT_MAIN=' + wt.isMainThread);
            console.log('PARENT_TID=' + wt.threadId);
            const w = new wt.Worker({path});
            w.on('message', (m) => {{
                console.log('CHILD_MAIN=' + m.isMain);
                console.log('CHILD_TID=' + m.tid);
                w.terminate().then(() => process.exit(0));
            }});
            setTimeout(() => process.exit(99), 60000);
        "#,
        path = js_str(child_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("PARENT_MAIN=true"), "stdout: {stdout}");
    assert!(stdout.contains("PARENT_TID=0"), "stdout: {stdout}");
    assert!(stdout.contains("CHILD_MAIN=false"), "stdout: {stdout}");
    assert!(stdout.contains("CHILD_TID=1"), "stdout: {stdout}");
}

/// `worker.on('exit', cb)` fires with the exit code observed from
/// the child process.
#[test]
#[serial]
fn exit_event_fires() {
    let dir = TempDir::new().expect("tempdir");
    let child_js = write_temp(
        &dir,
        "exit.js",
        r#"
            const { parentPort } = require('worker_threads');
            parentPort.postMessage('starting');
            setTimeout(() => process.exit(7), 50);
        "#,
    );

    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            const w = new Worker({path});
            w.on('exit', (code) => {{
                console.log('EXIT_CODE=' + code);
                process.exit(code === 7 ? 0 : 1);
            }});
            setTimeout(() => process.exit(99), 60000);
        "#,
        path = js_str(child_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("EXIT_CODE=7"), "stdout: {stdout}");
}

/// `workerData` round-trips through the init frame.
#[test]
#[serial]
#[allow(non_snake_case)]
fn workerData_integrity() {
    let dir = TempDir::new().expect("tempdir");
    let child_js = write_temp(
        &dir,
        "data.js",
        r#"
            const { parentPort, workerData } = require('worker_threads');
            parentPort.postMessage(workerData);
        "#,
    );

    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            const payload = {{
                kind: 'mixed',
                num: 42,
                str: 'héllo',
                arr: [1, 2, 3, null, true],
                nested: {{ a: {{ b: 'c' }} }},
            }};
            const w = new Worker({path}, {{ workerData: payload }});
            w.on('message', (m) => {{
                if (JSON.stringify(m) === JSON.stringify(payload)) {{
                    console.log('DATA_OK');
                    w.terminate().then(() => process.exit(0));
                }} else {{
                    console.error('mismatch: got', JSON.stringify(m), 'want', JSON.stringify(payload));
                    process.exit(2);
                }}
            }});
            setTimeout(() => process.exit(99), 60000);
        "#,
        path = js_str(child_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("DATA_OK"), "stdout: {stdout}");
}

/// Both directions of message flow work, multiple sends, and ordering
/// is preserved (FIFO over the IPC pipe).
#[test]
#[serial]
fn ordered_messages_both_directions() {
    let dir = TempDir::new().expect("tempdir");
    let child_js = write_temp(
        &dir,
        "echo_n.js",
        r#"
            const { parentPort } = require('worker_threads');
            let count = 0;
            parentPort.on('message', (m) => {
                if (m === 'done') {
                    parentPort.postMessage({ done: true, count: count });
                } else {
                    count++;
                    parentPort.postMessage({ ack: m });
                }
            });
        "#,
    );

    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            const w = new Worker({path});
            const seen = [];
            w.on('message', (m) => {{
                if (m.done) {{
                    if (m.count === 5 && JSON.stringify(seen) === JSON.stringify([0,1,2,3,4])) {{
                        console.log('ORDER_OK');
                        w.terminate().then(() => process.exit(0));
                    }} else {{
                        console.error('mismatch count=' + m.count + ' seen=' + JSON.stringify(seen));
                        process.exit(2);
                    }}
                }} else {{
                    seen.push(m.ack);
                }}
            }});
            w.on('online', () => {{
                for (let i = 0; i < 5; i++) w.postMessage(i);
                w.postMessage('done');
            }});
            setTimeout(() => process.exit(99), 60000);
        "#,
        path = js_str(child_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("ORDER_OK"), "stdout: {stdout}");
}
