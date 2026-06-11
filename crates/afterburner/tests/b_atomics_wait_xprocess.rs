// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Engine-ceiling close: real cross-process `Atomics.wait` /
//! `Atomics.notify` on a SharedArrayBuffer that's inherited by a
//! `worker_threads` subprocess via memfd + mmap.
//!
//! Validates:
//!
//! 1. `new SharedArrayBuffer(N)` allocates a real mmap region whose
//!    descriptor is non-empty.
//! 2. `Atomics.store` followed by `Atomics.load` in the same process
//!    returns the stored value (host atomic ops fire).
//! 3. A worker subprocess inherits the parent's SAB by descriptor and
//!    `Atomics.wait`s on a slot until the parent calls
//!    `Atomics.notify`. The wait is a real OS futex (Linux) /
//!    WaitOnAddress (Windows) - no busy poll on the JS side.
//! 4. `Atomics.wait` with a pre-existing mismatched slot returns
//!    `'not-equal'` synchronously.
//! 5. `Atomics.wait` with a short timeout that no notify arrives for
//!    returns `'timed-out'`.

use serial_test::serial;
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn write_temp(dir: &TempDir, name: &str, source: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(source.as_bytes()).expect("write");
    path
}

#[test]
#[serial]
fn sab_alloc_returns_descriptor() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "alloc.js",
        r#"
            const sab = new SharedArrayBuffer(64);
            if (sab.byteLength !== 64) {
                console.error('byteLength=', sab.byteLength); process.exit(2);
            }
            if (typeof sab._regionId !== 'number' || sab._regionId <= 0) {
                console.error('regionId=', sab._regionId); process.exit(3);
            }
            if (typeof sab._descriptor !== 'string' || sab._descriptor.length === 0) {
                console.error('descriptor=', sab._descriptor); process.exit(4);
            }
            console.log('SAB_ALLOC_OK');
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("SAB_ALLOC_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn atomic_store_load_in_process() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "atomic.js",
        r#"
            const sab = new SharedArrayBuffer(8);
            const arr = new Int32Array(sab);
            Atomics.store(arr, 0, 42);
            const v = Atomics.load(arr, 0);
            if (v !== 42) { console.error('v=', v); process.exit(2); }
            const old = Atomics.compareExchange(arr, 0, 42, 99);
            if (old !== 42) { console.error('cas old=', old); process.exit(3); }
            const cur = Atomics.load(arr, 0);
            if (cur !== 99) { console.error('cur=', cur); process.exit(4); }
            console.log('ATOMIC_LOAD_STORE_OK');
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("ATOMIC_LOAD_STORE_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn wait_returns_not_equal_when_slot_mismatched() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "ne.js",
        r#"
            const sab = new SharedArrayBuffer(8);
            const arr = new Int32Array(sab);
            Atomics.store(arr, 0, 7);
            const r = Atomics.wait(arr, 0, 99, 1000);
            if (r !== 'not-equal') { console.error('r=', r); process.exit(2); }
            console.log('WAIT_NE_OK');
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("WAIT_NE_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn wait_returns_timed_out_when_no_notify() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "to.js",
        r#"
            const sab = new SharedArrayBuffer(8);
            const arr = new Int32Array(sab);
            const start = Date.now();
            const r = Atomics.wait(arr, 0, 0, 100);
            const elapsed = Date.now() - start;
            if (r !== 'timed-out') { console.error('r=', r); process.exit(2); }
            if (elapsed < 50) { console.error('elapsed=', elapsed); process.exit(3); }
            console.log('WAIT_TIMEOUT_OK elapsed=' + elapsed);
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("WAIT_TIMEOUT_OK"), "STDOUT:\n{stdout}");
}

/// Real cross-process: parent allocates SAB, hands it to a worker via
/// workerData, worker `Atomics.wait`s on a slot, parent `Atomics.notify`s
/// after a delay, worker wakes and reports back.
#[test]
#[serial]
#[cfg(target_os = "linux")]
fn cross_process_wait_notify() {
    let dir = TempDir::new().expect("tempdir");
    let child = write_temp(
        &dir,
        "child.js",
        r#"
            const { workerData, parentPort } = require('worker_threads');
            const sab = workerData.sab;
            const arr = new Int32Array(sab);
            // Signal readiness BEFORE calling wait so the parent
            // doesn't race ahead and notify before we park.
            parentPort.postMessage({ phase: 'ready' });
            const r = Atomics.wait(arr, 0, 0, 5000);
            parentPort.postMessage({ phase: 'woken', status: r, value: Atomics.load(arr, 0) });
        "#,
    );
    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            const sab = new SharedArrayBuffer(8);
            const arr = new Int32Array(sab);
            Atomics.store(arr, 0, 0);
            const w = new Worker({path}, {{ workerData: {{ sab }} }});
            w.on('message', (m) => {{
                if (m.phase === 'ready') {{
                    // Small slack so the worker reaches Atomics.wait
                    // before we notify - wait() parks on the slot
                    // value match; if we store/notify before the
                    // park, the worker sees the post-store value and
                    // returns 'not-equal' (which is correct spec
                    // behaviour but doesn't exercise the futex).
                    setTimeout(() => {{
                        Atomics.store(arr, 0, 12345);
                        Atomics.notify(arr, 0, 1);
                    }}, 50);
                    return;
                }}
                if (m.phase === 'woken' && m.status === 'ok' && m.value === 12345) {{
                    console.log('XPROC_NOTIFY_OK');
                    w.terminate().then(() => process.exit(0));
                }} else {{
                    console.error('bad reply:', JSON.stringify(m));
                    w.terminate().then(() => process.exit(2));
                }}
            }});
            w.on('error', (e) => {{ console.error('w err:', e.message); process.exit(3); }});
            setTimeout(() => process.exit(99), 30000);
        "#,
        path = serde_json::to_string(child.to_str().unwrap()).unwrap()
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("XPROC_NOTIFY_OK"),
        "missing XPROC_NOTIFY_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}
