// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! C1 - `Atomics.waitAsync` real semantics.
//!
//! Validates:
//! 1. `waitAsync` returns `{async:false, value:'not-equal'}` when the
//!    slot already differs from the expected value (sync fast path).
//! 2. `waitAsync` returns `{async:true, value:Promise}` when the slot
//!    matches; the promise resolves to `'ok'` on `Atomics.notify`.
//! 3. The promise resolves to `'timed-out'` when the timeout elapses
//!    before any notify.
//! 4. `Atomics.notify(view, idx, count)` wakes exactly `count` waiters
//!    and returns the number woken.
//! 5. Multiple views over the same underlying buffer with matching
//!    byte offsets see each other's waiters.

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
fn waitAsync_not_equal_fast_path() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "ne.js",
        r#"
            const buf = new ArrayBuffer(8);
            const arr = new Int32Array(buf);
            arr[0] = 7;
            const r = Atomics.waitAsync(arr, 0, 99, 100);
            if (r.async !== false) { console.error('expected sync, got', r); process.exit(2); }
            if (r.value !== 'not-equal') { console.error('expected not-equal, got', r.value); process.exit(3); }
            console.log('NE_OK');
            process.exit(0);
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
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("NE_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn waitAsync_resolves_on_notify() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "notify.js",
        r#"
            const buf = new ArrayBuffer(8);
            const arr = new Int32Array(buf);
            arr[0] = 0;
            const r = Atomics.waitAsync(arr, 0, 0, 5000);
            if (r.async !== true) { console.error('expected async, got', r); process.exit(2); }
            r.value.then((status) => {
                if (status === 'ok') {
                    console.log('NOTIFY_OK');
                    process.exit(0);
                } else {
                    console.error('expected ok, got', status);
                    process.exit(3);
                }
            });
            // Wake the waiter on a microtask so the promise above is
            // pending when notify lands.
            setTimeout(() => {
                const woken = Atomics.notify(arr, 0, 1);
                if (woken !== 1) console.error('woken=' + woken);
            }, 30);
            setTimeout(() => process.exit(99), 30000);
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
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("NOTIFY_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn waitAsync_times_out() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "to.js",
        r#"
            const buf = new ArrayBuffer(8);
            const arr = new Int32Array(buf);
            arr[0] = 0;
            const start = Date.now();
            const r = Atomics.waitAsync(arr, 0, 0, 50);
            r.value.then((status) => {
                const elapsed = Date.now() - start;
                if (status === 'timed-out' && elapsed >= 30) {
                    console.log('TIMEOUT_OK elapsed=' + elapsed);
                    process.exit(0);
                } else {
                    console.error('bad timeout: status=' + status + ' elapsed=' + elapsed);
                    process.exit(2);
                }
            });
            setTimeout(() => process.exit(99), 30000);
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
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("TIMEOUT_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn notify_wakes_count_only() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "count.js",
        r#"
            const buf = new ArrayBuffer(16);
            const arr = new Int32Array(buf);
            arr[0] = 0;
            const r1 = Atomics.waitAsync(arr, 0, 0, 5000);
            const r2 = Atomics.waitAsync(arr, 0, 0, 5000);
            const r3 = Atomics.waitAsync(arr, 0, 0, 5000);
            const settled = [];
            r1.value.then(s => settled.push('r1:' + s));
            r2.value.then(s => settled.push('r2:' + s));
            r3.value.then(s => settled.push('r3:' + s));
            setTimeout(() => {
                const woken = Atomics.notify(arr, 0, 2);
                if (woken !== 2) {
                    console.error('expected 2 woken, got ' + woken);
                    process.exit(2);
                }
                setTimeout(() => {
                    if (settled.length !== 2) {
                        console.error('expected 2 settled, got', settled);
                        process.exit(3);
                    }
                    Atomics.notify(arr, 0, 1);
                    setTimeout(() => {
                        if (settled.length !== 3) {
                            console.error('expected 3 settled after second notify, got',
                                settled);
                            process.exit(4);
                        }
                        console.log('COUNT_OK ' + settled.join(','));
                        process.exit(0);
                    }, 30);
                }, 30);
            }, 30);
            setTimeout(() => process.exit(99), 30000);
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
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("COUNT_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn views_over_same_buffer_share_waiters() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "shared.js",
        r#"
            const buf = new ArrayBuffer(16);
            // Two Int32Array views over the same buffer.
            const a = new Int32Array(buf);
            const b = new Int32Array(buf);
            a[0] = 0;
            const r = Atomics.waitAsync(a, 0, 0, 5000);
            r.value.then((status) => {
                if (status === 'ok') {
                    console.log('SHARED_OK');
                    process.exit(0);
                } else {
                    console.error('bad status:', status);
                    process.exit(2);
                }
            });
            setTimeout(() => {
                // Notify on the OTHER view - should still wake.
                const woken = Atomics.notify(b, 0, 1);
                if (woken !== 1) {
                    console.error('cross-view notify did not wake: ' + woken);
                    process.exit(3);
                }
            }, 30);
            setTimeout(() => process.exit(99), 30000);
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
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("SHARED_OK"), "STDOUT:\n{stdout}");
}
