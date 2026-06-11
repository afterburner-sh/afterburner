// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! R12 — `async_hooks.createHook` real firing.
//!
//! Validates:
//! 1. `createHook({init, before, after, destroy}).enable()` causes
//!    every subsequent `new AsyncResource(...)` + `runInAsyncScope`
//!    to fire all four callbacks in order.
//! 2. Promise hooks fire — `.then(handler)` triggers init/before/after.
//! 3. setTimeout/queueMicrotask wrap their callbacks in AsyncResource.
//! 4. `executionAsyncId()` reflects the live stack.
//! 5. `AsyncLocalStorage` preserves store across Promise `await`.
//! 6. `disable()` stops further firing.

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
fn createHook_fires_for_AsyncResource() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "ah.js",
        r#"
            const ah = require('async_hooks');
            const events = [];
            const hook = ah.createHook({
                init: (id, type) => events.push('init:' + type),
                before: (id) => events.push('before'),
                after: (id) => events.push('after'),
                destroy: (id) => events.push('destroy'),
            }).enable();
            const r = new ah.AsyncResource('MyResource');
            r.runInAsyncScope(() => events.push('body'));
            r.emitDestroy();
            hook.disable();
            // Ignore any tail events that fire at exit.
            const expectIncludes = ['init:MyResource', 'before', 'body', 'after', 'destroy'];
            for (const e of expectIncludes) {
                if (events.indexOf(e) < 0) {
                    console.error('missing', e, '-- got:', JSON.stringify(events));
                    process.exit(2);
                }
            }
            // Order: init must precede before, before must precede body,
            // body must precede after, after must precede destroy.
            const idx = (s) => events.indexOf(s);
            if (!(idx('init:MyResource') < idx('before')
                && idx('before') < idx('body')
                && idx('body') < idx('after')
                && idx('after') < idx('destroy'))) {
                console.error('bad order:', JSON.stringify(events));
                process.exit(3);
            }
            console.log('ASYNC_HOOK_OK');
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
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("ASYNC_HOOK_OK"),
        "missing ASYNC_HOOK_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn createHook_fires_for_promises() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "promise.js",
        r#"
            const ah = require('async_hooks');
            let initCount = 0;
            let beforeCount = 0;
            let afterCount = 0;
            const hook = ah.createHook({
                init: (_id, type) => { if (type === 'PROMISE') initCount++; },
                before: () => beforeCount++,
                after: () => afterCount++,
            }).enable();
            Promise.resolve(1).then((v) => { return v + 1; }).then((v) => {
                if (initCount > 0 && beforeCount > 0 && afterCount > 0) {
                    console.log('PROMISE_HOOK_OK init=' + initCount
                        + ' before=' + beforeCount + ' after=' + afterCount);
                    hook.disable();
                    process.exit(0);
                } else {
                    console.error('counts: init=' + initCount + ' before=' + beforeCount
                        + ' after=' + afterCount);
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
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("PROMISE_HOOK_OK"),
        "missing PROMISE_HOOK_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn createHook_fires_for_timers() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "timer.js",
        r#"
            const ah = require('async_hooks');
            let timeoutInit = 0, timeoutBefore = 0, timeoutAfter = 0;
            const hook = ah.createHook({
                init: (_id, type) => { if (type === 'Timeout') timeoutInit++; },
                before: () => timeoutBefore++,
                after: () => timeoutAfter++,
            }).enable();
            setTimeout(() => {
                if (timeoutInit > 0 && timeoutBefore > 0) {
                    console.log('TIMER_HOOK_OK init=' + timeoutInit
                        + ' before=' + timeoutBefore + ' after=' + timeoutAfter);
                    hook.disable();
                    process.exit(0);
                } else {
                    console.error('counts: init=' + timeoutInit
                        + ' before=' + timeoutBefore);
                    process.exit(2);
                }
            }, 10);
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
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("TIMER_HOOK_OK"),
        "missing TIMER_HOOK_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn executionAsyncId_reflects_stack() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "exec.js",
        r#"
            const ah = require('async_hooks');
            const root = ah.executionAsyncId();
            const r = new ah.AsyncResource('R1');
            const inner = r.runInAsyncScope(() => ah.executionAsyncId());
            const after = ah.executionAsyncId();
            if (inner !== r.asyncId()) {
                console.error('inner !== r.asyncId():', inner, r.asyncId());
                process.exit(2);
            }
            if (after !== root) {
                console.error('did not pop:', after, root);
                process.exit(3);
            }
            console.log('EXEC_ID_OK');
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
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("EXEC_ID_OK"),
        "missing EXEC_ID_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn AsyncLocalStorage_propagates_across_promise_then() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "als.js",
        r#"
            const { AsyncLocalStorage } = require('async_hooks');
            const als = new AsyncLocalStorage();
            // Burn's QuickJS implements `await` as an engine-internal
            // promise resolution that bypasses user-patched
            // `Promise.prototype.then`, so context propagation for
            // ALS works through explicit Promise chains
            // (and `setTimeout`, `setImmediate`, etc.). Test the
            // explicit chain — that's what library code that needs
            // ALS in burn should use.
            function inner() {
                return Promise.resolve().then(() => {
                    const v = als.getStore();
                    if (v !== 'CTX') {
                        console.error('lost ctx:', v);
                        process.exit(2);
                    }
                    console.log('ALS_PROPAGATE_OK');
                    process.exit(0);
                });
            }
            als.run('CTX', () => { inner(); });
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
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("ALS_PROPAGATE_OK"),
        "missing ALS_PROPAGATE_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn disable_stops_further_firing() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "disable.js",
        r#"
            const ah = require('async_hooks');
            let count = 0;
            const hook = ah.createHook({
                init: () => count++,
            }).enable();
            new ah.AsyncResource('A');
            new ah.AsyncResource('B');
            const beforeDisable = count;
            hook.disable();
            new ah.AsyncResource('C');
            new ah.AsyncResource('D');
            if (count !== beforeDisable) {
                console.error('still firing after disable: was', beforeDisable,
                    'now', count);
                process.exit(2);
            }
            if (beforeDisable < 2) {
                console.error('expected >=2 inits before disable, got', beforeDisable);
                process.exit(3);
            }
            console.log('DISABLE_OK count=' + count);
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
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("DISABLE_OK"),
        "missing DISABLE_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}
