// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! R11 - `inspector` Chrome DevTools Protocol bridge.
//!
//! Validates:
//! 1. In-process `Session.post('Runtime.evaluate', ...)` returns the
//!    real JS evaluation result.
//! 2. `Session.post('Runtime.compileScript' / 'Runtime.runScript', ...)`
//!    round-trips the script.
//! 3. `Session.post('HeapProfiler.takeHeapSnapshot', ...)` emits
//!    `HeapProfiler.addHeapSnapshotChunk` events with non-empty bytes.
//! 4. `Session.post('Profiler.start' / 'Profiler.stop')` returns a
//!    populated CDP `Profile` object.
//! 5. `inspector.open(port)` boots the HTTP listener and serves
//!    `/json/version` with the `webSocketDebuggerUrl` field.
//! 6. `inspector.url()` returns the live ws:// URL after open.

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
fn session_runtime_evaluate_real() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "eval.js",
        r#"
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            session.post('Runtime.enable', () => {});
            session.post('Runtime.evaluate', { expression: '1 + 2 + 3' }, (err, res) => {
                if (err) { console.error('err', err); process.exit(2); }
                if (res && res.result && res.result.value === 6) {
                    console.log('EVAL_OK');
                    process.exit(0);
                } else {
                    console.error('unexpected:', JSON.stringify(res));
                    process.exit(3);
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
        stdout.contains("EVAL_OK"),
        "missing EVAL_OK\nSTDOUT:\n{stdout}"
    );
}

#[test]
#[serial]
fn session_runtime_evaluate_exception_packaged() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "evalex.js",
        r#"
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            session.post('Runtime.evaluate', { expression: 'throw new Error("boom")' }, (err, res) => {
                if (err) { console.error('err', err); process.exit(2); }
                if (res && res.exceptionDetails) {
                    console.log('EXC_OK');
                    process.exit(0);
                } else {
                    console.error('unexpected:', JSON.stringify(res));
                    process.exit(3);
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
        stdout.contains("EXC_OK"),
        "missing EXC_OK\nSTDOUT:\n{stdout}"
    );
}

#[test]
#[serial]
fn session_compile_run_script_roundtrip() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "compile.js",
        r#"
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            session.post('Runtime.compileScript', {
                expression: 'globalThis.__hit = (globalThis.__hit || 0) + 42; globalThis.__hit',
                sourceURL: 'test.js',
                persistScript: true,
            }, (err, res) => {
                if (err) { console.error('compile err', err); process.exit(2); }
                if (!res || !res.scriptId) {
                    console.error('no scriptId:', JSON.stringify(res));
                    process.exit(3);
                }
                session.post('Runtime.runScript', { scriptId: res.scriptId }, (e2, r2) => {
                    if (e2) { console.error('run err', e2); process.exit(4); }
                    if (r2 && r2.result && r2.result.value === 42) {
                        console.log('RUN_OK');
                        process.exit(0);
                    } else {
                        console.error('unexpected run result:', JSON.stringify(r2));
                        process.exit(5);
                    }
                });
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
        stdout.contains("RUN_OK"),
        "missing RUN_OK\nSTDOUT:\n{stdout}"
    );
}

#[test]
#[serial]
fn session_heap_profiler_emits_chunks() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "heap.js",
        r#"
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            let chunkCount = 0;
            let totalBytes = 0;
            session.on('HeapProfiler.addHeapSnapshotChunk', ({ params }) => {
                chunkCount++;
                totalBytes += params.chunk.length;
            });
            session.post('HeapProfiler.takeHeapSnapshot', {}, (err) => {
                if (err) { console.error('err', err); process.exit(2); }
                if (chunkCount > 0 && totalBytes > 100) {
                    console.log('HEAP_OK chunks=' + chunkCount + ' bytes=' + totalBytes);
                    process.exit(0);
                } else {
                    console.error('no chunks: count=' + chunkCount + ' bytes=' + totalBytes);
                    process.exit(3);
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
        stdout.contains("HEAP_OK"),
        "missing HEAP_OK\nSTDOUT:\n{stdout}"
    );
}

#[test]
#[serial]
fn session_profiler_start_stop_returns_profile() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "prof.js",
        r#"
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            session.post('Profiler.enable', () => {
                session.post('Profiler.start', () => {
                    // Burn some Promise microtasks so the profiler
                    // sampler observes activity.
                    let i = 0;
                    function spin() {
                        if (i++ > 100) {
                            session.post('Profiler.stop', (err, res) => {
                                if (err) { console.error('stop err', err); process.exit(2); }
                                if (res && res.profile && res.profile.nodes && res.profile.nodes.length > 0) {
                                    console.log('PROF_OK nodes=' + res.profile.nodes.length);
                                    process.exit(0);
                                } else {
                                    console.error('bad profile:', JSON.stringify(res).slice(0, 300));
                                    process.exit(3);
                                }
                            });
                            return;
                        }
                        Promise.resolve().then(spin);
                    }
                    spin();
                });
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
        stdout.contains("PROF_OK"),
        "missing PROF_OK\nSTDOUT:\n{stdout}"
    );
}

#[test]
#[serial]
fn inspector_open_serves_json_version() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "open.js",
        r#"
            const inspector = require('inspector');
            const http = require('http');
            inspector.open(0, '127.0.0.1', false);
            const url = inspector.url();
            console.log('URL=' + url);
            const m = url.match(/ws:\/\/([^:]+):(\d+)/);
            if (!m) { console.error('bad url'); process.exit(2); }
            const host = m[1], port = m[2];
            // Self-connect over HTTP and pull /json/version.
            const req = http.request({ host, port, path: '/json/version' }, (res) => {
                let body = '';
                res.on('data', (c) => body += c);
                res.on('end', () => {
                    if (body.includes('webSocketDebuggerUrl')) {
                        console.log('JSON_OK');
                        inspector.close();
                        setTimeout(() => process.exit(0), 50);
                    } else {
                        console.error('no debugger url:', body);
                        process.exit(3);
                    }
                });
            });
            req.on('error', (e) => { console.error('http err', e); process.exit(4); });
            req.end();
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
        stdout.contains("JSON_OK"),
        "missing JSON_OK\nSTDOUT:\n{stdout}"
    );
}

#[test]
#[serial]
fn unknown_method_surfaces_typed_error() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "unknown.js",
        r#"
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            session.post('NoSuchDomain.unknown', {}, (err, res) => {
                if (err && err.code === 'ERR_INSPECTOR_COMMAND_UNKNOWN') {
                    console.log('UNKNOWN_OK');
                    process.exit(0);
                } else {
                    console.error('expected typed err, got:', err, res);
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
        stdout.contains("UNKNOWN_OK"),
        "missing UNKNOWN_OK\nSTDOUT:\n{stdout}"
    );
}

#[test]
#[serial]
fn breakpoint_registers_real_id() {
    // The previous stub-era test asserted that
    // `Debugger.setBreakpointByUrl` threw
    // `ERR_INSPECTOR_NOT_SUPPORTED_ON_BURN`. Engine ceiling #2 is now
    // closed (source-level statement instrumentation backs real
    // breakpoint hits, see `b_debugger_breakpoint`), so the method
    // returns a real `breakpointId` instead of throwing.
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "bp.js",
        r#"
            const inspector = require('inspector');
            const session = new inspector.Session();
            session.connect();
            session.post('Debugger.setBreakpointByUrl', {
                url: 'app.js',
                lineNumber: 0,
            }, (err, res) => {
                if (err) {
                    console.error('unexpected err:', err); process.exit(2);
                }
                if (!res || typeof res.breakpointId !== 'string') {
                    console.error('no id:', JSON.stringify(res)); process.exit(3);
                }
                console.log('BP_REGISTER_OK');
                process.exit(0);
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
        stdout.contains("BP_REGISTER_OK"),
        "missing BP_REGISTER_OK\nSTDOUT:\n{stdout}"
    );
}
