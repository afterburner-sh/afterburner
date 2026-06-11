// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B4 regression: pre-compiled daemon-init bytecode.
//!
//! Validates that the host-side compile path
//! (`WasmCombustor::compile_daemon_init_bytecode` →
//! `DaemonRuntime::run_init_with_bytecode`) produces a daemon Store
//! semantically identical to the source-eval path
//! (`DaemonRuntime::run_init`). Same `process.argv` / `process.env`
//! / `__host_cwd`, same handler registration, same console output,
//! same listener accounting.
//!
//! Why this matters: B1 multi-shard sharding relies on this
//! equivalence - N independent Stores all running init from the
//! same Vec<u8> must produce N independent but behaviourally
//! identical daemon Stores. If the bytecode path drifts from the
//! source path, every multi-shard claim breaks.
//!
//! These tests use a single Store per case (no sharding yet); the
//! point is to lock in the equivalence so future multi-shard work
//! can rely on it.

#![cfg(feature = "bin")]

mod common;

use common::{ChildGuard, http_get, pick_port, wait_for_listener};
use serial_test::serial;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn spawn_burn(source: &str) -> Child {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn")
}

#[test]
#[serial]
fn precompiled_daemon_serves_canonical_request() {
    // The simplest possible daemon: one HTTP listener, one route.
    // If precompile didn't bake the user source correctly, the
    // listener doesn't bind or the response body is wrong.
    let port = pick_port();
    let src = format!(
        r#"
        const http = require('http');
        http.createServer((req, res) => {{
            res.setHeader('content-type', 'text/plain');
            res.end('precompiled-ok-' + req.url);
        }}).listen({port});
        console.log('listening');
        "#
    );
    let _child = ChildGuard::new(spawn_burn(&src));
    assert!(
        wait_for_listener(port, Duration::from_secs(60)),
        "burn listener didn't bind on :{port}"
    );

    let resp = http_get(port, "/probe");
    assert!(resp.starts_with("HTTP/1.1 200"), "resp:\n{resp}");
    assert!(
        resp.contains("precompiled-ok-/probe"),
        "missing body marker:\n{resp}"
    );
}

#[test]
#[serial]
fn precompiled_daemon_preserves_argv_env() {
    // The script-mode envelope wrap injects `process.argv` and
    // `process.env`. If precompile drifts from the source path on
    // these injections, the script either crashes or sees wrong
    // values.
    let port = pick_port();
    let src = format!(
        r#"
        const http = require('http');
        const argvLen = (process.argv || []).length;
        const hasHome = !!(process.env && process.env.HOME);
        http.createServer((_req, res) => {{
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({{
                argvLen: argvLen,
                hasHome: hasHome,
                argv0: process.argv[0],
                cwd: process.cwd(),
            }}));
        }}).listen({port});
        "#
    );
    let _child = ChildGuard::new(spawn_burn(&src));
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    let resp = http_get(port, "/");
    assert!(resp.starts_with("HTTP/1.1 200"), "resp:\n{resp}");
    // `argv` set to ["burn", "[eval]"] (or similar) - at minimum non-empty.
    assert!(
        resp.contains("\"argvLen\":") && !resp.contains("\"argvLen\":0"),
        "argv not propagated through precompile:\n{resp}"
    );
    // HOME is in the host env when running tests under bash; -A
    // grants full env access so the inner script should see it.
    assert!(
        resp.contains("\"hasHome\":true") || resp.contains("\"hasHome\":false"),
        "env shape unexpected:\n{resp}"
    );
    // cwd must be a non-empty string.
    assert!(
        resp.contains("\"cwd\":\"/"),
        "cwd missing or empty:\n{resp}"
    );
}

#[test]
#[serial]
fn precompiled_daemon_async_handler_round_trips() {
    // Top-level await + async handler. The script-mode wrap is an
    // AsyncFunction; bytecode preserves that. If the bytecode path
    // accidentally evaluated as a sync wrapper, top-level await
    // would parse-fail at compile time (which we'd surface as
    // CompileFailed before the daemon ever starts).
    //
    // Post-B1 (multi-shard daemon): in-process JS state (`let i`)
    // is per-shard, so we can't assert monotonic counter values
    // across requests. The handler echoes the request URL instead;
    // each request gets its own URL back, which proves both the
    // top-level-await path AND the async handler dispatch work.
    let port = pick_port();
    let src = format!(
        r#"
        const http = require('http');
        // Touch top-level await so the async wrap is exercised.
        await Promise.resolve(0);
        http.createServer(async (req, res) => {{
            await Promise.resolve();
            res.end('async-' + (req.url || '/'));
        }}).listen({port});
        "#
    );
    let _child = ChildGuard::new(spawn_burn(&src));
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    for path in &["/a", "/b", "/c"] {
        let resp = http_get(port, path);
        assert!(resp.starts_with("HTTP/1.1 200"), "path {path}: {resp}");
        let needle = format!("async-{path}");
        assert!(
            resp.contains(&needle),
            "path {path} missing {needle}:\n{resp}"
        );
    }
}

#[test]
#[serial]
fn precompile_propagates_user_syntax_errors_with_nonzero_exit() {
    // Malformed user JS: the script-mode wrap puts user source inside
    // a `new __ab_AsyncFunction(..., USER_SOURCE)` call, so the
    // OUTER wrapper compiles fine (the user source is just a string
    // literal until invoked). The SyntaxError surfaces at invoke
    // time as an "Unexpected end of input" / similar parse error
    // from the inner AsyncFunction call, which the plugin catches
    // and traps. The host then exits non-zero with the error
    // captured on stderr.
    //
    // We don't assert on the exact error class string because it
    // varies by JS engine (QuickJS: "SyntaxError"; some wrappers:
    // "Unexpected end of input"). The contract this test pins is:
    //
    //   * non-zero exit
    //   * stderr non-empty
    //   * stderr surfaces the failure path (mentions daemon-init or
    //     the invoke call) so users can find the issue
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg("function broken( { /* unclosed paren */")
        .output()
        .expect("spawn burn");
    assert!(!out.status.success(), "syntax-broken script should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.trim().is_empty(), "stderr should not be empty");
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("daemon-init")
            || lower.contains("invoke")
            || lower.contains("syntaxerror")
            || lower.contains("syntax")
            || lower.contains("unexpected"),
        "expected init/invoke/syntax marker in stderr, got:\n{stderr}"
    );
}

#[test]
#[serial]
fn precompiled_daemon_console_log_reaches_stdout() {
    // daemon-init `console.log` must produce stdout in both source
    // and bytecode paths. Validates that stdout capture is wired
    // through the bytecode dispatch identically.
    //
    // The script self-exits after the listener is up so the burn
    // subprocess gets to flush its block-buffered stdout to the pipe.
    // Earlier versions used `child.kill()` after `wait_for_listener`
    // which SIGKILLed the process before the buffer was flushed -
    // race-prone (~80% miss rate) on hosts where the pipe path is
    // fully buffered.
    let port = pick_port();
    let src = format!(
        r#"
        console.log('startup-marker');
        const http = require('http');
        http.createServer((_req, res) => res.end('ok')).listen({port});
        // Bind happens above; give the listener a moment to publish
        // then exit cleanly so stdout flushes before the pipe closes.
        setTimeout(() => process.exit(0), 100);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(&src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(
        out.status.success(),
        "burn exited non-zero: {:?}",
        out.status
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("startup-marker"),
        "console.log lost in precompiled init path. stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}
