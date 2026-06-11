// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B1 phase gate: `require('node:X')` and `require('X')` parity.
//!
//! Every module documented in `docs/NODE_COMPAT.md` must be reachable
//! under both forms. The plan's minimum gate lists path, events, url,
//! buffer, stream; we validate the full published surface here so
//! drop-in Node scripts don't trip on a missing factory registration.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Run `burn -e SRC --sandbox --allow-*=...` and return its output.
/// We explicitly sandbox + grant open env/net so scripts can call
/// host-backed modules without the default CLI banner flipping to
/// open everywhere.
fn run_burn(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("burn")
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} FAILED\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Helper that asserts `require('node:X')` and `require('X')` both
/// resolve to an object (or function). If either throws, the test
/// fails with the bad module name in the message.
fn both_forms(module: &str) {
    let src = format!(
        r#"
        const bare = require("{module}");
        const ns   = require("node:{module}");
        if (!bare) throw new Error("bare require('{module}') returned falsy");
        if (!ns) throw new Error("require('node:{module}') returned falsy");
        // Same factory + same cache key → identical reference.
        if (bare !== ns) throw new Error("require('{module}') !== require('node:{module}')");
        console.log("ok {module}");
        "#
    );
    let out = run_burn(&src);
    assert_ok(&out, &format!("require('{module}')"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("ok {module}")),
        "stdout = {stdout:?}"
    );
}

// ---- plan-gate modules (from §5 B1) ------------------------------------

#[test]
fn require_path() {
    both_forms("path");
}
#[test]
fn require_events() {
    both_forms("events");
}
#[test]
fn require_url() {
    both_forms("url");
}
#[test]
fn require_buffer() {
    both_forms("buffer");
}
#[test]
fn require_stream() {
    both_forms("stream");
}

// ---- pure-JS, always-available --------------------------------------

#[test]
fn require_assert() {
    both_forms("assert");
}
#[test]
fn require_console() {
    both_forms("console");
}
#[test]
fn require_punycode() {
    both_forms("punycode");
}
#[test]
fn require_querystring() {
    both_forms("querystring");
}
#[test]
fn require_string_decoder() {
    both_forms("string_decoder");
}
#[test]
fn require_timers() {
    both_forms("timers");
}
#[test]
fn require_util() {
    both_forms("util");
}

// ---- host-backed (capability-gated; `-A` grants everything) ------------

#[test]
fn require_fs() {
    both_forms("fs");
}
#[test]
fn require_fs_promises() {
    both_forms("fs/promises");
}
#[test]
fn require_crypto() {
    both_forms("crypto");
}
#[test]
fn require_http() {
    both_forms("http");
}
#[test]
fn require_https() {
    both_forms("https");
}
#[test]
fn require_dns() {
    both_forms("dns");
}
#[test]
fn require_dns_promises() {
    both_forms("dns/promises");
}
#[test]
fn require_os() {
    both_forms("os");
}
#[test]
fn require_zlib() {
    both_forms("zlib");
}
#[test]
fn require_child_process() {
    both_forms("child_process");
}

// ---- newer sub-module paths Node supports --------------------------

#[test]
fn require_stream_promises() {
    both_forms("stream/promises");
}
#[test]
fn require_timers_promises() {
    both_forms("timers/promises");
}

// ---- behaviours beyond pure resolution ----------------------------------

#[test]
fn unknown_module_throws_node_shaped_error() {
    // Node's error for a missing require is `Cannot find module 'X'`
    // with code ERR_MODULE_NOT_FOUND. We match the message.
    let out = run_burn(
        r#"
        try { require('does-not-exist'); throw new Error('unexpected'); }
        catch (e) {
            if (/Cannot find module/.test(String(e.message || e))) {
                console.log("ok");
            } else {
                throw new Error("bad shape: " + (e.message || e));
            }
        }
        "#,
    );
    assert_ok(&out, "unknown module error shape");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("ok"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn node_prefix_with_unknown_also_throws() {
    let out = run_burn(
        r#"
        try { require('node:does-not-exist'); throw new Error('unexpected'); }
        catch (e) {
            if (/Cannot find module/.test(String(e.message || e))) console.log("ok");
            else throw e;
        }
        "#,
    );
    assert_ok(&out, "node: prefix unknown module");
    assert!(String::from_utf8_lossy(&out.stdout).contains("ok"));
}

#[test]
fn fs_promises_readfile_works_end_to_end() {
    // Confirms that `fs/promises` doesn't just resolve - its API
    // actually hits the host, matching `require('fs').promises`.
    let src = r#"
        (async () => {
            const fs = require('node:fs');
            const fsp = require('node:fs/promises');
            if (fs.promises !== fsp) throw new Error("fs.promises !== fs/promises");
            // Round-trip a temp file.
            const tmp = "/tmp/burn-b1-fsp-" + process.pid + ".txt";
            await fsp.writeFile(tmp, "ok");
            const back = await fsp.readFile(tmp, "utf8");
            if (back !== "ok") throw new Error("read != wrote: " + back);
            await fsp.unlink(tmp);
            console.log("fs/promises ok");
        })();
        "#;
    let out = run_burn(src);
    assert_ok(&out, "fs/promises round-trip");
    assert!(String::from_utf8_lossy(&out.stdout).contains("fs/promises ok"));
}
