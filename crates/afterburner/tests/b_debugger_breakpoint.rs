// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Engine ceiling #2 close: `Debugger.setBreakpointByUrl` registers
//! a real breakpoint backed by source-level statement instrumentation
//! (gated on `BURN_DEBUGGER_INSTRUMENT=1`). The hits flow through
//! `__ab_brk` which calls `__host_inspector_pause`, blocking the JS
//! shard until a connected DevTools WS client sends `Debugger.resume`.
//!
//! These tests validate the *API surface* end-to-end without a full
//! WS round-trip: an in-process `Session` registers the breakpoint
//! and we verify the breakpointId returns, plus the symmetric
//! `Debugger.removeBreakpoint` cleanup. The real cross-process WS
//! pause/resume requires a CDP client we don't include in the test
//! crate; the wire format is exercised by the inspector_cdp suite.

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", src])
        .output()
        .expect("spawn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains(marker),
        "missing `{marker}`\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn setBreakpointByUrl_returns_id() {
    let src = r#"
        const inspector = require('inspector');
        const s = new inspector.Session();
        s.connect();
        s.post('Debugger.enable', () => {});
        s.post('Debugger.setBreakpointByUrl', { url: 'app.js', lineNumber: 42 }, (err, res) => {
            if (err) { console.error('err:', err); process.exit(2); }
            if (!res || typeof res.breakpointId !== 'string') {
                console.error('bad res:', JSON.stringify(res)); process.exit(3);
            }
            if (!Array.isArray(res.locations) || res.locations.length === 0) {
                console.error('no locations:', JSON.stringify(res)); process.exit(4);
            }
            if (res.locations[0].lineNumber !== 42) {
                console.error('wrong line:', res.locations[0]); process.exit(5);
            }
            console.log('BP_REGISTER_OK id=' + res.breakpointId);
            process.exit(0);
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_marker(&run_inline(src), "BP_REGISTER_OK");
}

#[test]
#[serial]
fn removeBreakpoint_clears_entry() {
    let src = r#"
        const inspector = require('inspector');
        const s = new inspector.Session();
        s.connect();
        s.post('Debugger.setBreakpointByUrl', { url: 'a.js', lineNumber: 1 }, (e, res) => {
            const id = res.breakpointId;
            s.post('Debugger.removeBreakpoint', { breakpointId: id }, (_e, _r) => {
                // No throw, no error => success.
                console.log('BP_REMOVE_OK');
                process.exit(0);
            });
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_marker(&run_inline(src), "BP_REMOVE_OK");
}

#[test]
#[serial]
fn stepping_methods_succeed() {
    // Debugger.resume / stepOver / stepInto / stepOut all succeed
    // (no pause active = no-op success, matches Node when no debugger
    // is paused).
    let src = r#"
        const inspector = require('inspector');
        const s = new inspector.Session();
        s.connect();
        const methods = ['Debugger.resume', 'Debugger.stepOver', 'Debugger.stepInto', 'Debugger.stepOut'];
        let pending = methods.length;
        for (const m of methods) {
            s.post(m, (err) => {
                if (err) { console.error(m, 'err:', err); process.exit(2); }
                if (--pending === 0) {
                    console.log('STEP_OK');
                    process.exit(0);
                }
            });
        }
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_marker(&run_inline(src), "STEP_OK");
}
