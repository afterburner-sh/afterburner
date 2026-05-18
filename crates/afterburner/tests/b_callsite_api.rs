// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Phase 0 / Gap B regression: V8 `CallSite` proto carries the Node-
//! shaped methods that QuickJS doesn't ship natively (`isEval`,
//! `getEvalOrigin`, `isToplevel`, `isConstructor`, `getThis`,
//! `getTypeName`, `getMethodName`). Plugin install patches the proto
//! at Wizer pre-init time so every Store sees a complete API from
//! tick zero.
//!
//! Why this matters: `depd` (transitively required by `body-parser`,
//! `serve-static`, `morgan`, `finalhandler` — which is to say "every
//! Express middleware tree") inspects call frames inside
//! `callSiteLocation` and calls `callSite.isEval()` first. Without the
//! patch this throws `TypeError: not a function` and Express module
//! init aborts before any route is registered.
//!
//! Coverage:
//!   * All 14 CallSite methods (the 7 QuickJS ships + the 7 we patch
//!     in) are functions on the proto and don't throw when called.
//!   * The 7 patched-in methods return Node-conventional sentinel
//!     values (`false`, `null`, `undefined`).
//!   * `Error.prepareStackTrace` invariant — when user code does NOT
//!     install a custom hook, `(new Error()).stack` is still a string.
//!   * Hook is callable: when user code installs
//!     `Error.prepareStackTrace = (_, frames) => frames.map(f => f.isEval())`,
//!     it gets back an array of `false`.
//!   * `depd`-shaped call sequence (the exact pattern that crashed
//!     pre-patch): set hook → captureStackTrace → read .stack → call
//!     `.isEval()` on every frame → restore hook. Round-trips clean.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

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
        .expect("spawn burn")
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} FAILED\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn callsite_methods_are_all_callable() {
    let out = run_burn(
        r#"
        Error.prepareStackTrace = function(_e, frames) { return frames; };
        const obj = {};
        Error.captureStackTrace(obj);
        const f = obj.stack[0];
        const methods = [
            'getFileName', 'getLineNumber', 'getColumnNumber',
            'isEval', 'getEvalOrigin', 'getFunctionName',
            'isToplevel', 'isNative', 'isConstructor',
            'getThis', 'getTypeName', 'getFunction',
            'getMethodName', 'toString',
        ];
        for (const m of methods) {
            if (typeof f[m] !== 'function') {
                throw new Error('CallSite method missing: ' + m);
            }
            // Must not throw when called (Node convention — the API
            // surface is non-throwing, sentinel values for "not
            // applicable").
            f[m]();
        }
        console.log('ok');
        "#,
    );
    assert_ok(&out, "CallSite method completeness");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok"), "stdout = {stdout:?}");
}

#[test]
fn patched_methods_return_node_conventional_sentinels() {
    let out = run_burn(
        r#"
        Error.prepareStackTrace = function(_e, frames) { return frames; };
        const obj = {};
        Error.captureStackTrace(obj);
        const f = obj.stack[0];
        if (f.isEval()        !== false)     throw new Error('isEval expected false, got ' + f.isEval());
        if (f.isToplevel()    !== false)     throw new Error('isToplevel expected false');
        if (f.isConstructor() !== false)     throw new Error('isConstructor expected false');
        if (f.getEvalOrigin() !== undefined) throw new Error('getEvalOrigin expected undefined');
        if (f.getThis()       !== undefined) throw new Error('getThis expected undefined');
        if (f.getTypeName()   !== null)      throw new Error('getTypeName expected null');
        if (f.getMethodName() !== null)      throw new Error('getMethodName expected null');
        console.log('ok');
        "#,
    );
    assert_ok(&out, "CallSite sentinel returns");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok"), "stdout = {stdout:?}");
}

#[test]
fn error_stack_remains_a_string_when_no_hook_installed() {
    // Regression: the patch must NOT set Error.prepareStackTrace
    // globally — user code that doesn't install a hook must still see
    // the default stack-string format.
    let out = run_burn(
        r#"
        const e = new Error('x');
        if (typeof e.stack !== 'string') {
            throw new Error('e.stack should be a string when no hook is set; got ' + typeof e.stack);
        }
        // Sanity: stack contains a frame reference.
        if (e.stack.length < 5) {
            throw new Error('e.stack too short: ' + JSON.stringify(e.stack));
        }
        console.log('ok');
        "#,
    );
    assert_ok(&out, "Error.stack default-string regression");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok"), "stdout = {stdout:?}");
}

#[test]
fn user_prepareStackTrace_hook_sees_patched_proto() {
    let out = run_burn(
        r#"
        Error.prepareStackTrace = function(_e, frames) {
            return frames.map(f => f.isEval());
        };
        const e = new Error('x');
        const stack = e.stack;
        if (!Array.isArray(stack)) throw new Error('stack should be array');
        if (stack.length === 0)    throw new Error('stack empty');
        for (const v of stack) {
            if (v !== false) throw new Error('non-false isEval result: ' + v);
        }
        console.log('ok ' + stack.length);
        "#,
    );
    assert_ok(&out, "user hook with patched method");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("ok "), "stdout = {stdout:?}");
}

#[test]
fn depd_shaped_call_sequence_round_trips() {
    // Exact pattern from `depd/index.js::getStack`:
    //   1. Save current Error.prepareStackTrace.
    //   2. Replace with (_e, stack) => stack.
    //   3. captureStackTrace.
    //   4. Read .stack → array of CallSite frames.
    //   5. Restore previous hook.
    //   6. For each frame, call getFileName/getLineNumber/getColumnNumber
    //      and the previously-missing isEval/getEvalOrigin.
    let out = run_burn(
        r#"
        function getStack() {
            const obj = {};
            const prev = Error.prepareStackTrace;
            Error.prepareStackTrace = (_e, stack) => stack;
            Error.captureStackTrace(obj);
            const stack = obj.stack;
            Error.prepareStackTrace = prev;
            return stack;
        }
        function locate(callSite) {
            return [
                callSite.getFileName() || '<anon>',
                callSite.getLineNumber(),
                callSite.getColumnNumber(),
                callSite.isEval(),
                callSite.getEvalOrigin(),
                callSite.getFunctionName(),
            ];
        }
        const stack = getStack();
        if (!Array.isArray(stack)) throw new Error('stack not array');
        for (const frame of stack) {
            const loc = locate(frame);
            if (loc.length !== 6) throw new Error('locate shape wrong');
        }
        // Confirm the previous hook restoration worked: an Error
        // created after restoration has a string stack.
        const e = new Error('after-restore');
        if (typeof e.stack !== 'string') {
            throw new Error('hook not restored; e.stack is ' + typeof e.stack);
        }
        console.log('ok');
        "#,
    );
    assert_ok(&out, "depd-shaped sequence");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok"), "stdout = {stdout:?}");
}
