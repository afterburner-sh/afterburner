// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Process shutdown-lifecycle events: `process.on('beforeExit')` and
//! `process.on('exit')` must fire when a CLI script finishes by
//! draining the event loop (rather than calling `process.exit()`).
//!
//! This is load-bearing for real Node programs: npm — and a great many
//! CLIs — buffer ALL of their output and flush it from a single
//! `process.on('exit')` handler, then exit *naturally* (they set
//! `process.exitCode` and let the loop drain; they never call
//! `process.exit()`). Before the daemon event loop learned to emit
//! these events on natural drain, such programs produced **zero**
//! output and never finalized — `burn npm install express` printed
//! nothing and installed nothing. See
//! `afterburner-wasi/src/daemon_shard_pool.rs::emit_lifecycle` and the
//! `'lifecycle'` branch of the daemon-event dispatcher.
//!
//! Node guarantees:
//! * `'exit'` fires exactly once, regardless of how the process ends.
//! * `'beforeExit'` fires when the loop empties and may re-arm it
//!   (scheduling more work), in which case it can fire again later.
//! * `'beforeExit'` does NOT fire when the process ends via
//!   `process.exit()`.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Run `burn -e <code>` single-shard with the resource banner muted.
/// Returns `(stdout, stderr, success)`.
fn run_eval(code: &str) -> (String, String, bool) {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        // Lifecycle is per-shard; pin to one shard so a single 'exit'
        // emission is deterministic (non-HTTP scripts collapse to one
        // shard anyway, but be explicit).
        .env("BURN_SHARDS", "1")
        .arg("-e")
        .arg(code)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

#[test]
fn exit_event_fires_on_natural_completion() {
    // The npm shape: a handler registered on 'exit' must run when the
    // script ends by draining the loop.
    let (out, err, ok) = run_eval(
        "process.on('exit', () => process.stdout.write('EXIT-HANDLER\\n')); console.log('BODY');",
    );
    assert!(ok, "burn should exit 0; stderr={err}");
    assert!(out.contains("BODY"), "body output missing: {out:?}");
    assert!(
        out.contains("EXIT-HANDLER"),
        "process.on('exit') handler did not run on natural completion: {out:?}"
    );
}

#[test]
fn before_exit_event_fires_on_natural_completion() {
    let (out, err, ok) = run_eval(
        "process.on('beforeExit', () => process.stdout.write('BEFORE-EXIT\\n')); console.log('BODY');",
    );
    assert!(ok, "stderr={err}");
    assert!(
        out.contains("BEFORE-EXIT"),
        "process.on('beforeExit') did not fire: {out:?}"
    );
}

#[test]
fn lifecycle_order_is_body_then_before_exit_then_exit() {
    let (out, err, ok) = run_eval(
        "process.on('beforeExit', () => console.log('MARK-BEFORE')); \
         process.on('exit', () => console.log('MARK-EXIT')); \
         console.log('MARK-BODY');",
    );
    assert!(ok, "stderr={err}");
    let body = out.find("MARK-BODY");
    let before = out.find("MARK-BEFORE");
    let exit = out.find("MARK-EXIT");
    assert!(
        body.is_some() && before.is_some() && exit.is_some(),
        "all three lifecycle markers should be present: {out:?}"
    );
    assert!(body < before, "body must precede beforeExit: {out:?}");
    assert!(before < exit, "beforeExit must precede exit: {out:?}");
}

#[test]
fn exit_event_fires_exactly_once_on_natural_completion() {
    let (out, err, ok) = run_eval(
        "process.on('exit', () => process.stdout.write('EXIT-ONCE\\n')); console.log('BODY');",
    );
    assert!(ok, "stderr={err}");
    assert_eq!(
        out.matches("EXIT-ONCE").count(),
        1,
        "'exit' must fire exactly once: {out:?}"
    );
}

#[test]
fn exit_handler_receives_zero_code_on_clean_drain() {
    let (out, err, ok) =
        run_eval("process.on('exit', (code) => process.stdout.write('CODE=' + code + '\\n'));");
    assert!(ok, "stderr={err}");
    assert!(
        out.contains("CODE=0"),
        "exit handler should receive code 0 on clean drain: {out:?}"
    );
}

#[test]
fn before_exit_can_rearm_the_event_loop() {
    // A 'beforeExit' handler that schedules new async work keeps the
    // process alive; the scheduled work runs, then the loop drains
    // again and 'exit' fires after it.
    let (out, err, ok) = run_eval(
        "let armed = false; \
         process.on('beforeExit', () => { if (!armed) { armed = true; setTimeout(() => console.log('REARMED'), 5); } }); \
         process.on('exit', () => process.stdout.write('FINAL-EXIT\\n')); \
         console.log('BODY');",
    );
    assert!(ok, "stderr={err}");
    assert!(
        out.contains("REARMED"),
        "beforeExit re-arm work did not run: {out:?}"
    );
    assert!(
        out.contains("FINAL-EXIT"),
        "exit did not fire after the re-arm drained: {out:?}"
    );
    assert!(
        out.find("REARMED") < out.find("FINAL-EXIT"),
        "exit must fire after the re-armed work completes: {out:?}"
    );
}

#[test]
fn explicit_process_exit_fires_exit_exactly_once() {
    // The double-emit guard: `process.exit()` emits 'exit' itself, and
    // the host must NOT emit it a second time on teardown.
    let (out, err, ok) = run_eval(
        "process.on('exit', () => process.stdout.write('ONLY-ONCE\\n')); console.log('BODY'); process.exit(0);",
    );
    assert!(ok, "stderr={err}");
    assert_eq!(
        out.matches("ONLY-ONCE").count(),
        1,
        "'exit' must fire exactly once even with an explicit process.exit(): {out:?}"
    );
}

#[test]
fn exit_fires_after_pending_async_work_completes() {
    // Async work that resolves through the event loop must complete
    // before 'exit' fires — the exact npm pattern (do async I/O, then
    // flush from the exit handler).
    let (out, err, ok) = run_eval(
        "require('fs').promises.readFile('/etc/hostname', 'utf8') \
           .then(() => console.log('ASYNC-DONE')); \
         process.on('exit', () => process.stdout.write('EXIT-AFTER\\n'));",
    );
    assert!(ok, "stderr={err}");
    assert!(
        out.contains("ASYNC-DONE"),
        "pending async work did not complete before exit: {out:?}"
    );
    assert!(out.contains("EXIT-AFTER"), "exit did not fire: {out:?}");
    assert!(
        out.find("ASYNC-DONE") < out.find("EXIT-AFTER"),
        "exit must fire only after async work resolved: {out:?}"
    );
}
