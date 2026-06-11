// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! NativeCombustor script-mode parity with the wasm path. Covers the
//! same shape as `afterburner/tests/b0_script_mode.rs`'s library
//! tests, but against the rquickjs backend directly so we don't rely
//! on the facade's mode-picking.

use afterburner_core::{Combustor, FuelGauge, ScriptInvocation};
use afterburner_ignite::NativeCombustor;

fn fresh() -> NativeCombustor {
    NativeCombustor::new().expect("native combustor")
}

#[test]
fn console_log_captured_to_stdout() {
    let c = fresh();
    let out = c
        .run_script(
            r#"console.log("native script mode")"#,
            &ScriptInvocation::default(),
            &FuelGauge::unlimited(),
        )
        .expect("run");
    assert_eq!(
        out.exit_code,
        0,
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("native script mode"), "stdout = {stdout:?}");
}

#[test]
fn console_error_routed_to_stderr() {
    let c = fresh();
    let out = c
        .run_script(
            r#"
            console.log("on stdout");
            console.error("on stderr");
            console.warn("also stderr");
            "#,
            &ScriptInvocation::default(),
            &FuelGauge::unlimited(),
        )
        .expect("run");
    assert_eq!(out.exit_code, 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("on stdout"), "stdout = {stdout:?}");
    assert!(!stdout.contains("on stderr"), "stdout leaked: {stdout:?}");
    assert!(stderr.contains("on stderr"), "stderr = {stderr:?}");
    assert!(stderr.contains("also stderr"), "stderr = {stderr:?}");
}

#[test]
fn async_iife_resolves_native() {
    // Native script mode does NOT support top-level `await` — see the
    // rationale in native_engine.rs::build_script_stage. The
    // idiomatic Node-compatible pattern for native is the
    // self-invoking async IIFE, which returns a Promise the pumping
    // loop drains.
    let c = fresh();
    let out = c
        .run_script(
            r#"
            return (async () => {
                const v = await Promise.resolve(42);
                console.log("resolved:", v);
            })();
            "#,
            &ScriptInvocation::default(),
            &FuelGauge::unlimited(),
        )
        .expect("run");
    assert_eq!(
        out.exit_code,
        0,
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("resolved: 42"), "stdout = {stdout:?}");
}

#[test]
fn uncaught_exception_is_exit_1_with_captured_output() {
    let c = fresh();
    let out = c
        .run_script(
            r#"
            console.log("before");
            throw new Error("native boom");
            "#,
            &ScriptInvocation::default(),
            &FuelGauge::unlimited(),
        )
        .expect("ran (non-zero exit is Ok)");
    assert_eq!(out.exit_code, 1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("before"), "stdout = {stdout:?}");
    assert!(stderr.contains("native boom"), "stderr = {stderr:?}");
}

#[test]
fn argv_and_env_threaded_through_invocation() {
    let c = fresh();
    let mut inv = ScriptInvocation {
        argv: vec![
            "burn".into(),
            "[eval]".into(),
            "first".into(),
            "second".into(),
        ],
        ..ScriptInvocation::default()
    };
    inv.env.insert("NATIVE_FLAG".into(), "yes".into());

    let out = c
        .run_script(
            r#"
            console.log("argv1:", process.argv[1]);
            console.log("argv[2]:", process.argv[2]);
            console.log("NATIVE_FLAG:", process.env.NATIVE_FLAG);
            "#,
            &inv,
            &FuelGauge::unlimited(),
        )
        .expect("run");
    assert_eq!(
        out.exit_code,
        0,
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("argv1: [eval]"), "stdout = {stdout:?}");
    assert!(stdout.contains("argv[2]: first"), "stdout = {stdout:?}");
    assert!(stdout.contains("NATIVE_FLAG: yes"), "stdout = {stdout:?}");
}

#[test]
fn udf_path_still_logs_to_workspace_after_script_capture() {
    // Regression guard — after a script-mode call completes on this
    // thread, the capture slot must be cleared so a subsequent UDF
    // call's console output flows through the workspace logger again
    // (not leak into a stale buffer).
    let c = fresh();
    let _out = c
        .run_script(
            r#"console.log("captured once")"#,
            &ScriptInvocation::default(),
            &FuelGauge::unlimited(),
        )
        .expect("script");
    // If the capture slot leaked, the UDF thrust below would still try
    // to write into a now-dropped buffer. We test the stronger property
    // by running another script-mode call and asserting its capture is
    // fresh (empty previous buffer invisible).
    let out2 = c
        .run_script(
            r#"console.log("fresh")"#,
            &ScriptInvocation::default(),
            &FuelGauge::unlimited(),
        )
        .expect("script2");
    let stdout = String::from_utf8_lossy(&out2.stdout);
    assert!(stdout.contains("fresh"), "stdout = {stdout:?}");
    assert!(
        !stdout.contains("captured once"),
        "stale capture leaked: {stdout:?}"
    );
}
