// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Security tests - every threat listed in the design doc's security
//! matrix exercised through the real WasmCombustor.
//!
//! These integration tests are gated on a working Javy CLI. When Javy
//! isn't available the tests print a skip notice and exit 0 - CI failure
//! there would obscure real regressions.

use afterburner_core::{AfterburnerError, Combustor, FuelGauge};
use afterburner_wasi::{WasmCombustor, WasmConfig};
use serde_json::json;

fn make_combustor() -> WasmCombustor {
    WasmCombustor::new(WasmConfig::default()).unwrap()
}

macro_rules! combustor_or_skip {
    () => {
        make_combustor()
    };
}

#[test]
fn infinite_loop_terminates_via_fuel() {
    let c = combustor_or_skip!();
    let id = c
        .ignite("module.exports = () => { while (true) { /* burn */ } }")
        .unwrap();
    let limits = FuelGauge {
        fuel: Some(10_000_000),
        ..FuelGauge::default()
    };
    let err = c.thrust(&id, &json!(null), &limits).unwrap_err();
    assert!(
        matches!(err, AfterburnerError::FuelExhausted),
        "expected FuelExhausted, got {err:?}"
    );
}

#[test]
fn infinite_loop_terminates_via_timeout() {
    let c = combustor_or_skip!();
    let id = c
        .ignite("module.exports = () => { while (true) { /* burn */ } }")
        .unwrap();
    let limits = FuelGauge {
        timeout_ms: Some(500),
        ..FuelGauge::default()
    };
    let err = c.thrust(&id, &json!(null), &limits).unwrap_err();
    assert!(
        matches!(err, AfterburnerError::Timeout),
        "expected Timeout, got {err:?}"
    );
}

#[test]
fn memory_bomb_capped() {
    let c = combustor_or_skip!();
    // Allocate a very large string until the memory cap is hit.
    let id = c
        .ignite(
            "module.exports = () => { \
                 let s = 'x'; \
                 for (let i = 0; i < 40; i++) s = s + s; \
                 return s.length; \
             }",
        )
        .unwrap();
    let limits = FuelGauge {
        memory_bytes: Some(4 * 1024 * 1024),
        timeout_ms: Some(10_000),
        ..FuelGauge::default()
    };
    let err = c.thrust(&id, &json!(null), &limits).unwrap_err();
    // Could surface as MemoryLimit (wasmtime ResourceLimiter at
    // runtime growth), FuelExhausted (if we run out first), Timeout,
    // WasmTrap (QuickJS allocation failure becoming an uncaught
    // exception), OR Engine (wasmtime's pooling-allocator pre-instantiate
    // rejects when the plugin's minimum memory size exceeds the
    // FuelGauge cap). All five are acceptable - what matters is that
    // the runaway script never gets to actually run unbounded.
    assert!(
        matches!(
            err,
            AfterburnerError::MemoryLimit
                | AfterburnerError::FuelExhausted
                | AfterburnerError::Timeout
                | AfterburnerError::WasmTrap(_)
                | AfterburnerError::Engine(_)
        ),
        "expected termination error; got {err:?}"
    );
}

#[test]
fn no_fs_access() {
    let c = combustor_or_skip!();
    // Javy doesn't expose Node.js `fs`; `require('fs')` is a reference
    // error. The uncaught exception surfaces as a non-zero WASM exit.
    let id = c
        .ignite("module.exports = () => require('fs').readFileSync('/etc/passwd')")
        .unwrap();
    let err = c
        .thrust(&id, &json!(null), &FuelGauge::unlimited())
        .unwrap_err();
    assert!(
        matches!(err, AfterburnerError::WasmTrap(_)),
        "expected trap when FS access is attempted; got {err:?}"
    );
}

#[test]
fn no_network_access_by_default() {
    let c = combustor_or_skip!();
    // Under sealed Manifold (default), `fetch()` / `http.request()` /
    // the plugin's host import all surface a permission error. The
    // polyfill catches the host failure and throws with `EACCES`-style
    // semantics; the script captures it and returns the message.
    let id = c
        .ignite(
            r#"
            module.exports = () => {
                try {
                    require('http').get('http://example.com/', () => {});
                    return 'unexpected';
                } catch (e) { return e.message; }
            };
            "#,
        )
        .unwrap();
    let out = c
        .thrust(&id, &json!(null), &FuelGauge::unlimited())
        .unwrap();
    let msg = out.as_str().unwrap().to_lowercase();
    assert!(
        msg.contains("permission denied") || msg.contains("not available"),
        "expected permission denial; got {msg}"
    );
}

#[test]
fn no_process_spawn() {
    let c = combustor_or_skip!();
    // `process.spawn`, `child_process` - none of it exists in Javy.
    let id = c
        .ignite("module.exports = () => require('child_process').execSync('/bin/ls')")
        .unwrap();
    let err = c
        .thrust(&id, &json!(null), &FuelGauge::unlimited())
        .unwrap_err();
    assert!(matches!(err, AfterburnerError::WasmTrap(_)));
}

#[test]
fn fuel_exhaustion_returns_typed_error() {
    // Synonym for infinite_loop_terminates_via_fuel - kept separately to
    // align with the plan's security matrix checklist.
    let c = combustor_or_skip!();
    let id = c
        .ignite("module.exports = () => { let n = 0; while (true) n++; }")
        .unwrap();
    let limits = FuelGauge {
        fuel: Some(1_000_000),
        ..FuelGauge::default()
    };
    let err = c.thrust(&id, &json!(null), &limits).unwrap_err();
    assert!(matches!(err, AfterburnerError::FuelExhausted));
}

#[test]
fn concurrent_invocations_isolated() {
    use std::sync::Arc;
    use std::thread;

    let c = Arc::new(combustor_or_skip!());
    let id = c
        .ignite(
            "module.exports = (d) => { \
                 let sum = 0; \
                 for (let i = 0; i < d.n; i++) sum += i; \
                 return sum; \
             }",
        )
        .unwrap();

    // 8 threads, each calling thrust with a different n. Per-invocation
    // Stores mean no state bleeds between calls - each must see only its
    // own input and compute the correct answer.
    let mut handles = Vec::new();
    for n in 1..=8u64 {
        let c = c.clone();
        handles.push(thread::spawn(move || {
            let out = c
                .thrust(&id, &json!({ "n": n }), &FuelGauge::unlimited())
                .unwrap();
            // Sum of 0..n-1 = n*(n-1)/2
            let expected = n * (n - 1) / 2;
            assert_eq!(out, json!(expected));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_thrusts_do_not_steal_each_others_timeouts() {
    // Regression for the engine-global increment_epoch bug. Previously,
    // a thrust with a short timeout would spawn a sleeper that called
    // engine.increment_epoch(), tripping every concurrent thrust whose
    // store had set_epoch_deadline(1). With the shared ticker, each
    // thrust's deadline is computed in ticks, so a fast script that
    // finishes well within its own deadline must NOT trip even when a
    // sibling thrust on the same engine has a much shorter timeout.
    use std::sync::Arc;
    use std::thread;

    let c = Arc::new(combustor_or_skip!());
    let trivial = c.ignite("module.exports = (d) => d.n + 1").unwrap();
    let infinite = c
        .ignite("module.exports = () => { while (true) {} }")
        .unwrap();

    // Generous deadline for the trivial side; an infinite loop that the
    // ticker will trap after ~50 ms on the other side.
    let trivial_limits = FuelGauge {
        timeout_ms: Some(10_000),
        ..FuelGauge::default()
    };
    let infinite_limits = FuelGauge {
        timeout_ms: Some(50),
        ..FuelGauge::default()
    };

    // Spawn the doomed infinite-loop thrust first so its short deadline
    // is in flight while the trivial thrusts run.
    let infinite_handle = {
        let c = c.clone();
        let id = infinite;
        thread::spawn(move || {
            let err = c.thrust(&id, &json!(null), &infinite_limits).unwrap_err();
            assert!(
                matches!(err, AfterburnerError::Timeout),
                "infinite-loop side must time out, got {err:?}"
            );
        })
    };

    // Concurrently run a batch of trivial thrusts with a long deadline.
    // None of them should observe the infinite-loop's timeout.
    let mut trivial_handles = Vec::new();
    for n in 0..16u64 {
        let c = c.clone();
        let id = trivial;
        let limits = trivial_limits.clone();
        trivial_handles.push(thread::spawn(move || {
            let out = c.thrust(&id, &json!({"n": n}), &limits).unwrap();
            assert_eq!(out, json!(n + 1));
        }));
    }
    for h in trivial_handles {
        h.join().unwrap();
    }
    infinite_handle.join().unwrap();
}
