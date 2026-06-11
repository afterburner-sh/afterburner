// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Phase E: event-loop regression tests. Scripts can now return
//! Promises / use `await` / chain `.then()` / schedule microtasks via
//! `queueMicrotask`, because:
//!
//! * afterburner-plugin enables `javy_plugin_api::Config::event_loop(true)`
//!   so Javy drains pending microtasks after the script invocation.
//! * afterburner-ignite pumps `ctx.execute_pending_job()` after the
//!   envelope eval when the user returned a thenable.
//!
//! The same JS script runs against both engines — behavior must match.

use afterburner_core::{Combustor, FuelGauge, Manifold};
use afterburner_ignite::NativeCombustor;
use afterburner_wasi::{WasmCombustor, WasmConfig};
use serde_json::{Value, json};

fn native() -> NativeCombustor {
    NativeCombustor::new().unwrap()
}
fn wasm() -> WasmCombustor {
    WasmCombustor::new(WasmConfig::default()).unwrap()
}

fn run_on<C: Combustor>(c: &C, src: &str) -> Value {
    let id = c.ignite(src).unwrap();
    let limits = FuelGauge {
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    c.thrust(&id, &json!(null), &limits).unwrap()
}

/// Helper for tests that must pass on both engines.
fn run_both(src: &str) -> (Value, Value) {
    let n = run_on(&native(), src);
    let w = run_on(&wasm(), src);
    assert_eq!(n, w, "native vs wasm mismatch");
    (n, w)
}

#[test]
fn returns_plain_value_still_works() {
    // Sanity: the Phase E changes didn't break the fast path. A script
    // that returns a non-thenable goes through the pre-Phase-E code
    // route (no pump, no Promise.from_value) on native; on WASM it's
    // handled directly by Javy.
    let (n, _) = run_both("module.exports = () => 42;");
    assert_eq!(n, json!(42));
}

#[test]
fn returns_resolved_promise() {
    let (n, _) = run_both("module.exports = () => Promise.resolve(123);");
    assert_eq!(n, json!(123));
}

#[test]
fn promise_then_chain() {
    let src = r#"
        module.exports = () =>
            Promise.resolve(10)
                .then(n => n * 2)
                .then(n => n + 1)
                .then(n => ({ result: n }));
    "#;
    let (n, _) = run_both(src);
    assert_eq!(n, json!({ "result": 21 }));
}

#[test]
fn async_await_resolves() {
    let src = r#"
        module.exports = async () => {
            const a = await Promise.resolve(5);
            const b = await Promise.resolve(7);
            return a + b;
        };
    "#;
    let (n, _) = run_both(src);
    assert_eq!(n, json!(12));
}

#[test]
fn queue_microtask_fires_before_return() {
    let src = r#"
        module.exports = () => new Promise(resolve => {
            let hits = 0;
            queueMicrotask(() => { hits++; });
            queueMicrotask(() => { hits++; resolve(hits); });
        });
    "#;
    let (n, _) = run_both(src);
    assert_eq!(n, json!(2));
}

#[test]
fn set_timeout_zero_defers_to_microtask() {
    // Prior to Phase E, `setTimeout(fn, 0)` fired synchronously. Now
    // it queues a microtask: the inline code runs first, then the
    // callback. Observing the order is the test.
    let src = r#"
        module.exports = () => new Promise(resolve => {
            const order = [];
            order.push('before');
            setTimeout(() => {
                order.push('timer');
                resolve(order);
            }, 0);
            order.push('after');
        });
    "#;
    let (n, _) = run_both(src);
    assert_eq!(n, json!(["before", "after", "timer"]));
}

#[test]
fn set_timeout_nonzero_still_throws() {
    let src = r#"
        module.exports = () => {
            try { setTimeout(() => {}, 100); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let (n, _) = run_both(src);
    let msg = n.as_str().unwrap().to_lowercase();
    assert!(
        msg.contains("non-zero") || msg.contains("not supported"),
        "got: {msg}"
    );
}

#[test]
fn set_immediate_defers() {
    let src = r#"
        module.exports = () => new Promise(resolve => {
            const order = [];
            order.push('sync');
            setImmediate(() => {
                order.push('immediate');
                resolve(order);
            });
        });
    "#;
    let (n, _) = run_both(src);
    assert_eq!(n, json!(["sync", "immediate"]));
}

#[test]
fn nested_microtasks_resolve() {
    // Microtask that schedules another microtask — the pump must
    // drain the queue until empty.
    let src = r#"
        module.exports = () => new Promise(resolve => {
            let n = 0;
            function step() {
                n++;
                if (n < 5) queueMicrotask(step);
                else resolve(n);
            }
            queueMicrotask(step);
        });
    "#;
    let (n, _) = run_both(src);
    assert_eq!(n, json!(5));
}

#[test]
fn promise_rejection_surfaces_as_error() {
    let src = r#"
        module.exports = async () => {
            try { await Promise.reject(new Error('boom')); return 'unexpected'; }
            catch (e) { return { caught: e.message }; }
        };
    "#;
    let (n, _) = run_both(src);
    assert_eq!(n, json!({ "caught": "boom" }));
}

#[test]
fn unhandled_rejection_surfaces_as_thrust_error() {
    // Prior review flagged the WASM envelope's .then without .catch as
    // potentially swallowing uncaught rejections. This test locks in
    // the contract: if a script returns a rejecting Promise without
    // handling it, thrust returns Err, not a successful empty value.
    let src = r#"
        module.exports = () => Promise.reject(new Error('unhandled'));
    "#;
    // Native
    {
        let c = native();
        let id = c.ignite(src).unwrap();
        let lim = FuelGauge {
            manifold: Manifold::sealed(),
            ..FuelGauge::default()
        };
        let out = c.thrust(&id, &json!(null), &lim);
        assert!(
            out.is_err(),
            "native: expected Err on unhandled rejection; got {out:?}"
        );
    }
    // WASM
    {
        let c = wasm();
        let id = c.ignite(src).unwrap();
        let lim = FuelGauge {
            manifold: Manifold::sealed(),
            ..FuelGauge::default()
        };
        let out = c.thrust(&id, &json!(null), &lim);
        assert!(
            out.is_err(),
            "wasm: expected Err on unhandled rejection; got {out:?}"
        );
    }
}

#[test]
fn native_infinite_microtask_chain_is_bounded() {
    // A script that schedules itself forever as a microtask previously
    // wedged the native engine: each job's opcode count was too low
    // for the rquickjs interrupt handler to accumulate enough counter
    // ticks to fire. run_script now caps the drain loop at a hard
    // MAX_PUMP_ITERATIONS, surfacing as FuelExhausted.
    let src = r#"
        module.exports = () => new Promise(() => {
            function step() { queueMicrotask(step); }
            step();
        });
    "#;
    let lim = FuelGauge {
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    let c = native();
    let id = c.ignite(src).unwrap();
    let out = c.thrust(&id, &json!(null), &lim);
    assert!(
        matches!(out, Err(afterburner_core::AfterburnerError::FuelExhausted)),
        "expected FuelExhausted from the pump cap; got {out:?}"
    );
}

#[test]
fn wasm_infinite_microtask_chain_is_bounded() {
    // T5 gate (plan §6, REVIEW.md Pitfall 18): the WASM counterpart of
    // the native pump-cap test. A script that schedules itself forever
    // as a microtask must not wedge the worker — we expect Timeout or
    // FuelExhausted, *never* a hang.
    //
    // The mechanism is wasmtime epoch interruption: the shared engine
    // ticker bumps the epoch every 10 ms; Cranelift-emitted safepoints
    // inside Javy's Promise::finish pump re-read the epoch on each
    // iteration and surface a Trap::Interrupt when the deadline elapses.
    // Fuel is the secondary guard — if safepoints are sparse enough
    // that epoch misses the pump, fuel still exhausts eventually.
    let src = r#"
        module.exports = () => new Promise(() => {
            function step() { queueMicrotask(step); }
            step();
        });
    "#;
    let lim = FuelGauge {
        // Large-but-finite fuel so exhaustion is a real outcome, not a
        // liveness workaround.
        fuel: Some(5_000_000_000),
        // 3-second wall clock is comfortable above the 10 ms tick
        // resolution — the pump must terminate well before we'd notice
        // in CI.
        timeout_ms: Some(3_000),
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    let c = wasm();
    let id = c.ignite(src).unwrap();
    let start = std::time::Instant::now();
    let out = c.thrust(&id, &json!(null), &lim);
    let elapsed = start.elapsed();
    // Upper bound: something caught it. Elapsed is bounded by fuel OR
    // epoch, and we gave both finite budgets.
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "WASM microtask pump did not terminate within 10s (elapsed={elapsed:?})"
    );
    assert!(
        matches!(
            out,
            Err(afterburner_core::AfterburnerError::Timeout)
                | Err(afterburner_core::AfterburnerError::FuelExhausted)
        ),
        "expected Timeout or FuelExhausted from the WASM pump; got {out:?}"
    );
}

#[test]
fn wasm_microtask_pump_bounded_by_fuel_alone() {
    // P8 defense-in-depth: prove *fuel* — without any wall-clock
    // timeout — also bounds the microtask pump. If the epoch mechanism
    // ever silently broke on a new wasmtime version, fuel is still a
    // hard cap.
    //
    // We set `timeout_ms = None` (wall clock disabled), `fuel =
    // 100_000_000` (moderate but finite), and assert the pump
    // terminates with `FuelExhausted` in bounded wall time.
    let src = r#"
        module.exports = () => new Promise(() => {
            function step() { queueMicrotask(step); }
            step();
        });
    "#;
    let lim = FuelGauge {
        fuel: Some(100_000_000),
        timeout_ms: None,
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    let c = wasm();
    let id = c.ignite(src).unwrap();
    let start = std::time::Instant::now();
    let out = c.thrust(&id, &json!(null), &lim);
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "fuel-only pump cap did not terminate within 10s (elapsed={elapsed:?})"
    );
    assert!(
        matches!(out, Err(afterburner_core::AfterburnerError::FuelExhausted)),
        "expected FuelExhausted, got {out:?}"
    );
}

#[test]
fn wasm_microtask_pump_bounded_by_timeout_alone() {
    // P8 defense-in-depth (the other belt): prove *timeout* — without
    // any fuel cap — also bounds the pump. Pairs with
    // `wasm_microtask_pump_bounded_by_fuel_alone` so we know each
    // mechanism stands on its own.
    let src = r#"
        module.exports = () => new Promise(() => {
            function step() { queueMicrotask(step); }
            step();
        });
    "#;
    let lim = FuelGauge {
        fuel: None,
        timeout_ms: Some(500),
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    let c = wasm();
    let id = c.ignite(src).unwrap();
    let start = std::time::Instant::now();
    let out = c.thrust(&id, &json!(null), &lim);
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "timeout-only pump cap did not terminate within 5s (elapsed={elapsed:?})"
    );
    assert!(
        matches!(out, Err(afterburner_core::AfterburnerError::Timeout)),
        "expected Timeout, got {out:?}"
    );
}
