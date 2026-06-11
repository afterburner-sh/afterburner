// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! P2 gate: bounded queues + injector + `Overloaded` backpressure.
//!
//! Production-grade scheduling must refuse new work when both the
//! per-worker queue and the global injector are at cap, instead of
//! growing memory unboundedly. Refusal surfaces as
//! `AfterburnerError::Overloaded` on the thrust handle's recv.

use afterburner_core::{AfterburnerError, FuelGauge};
use afterburner_thrust::{ThrustEngine, ThrustEngineConfig};
use serde_json::json;
use std::sync::Arc;

fn mk(local: usize, injector: usize, workers: usize) -> Arc<ThrustEngine> {
    let cfg = ThrustEngineConfig {
        compute_workers: workers,
        local_queue_capacity: local,
        injector_capacity: injector,
        ..ThrustEngineConfig::default()
    };
    ThrustEngine::new(cfg).expect("engine new")
}

#[test]
fn overflow_to_injector_is_drained() {
    // With local_cap = 2 and a single worker, submitting 8 thrusts of
    // a CPU-bound script means the first ~2 fill the local queue, the
    // remainder spill to the injector. Workers drain both. Final state:
    // every job completes, the via_injector counter is non-zero.
    let engine = mk(2, 16, 1);
    let id = engine
        .register("module.exports = () => { let s=0; for(let i=0;i<200000;i++) s+=i; return s; };")
        .unwrap();

    let mut handles = Vec::with_capacity(8);
    for _ in 0..8 {
        handles.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), None));
    }
    for h in handles {
        let _ = h.recv().expect("thrust must succeed");
    }
    let s = engine.stats();
    assert_eq!(s.thrusts_completed, 8);
    assert!(
        s.thrusts_via_injector >= 1,
        "expected at least one job to spill to injector; got {}",
        s.thrusts_via_injector
    );
    assert_eq!(s.thrusts_overloaded, 0, "no overload expected");
}

#[test]
fn both_full_returns_overloaded() {
    // local_cap=1 + injector_cap=1 + 1 worker + a slow script - burst
    // 16 thrusts. The first 1-3 land (one in worker, one in injector,
    // one being processed); the rest hit Overloaded.
    let engine = mk(1, 1, 1);
    let id = engine
        .register("module.exports = () => { let s=0; for(let i=0;i<300000;i++) s+=i; return s; };")
        .unwrap();

    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        handles.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), None));
    }
    let mut ok = 0;
    let mut overloaded = 0;
    for h in handles {
        match h.recv() {
            Ok(_) => ok += 1,
            Err(AfterburnerError::Overloaded) => overloaded += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert!(
        overloaded >= 5,
        "expected several Overloaded refusals; got {overloaded}"
    );
    assert!(ok >= 1, "expected at least one to succeed; got {ok}");
    let s = engine.stats();
    assert_eq!(s.thrusts_overloaded as usize, overloaded);
    assert_eq!(s.thrusts_completed as usize, ok);
}

#[test]
fn injector_drained_by_idle_workers() {
    // Hash-route all jobs to worker 0 by reusing the same ScriptId.
    // local_cap = 1 → 7 of 8 submissions spill to injector. The OTHER
    // workers are idle and must steal from the injector via the
    // every-64-iter injector poll + post-steal-sweep injector check.
    let engine = mk(1, 64, 4);
    let id = engine.register("module.exports = () => 1").unwrap();

    let mut handles = Vec::with_capacity(8);
    for _ in 0..8 {
        handles.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), None));
    }
    for h in handles {
        h.recv().unwrap();
    }
    let s = engine.stats();
    assert_eq!(s.thrusts_completed, 8);
    assert!(s.thrusts_via_injector >= 1);
}

#[test]
fn overloaded_does_not_count_as_completed() {
    let engine = mk(1, 1, 1);
    let id = engine
        .register("module.exports = () => { for(let i=0;i<200000;i++); return 1; };")
        .unwrap();
    let mut over = 0;
    let mut ok = 0;
    let mut hs = Vec::new();
    for _ in 0..40 {
        hs.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), None));
    }
    for h in hs {
        match h.recv() {
            Ok(_) => ok += 1,
            Err(AfterburnerError::Overloaded) => over += 1,
            other => panic!("unexpected: {other:?}"),
        }
    }
    let s = engine.stats();
    assert_eq!(s.thrusts_completed as usize, ok);
    assert_eq!(s.thrusts_overloaded as usize, over);
    assert!(over > 0 && ok > 0);
}

#[test]
fn cap_zero_falls_back_to_default() {
    // local_queue_capacity == 0 should adopt 256 (the plan §5.1 default).
    // We test it doesn't panic / lock up under burst.
    let cfg = ThrustEngineConfig {
        compute_workers: 2,
        local_queue_capacity: 0,
        injector_capacity: 0,
        ..ThrustEngineConfig::default()
    };
    let engine = ThrustEngine::new(cfg).unwrap();
    let id = engine.register("module.exports = () => 1").unwrap();
    let mut hs = Vec::new();
    for _ in 0..50 {
        hs.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), None));
    }
    for h in hs {
        h.recv().unwrap();
    }
    assert_eq!(engine.stats().thrusts_completed, 50);
    assert_eq!(engine.stats().thrusts_overloaded, 0);
}
