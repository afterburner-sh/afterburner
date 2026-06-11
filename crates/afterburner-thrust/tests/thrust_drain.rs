// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! P6 gate: graceful shutdown drains pending queued jobs before
//! workers exit, with a hard-deadline force-exit fallback.

use afterburner_core::FuelGauge;
use afterburner_thrust::{ThrustEngine, ThrustEngineConfig};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn mk_engine_with_drain(workers: usize, drain_deadline: Duration) -> Arc<ThrustEngine> {
    let cfg = ThrustEngineConfig {
        compute_workers: workers,
        shutdown_drain_deadline: drain_deadline,
        ..ThrustEngineConfig::default()
    };
    ThrustEngine::new(cfg).expect("engine new")
}

#[test]
fn drop_drains_queued_jobs_before_exiting() {
    // Submit a wave of CPU-bound thrusts, drop the engine, and assert
    // every job's reply made it back to the caller (i.e. workers
    // didn't drop the queue mid-flight). Drain deadline is 30s - well
    // above the actual completion time so we know we're testing the
    // drain path, not the force-exit fallback.
    let engine = mk_engine_with_drain(2, Duration::from_secs(30));
    let id = engine
        .register(
            "module.exports = (d) => { let s=0; for(let i=0;i<200000;i++) s+=i; return d.n; };",
        )
        .unwrap();

    let mut handles = Vec::with_capacity(20);
    for i in 0..20 {
        handles.push(engine.thrust(&id, json!({ "n": i }), FuelGauge::unlimited(), None));
    }

    // Drop while jobs are still in flight. shutdown(self) calls
    // try_unwrap which succeeds (we hold the only Arc - handles share
    // only the reply channels).
    engine.shutdown();

    // Every handle must return a real value - not a closed-channel Err.
    for (i, h) in handles.into_iter().enumerate() {
        let v = h.recv().expect("drain must complete every queued job");
        assert_eq!(v, json!(i));
    }
}

#[test]
fn force_exit_fires_when_drain_deadline_elapses() {
    // 100ms deadline + a slow workload that can't possibly all finish
    // in 100ms. Some jobs MUST get the closed-channel Err on recv().
    let engine = mk_engine_with_drain(1, Duration::from_millis(100));
    let id = engine
        .register("module.exports = () => { let s=0; for(let i=0;i<500000;i++) s+=i; return s; };")
        .unwrap();

    let mut handles = Vec::with_capacity(40);
    for _ in 0..40 {
        handles.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), None));
    }

    let t0 = Instant::now();
    engine.shutdown();
    let drop_took = t0.elapsed();

    // Drop returned within the deadline + reasonable join slack.
    assert!(
        drop_took < Duration::from_secs(2),
        "Drop took {drop_took:?}; force-exit didn't fire"
    );

    // Some completed; some got the closed-channel Err. We require both.
    let mut ok = 0;
    let mut closed = 0;
    for h in handles {
        match h.recv() {
            Ok(_) => ok += 1,
            Err(_) => closed += 1,
        }
    }
    assert!(
        ok > 0,
        "expected some jobs to complete during the 100ms drain window"
    );
    assert!(
        closed > 0,
        "expected some jobs to be force-cancelled past the deadline"
    );
    assert_eq!(ok + closed, 40);
}

#[test]
fn drop_is_quick_with_idle_workers() {
    // No queued work. Drop should not pay the full drain deadline -
    // workers see the Drain state, find empty queues, exit immediately.
    let engine = mk_engine_with_drain(4, Duration::from_secs(30));
    // Touch register to spin up the combustor before the timing
    // measurement (so we're not measuring lazy-init overhead).
    let _ = engine.register("module.exports = () => 1").unwrap();

    let t0 = Instant::now();
    engine.shutdown();
    let took = t0.elapsed();

    assert!(
        took < Duration::from_millis(500),
        "Drop with idle workers took {took:?}; should be near-instant"
    );
}

#[test]
fn shutdown_drain_deadline_zero_skips_drain_phase() {
    // shutdown_drain_deadline == 0 means "go straight to force exit".
    // Useful for callers that want fast Drop + accept losing in-flight
    // jobs. We just verify it doesn't deadlock and exits fast.
    let engine = mk_engine_with_drain(2, Duration::ZERO);
    let id = engine.register("module.exports = () => 1").unwrap();
    for _ in 0..10 {
        let _ = engine.thrust(&id, json!(null), FuelGauge::unlimited(), None);
    }
    let t0 = Instant::now();
    engine.shutdown();
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(1));
}
