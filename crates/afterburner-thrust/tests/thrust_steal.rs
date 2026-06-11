// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! T3 gate: imbalanced load (every job hashes to one worker) still
//! drains across N workers via steal-when-idle.
//!
//! We pin every thrust to the *same* `ScriptId` - so hash routing
//! deterministically targets a single worker - then submit a CPU-bound
//! batch and assert the wall-clock falls well below "single-threaded
//! sum of execution times." Since `worker_id` victim selection in
//! `worker_loop` cycles through peers, all idle workers should pick up
//! some of the load.
//!
//! Container-friendliness mirrors `thrust_scale.rs`: skip cleanly when
//! `available_parallelism() < 2`.

use afterburner_core::FuelGauge;
use afterburner_thrust::{ThrustEngine, ThrustEngineConfig};
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

fn mk_engine(n_workers: usize) -> Arc<ThrustEngine> {
    let cfg = ThrustEngineConfig {
        compute_workers: n_workers,
        ..ThrustEngineConfig::default()
    };
    ThrustEngine::new(cfg).expect("engine new")
}

#[test]
fn imbalanced_workload_drains_via_stealing() {
    if std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        < 2
    {
        eprintln!("skipping steal test: available_parallelism() < 2");
        return;
    }

    // CPU-bound: 1.5M-iter sum. ~25-40 ms per thrust in debug.
    let source = "module.exports = () => { let s=0; for(let i=0;i<1500000;i++) s+=i; return s; };";

    // Single worker: all 16 jobs go to it sequentially. Baseline.
    let engine_1 = mk_engine(1);
    let id_1 = engine_1.register(source).unwrap();
    let lim = FuelGauge::unlimited();

    let n_jobs = 16;
    let t0 = Instant::now();
    let mut h = Vec::with_capacity(n_jobs);
    for _ in 0..n_jobs {
        h.push(engine_1.thrust(&id_1, json!(null), lim.clone(), None));
    }
    for handle in h {
        handle.recv().unwrap();
    }
    let t1_dur = t0.elapsed();
    drop(engine_1);

    // 4 workers, but every job has the *same* ScriptId - so without
    // steal-when-idle, all jobs would land on a single worker and the
    // wall-clock would match the 1-worker baseline. With steal, idle
    // workers grab jobs from the saturated peer's queue.
    let engine_4 = mk_engine(4);
    let id_4 = engine_4.register(source).unwrap();
    let t0 = Instant::now();
    let mut h = Vec::with_capacity(n_jobs);
    for _ in 0..n_jobs {
        h.push(engine_4.thrust(&id_4, json!(null), lim.clone(), None));
    }
    for handle in h {
        handle.recv().unwrap();
    }
    let t4_dur = t0.elapsed();

    let speedup = t1_dur.as_secs_f64() / t4_dur.as_secs_f64();
    eprintln!(
        "imbalanced 16 jobs, same-script: 1w={t1_dur:?}  4w={t4_dur:?}  speedup={speedup:.2}x"
    );

    // 4-worker speedup should beat 1.5× even on a 2-CPU CI box (where
    // theoretical max is 2×). On 4+ CPUs we typically see >2.5×. The
    // 1.5× floor is the regression boundary - anything below means
    // steal stopped working.
    assert!(
        speedup >= 1.5,
        "expected ≥1.5x speedup with steal, got {speedup:.2}x"
    );
    assert_eq!(engine_4.stats().thrusts_completed, n_jobs as u64);
}

#[test]
fn idle_workers_park_and_dont_burn_cpu() {
    // Sanity: if no work arrives, workers shouldn't busy-loop. We can't
    // measure CPU directly without heavy machinery, but we can at least
    // verify the engine constructs, sits idle for 200ms, and then
    // picks up a single thrust within 50ms - which would NOT happen if
    // workers were spinning at 100% with no backoff (they'd starve the
    // OS scheduler enough that the test runner skews).
    let engine = mk_engine(4);
    let id = engine.register("module.exports = () => 7").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let t0 = Instant::now();
    let v = engine
        .thrust_sync(&id, json!(null), FuelGauge::unlimited(), None)
        .unwrap();
    let took = t0.elapsed();
    assert_eq!(v, json!(7));
    assert!(
        took < std::time::Duration::from_millis(500),
        "first thrust after idle period took too long: {took:?}"
    );
}

#[test]
fn shutdown_during_active_load_completes_cleanly() {
    // Submit a wave, drop the engine while jobs may still be in
    // flight. shutdown should drain workers within a reasonable bound
    // and not deadlock.
    let engine = mk_engine(2);
    let id = engine
        .register("module.exports = () => { let s=0; for(let i=0;i<300000;i++) s+=i; return s; };")
        .unwrap();
    for _ in 0..6 {
        let _ = engine.thrust(&id, json!(null), FuelGauge::unlimited(), None);
    }
    let t0 = Instant::now();
    drop(engine); // triggers Drop → shutdown → join
    let join_took = t0.elapsed();
    assert!(
        join_took < std::time::Duration::from_secs(5),
        "shutdown took too long under active load: {join_took:?}"
    );
}
