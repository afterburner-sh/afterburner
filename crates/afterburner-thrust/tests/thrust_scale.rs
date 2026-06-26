// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! T2 gate: N workers + hash routing scale linearly.
//!
//! This test measures aggregate throughput with 1 worker vs N workers on
//! a CPU-bound JS workload and asserts N-worker throughput is materially
//! better than single-worker.
//!
//! ### Container-friendliness
//!
//! Per the workspace constraint (project memory:
//! `project_docker_cap_constraint`), this test short-circuits cleanly
//! when the runtime only has one CPU available - e.g., a Docker
//! container pinned via `--cpus=1`. No CAP_SYS_NICE or real-time
//! scheduling is used; measurements rely on wall-clock only.
//!
//! ### Hash-routing caveat
//!
//! `ThrustEngine` routes `thrust()` calls by `hash(script_id) % N`, so
//! the *same* ScriptId always lands on the same worker (plan §5.1
//! affinity). To actually observe parallelism with N=2 we construct N
//! source variants explicitly chosen so their SHA-256 hashes reduce to
//! distinct worker indices.
//!
//! The hash formula is a stable crate contract, documented in plan §5.1,
//! and replicating it here is intentional so the integration test doesn't
//! need crate-private access.

use afterburner_core::{FuelGauge, Manifold, ScriptId, sha256};
use afterburner_thrust::{ThrustEngine, ThrustEngineConfig};
use serde_json::json;
use std::time::{Duration, Instant};

/// Same routing function `ThrustEngine` uses internally. Documented in
/// plan §5.1 as stable - replicated here for test-only use.
fn route_worker(hash: &[u8; 32], n_workers: usize) -> usize {
    let bytes: [u8; 8] = hash[..8].try_into().unwrap();
    (u64::from_le_bytes(bytes) as usize) % n_workers
}

/// Find `per_worker` source strings (CPU-bound - loop of `iters` steps)
/// that each route to `target_worker` under N-worker hash routing.
///
/// Appends a free-form version comment to the template until the hash
/// lands on the desired worker. Deterministic given the template.
fn sources_targeting_worker(
    target_worker: usize,
    n_workers: usize,
    per_worker: usize,
    iters: u64,
) -> Vec<String> {
    let mut out = Vec::with_capacity(per_worker);
    let mut counter = 0u64;
    while out.len() < per_worker {
        counter += 1;
        let source = format!(
            "/* v{counter} */ module.exports = () => {{ let s=0; for(let i=0;i<{iters};i++) s+=i; return s; }};"
        );
        let hash = sha256(source.as_bytes());
        if route_worker(&hash, n_workers) == target_worker {
            out.push(source);
        }
    }
    out
}

/// Builds a balanced work-set of `per_worker × n_workers` sources, each
/// routing to its intended worker.
fn balanced_workload(n_workers: usize, per_worker: usize, iters: u64) -> Vec<String> {
    let mut all = Vec::with_capacity(n_workers * per_worker);
    for w in 0..n_workers {
        all.extend(sources_targeting_worker(w, n_workers, per_worker, iters));
    }
    all
}

fn run_workload(engine: &ThrustEngine, ids: &[ScriptId]) -> Duration {
    let limits = FuelGauge::unlimited();
    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(ids.len());
    for id in ids {
        handles.push(engine.thrust(id, json!(null), limits.clone(), None));
    }
    for h in handles {
        let out = h.recv();
        // Non-asserting on value; we only care about timing in this test.
        // But we do surface compilation / runtime errors so the test
        // doesn't silently measure failure paths.
        if let Err(e) = out {
            panic!("thrust failed: {e:?}");
        }
    }
    t0.elapsed()
}

fn mk_engine(n_workers: usize) -> std::sync::Arc<ThrustEngine> {
    let cfg = ThrustEngineConfig {
        compute_workers: n_workers,
        ..ThrustEngineConfig::default()
    };
    ThrustEngine::new(cfg).expect("engine new")
}

#[test]
fn two_workers_beat_one_on_cross_script_load() {
    // CPU-throttled environment (Docker --cpus=1, restricted cgroup,
    // etc.) - assert only that the engine still *works*, not that it
    // scales. See project memory `project_docker_cap_constraint`.
    if std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        < 2
    {
        eprintln!("skipping scale test: available_parallelism() < 2");
        return;
    }

    // Each script runs a 2_000_000-iter sum. In debug this is ~40-60 ms
    // per thrust; in release ~5-10 ms. We submit 8 scripts per worker
    // → 16 total, evenly split.
    let iters = 2_000_000u64;
    let per_worker = 8usize;

    // Prepare sources: same hash-route for 1-worker (everything lands
    // on worker 0) but spread 50/50 across 2 workers.
    let sources_1w = balanced_workload(1, per_worker * 2, iters);
    let sources_2w = balanced_workload(2, per_worker, iters);

    // Sanity-check distribution on the 2-worker side.
    let dist: Vec<usize> = sources_2w
        .iter()
        .map(|s| route_worker(&sha256(s.as_bytes()), 2))
        .collect();
    let w0 = dist.iter().filter(|&&i| i == 0).count();
    let w1 = dist.iter().filter(|&&i| i == 1).count();
    assert_eq!(w0, per_worker, "worker-0 share");
    assert_eq!(w1, per_worker, "worker-1 share");

    // 1-worker baseline.
    let engine_1 = mk_engine(1);
    let ids_1: Vec<ScriptId> = sources_1w
        .iter()
        .map(|s| engine_1.register(s).unwrap())
        .collect();
    let t1 = run_workload(&engine_1, &ids_1);
    drop(engine_1);

    // 2-worker run.
    let engine_2 = mk_engine(2);
    let ids_2: Vec<ScriptId> = sources_2w
        .iter()
        .map(|s| engine_2.register(s).unwrap())
        .collect();
    let t2 = run_workload(&engine_2, &ids_2);

    eprintln!("1-worker: {t1:?}  |  2-worker: {t2:?}");

    // Speedup: t1 / t2. Ideal = 2.0. We assert ≥ 1.3× to stay robust
    // under background noise, debug-mode variance, and container CPU
    // jitter. The plan targets 2× on a dedicated box - that's a release-
    // mode, perf-harness claim; this is the regression gate.
    let speedup = t1.as_secs_f64() / t2.as_secs_f64();
    eprintln!("speedup: {speedup:.2}x");
    assert!(
        speedup >= 1.3,
        "expected ≥1.3x speedup at 2 workers, got {speedup:.2}x (t1={t1:?}, t2={t2:?})"
    );
}

#[test]
fn worker_count_reflects_config() {
    let e = mk_engine(3);
    assert_eq!(e.worker_count(), 3);
}

#[test]
fn zero_compute_workers_auto_probes() {
    let e = mk_engine(0);
    // Whatever the host reports. Must be at least 1.
    assert!(e.worker_count() >= 1);
}

#[test]
fn hash_routing_is_stable_across_registrations() {
    // Same source → same ScriptId → same worker under the same engine
    // layout. This is the contract `route_worker` leans on.
    let engine = mk_engine(4);
    let src = "module.exports = () => 42;";
    let id1 = engine.register(src).unwrap();
    let id2 = engine.register(src).unwrap();
    assert_eq!(id1.hash, id2.hash);
    assert_eq!(
        route_worker(&id1.hash, 4),
        route_worker(&id2.hash, 4),
        "same hash must route to the same worker"
    );
}

#[test]
fn fanout_completes_under_cap_load() {
    // Smaller-scale correctness check, intentionally short. Every
    // thrust must complete with a real value - not be lost by hash
    // routing, not deadlock the worker loop. Runs even on 1-CPU
    // containers.
    let engine = mk_engine(4);
    let sources = balanced_workload(4, 3, 100_000);
    let ids: Vec<_> = sources
        .iter()
        .map(|s| engine.register(s).unwrap())
        .collect();

    let lims = FuelGauge {
        timeout_ms: Some(30_000),
        manifold: Manifold::sealed(),
        ..FuelGauge::unlimited()
    };
    let mut handles = Vec::with_capacity(ids.len());
    for id in &ids {
        handles.push(engine.thrust(id, json!(null), lims.clone(), None));
    }
    for h in handles {
        let v = h.recv().expect("thrust result");
        assert!(v.is_number(), "expected number result, got {v:?}");
    }
    assert_eq!(engine.stats().thrusts_completed, ids.len() as u64);
}
