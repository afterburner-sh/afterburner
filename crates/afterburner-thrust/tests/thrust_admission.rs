// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! T4 gate: single-tenant flood is throttled to the configured rate;
//! other tenants are unaffected; `tenant: None` bypasses the bucket.
//!
//! Wall-clock based; uses only `Instant::now()`. No SCHED_FIFO, no
//! signals. Runs under default Docker caps.

use afterburner_core::{AfterburnerError, FuelGauge};
use afterburner_thrust::{TenantId, ThrustEngine, ThrustEngineConfig};
use serde_json::json;

fn mk_engine_with_admission(rate: u64, burst: u64) -> std::sync::Arc<ThrustEngine> {
    let cfg = ThrustEngineConfig {
        compute_workers: 2,
        admission_tokens_per_sec: Some(rate),
        admission_burst_tokens: burst,
        ..ThrustEngineConfig::default()
    };
    ThrustEngine::new(cfg).expect("engine new")
}

fn tid(n: u32) -> TenantId {
    TenantId::new(n).unwrap()
}

#[test]
fn single_tenant_flood_is_throttled() {
    // 10 tokens/sec, burst 2 — a flood of 50 from one tenant should
    // see exactly 2 allowed and 48 rejected in the immediate window.
    let engine = mk_engine_with_admission(10, 2);
    let id = engine.register("module.exports = () => 1").unwrap();

    let mut handles = Vec::with_capacity(50);
    for _ in 0..50 {
        handles.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), Some(tid(1))));
    }
    let mut allowed = 0;
    let mut rate_limited = 0;
    for h in handles {
        match h.recv() {
            Ok(_) => allowed += 1,
            Err(AfterburnerError::RateLimited { tenant, .. }) => {
                assert_eq!(tenant, Some(1));
                rate_limited += 1;
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    // GCRA with burst=2 allows 2 immediate; the window is small enough
    // that the third-onward all reject. Allow some slack for clock jitter
    // (a refill could sneak a third through in rare scheduling).
    assert!(
        (2..=4).contains(&allowed),
        "expected 2-4 allowed, got {allowed}"
    );
    assert_eq!(allowed + rate_limited, 50);
    let s = engine.stats();
    assert_eq!(s.thrusts_rejected as usize, rate_limited);
    assert_eq!(s.thrusts_completed as usize, allowed);
}

#[test]
fn other_tenants_unaffected_by_noisy_neighbor() {
    // Tenant 1 exhausts its bucket; tenant 2 still has full capacity.
    let engine = mk_engine_with_admission(10, 3);
    let id = engine.register("module.exports = () => 42").unwrap();

    // Drain tenant 1.
    let mut noisy = Vec::new();
    for _ in 0..20 {
        noisy.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), Some(tid(1))));
    }
    for h in noisy {
        let _ = h.recv();
    }
    // Tenant 2 should still get its burst — 3 allowances — back-to-back.
    let mut quiet = Vec::new();
    for _ in 0..3 {
        quiet.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), Some(tid(2))));
    }
    for h in quiet {
        let out = h.recv();
        assert!(
            out.is_ok(),
            "tenant 2 burst slot was denied unexpectedly: {out:?}"
        );
    }
}

#[test]
fn tenant_none_bypasses_admission() {
    // Extremely restrictive admission: 1 tokens/sec, burst 1. A flood
    // from the trusted (None-tenant) path must ALL pass — admission
    // is gated by tenant presence.
    let engine = mk_engine_with_admission(1, 1);
    let id = engine.register("module.exports = () => 1").unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(engine.thrust(&id, json!(null), FuelGauge::unlimited(), None));
    }
    for h in handles {
        let out = h.recv();
        assert!(out.is_ok(), "None-tenant was throttled: {out:?}");
    }
}

#[test]
fn admission_disabled_when_config_rate_is_none() {
    // No rate in config → no admission layer → tenant-bearing flood is
    // not throttled either.
    let cfg = ThrustEngineConfig {
        compute_workers: 2,
        admission_tokens_per_sec: None,
        ..ThrustEngineConfig::default()
    };
    let engine = ThrustEngine::new(cfg).unwrap();
    let id = engine.register("module.exports = () => 7").unwrap();
    for _ in 0..20 {
        let v = engine
            .thrust_sync(&id, json!(null), FuelGauge::unlimited(), Some(tid(9)))
            .unwrap();
        assert_eq!(v, json!(7));
    }
}

#[test]
fn retry_after_ms_is_reported() {
    let engine = mk_engine_with_admission(100, 1);
    let id = engine.register("module.exports = () => 1").unwrap();
    // First call consumes the burst slot.
    let _ = engine
        .thrust_sync(&id, json!(null), FuelGauge::unlimited(), Some(tid(5)))
        .unwrap();
    // Second is rejected; retry_after should be within one period + 1ms
    // rounding headroom.
    let out = engine.thrust_sync(&id, json!(null), FuelGauge::unlimited(), Some(tid(5)));
    match out {
        Err(AfterburnerError::RateLimited {
            tenant,
            retry_after_ms,
        }) => {
            assert_eq!(tenant, Some(5));
            assert!(
                (1..=15).contains(&retry_after_ms),
                "retry_after_ms out of band: {retry_after_ms}"
            );
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}
