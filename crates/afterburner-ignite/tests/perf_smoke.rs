// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Throughput smoke test for the native tier. The plan target is >100 K
//! thrusts/sec on a single core for a trivial transform. We run 10 K
//! iterations (to keep CI time reasonable) and assert the rate stays
//! well above a conservative floor. Tightened floors are welcome but
//! not enforced - CI machines vary.

use afterburner_core::log::Level;
use afterburner_core::{Combustor, FuelGauge, ab_event};
use afterburner_ignite::NativeCombustor;
use serde_json::json;
use std::hint::black_box;
use std::time::Instant;

#[test]
fn native_thrust_rate_meets_floor() {
    let combustor = NativeCombustor::new().unwrap();
    let id = combustor.ignite("module.exports = (d) => d.n + 1").unwrap();

    const ITERS: u64 = 10_000;
    let input = json!({ "n": 41 });
    let limits = FuelGauge::unlimited();

    let start = Instant::now();
    for _ in 0..ITERS {
        let out = combustor.thrust(&id, &input, &limits).unwrap();
        // Prevent compiler from optimizing the thrust away.
        black_box(out);
    }
    let elapsed = start.elapsed();
    let per_sec = ITERS as f64 / elapsed.as_secs_f64();

    ab_event!(
        Level::Info,
        "perf_smoke.native_thrust",
        "iters" => ITERS,
        "per_sec" => format!("{per_sec:.0}"),
        "elapsed_ms" => format!("{:.2}", elapsed.as_secs_f64() * 1000.0),
    );

    // Catastrophic-regression guard only. The 8 K/sec debug rate has no
    // margin on shared CI runners (one measured 7964/sec), so the floor
    // is set to 2 K: it still catches a multi-x regression while
    // tolerating runner-speed variance. Plan target is 100 K+ in release;
    // release-mode runs comfortably clear it.
    assert!(
        per_sec > 2_000.0,
        "native throughput regressed below 2K/sec debug floor: {per_sec:.0}/sec"
    );
}
