// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Throughput smoke test for the WASM path. Not a replacement for a
//! criterion bench — just a regression tripwire that fails if thrust
//! drops below a conservative floor.

use afterburner_core::{Combustor, FuelGauge};
use afterburner_wasi::{WasmCombustor, WasmConfig};
use serde_json::json;
use std::hint::black_box;
use std::time::Instant;

#[test]
fn wasm_thrust_rate_meets_floor() {
    let c = WasmCombustor::new(WasmConfig::default()).unwrap();
    let id = c.ignite("module.exports = (d) => d.n + 1").unwrap();

    const ITERS: u64 = 200;
    let input = json!({ "n": 41 });
    let limits = FuelGauge::unlimited();

    // Warmup one call so any first-time setup noise is out of the way.
    let _ = c.thrust(&id, &input, &limits).unwrap();

    let start = Instant::now();
    for _ in 0..ITERS {
        let out = c.thrust(&id, &input, &limits).unwrap();
        black_box(out);
    }
    let elapsed = start.elapsed();
    let per_sec = ITERS as f64 / elapsed.as_secs_f64();

    eprintln!(
        "wasm thrust throughput: {per_sec:.0}/sec over {ITERS} iters ({:.2} ms total)",
        elapsed.as_secs_f64() * 1000.0
    );

    // 50/sec is extremely conservative — debug builds with the full
    // ~1.6 MB Wizer-preinit plugin instantiated per call still beat
    // this comfortably. Release-mode throughput is much higher.
    assert!(
        per_sec > 50.0,
        "wasm throughput dropped below 50/sec floor: {per_sec:.0}/sec"
    );
}

#[test]
fn wasm_thrust_with_require_path_overhead_is_bounded() {
    // A scripted `require('path').join(...)` pays the require resolver
    // overhead on top of the bare thrust. On a warmed-up plugin the
    // total should stay within a small multiple of the baseline.
    let c = WasmCombustor::new(WasmConfig::default()).unwrap();
    let id = c
        .ignite("module.exports = () => require('path').join('/a','b','c.js')")
        .unwrap();

    const ITERS: u64 = 100;
    let limits = FuelGauge::unlimited();
    let _ = c.thrust(&id, &json!(null), &limits).unwrap();

    let start = Instant::now();
    for _ in 0..ITERS {
        let out = c.thrust(&id, &json!(null), &limits).unwrap();
        black_box(out);
    }
    let elapsed = start.elapsed();
    let per_sec = ITERS as f64 / elapsed.as_secs_f64();
    eprintln!("wasm require('path') throughput: {per_sec:.0}/sec over {ITERS} iters");
    assert!(
        per_sec > 20.0,
        "require('path') throughput dropped below 20/sec: {per_sec:.0}/sec"
    );
}
