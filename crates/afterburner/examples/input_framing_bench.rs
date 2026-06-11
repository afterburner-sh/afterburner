// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Input-framing cost probe for the embedded `run` path.
//!
//! Measures, per input size, (a) wall time of one `run()` and (b) the
//! exact fuel the call consumes. Fuel is not surfaced by the public
//! API, so it is recovered by bisection over the per-call fuel limit:
//! fuel metering is deterministic (instruction-count based), so the
//! smallest limit that completes IS the consumption.
//!
//! Run: `cargo run --release -p afterburner --example input_framing_bench`
//!
//! Scenarios per size N (string payload of N ASCII bytes):
//!  * `json`  — input `{"payload":"<N bytes>"}` through `run()`;
//!    the script touches only `.payload.length` so output framing is
//!    negligible. This is the full input-crossing tax.
//!  * `raw`   — same payload bytes through `run_raw()` (when built
//!    with the raw fast path); script reads `.length` of the
//!    `Uint8Array` it receives.

use std::time::Instant;

use afterburner::{Afterburner, AfterburnerError, FuelGauge, ScriptId};
use serde_json::{Value, json};

const SIZES: &[(&str, usize)] = &[
    ("1 KiB", 1024),
    ("1 MiB", 1024 * 1024),
    ("22 MB", 22 * 1000 * 1000),
];

fn gauge(fuel: Option<u64>) -> FuelGauge {
    FuelGauge {
        fuel,
        ..FuelGauge::unlimited()
    }
}

/// Smallest fuel limit that lets `call` succeed == exact fuel consumed.
fn measure_fuel(call: &dyn Fn(&FuelGauge) -> Result<Value, AfterburnerError>) -> u64 {
    // Bracket by doubling.
    let mut hi: u64 = 1 << 20;
    loop {
        match call(&gauge(Some(hi))) {
            Ok(_) => break,
            Err(AfterburnerError::FuelExhausted) => {
                hi = hi.checked_mul(2).expect("fuel bracket overflow");
            }
            Err(e) => panic!("unexpected error while bracketing fuel: {e:?}"),
        }
    }
    // Bisect to ~0.2% precision — plenty for orders-of-magnitude
    // comparisons and keeps the 22 MB scenario under a minute.
    let mut lo = hi / 2;
    while hi - lo > hi / 512 {
        let mid = lo + (hi - lo) / 2;
        match call(&gauge(Some(mid))) {
            Ok(_) => hi = mid,
            Err(AfterburnerError::FuelExhausted) => lo = mid,
            Err(e) => panic!("unexpected error while bisecting fuel: {e:?}"),
        }
    }
    hi
}

fn time_one(call: &dyn Fn(&FuelGauge) -> Result<Value, AfterburnerError>) -> f64 {
    // Median of 3.
    let mut samples: Vec<f64> = (0..3)
        .map(|_| {
            let t = Instant::now();
            call(&gauge(None)).expect("timed run failed");
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).expect("non-NaN"));
    samples[1]
}

fn report(
    label: &str,
    size_label: &str,
    call: &dyn Fn(&FuelGauge) -> Result<Value, AfterburnerError>,
) {
    let ms = time_one(call);
    let fuel = measure_fuel(call);
    println!("{label:<14} {size_label:>6}  fuel={fuel:>14}  wall={ms:>9.2} ms");
}

fn main() {
    let ab = Afterburner::new().expect("engine build");

    let json_id: ScriptId = ab
        .register("module.exports = (d) => d.payload.length")
        .expect("register json script");

    for (size_label, n) in SIZES {
        let payload = "a".repeat(*n);
        let input = json!({ "payload": payload });
        report("json-input", size_label, &|g: &FuelGauge| {
            ab.run_with(&json_id, &input, g)
        });
    }

    // Decomposition: how much of the tax is the guest-side input
    // string materialization (`__AB_GET_INPUT__`) vs `JSON.parse`?
    // The script calls the input getter a second time; the delta vs
    // `json-input` above is the getter's cost alone (the wrapper
    // already paid getter + JSON.parse once before user code ran).
    let get_again_id = ab
        .register("module.exports = (d) => __AB_GET_INPUT__().length")
        .expect("register get-again script");
    for (size_label, n) in SIZES {
        let payload = "a".repeat(*n);
        let input = json!({ "payload": payload });
        report("json+get-again", size_label, &|g: &FuelGauge| {
            ab.run_with(&get_again_id, &input, g)
        });
    }

    // Raw fast path: same payload bytes, no JSON framing on the way in.
    let raw_id = ab
        .register("module.exports = (bytes) => bytes.length")
        .expect("register raw script");
    for (size_label, n) in SIZES {
        let payload = vec![b'a'; *n];
        report("raw-input", size_label, &|g: &FuelGauge| {
            ab.run_raw_with(&raw_id, &payload, g)
        });
    }
}
