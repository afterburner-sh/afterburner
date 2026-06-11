// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Output-framing cost probe - the result-side mirror of
//! `input_framing_bench`.
//!
//! Measures, per result size, (a) wall time of one call and (b) the
//! exact fuel it consumes (recovered by bisection over the per-call
//! fuel limit; fuel metering is deterministic so the smallest limit
//! that completes IS the consumption).
//!
//! Run: `cargo run --release -p afterburner --example output_framing_bench`
//!
//! Scenarios per result size N:
//!  * `json-result` - the module returns an N-byte string; the result
//!    crosses as `JSON.stringify` text over stdout (`run()`), paying
//!    guest-side stringify + stdout framing. Inputs are tiny so input
//!    framing is negligible: this is the full output-crossing tax.
//!  * `raw-result`  - the module returns an N-byte `Uint8Array`; the
//!    bytes cross through the `host_raw_output` import
//!    (`run_out()` → `OutputValue::Bytes`), skipping stringify and
//!    stdout framing entirely.
//!
//! Historical note: before the ceiling-bounded capture landed, every
//! `json-result` row past 1 MiB trapped (`fd_write` errno 29 inside
//! `__ab_write_stdout` against the fixed 1 MiB stdout buffer).

use std::time::Instant;

use afterburner::{Afterburner, AfterburnerError, FuelGauge, OutputValue};
use serde_json::json;

const MIB: usize = 1024 * 1024;
const SIZES: &[(&str, usize)] = &[
    ("0.5 MiB", MIB / 2),
    ("1 MiB", MIB),
    ("2 MiB", 2 * MIB),
    ("8 MiB", 8 * MIB),
    ("16 MiB", 16 * MIB),
    ("32 MiB", 32 * MIB),
];

fn gauge(fuel: Option<u64>) -> FuelGauge {
    FuelGauge {
        fuel,
        ..FuelGauge::unlimited()
    }
}

/// Smallest fuel limit that lets `call` succeed == exact fuel consumed.
fn measure_fuel(call: &dyn Fn(&FuelGauge) -> Result<usize, AfterburnerError>) -> u64 {
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

fn time_one(call: &dyn Fn(&FuelGauge) -> Result<usize, AfterburnerError>) -> (f64, usize) {
    // Median of 3.
    let mut size = 0usize;
    let mut samples: Vec<f64> = (0..3)
        .map(|_| {
            let t = Instant::now();
            size = call(&gauge(None)).expect("timed run failed");
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).expect("non-NaN"));
    (samples[1], size)
}

fn report(
    label: &str,
    size_label: &str,
    call: &dyn Fn(&FuelGauge) -> Result<usize, AfterburnerError>,
) {
    let (ms, result_bytes) = time_one(call);
    let fuel = measure_fuel(call);
    println!(
        "{label:<12} {size_label:>8}  result={result_bytes:>9} B  fuel={fuel:>14}  wall={ms:>9.2} ms"
    );
}

fn main() {
    // 64 MiB default ceiling covers every scenario below; the 32 MiB
    // JSON row needs ~32 MiB of capture.
    let ab = Afterburner::new().expect("engine build");

    // JSON-string result: N-byte string out through JSON.stringify +
    // stdout.
    let json_id = ab
        .register("module.exports = (d) => 'a'.repeat(d.n)")
        .expect("register json-result script");
    for (size_label, n) in SIZES {
        let input = json!({ "n": n });
        report("json-result", size_label, &|g: &FuelGauge| {
            let v = ab.run_with(&json_id, &input, g)?;
            Ok(v.as_str().map(str::len).unwrap_or(0))
        });
    }

    // Raw result: N-byte Uint8Array out through host_raw_output.
    // Filled (not just zeroed) so the guest-side work is comparable
    // to the string scenario's repeat().
    let raw_id = ab
        .register("module.exports = (d) => new Uint8Array(d.n).fill(97)")
        .expect("register raw-result script");
    for (size_label, n) in SIZES {
        let input = json!({ "n": n });
        report("raw-result", size_label, &|g: &FuelGauge| match ab
            .run_out_with(&raw_id, &input, g)?
        {
            OutputValue::Bytes(b) => Ok(b.len()),
            OutputValue::Json(v) => panic!("expected bytes, got JSON: {v}"),
        });
    }
}
