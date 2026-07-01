// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Micro-benchmark for the effect-capture hot path.
//!
//! Measures the cost the capture seam ADDS per host effect: the BLAKE3
//! content hash (the per-byte cost) and the `HostEffect` + `HostEffectRecord`
//! construction (the per-op fixed cost), plus the sealed-path `Option<Arc>`
//! None-check that a non-capturing run pays per syscall.
//!
//! Run in release for real numbers:
//!   cargo run --release -p afterburner-core --example capture_bench
//!
//! Reports median-of-repeats to stay robust under machine load.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use afterburner_core::{
    EffectDetail, EffectKind, EffectStatus, FileOp, HostContext, HostEffect, HostEffectRecord,
    content_hash, fs_target,
};

/// Median wall-clock nanoseconds per iteration over `reps` timed passes of
/// `iters` calls to `f`, so a single scheduler hiccup does not skew the number.
fn median_ns_per_op(reps: usize, iters: u64, mut f: impl FnMut()) -> f64 {
    let mut samples: Vec<f64> = (0..reps)
        .map(|_| {
            let t0 = Instant::now();
            for _ in 0..iters {
                f();
            }
            t0.elapsed().as_nanos() as f64 / iters as f64
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn main() {
    println!("== afterburner effect-capture micro-benchmark ==");
    println!("(median of 5 passes; release build; machine may be under load)\n");

    // 1. BLAKE3 content_hash throughput: the per-byte capture cost.
    println!("content_hash (BLAKE3) throughput:");
    for &size in &[64usize, 1024, 65_536, 1_048_576] {
        let buf = vec![0xABu8; size];
        // Aim for ~256 MiB hashed per pass so the number is stable.
        let iters = (256 * 1024 * 1024 / size).max(64) as u64;
        let ns = median_ns_per_op(5, iters, || {
            black_box(content_hash(black_box(&buf)));
        });
        let gbps = size as f64 / ns; // bytes/ns == GB/s
        println!(
            "  {:>9} B  ->  {:>10.1} ns/op   {:>6.2} GB/s",
            size, ns, gbps
        );
    }

    // 2. Full capture-effect construction per op (the fixed per-effect cost:
    //    build HostEffect incl input_hash, then HostEffectRecord incl output_hash).
    println!(
        "\nfull effect construction (HostEffect + HostEffectRecord, incl. both BLAKE3 hashes):"
    );
    let target = fs_target("/work/x.bin");
    for &(label, in_len, out_len) in &[
        ("32 B write", 32usize, 0usize),
        ("64 KiB read", 0, 65_536),
        ("1 MiB read", 0, 1_048_576),
    ] {
        let input = vec![0xCDu8; in_len];
        let output = vec![0xEFu8; out_len];
        let ns = median_ns_per_op(5, 20_000, || {
            let eff = HostEffect::new(
                black_box(EffectKind::Fs(FileOp::Write)),
                black_box(target.clone()),
                black_box(input.clone()),
                EffectDetail::None,
                None,
            );
            let rec = HostEffectRecord::new(
                eff,
                black_box(output.clone()),
                0,
                EffectStatus::Ok {
                    code: 0,
                    rows: None,
                },
            );
            black_box(rec);
        });
        println!("  {:>12}  ->  {:>10.1} ns/op", label, ns);
    }

    // 3. The sealed-path per-syscall cost: the None-check a NON-capturing run
    //    pays (Option<Arc<dyn HostContext>>::clone on None + the branch).
    println!("\nsealed-path per-call cost (Option<Arc> None-check, the non-capture hot path):");
    let none: Option<Arc<dyn HostContext>> = None;
    let ns = median_ns_per_op(5, 5_000_000, || {
        let c = black_box(&none).clone();
        // Mirror the seam's `let Some(ctx) = ... else { return Off }`.
        if black_box(c).is_some() {
            unreachable!();
        }
    });
    println!("  None-check  ->  {:>10.2} ns/op", ns);

    println!("\n(reference: a 1013-effect CRuby boot pays ~1013x the per-op cost above,");
    println!(" plus the per-byte hash over the bytes actually read/written.)");
}
