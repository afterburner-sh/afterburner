// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn bench` - throughput + p50/p99 latency harness.
//!
//! Register once; submit `iters` thrusts via the configured engine;
//! measure total wall-clock + per-iteration latency; report throughput
//! + p50/p99 on stderr.
//!
//! For `workers > 1`: we build the threaded engine and fan out `N`
//! submitter threads (matching `workers`) via `std::thread::scope` so
//! the pool is actually exercised in parallel. Without this, a
//! single-threaded submit loop would serialize the caller side and
//! leave the worker pool mostly idle.

use crate::AfterburnerError;
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::args::Cli;
use super::build::build_afterburner;

#[cfg(feature = "thrust")]
use super::build::build_threaded_for_bench;

#[allow(clippy::needless_return)]
pub fn bench(cli: &Cli, path: &PathBuf, iters: usize, workers: usize) -> Result<()> {
    let source = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;

    // `--workers 0` (the default) resolves to BURN_SHARDS if set,
    // else `available_parallelism()`. Same auto-detect path the
    // daemon uses, so `docker run --cpus=4 burn bench foo.js`
    // gets 4 workers automatically.
    let workers = if workers == 0 {
        if let Ok(s) = std::env::var("BURN_SHARDS")
            && let Ok(n) = s.trim().parse::<usize>()
            && (1..=128).contains(&n)
        {
            n
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        }
    } else {
        workers
    };

    if workers <= 1 {
        let ab = build_afterburner(cli)?;
        let id = ab.register(&source).context("compile")?;
        let mut latencies = Vec::with_capacity(iters);
        let t0 = Instant::now();
        for _ in 0..iters {
            let i0 = Instant::now();
            ab.run(&id, &Value::Null)
                .map_err(|e: AfterburnerError| anyhow::anyhow!("{e}"))?;
            latencies.push(i0.elapsed().as_micros());
        }
        let total = t0.elapsed();
        report_bench(total, &mut latencies, iters, workers);
        return Ok(());
    }

    #[cfg(feature = "thrust")]
    {
        let ab = build_threaded_for_bench(cli, workers)?;
        let id = ab.register(&source).context("compile")?;
        let per_thread = iters / workers;
        let remainder = iters % workers;
        let ab_ref = &ab;
        let id_ref = &id;

        let t0 = Instant::now();
        let all_latencies: Vec<u128> = std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(workers);
            for w in 0..workers {
                let my_iters = per_thread + if w < remainder { 1 } else { 0 };
                handles.push(s.spawn(move || -> Result<Vec<u128>> {
                    let mut lat = Vec::with_capacity(my_iters);
                    for _ in 0..my_iters {
                        let i0 = Instant::now();
                        ab_ref
                            .run(id_ref, &Value::Null)
                            .map_err(|e: AfterburnerError| anyhow::anyhow!("{e}"))?;
                        lat.push(i0.elapsed().as_micros());
                    }
                    Ok(lat)
                }));
            }
            let mut all: Vec<u128> = Vec::with_capacity(iters);
            for h in handles {
                let part = h
                    .join()
                    .map_err(|_| anyhow::anyhow!("bench thread panic"))??;
                all.extend(part);
            }
            Ok::<Vec<u128>, anyhow::Error>(all)
        })?;
        let total = t0.elapsed();
        let mut lat = all_latencies;
        report_bench(total, &mut lat, iters, workers);
        return Ok(());
    }

    #[cfg(not(feature = "thrust"))]
    anyhow::bail!(
        "bench with --workers > 1 requires the `thrust` feature; rebuild with `--features thrust`"
    );
}

fn report_bench(total: Duration, latencies: &mut [u128], iters: usize, workers: usize) {
    latencies.sort_unstable();
    let throughput = iters as f64 / total.as_secs_f64();
    let p50 = latencies[latencies.len() / 2];
    let p99_idx = ((latencies.len() as f64) * 0.99) as usize;
    let p99 = latencies[p99_idx.min(latencies.len() - 1)];
    eprintln!(
        "burn bench: iters={iters} workers={workers} total={:.2}ms throughput={:.0}/sec \
         p50={p50}us p99={p99}us",
        total.as_secs_f64() * 1000.0,
        throughput
    );
}
