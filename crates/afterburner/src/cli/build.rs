// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Afterburner engine construction from CLI flags. Shared by every
//! subcommand that needs to run JS.

use crate::{Afterburner, FuelGauge};
use anyhow::{Context, Result};

use super::args::{Cli, parse_mode};
use super::manifold::build_manifold;

pub fn build_afterburner(cli: &Cli) -> Result<Afterburner> {
    let mut b = Afterburner::builder();
    if let Some(mode_str) = cli.mode.as_deref() {
        b = b.mode(parse_mode(mode_str)?);
    }
    if let Some(fuel) = cli.fuel {
        b = b.fuel(fuel);
    }
    if let Some(mem) = cli.memory {
        b = b.memory_bytes(mem);
    }
    if let Some(ms) = cli.timeout_ms {
        b = b.timeout_ms(ms);
    }
    b = b.manifold(build_manifold(cli));
    // Reference FuelGauge here so future changes that rebuild the
    // gauge from CLI flags at this site don't need a fresh import.
    let _ = FuelGauge::unlimited();
    b.build().context("build afterburner")
}

#[cfg(feature = "thrust")]
pub fn build_threaded_for_bench(cli: &Cli, workers: usize) -> Result<Afterburner> {
    let mut b = Afterburner::builder();
    if let Some(fuel) = cli.fuel {
        b = b.fuel(fuel);
    }
    if let Some(mem) = cli.memory {
        b = b.memory_bytes(mem);
    }
    if let Some(ms) = cli.timeout_ms {
        b = b.timeout_ms(ms);
    }
    b = b.manifold(build_manifold(cli));
    b.threaded(workers).build().context("build threaded")
}
