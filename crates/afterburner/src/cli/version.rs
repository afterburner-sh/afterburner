// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn version` — build info.

use anyhow::Result;

pub fn print_version() -> Result<()> {
    println!("burn {}", env!("CARGO_PKG_VERSION"));
    println!("features:");
    println!("  wasm      = {}", cfg!(feature = "wasm"));
    println!("  native    = {}", cfg!(feature = "native"));
    println!("  adaptive  = {}", cfg!(feature = "adaptive"));
    println!("  thrust    = {}", cfg!(feature = "thrust"));
    println!("  flow      = {}", cfg!(feature = "flow"));
    println!("  host-http = {}", cfg!(feature = "host-http"));
    Ok(())
}
