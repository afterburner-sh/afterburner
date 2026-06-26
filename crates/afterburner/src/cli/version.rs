// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `burn version` - build info.

use super::style;
use anyhow::Result;

pub fn print_version() -> Result<()> {
    println!(
        "{} {}",
        style::flame("burn"),
        style::accent(env!("CARGO_PKG_VERSION"))
    );
    println!("{}", style::muted("features:"));
    for (name, on) in [
        ("wasm", cfg!(feature = "wasm")),
        ("native", cfg!(feature = "native")),
        ("adaptive", cfg!(feature = "adaptive")),
        ("thrust", cfg!(feature = "thrust")),
        ("flow", cfg!(feature = "flow")),
        ("host-http", cfg!(feature = "host-http")),
    ] {
        if on {
            println!("  {}", style::ok(name));
        } else {
            println!("  {} {}", style::muted("·"), style::muted(name));
        }
    }
    Ok(())
}
