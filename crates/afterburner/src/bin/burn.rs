// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn` — the Afterburner command-line runtime.
//!
//! Thin entrypoint. All subcommand logic lives in [`afterburner::cli`].

fn main() {
    if let Err(e) = afterburner::cli::run() {
        eprintln!("burn: {e:#}");
        std::process::exit(1);
    }
}
