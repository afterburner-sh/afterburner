// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn check` — parse-only, no execution. Matches `node --check`.
//!
//! Calls `Afterburner::register`, which routes through the combustor's
//! compile step. The wasm path runs the Javy plugin's `compile`
//! envelope — Javy parses the user source's wrapper *as an ES
//! module*, eagerly validating any `new Function(...)` constants
//! inlined into the module body. That's what surfaces syntactic
//! errors in the user's source text without executing the user code:
//! a bad source turns into a compile-time exception that maps to
//! [`AfterburnerError::CompileFailed`]. Runtime-only errors
//! (ReferenceError, TypeError) pass the check, same as Node.

use crate::AfterburnerError;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use super::args::Cli;
use super::build::build_afterburner;

pub fn check_file(cli: &Cli, path: &PathBuf) -> Result<()> {
    let source = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let ab = build_afterburner(cli)?;
    ab.register(&source)
        .map_err(|e: AfterburnerError| anyhow::anyhow!("{e}"))?;
    // Quiet-on-success for CI friendliness.
    Ok(())
}
