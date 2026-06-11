// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn thrust` — UDF mode. JSON from stdin becomes the script's
//! `data` argument; `module.exports`'s return value is serialized back
//! to stdout.

use crate::AfterburnerError;
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use super::args::Cli;
use super::build::build_afterburner;

pub fn thrust_from_stdin(cli: &Cli, path: &PathBuf) -> Result<()> {
    let source = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let mut stdin_bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut stdin_bytes)
        .context("reading stdin")?;
    let input: Value = if stdin_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&stdin_bytes).context("parse stdin as JSON")?
    };

    let ab = build_afterburner(cli)?;
    let id = ab.register(&source).context("compile")?;
    let out = ab
        .run(&id, &input)
        .map_err(|e: AfterburnerError| anyhow::anyhow!("{e}"))?;
    // In UDF mode we always print the return value — null included —
    // so downstream pipes see a well-formed JSON document every time.
    println!("{}", serde_json::to_string(&out).unwrap_or_default());
    Ok(())
}
