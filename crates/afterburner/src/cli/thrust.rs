// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn thrust` - UDF mode. JSON from stdin becomes the script's
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
    // The value API carries no ScriptInvocation, so without help the
    // require() resolver has no entry dir and `require('ns/pkg')` from a
    // UDF can never find ./node_modules. Hand it the same context file
    // mode gets: an absolute argv[1] (entry dir) + the script's cwd.
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
    let cwd = abs
        .parent()
        .map_or_else(|| "/".to_string(), |d| d.to_string_lossy().into_owned());
    // The refresh call rebuilds the entry `require` from the globals just
    // set - the plenum installed it at init time, before this script ran.
    let source = format!(
        "globalThis.__host_cwd = {cwd_json}; globalThis.__ab_argv = ['burn', {path_json}]; \
         if (typeof globalThis.__plenum_refresh_entry_require === 'function') globalThis.__plenum_refresh_entry_require();
{source}",
        cwd_json = serde_json::to_string(&cwd)?,
        path_json = serde_json::to_string(&abs.to_string_lossy())?,
    );
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
    // In UDF mode we always print the return value - null included -
    // so downstream pipes see a well-formed JSON document every time.
    println!("{}", serde_json::to_string(&out).unwrap_or_default());
    Ok(())
}
