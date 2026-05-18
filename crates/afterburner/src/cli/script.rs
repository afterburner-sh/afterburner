// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Script-mode plumbing shared by `run_file` / `run_source`.
//!
//! Builds a [`ScriptInvocation`] from CLI flags + user-supplied
//! trailing args, then delegates to the facade's
//! [`Afterburner::run_script_with`]. The captured stdout/stderr are
//! streamed to the real host process streams; the Node-style exit
//! code flows out through `std::process::exit`.

use crate::{Afterburner, AfterburnerError, EnvAccess, ScriptInvocation};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::Write;

use super::args::Cli;
use super::manifold::build_manifold;

/// Compose a [`ScriptInvocation`] matching the Node convention
/// `["program", "<script>", ...user_args]`. `script_label` is the
/// string to put at `argv[1]` — the absolute file path for `run`, or
/// `"[eval]"` for `-e`.
pub fn build_invocation(cli: &Cli, script_label: &str, user_args: &[String]) -> ScriptInvocation {
    let mut argv = Vec::with_capacity(2 + user_args.len());
    argv.push("burn".to_string());
    argv.push(script_label.to_string());
    argv.extend(user_args.iter().cloned());

    ScriptInvocation {
        argv,
        env: collect_env(cli),
        cwd: cli_cwd(),
    }
}

/// CLI's current working directory as a string. Used so
/// `process.cwd()` and B6's `require()` path resolver have a sensible
/// baseline when the entry script is `-e` eval mode (no `__dirname`
/// of its own). Falls back to `"/"` if the host refuses to report a
/// directory — the script still runs, just with a degraded baseline.
pub fn cli_cwd() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".to_string())
}

/// Resolve the `process.env` map per the active [`Manifold`]:
///
/// * `EnvAccess::None` → empty map.
/// * `EnvAccess::AllowList(keys)` → exactly those keys (missing ones
///   are silently omitted rather than surfaced as empty strings).
/// * `EnvAccess::Full` → every env var currently in the host
///   process's environment.
fn collect_env(cli: &Cli) -> BTreeMap<String, String> {
    let manifold = build_manifold(cli);
    let mut env: BTreeMap<String, String> = match &manifold.env {
        EnvAccess::None => BTreeMap::new(),
        EnvAccess::AllowList(keys) => keys
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
            .collect(),
        EnvAccess::Full => std::env::vars().collect(),
    };
    // `--env-file=path` (Node 20.6+): merge `.env`-style files in the
    // order they appear on the CLI so later ones override earlier
    // keys, matching Node's behaviour. Lines without `=` are skipped;
    // surrounding single/double quotes on values are stripped.
    for path in &cli.env_file {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some(eq) = line.find('=') else {
                    continue;
                };
                let key = line[..eq].trim();
                if key.is_empty() {
                    continue;
                }
                let mut val = line[eq + 1..].trim();
                if val.len() >= 2
                    && ((val.starts_with('"') && val.ends_with('"'))
                        || (val.starts_with('\'') && val.ends_with('\'')))
                {
                    val = &val[1..val.len() - 1];
                }
                env.insert(key.to_string(), val.to_string());
            }
        }
    }
    env
}

/// Run `source` in script mode and forward the captured stdout,
/// stderr, and exit code to the real host process streams. On
/// `exit_code != 0` this calls [`std::process::exit`] — same
/// semantics as Node.
pub fn execute(
    ab: &Afterburner,
    source: &str,
    script_label: &str,
    user_args: &[String],
    cli: &Cli,
) -> Result<()> {
    let invocation = build_invocation(cli, script_label, user_args);
    let outcome = ab
        .run_script_with(source, &invocation, ab.default_limits())
        .map_err(|e: AfterburnerError| anyhow::anyhow!("{e}"))?;

    std::io::stdout()
        .write_all(&outcome.stdout)
        .context("write script stdout")?;
    std::io::stderr()
        .write_all(&outcome.stderr)
        .context("write script stderr")?;

    if outcome.exit_code != 0 {
        // Preserve the script's exit code via `process::exit`. Node
        // does the same — and there is no sensible "anyhow::Result"
        // mapping for "script exited cleanly with code 2."
        std::process::exit(outcome.exit_code);
    }
    Ok(())
}
