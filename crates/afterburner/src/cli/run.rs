// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn run FILE args…` and `burn -e CODE args…` — execute a
//! top-level script.
//!
//! Routes through the plugin's **daemon mode** (Q2-A): user source
//! runs via `daemon-init`; if it didn't install any HTTP listeners
//! (or `setInterval` — B3) the script exits cleanly like a plain
//! one-shot. When listeners are present the CLI transitions into
//! the dispatcher event loop until SIGINT.
//!
//! The UDF shape (`module.exports = (data) => …`) remains available
//! via `burn thrust`.
//!
//! **Exit codes** follow Node's convention: clean completion → 0,
//! `process.exit(n)` → n, and any uncaught error → 1 — including a
//! top-level `throw`, a rejected promise assigned to
//! `module.exports`, and an exported async function that throws (the
//! script envelope awaits an exported thenable; see
//! `afterburner-plugin/src/envelope.rs::wrap_script_source`). The
//! error message + stack go to stderr. A *resolved* exported promise
//! exits 0 with its value discarded.
//!
//! `.ts` / `.mts` / `.cts` files are transpiled via `oxc` before
//! dispatch when the crate is built with the `ts` feature. Without
//! `ts`, running a `.ts` file surfaces a typed error pointing at the
//! feature flag rather than letting the JS parser choke on
//! type annotations.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use super::args::Cli;
use super::daemon::{execute, script_label};

/// Recover a script's `process.argv[2..]` straight from the raw process
/// argv, slicing everything after the FILE token.
///
/// Needed because when a script's own arguments collide with a burn
/// subcommand name (`burn app.js install foo`, or npm's internal
/// `node npm-cli.js install foo` re-entering through the PATH shim as
/// `burn npm-cli.js install foo`), clap binds the colliding token as a
/// `Cmd` and swallows the rest, so they never reach `cli.rest_args`.
/// The script is an explicit "run this file", so its args are whatever
/// followed the FILE token in argv.
pub fn script_args_from_argv(file: &std::path::Path) -> Vec<String> {
    let file_str = file.to_string_lossy();
    let argv: Vec<String> = std::env::args().collect();
    match argv.iter().skip(1).position(|a| *a == *file_str) {
        // `position` is relative to `skip(1)`; +1 back to the full-argv
        // index of the FILE token, +1 more to start after it.
        Some(pos) => argv[pos + 2..].to_vec(),
        None => Vec::new(),
    }
}

/// Recover an eval script's `process.argv[1..]` from raw argv when a
/// trailing arg collided with a subcommand name and clap swallowed the
/// positionals into `cli.command` (`burn -e CODE install foo`).
///
/// The args are every argv token after the eval `CODE` value. `CODE`
/// arrives via `-e`/`--eval` in any of `-e CODE`, `-eCODE`,
/// `--eval CODE`, `--eval=CODE`; we slice after the token that *equals*
/// `code` (the separate-value forms) or, failing that, after the first
/// token that carries `code` as an attached value.
pub fn eval_args_from_argv(code: &str) -> Vec<String> {
    let argv: Vec<String> = std::env::args().collect();
    let tail = argv.iter().skip(1).enumerate();
    // Separate-value form: a token equal to CODE preceded by -e/--eval.
    for (i, tok) in tail.clone() {
        if tok == code {
            return argv[i + 2..].to_vec();
        }
    }
    // Attached-value form: `-eCODE` / `--eval=CODE`.
    for (i, tok) in tail {
        let attached =
            tok.strip_prefix("-e") == Some(code) || tok.strip_prefix("--eval=") == Some(code);
        if attached {
            return argv[i + 2..].to_vec();
        }
    }
    Vec::new()
}

pub fn run_file(cli: &Cli, path: &PathBuf, user_args: &[String]) -> Result<()> {
    if cli.watch {
        return watch::run_with_watch(cli, path, user_args);
    }
    let source = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let label = script_label(path);
    let js_source = with_preload(cli, &maybe_transpile_ts(&source, path)?);
    if cli.internal_worker {
        // worker child mode. Bootstraps a `DaemonWorkers::new_child`
        // (which blocks on stdin for the init frame) and runs the
        // script under the same daemon-mode plumbing the parent uses.
        return super::worker::execute(cli, &js_source, &label, user_args);
    }
    execute(cli, &js_source, &label, user_args)
}

pub fn run_source(cli: &Cli, source: &str, user_args: &[String]) -> Result<()> {
    let prepared = with_preload(cli, source);
    if cli.internal_worker {
        return super::worker::execute(cli, &prepared, "[eval]", &[]);
    }
    execute(cli, &prepared, "[eval]", user_args)
}

/// Prepend `--require=mod` / `--import=mod` preload modules to the
/// user source, plus the `--permission` grant map. Both flags collapse
/// onto `require(spec)` here — burn has a single CJS-shaped resolver,
/// so the ESM `--import` form is a `require()` of a module that was
/// lowered through TS-strip + ESM rewrite at load time. Order matches
/// Node: `--require` first, then `--import`.
fn with_preload(cli: &Cli, source: &str) -> String {
    let permission_prelude = build_permission_prelude(cli);
    if cli.require.is_empty() && cli.import.is_empty() && permission_prelude.is_empty() {
        return source.to_string();
    }
    let mut out = String::with_capacity(source.len() + 256);
    out.push_str(&permission_prelude);
    for spec in cli.require.iter().chain(cli.import.iter()) {
        // Each spec gets its own try-wrapped require so a missing
        // preload doesn't kill the user script silently. Failures
        // surface on stderr and the script still runs.
        let escaped = spec.replace('\\', "\\\\").replace('\'', "\\'");
        out.push_str(&format!(
            "try {{ require('{escaped}'); }} catch (e) {{ \
             console.error('burn: preload failed for', '{escaped}', ':', e && e.message); \
            }}\n"
        ));
    }
    out.push_str(source);
    out
}

/// Build the JS prelude that installs `globalThis.__ab_permission_grants`
/// when `--permission` is set on the CLI. Empty when the flag is off —
/// `process.permission.has` then defaults to allow-all (manifold is the
/// real gate). Each `--allow-*` flag becomes one entry on the grants
/// map; the JS-side `has()` implementation does the prefix / wildcard
/// matching.
fn build_permission_prelude(cli: &Cli) -> String {
    if !cli.permission {
        return String::new();
    }
    let mut entries: Vec<String> = Vec::new();
    if let Some(v) = cli.allow_fs_read.as_deref() {
        entries.push(format!("'fs.read': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_fs_write.as_deref() {
        entries.push(format!("'fs.write': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_fs.as_deref() {
        // Plain --allow-fs grants both read and write on the same set.
        entries.push(format!("'fs.read': {}", json_string(v)));
        entries.push(format!("'fs.write': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_net.as_deref() {
        entries.push(format!("'net': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_env.as_deref() {
        entries.push(format!("'env': {}", json_string(v)));
    }
    if cli.allow_child_process {
        entries.push("'child_process': true".to_string());
    }
    if cli.allow_worker {
        entries.push("'worker': true".to_string());
    }
    format!(
        "globalThis.__ab_permission_grants = {{ {} }};\n",
        entries.join(", ")
    )
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

mod watch {
    use super::{maybe_transpile_ts, script_label, with_preload};
    use crate::cli::args::Cli;
    use crate::cli::daemon::execute;
    use anyhow::{Context, Result};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    /// `--watch` loop: poll the entry script's mtime; when it changes,
    /// run a fresh execution. Polling at 250 ms feels close to inotify
    /// for an interactive workflow without taking a host-watcher
    /// dependency. Running the script is synchronous here — daemon
    /// mode exits naturally when listeners close, and we re-loop.
    /// We re-run on entry-script change only, matching Node's pre-22
    /// default; transitive `require()` tracking can land later.
    pub(super) fn run_with_watch(cli: &Cli, path: &Path, user_args: &[String]) -> Result<()> {
        let mut last_mtime = mtime_of(path);
        // Fire the script once immediately.
        run_once(cli, path, user_args)?;
        eprintln!("burn --watch: watching {} (Ctrl-C to exit)", path.display());
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let cur = mtime_of(path);
            if cur > last_mtime {
                last_mtime = cur;
                eprintln!("burn --watch: change detected, re-running…");
                if let Err(e) = run_once(cli, path, user_args) {
                    eprintln!("burn --watch: error: {e}");
                }
            }
        }
    }

    fn run_once(cli: &Cli, path: &Path, user_args: &[String]) -> Result<()> {
        let buf = path.to_path_buf();
        let _: PathBuf = buf;
        let source = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
        let label = script_label(path);
        let js_source = with_preload(cli, &maybe_transpile_ts(&source, path)?);
        execute(cli, &js_source, &label, user_args)
    }

    fn mtime_of(path: &Path) -> SystemTime {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

/// With the `ts` feature: TS files are transpiled (strip-types +
/// ESM→CJS) via oxc, and `.js`/`.mjs` files are ESM-lowered to CJS
/// so `import`/`export` works under our CJS runtime.
///
/// Without the `ts` feature: TS files surface a typed error; `.js`
/// files pass through unchanged (no ESM lowering available without
/// the transpile dep graph).
#[cfg(feature = "ts")]
fn maybe_transpile_ts(source: &str, path: &std::path::Path) -> Result<String> {
    if crate::ts::is_typescript(path) {
        return crate::ts::transpile(source, path).map_err(|e| anyhow::anyhow!("{e}"));
    }
    // lower ESM in plain JS too. Plain CJS source contains no
    // ESM declarations and returns unchanged.
    crate::ts::lower_esm_js(source, path).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(not(feature = "ts"))]
fn maybe_transpile_ts(source: &str, path: &std::path::Path) -> Result<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(
        ext.as_deref(),
        Some("ts") | Some("mts") | Some("cts") | Some("tsx")
    ) {
        anyhow::bail!(
            "burn: TypeScript support requires the `ts` cargo feature (rebuild with `cargo install afterburner --features ts`). \
             File: {}",
            path.display()
        );
    }
    Ok(source.to_string())
}
