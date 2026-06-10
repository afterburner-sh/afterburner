// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pass-through dispatch: `burn node foo.js`, `burn npm install`,
//! `burn pnpm run dev`, and the Q5-A general case — any first-arg
//! that isn't a subcommand and isn't a local file but *is* on `PATH`
//! runs as a pass-through via the PATH shim in [`super::shim`].
//!
//! **Q5-A precedence** (locked):
//! 1. Existing-file wins — if `argv[1]` resolves to a file in cwd,
//!    we run it as a script regardless of whether the name also
//!    exists on `PATH`.
//! 2. Known targets (`node`, `npm`, `npx`, `pnpm`, `yarn`, `bun`)
//!    always enter pass-through; if the binary isn't on `PATH`, we
//!    surface the typed not-found error (Q5-2) rather than silently
//!    failing.
//! 3. Anything else on `PATH` enters pass-through.
//! 4. Everything else errors with `burn: unknown command '<arg>'`
//!    (Q5-2) before any `exec(3)`, so users don't see the classic
//!    `could not exec noed: No such file` confusion.
//!
//! **Shim recursion guard (Q5-3)**: every pass-through increments
//! `BURN_SHIM_DEPTH`. Hitting 8 surfaces a typed error instead of
//! fork-bombing.

#[cfg(not(unix))]
use anyhow::Context;
use anyhow::Result;
use std::env;
use std::path::{Path, PathBuf};

use super::args::Cli;
use super::banner;
use super::run;
use super::shim;

/// Names that get first-class treatment. Being on this list is not
/// strictly required (Q5-A passes any PATH binary through), but these
/// names anchor the user's mental model and get a clearer not-found
/// message if the binary is missing.
const KNOWN_TARGETS: &[&str] = &["node", "npm", "npx", "pnpm", "yarn", "bun"];

const SHIM_DEPTH_LIMIT: u32 = 8;
const SHIM_DEPTH_ENV: &str = "BURN_SHIM_DEPTH";

/// What [`detect`] decided about `argv[1]`.
///
/// The split between [`Detected::KnownTarget`] and
/// [`Detected::PathTarget`] exists to disambiguate `-e CODE` eval
/// mode: `burn -e 'code' hello` should treat `hello` as a script arg
/// even if a `/usr/bin/hello` exists on PATH, but `burn node -e
/// 'code' hello` must still route to the node pass-through (the user
/// explicitly named a Node-compat entry point). Anchoring only the
/// hard-coded names as "always pass through" makes that decision
/// deterministic without magic.
pub enum Detected {
    /// Hard-coded Node-ecosystem entry point — dispatch as
    /// pass-through regardless of eval-mode context.
    KnownTarget(String),
    /// Arbitrary PATH-resolved binary — Q5-A general case. The
    /// caller should only dispatch as pass-through when `-e CODE`
    /// is *not* in play.
    PathTarget(String),
    /// Not a pass-through target — fall back to "run this as a file"
    /// (the existing positional-file path).
    Runnable,
    /// `argv[1]` is neither a known subcommand, a file, nor on
    /// `PATH`. Surface a typed unknown-command error (Q5-2) before
    /// any exec attempt — unless we're in eval mode, where the
    /// positional is a script arg and this verdict is ignored.
    Unknown(String),
}

/// Reconstruct the pass-through argument vector straight from the raw
/// process argv.
///
/// Why we can't just use `cli.rest_args`: when a pass-through target's
/// own arguments happen to collide with one of burn's subcommand names
/// (`burn npm install …`, `burn pnpm run …`, `burn yarn test`), clap
/// binds the colliding token (`install` / `run` / `test`) as *burn's*
/// subcommand and swallows the rest into that subcommand's fields, so
/// they never reach `cli.rest_args`. The tokens belong to the target,
/// not to burn — recover them from argv by slicing everything after the
/// first standalone occurrence of `target`.
///
/// `target` is `cli.file` (the first positional clap bound), so the
/// slice point is the first argv token equal to `target` that isn't the
/// value of a preceding `--flag value` global. We approximate that with
/// the first exact match in `argv[1..]`; global flags that take a value
/// (`--mode`, `--fuel`, …) never legitimately carry one of the
/// ecosystem target names as their value, so a plain first-match is
/// safe in practice and degrades to "no trailing args" otherwise.
pub fn args_after_target(target: &str) -> Vec<String> {
    let argv: Vec<String> = std::env::args().collect();
    if let Some(pos) = argv.iter().skip(1).position(|a| a == target) {
        // `position` is relative to the `skip(1)` view; +1 maps back to
        // the full argv index, then +1 again to start *after* the target.
        argv[pos + 2..].to_vec()
    } else {
        Vec::new()
    }
}

/// Classify `argv[1]` per the Q5-A precedence above.
pub fn detect(file: &Path) -> Detected {
    // Path-qualified forms (`./node`, `/usr/bin/node`, `subdir/node`)
    // are always "run the file at this path". Pass-through is only
    // for bare names.
    if file.components().count() != 1 {
        return Detected::Runnable;
    }
    // Q5-A #1: existing-file-wins.
    if file.exists() {
        return Detected::Runnable;
    }
    let name = file.to_string_lossy().into_owned();
    if KNOWN_TARGETS.contains(&name.as_str()) {
        return Detected::KnownTarget(name);
    }
    if is_on_path(&name) {
        return Detected::PathTarget(name);
    }
    Detected::Unknown(name)
}

pub fn dispatch(cli: &mut Cli, target: &str) -> Result<()> {
    banner::maybe_show(cli);
    match target {
        // `node` stays a pure in-process dispatch — no subprocess, no
        // PATH lookup. It's just "run this script under burn".
        "node" => dispatch_node(cli),
        _ => dispatch_via_shim(cli, target),
    }
}

/// `burn node foo.js arg1 arg2` → `burn run foo.js arg1 arg2`
/// `burn node -e 'code' arg1`   → `burn -e 'code' arg1`
fn dispatch_node(cli: &mut Cli) -> Result<()> {
    if let Some(code) = cli.eval_code.take() {
        return run::run_source(cli, &code, &cli.rest_args);
    }

    let args = std::mem::take(&mut cli.rest_args);
    if args.is_empty() {
        anyhow::bail!(
            "burn node: missing script path\n\
             usage: burn node <file.js> [args…]\n\
             usage: burn node -e '<code>' [args…]"
        );
    }

    let file = PathBuf::from(&args[0]);
    let user_args = &args[1..];
    run::run_file(cli, &file, user_args)
}

/// `burn npm install express` → find real `npm`, prepend shim dir to
/// its `PATH`, exec. npm's internal `node <script>` invocations hit
/// our shim and re-enter burn.
fn dispatch_via_shim(cli: &mut Cli, target: &str) -> Result<()> {
    check_shim_depth()?;
    let shim_dir = shim::ensure_shim_dir()?;
    let real = find_real_binary(target, &shim_dir)
        .ok_or_else(|| anyhow::anyhow!("burn: '{target}' not found on PATH"))?;
    let args = passthrough_args(cli, target);
    exec_with_shim(&real, &args, &shim_dir)
}

/// The target's argument vector. Prefer `cli.rest_args` (the common
/// case where clap left the trailing tokens alone); fall back to the
/// raw-argv reconstruction when a subcommand-name collision (`npm
/// install`, `pnpm run`, …) caused clap to swallow them into a burn
/// subcommand. See [`args_after_target`].
fn passthrough_args(cli: &mut Cli, target: &str) -> Vec<String> {
    let rest = std::mem::take(&mut cli.rest_args);
    if rest.is_empty() {
        args_after_target(target)
    } else {
        rest
    }
}

fn check_shim_depth() -> Result<()> {
    let depth = current_shim_depth();
    if depth >= SHIM_DEPTH_LIMIT {
        anyhow::bail!(
            "burn: shim recursion limit reached ({SHIM_DEPTH_ENV}={depth}, limit={SHIM_DEPTH_LIMIT}).\n\
             a process in this tree kept spawning `burn` via the PATH shim — check for a fork loop."
        );
    }
    Ok(())
}

fn current_shim_depth() -> u32 {
    env::var(SHIM_DEPTH_ENV)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

fn is_on_path(name: &str) -> bool {
    // Exclude our shim dir so a stray `BURN_SHIM_DEPTH=0` with an
    // already-prepended shim dir doesn't mis-classify `node` itself
    // as "on PATH via burn's shim". The shim dir is recreated by
    // `ensure_shim_dir` on dispatch; here we only need to avoid
    // false positives.
    let shim_dir_pattern = format!("burn-shim-{}", std::process::id());
    let Some(path_var) = env::var_os("PATH") else {
        return false;
    };
    for dir in env::split_paths(&path_var) {
        if dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == shim_dir_pattern)
        {
            continue;
        }
        if binary_exists_in(&dir, name) {
            return true;
        }
    }
    false
}

fn find_real_binary(name: &str, exclude: &Path) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        if dir == exclude {
            continue;
        }
        if let Some(p) = locate_in(&dir, name) {
            return Some(p);
        }
    }
    None
}

fn locate_in(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidates = binary_candidates(name);
    for cand in candidates {
        let p = dir.join(&cand);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn binary_exists_in(dir: &Path, name: &str) -> bool {
    binary_candidates(name)
        .into_iter()
        .any(|c| dir.join(c).is_file())
}

#[cfg(windows)]
fn binary_candidates(name: &str) -> Vec<String> {
    // Honor PATHEXT for Windows resolution; default to the common set
    // when the variable is missing.
    let pathext = env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    let mut out = vec![name.to_string()];
    for ext in pathext.split(';') {
        let ext = ext.trim();
        if ext.is_empty() {
            continue;
        }
        out.push(format!("{name}{ext}"));
    }
    out
}

#[cfg(not(windows))]
fn binary_candidates(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

#[cfg(unix)]
fn exec_with_shim(real: &Path, args: &[String], shim_dir: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let new_path = build_prepended_path(shim_dir);
    let next_depth = current_shim_depth() + 1;
    // `exec` replaces the current process on success and returns only
    // on error. Propagate the underlying errno to the caller.
    let err = std::process::Command::new(real)
        .args(args)
        .env("PATH", new_path)
        .env(SHIM_DEPTH_ENV, next_depth.to_string())
        .exec();
    Err(anyhow::Error::new(err).context(format!("exec {real:?} failed")))
}

#[cfg(not(unix))]
fn exec_with_shim(real: &Path, args: &[String], shim_dir: &Path) -> Result<()> {
    let new_path = build_prepended_path(shim_dir);
    let next_depth = current_shim_depth() + 1;
    let status = std::process::Command::new(real)
        .args(args)
        .env("PATH", new_path)
        .env(SHIM_DEPTH_ENV, next_depth.to_string())
        .status()
        .with_context(|| format!("spawning {real:?}"))?;
    // Propagate exit code verbatim so CI tooling (which cares) stays
    // correct. `None` means the child died by signal — map to 1.
    std::process::exit(status.code().unwrap_or(1));
}

fn build_prepended_path(shim_dir: &Path) -> std::ffi::OsString {
    let mut new_path = std::ffi::OsString::from(shim_dir);
    if let Some(existing) = env::var_os("PATH")
        && !existing.is_empty()
    {
        #[cfg(windows)]
        new_path.push(";");
        #[cfg(not(windows))]
        new_path.push(":");
        new_path.push(&existing);
    }
    new_path
}
