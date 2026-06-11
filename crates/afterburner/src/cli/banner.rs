// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! First-run open-capabilities banner (Q1-D).
//!
//! The CLI defaults to `Manifold::open()` so Node scripts drop in
//! without capability flags. To keep the security posture
//! *discoverable*, we print a one-line banner to stderr the **first
//! time** a user runs `burn` with implicit open and record an
//! ack-marker so it never repeats.
//!
//! Silencing:
//!
//! * `--quiet` / `-q` → no banner this invocation.
//! * `BURN_QUIET=1` → no banner this invocation.
//! * Ack-marker present at `~/.cache/burn/opened` (or
//!   `%LOCALAPPDATA%\burn\opened` on Windows) → no banner.
//!
//! A corrupted / unwriteable ack-marker is not fatal: the banner will
//! keep printing on every run until the file can be written. That's
//! noisy but not dangerous.

use std::env;
use std::fs;
use std::path::PathBuf;

use super::args::Cli;
use super::manifold::is_implicit_open;
use super::style;

const ACK_FILENAME: &str = "opened";
const BANNER: &str = "running with open capabilities. --sandbox to seal, BURN_QUIET=1 to silence";

/// Show the open-capabilities banner if the current invocation is
/// running under the implicit-open default and we haven't shown it to
/// this user before. Idempotent and best-effort — never returns an
/// error to the caller.
pub fn maybe_show(cli: &Cli) {
    if cli.quiet {
        return;
    }
    if env::var_os("BURN_QUIET").is_some() {
        return;
    }
    if !is_implicit_open(cli) {
        return;
    }
    let marker = match ack_marker_path() {
        Some(p) => p,
        None => {
            // No HOME / LOCALAPPDATA — print every time. Still
            // preferable to silently running open without a warning.
            eprintln!("{}", style::warn(BANNER));
            return;
        }
    };
    if marker.exists() {
        return;
    }
    eprintln!("{BANNER}");
    // Best-effort ack; errors are ignored. On failure the banner
    // shows again next run — noisy but not dangerous.
    if let Some(parent) = marker.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&marker, b"1\n");
}

fn ack_marker_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let base = env::var_os("LOCALAPPDATA").or_else(|| env::var_os("USERPROFILE"))?;
        Some(PathBuf::from(base).join("burn").join(ACK_FILENAME))
    }
    #[cfg(not(windows))]
    {
        // Prefer XDG_CACHE_HOME, fall back to $HOME/.cache. Matches the
        // XDG Base Directory Specification so well-configured systems
        // don't get a stray dir in $HOME.
        if let Some(xdg) = env::var_os("XDG_CACHE_HOME") {
            return Some(PathBuf::from(xdg).join("burn").join(ACK_FILENAME));
        }
        let home = env::var_os("HOME")?;
        Some(
            PathBuf::from(home)
                .join(".cache")
                .join("burn")
                .join(ACK_FILENAME),
        )
    }
}
