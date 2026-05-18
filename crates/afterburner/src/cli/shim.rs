// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! PATH shim: creates a temp dir containing a `node` executable that
//! re-enters the current `burn` binary. When `burn npm install` (or
//! `pnpm`/`yarn`/`npx`/`bun`) prepends this dir to the spawned
//! command's `PATH`, every internal `node <script>` invocation in the
//! child-process tree resolves to our shim and therefore runs inside
//! the burn sandbox.
//!
//! * **Unix** — shell script `#!/usr/bin/env sh\nexec $BURN "$@"\n`
//!   made executable (0755).
//! * **Windows** — `.cmd` batch file `@"$BURN" %*` (`.cmd` is picked
//!   up by `PATHEXT` by default on both cmd.exe and PowerShell).
//!
//! One shim dir per burn process at `$TMP/burn-shim-$PID/`. The dir
//! is created on demand, idempotent within a single invocation, and
//! intentionally leaked — `exec(3)` replaces us before we could clean
//! up, and the temp files are a few dozen bytes each. OS-level temp
//! cleanup handles stale dirs across reboots.

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Create the shim dir (if missing), populate it with a `node` shim
/// that re-enters the current `burn` binary, and return the dir path.
pub fn ensure_shim_dir() -> Result<PathBuf> {
    let dir = shim_dir_path();
    fs::create_dir_all(&dir).with_context(|| format!("creating shim dir {dir:?}"))?;
    let burn_exe = env::current_exe().context("locating burn binary")?;
    write_node_shim(&dir, &burn_exe)?;
    Ok(dir)
}

fn shim_dir_path() -> PathBuf {
    let pid = std::process::id();
    env::temp_dir().join(format!("burn-shim-{pid}"))
}

#[cfg(unix)]
fn write_node_shim(dir: &Path, burn_exe: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let shim_path = dir.join("node");
    let burn_str = burn_exe.to_string_lossy();
    // Escape single quotes for a POSIX single-quoted string: ' → '\''.
    // `exec` replaces the shell with burn so the trampoline adds no
    // process overhead after the first fork.
    let escaped = burn_str.replace('\'', r"'\''");
    let body = format!("#!/usr/bin/env sh\nexec '{escaped}' \"$@\"\n");
    fs::write(&shim_path, body).with_context(|| format!("writing {shim_path:?}"))?;
    let mut perms = fs::metadata(&shim_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&shim_path, perms).with_context(|| format!("chmod +x {shim_path:?}"))?;
    Ok(())
}

#[cfg(windows)]
fn write_node_shim(dir: &Path, burn_exe: &Path) -> Result<()> {
    let shim_path = dir.join("node.cmd");
    let burn_str = burn_exe.to_string_lossy();
    // `%*` forwards all arguments; the outer quotes handle spaces in
    // the burn install path. CRLF to match Windows batch conventions.
    let body = format!("@\"{burn_str}\" %*\r\n");
    fs::write(&shim_path, body).with_context(|| format!("writing {shim_path:?}"))?;
    Ok(())
}
