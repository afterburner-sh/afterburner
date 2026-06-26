// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! B5 phase gate: PATH shim for `burn npm` / `burn pnpm` / `burn
//! npx` / `burn yarn` / `burn bun` + the Q5-A general-case pass-
//! through (any first-arg that's on PATH becomes a pass-through).
//!
//! Covered here:
//!
//! * **Mechanism.** `burn <target>` locates the real target on PATH
//!   and invokes it; when the target is missing we emit Q5-2's typed
//!   error before any exec.
//! * **Recursion guard (Q5-3).** `BURN_SHIM_DEPTH >= 8` surfaces a
//!   typed error rather than fork-bombing.
//! * **Unknown-command (Q5-2).** Arbitrary first-args that aren't a
//!   subcommand, a local file, or on PATH produce `burn: unknown
//!   command '<arg>'` without touching exec.
//! * **Q5-A fall-through.** Any PATH binary (not just the hard-coded
//!   known set) passes through.
//! * **node shim payload.** Running the generated shim from within a
//!   child process re-enters burn - proves the shim file is actually
//!   on PATH and is executable, which is what makes `burn npm
//!   install` route npm's internal `node <script>` back through
//!   burn.
//! * **Existing-file-wins (Q5-A #1).** A local file named `npm` wins
//!   over pass-through dispatch.

#![cfg(feature = "bin")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn tmp_dir(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_b5_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---- target-missing surfaces typed error (Q5-2 for known targets) -------

#[test]
fn missing_target_on_path_errors_typed() {
    // Force a PATH that can't possibly contain the target so we
    // exercise the `not found` branch without depending on the
    // host's real tooling inventory. Using `/nonexistent` matches
    // CI sandboxes where npm genuinely isn't installed.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("PATH", "/nonexistent-burn-b5")
        .args(["npm", "install", "express"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(!out.status.success(), "missing target should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("'npm' not found on PATH"),
        "expected typed not-found message, got: {stderr}"
    );
    assert!(
        !stderr.contains("No such file or directory"),
        "should not leak raw exec errno: {stderr}"
    );
}

#[test]
fn missing_pnpm_yarn_bun_npx_also_typed() {
    // Use an arg clap won't intercept - `--version` is a global flag
    // and `help` is the auto-generated help subcommand; either would
    // bypass passthrough dispatch entirely. A plain string like
    // `install` keeps clap in positional-fallback mode.
    for target in &["pnpm", "yarn", "bun", "npx"] {
        let out = Command::new(BURN)
            .env("BURN_QUIET", "1")
            .env("BURN_SHARDS", "2")
            .env("PATH", "/nonexistent-burn-b5")
            .args([target, "install"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn burn");
        assert!(!out.status.success(), "{target}: should fail");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!("'{target}' not found on PATH")),
            "{target}: expected typed not-found, got: {stderr}"
        );
    }
}

// ---- unknown-command (Q5-2) ---------------------------------------------

#[test]
fn unknown_first_arg_not_on_path_errors_typed() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("PATH", "/nonexistent-burn-b5")
        .arg("definitely_not_a_real_binary_73192")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown command 'definitely_not_a_real_binary_73192'"),
        "expected Q5-2 typed unknown-command, got: {stderr}"
    );
}

#[test]
fn unknown_command_is_reported_before_any_exec() {
    // The specific gripe in Q5-2: no raw errno leakage like
    // `could not exec noed: No such file or directory`.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("PATH", "/nonexistent-burn-b5")
        .arg("noed")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        !stderr.contains("No such file or directory"),
        "must not leak exec errno: {stderr}"
    );
    assert!(
        stderr.contains("unknown command 'noed'"),
        "expected typed unknown-command, got: {stderr}"
    );
}

// ---- recursion guard (Q5-3) --------------------------------------------

#[test]
fn shim_depth_limit_surfaces_typed_error() {
    // Pretend we're already 8 levels deep; the next pass-through must
    // refuse to spawn rather than fork-bomb.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("BURN_SHIM_DEPTH", "8")
        .args(["npm", "install"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("shim recursion limit reached"),
        "expected recursion-guard message, got: {stderr}"
    );
    assert!(
        stderr.contains("BURN_SHIM_DEPTH"),
        "message should mention the env var so users can diagnose: {stderr}"
    );
}

#[test]
fn shim_depth_limit_ignores_garbage_values() {
    // Non-numeric `BURN_SHIM_DEPTH` must be treated as 0 (fresh
    // invocation) rather than panicking or erroring out.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("BURN_SHIM_DEPTH", "garbage")
        .env("PATH", "/nonexistent-burn-b5")
        .args(["npm", "install"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    // Should surface the "not found on PATH" error (depth treated as
    // 0, proceeded to lookup, lookup failed) - NOT the recursion
    // limit.
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("'npm' not found on PATH"),
        "expected not-found, got: {stderr}"
    );
    assert!(
        !stderr.contains("recursion limit"),
        "garbage depth must not trigger the limit: {stderr}"
    );
}

// ---- Q5-A fall-through: arbitrary PATH binaries pass through ------------

#[test]
fn arbitrary_path_binary_passes_through() {
    // Build a scratch dir that holds a trivial shell "binary" and
    // set PATH to contain only that dir, so we know exactly what
    // burn will find. Use a distinct name so we don't collide with
    // anything on the host's real PATH.
    let dir = tmp_dir("qa_arbitrary");
    let bin_name = "burnb5_echo_marker";
    let bin_path = dir.join(bin_name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `#!/bin/sh` bypasses PATH for the shebang resolution; the
        // restricted PATH we hand to burn would otherwise leave
        // `/usr/bin/env sh` unable to locate `sh`.
        fs::write(&bin_path, "#!/bin/sh\necho passthrough-marker-$1\n").unwrap();
        let mut p = fs::metadata(&bin_path).unwrap().permissions();
        p.set_mode(0o755);
        fs::set_permissions(&bin_path, p).unwrap();
    }
    #[cfg(windows)]
    {
        let bin_path = dir.join(format!("{bin_name}.cmd"));
        fs::write(&bin_path, "@echo passthrough-marker-%1\r\n").unwrap();
    }

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("PATH", &dir)
        .args([bin_name, "howdy"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "arbitrary PATH binary should pass through, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("passthrough-marker-howdy"),
        "expected arg forwarded through pass-through, got: {stdout}"
    );
}

// ---- existing-file-wins (Q5-A #1) ---------------------------------------

#[test]
fn existing_file_named_npm_wins_over_passthrough() {
    let dir = tmp_dir("existing_npm");
    let npm_file = dir.join("npm");
    fs::write(&npm_file, "console.log('i am a local file called npm');").unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(&dir)
        .arg("npm")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "exit {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("i am a local file called npm"),
        "existing file should win, stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// ---- shim trampoline: `sh <shim>/node <script>` re-enters burn ---------
//
// This is the mechanism that makes `burn npm install` work at all:
// npm internally spawns `node <script>`; our shim file, placed first
// on PATH by the pass-through code, has to resolve to burn.
// Directly invoking the shim is the tightest test - it doesn't need
// npm to be installed in CI to validate the core primitive.

#[test]
#[cfg(unix)]
fn shim_dir_node_shim_forwards_to_burn() {
    // Build a fresh shim dir by running `burn` with a pass-through
    // target configured to exist in a scratch PATH. We can't easily
    // probe the shim dir from inside a test, so we borrow the same
    // `ensure_shim_dir` mechanism by spawning a subprocess that runs
    // `env` as the "real binary" and inspects the resulting PATH.
    //
    // Simpler, directly targeted: spawn `sh -c "$(burn-shim)/node -e
    // ..."` via the subprocess API we already have. We synthesize a
    // shim dir by running a trivial pass-through against `env`: burn
    // execs `env PATH=<shim>:$PATH`, `env` prints its PATH; we pull
    // the shim dir out of the first path entry, then drive it.
    let scratch = tmp_dir("shim_trampoline");
    // Stage `env` into the scratch dir so PATH lookup finds it there
    // (doesn't matter where real `env` lives - we just need something
    // executable to pass through to).
    let env_link = scratch.join("env");
    // `/usr/bin/env` is the most portable location for env on Unix.
    std::os::unix::fs::symlink("/usr/bin/env", &env_link)
        .or_else(|_| std::os::unix::fs::symlink("/bin/env", &env_link))
        .expect("symlinking env into scratch");

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("PATH", &scratch)
        .arg("env")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&scratch);
    assert!(
        out.status.success(),
        "env pass-through failed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // env's output contains `PATH=<shim-dir>:<original-path>` - first
    // path entry is our shim dir.
    let path_line = stdout
        .lines()
        .find(|l| l.starts_with("PATH="))
        .expect("env should print PATH");
    let path_val = &path_line["PATH=".len()..];
    let shim_dir = path_val.split(':').next().expect("PATH has entries");
    let shim_node = PathBuf::from(shim_dir).join("node");
    assert!(
        shim_node.exists(),
        "shim dir must contain a `node` shim: {shim_node:?}"
    );

    // Run the shim via `sh` to prove it's a well-formed exec wrapper.
    // Passing `-e 'console.log(42)'` through the shim should land in
    // burn's eval path and print 42.
    let shim_out = Command::new(&shim_node)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-e", "console.log(6 * 7)"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn shim/node");
    assert!(
        shim_out.status.success(),
        "shim exec failed, stderr: {}",
        String::from_utf8_lossy(&shim_out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&shim_out.stdout).trim(), "42");
}

// ---- exit-code propagation through pass-through -------------------------

#[test]
fn passthrough_exit_code_propagates() {
    // A pass-through target that exits non-zero must surface its exit
    // code, not mangle it to 1. Synthesize a "binary" that exits with
    // a specific code so we control the outcome independently of
    // whatever real binaries are installed in CI.
    let dir = tmp_dir("exit_code");
    let bin_name = "burnb5_exit_code_probe";
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin_path = dir.join(bin_name);
        fs::write(&bin_path, "#!/bin/sh\nexit 17\n").unwrap();
        let mut p = fs::metadata(&bin_path).unwrap().permissions();
        p.set_mode(0o755);
        fs::set_permissions(&bin_path, p).unwrap();
    }
    #[cfg(windows)]
    {
        let bin_path = dir.join(format!("{bin_name}.cmd"));
        fs::write(&bin_path, "@exit /b 17\r\n").unwrap();
    }

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("PATH", &dir)
        .arg(bin_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        out.status.code(),
        Some(17),
        "exit code 17 should propagate, got {:?}",
        out.status.code()
    );
}
