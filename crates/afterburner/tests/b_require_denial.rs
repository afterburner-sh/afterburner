// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! require() failure-cause truthfulness.
//!
//! Under a sealed manifold, a filesystem-backed `require('./x.js')`
//! used to report Node's "Cannot find module" even though the file
//! existed and the real cause was a DENIED fs read - operators chased
//! phantom missing files instead of granting the capability. The
//! resolver (`polyfills/require.js`) now disambiguates on the failure
//! path: a manifold denial surfaces as EACCES
//! ("permission denied reading '<path>' …"), while a genuinely absent
//! file keeps MODULE_NOT_FOUND, now carrying the directory the
//! relative specifier resolved against.
//!
//! Also pinned here: relative require is file-relative (Node
//! semantics) - a module loaded from a subdirectory resolves its own
//! `./sibling` next to ITSELF, not against the process CWD; the entry
//! script resolves relative to its own file. Only `-e` eval mode
//! falls back to the CWD (no requiring file exists).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn tmp_dir(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_reqdenial_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).expect("create tmp dir");
    dir
}

fn run_burn(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .current_dir(cwd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

#[test]
fn sealed_manifold_require_reports_permission_denied_not_missing() {
    let dir = tmp_dir("sealed");
    fs::write(dir.join("present.js"), "module.exports = { ok: true };\n").unwrap();
    fs::write(
        dir.join("main.js"),
        "const x = require('./present.js'); console.log('loaded', x.ok);\n",
    )
    .unwrap();

    // Any --allow-* flag seals the manifold; net-only grants leave fs
    // at FsAccess::None, so the require's fs probes are DENIED even
    // though present.js exists.
    let main = dir.join("main.js");
    let out = run_burn(
        &["run", main.to_str().unwrap(), "--allow-net", "localhost"],
        &dir,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code(),
        Some(0),
        "denied require must fail the run; stderr: {stderr}"
    );
    assert!(
        stderr.contains("permission denied reading"),
        "denial must be reported as a permission problem; got: {stderr}"
    );
    assert!(
        stderr.contains("present.js"),
        "denial must name the denied path; got: {stderr}"
    );
    assert!(
        !stderr.contains("Cannot find module"),
        "a denied read must NOT masquerade as a missing module; got: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn missing_module_still_reports_cannot_find_with_resolution_base() {
    let dir = tmp_dir("missing");
    fs::write(dir.join("main.js"), "require('./definitely-absent.js');\n").unwrap();

    // Open manifold (no flags): fs reads are allowed, the file truly
    // does not exist - the Node-shaped error must survive, and the
    // message must show WHICH directory the specifier resolved
    // against (file-relative, not CWD).
    let main = dir.join("main.js");
    let out = run_burn(&["run", main.to_str().unwrap()], &dir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "missing module must fail");
    assert!(
        stderr.contains("Cannot find module './definitely-absent.js'"),
        "genuinely absent file keeps MODULE_NOT_FOUND; got: {stderr}"
    );
    assert!(
        stderr.contains("resolved against"),
        "message must carry the resolution base for triage; got: {stderr}"
    );
    assert!(
        !stderr.contains("permission denied"),
        "an absent file must not be misreported as a denial; got: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn relative_require_resolves_against_requiring_file_with_fs_grant() {
    // Entry in <dir>, requiring ./sub/a.js, which requires
    // ./inner/b.js - the second hop only resolves if a.js's require
    // is rooted at <dir>/sub (file-relative), not at the process CWD
    // (which we point somewhere unrelated).
    let dir = tmp_dir("filerel");
    let elsewhere = tmp_dir("cwd_elsewhere");
    fs::create_dir_all(dir.join("sub/inner")).unwrap();
    fs::write(
        dir.join("main.js"),
        "const a = require('./sub/a.js'); console.log('chain:' + a.v);\n",
    )
    .unwrap();
    fs::write(
        dir.join("sub/a.js"),
        "const b = require('./inner/b.js'); module.exports = { v: 'a+' + b.v };\n",
    )
    .unwrap();
    fs::write(dir.join("sub/inner/b.js"), "module.exports = { v: 'b' };\n").unwrap();

    // Sealed manifold + fs read grant on the script dir: resolution
    // works through the granted capability, from an unrelated CWD.
    let main = dir.join("main.js");
    let out = run_burn(
        &[
            "run",
            main.to_str().unwrap(),
            "--allow-fs",
            dir.to_str().unwrap(),
        ],
        &elsewhere,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "file-relative chain must load; stderr: {stderr}"
    );
    assert!(
        stdout.contains("chain:a+b"),
        "both hops must resolve file-relative; got stdout: {stdout}"
    );
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&elsewhere);
}
