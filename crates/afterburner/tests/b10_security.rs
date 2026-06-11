// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! B10 security guardrails for `worker_threads`.
//!
//! These tests are the contract behind every "no security problems"
//! promise in the implementation plan. Each one targets a single
//! defense in `daemon_workers::spawn_worker` or its surrounding glue.
//! If any of them turn red, the threat model has regressed:
//!
//! * **capability inheritance never widens** — a sandboxed parent
//!   spawns a sandboxed child; FS / net / env grants do not leak.
//! * **`BURN_WORKER_DEPTH` cap** — fork-bomb defense.
//! * **`{eval:true}` rejected at the JS layer** — explicit error
//!   rather than silent code injection.
//! * **path outside the FS allow-list rejected before spawn** — no
//!   subprocess is created for a denied script.
//! * **manifold codec round-trip** — a unit test on the
//!   `manifold_to_cli_args` ↔ `build_manifold` boundary, covering
//!   the security-critical "narrows but never widens" invariant.

use afterburner_core::{EnvAccess, FsAccess, Manifold, NetAccess};
use afterburner_wasi::manifold_codec::manifold_to_cli_args;
use serial_test::serial;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn write_temp(dir: &TempDir, name: &str, source: &str) -> PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(source.as_bytes()).expect("write");
    path
}

fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

// ---------------------------------------------------------------------
// (1) capability inheritance never widens
// ---------------------------------------------------------------------

/// Parent runs `--sandbox` with no grants. Worker child is spawned
/// with the same posture: an `fs.readFileSync('/etc/hostname')` call
/// inside the child must throw `PermissionDenied`.
#[test]
#[serial]
fn worker_inherits_sandbox_no_fs() {
    let dir = TempDir::new().expect("tempdir");
    let child_js = write_temp(
        &dir,
        "denied.js",
        r#"
            const { parentPort } = require('worker_threads');
            const fs = require('fs');
            try {
                fs.readFileSync('/etc/hostname', 'utf8');
                parentPort.postMessage({ ok: true });
            } catch (e) {
                parentPort.postMessage({ ok: false, msg: String(e && e.message || e) });
            }
        "#,
    );

    // Parent needs to *spawn* the worker, which means it needs to
    // know the child path. With pure `--sandbox` the parent itself
    // can't read its own arg as a file — but `new Worker(absPath)`
    // doesn't need to read it; only canonicalize. So sandboxed
    // parent + absolute child path is the right test shape.
    //
    // We grant ONLY the directory containing child.js so the spawn
    // path validation succeeds, then assert the child *can't* read
    // outside that root.
    let dir_str = dir.path().to_string_lossy().into_owned();

    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            const w = new Worker({path});
            w.on('message', (m) => {{
                if (m.ok) {{
                    console.error('LEAK: worker read /etc/hostname despite sandboxed parent');
                    process.exit(1);
                }} else {{
                    console.log('SANDBOX_HELD');
                    w.terminate().then(() => process.exit(0));
                }}
            }});
            setTimeout(() => process.exit(99), 30000);
        "#,
        path = js_str(child_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["--sandbox", "--allow-fs", &dir_str, "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("SANDBOX_HELD"),
        "expected SANDBOX_HELD; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------
// (2) BURN_WORKER_DEPTH cap (fork-bomb defense)
// ---------------------------------------------------------------------

/// Pre-set `BURN_WORKER_DEPTH=8` on the parent process; the very
/// first `new Worker(...)` then must fail with the typed depth-cap
/// error rather than spawning anything.
#[test]
#[serial]
fn depth_cap_rejects_when_at_limit() {
    let dir = TempDir::new().expect("tempdir");
    let child_js = write_temp(&dir, "noop.js", "/* never runs */");

    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            try {{
                const w = new Worker({path});
                console.error('UNEXPECTED_SPAWN');
                process.exit(1);
            }} catch (e) {{
                const msg = String(e && e.message || e);
                if (/depth limit/.test(msg)) {{
                    console.log('DEPTH_CAP_HELD');
                    process.exit(0);
                }}
                console.error('wrong error:', msg);
                process.exit(2);
            }}
        "#,
        path = js_str(child_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("BURN_WORKER_DEPTH", "8")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("DEPTH_CAP_HELD"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------
// (3) {eval:true} rejected
// ---------------------------------------------------------------------

#[test]
#[serial]
fn eval_mode_rejected() {
    let parent = r#"
        const { Worker } = require('worker_threads');
        try {
            const w = new Worker('console.log(1)', { eval: true });
            console.error('UNEXPECTED_SPAWN');
            process.exit(1);
        } catch (e) {
            const msg = String(e && e.message || e);
            if (/eval.*not supported|not supported.*eval/i.test(msg)) {
                console.log('EVAL_REJECTED');
                process.exit(0);
            }
            console.error('wrong error:', msg);
            process.exit(2);
        }
    "#;

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", parent])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("EVAL_REJECTED"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------
// (4) path outside the FS allow-list rejected before spawn
// ---------------------------------------------------------------------

/// Parent's manifold grants only `/tmp/safe-XXX`; pointing the worker
/// at a file *outside* that root must throw a typed error before any
/// subprocess is created. We assert by observing that the parent
/// returns from `new Worker(...)` synchronously with an error and
/// never logs `SHOULD_NEVER_RUN` from the would-be child.
#[test]
#[serial]
fn path_outside_fs_allowlist_rejected() {
    let safe_dir = TempDir::new().expect("safe tempdir");
    let outside_dir = TempDir::new().expect("outside tempdir");
    let outside_js = write_temp(
        &outside_dir,
        "outside.js",
        r#"
            const { parentPort } = require('worker_threads');
            console.log('SHOULD_NEVER_RUN');
            parentPort.postMessage('boom');
        "#,
    );

    let parent = format!(
        r#"
            const {{ Worker }} = require('worker_threads');
            try {{
                const w = new Worker({path});
                console.error('UNEXPECTED_SPAWN');
                process.exit(1);
            }} catch (e) {{
                const msg = String(e && e.message || e);
                if (/outside fs allow-list|fs access not granted|permission denied/i.test(msg)) {{
                    console.log('PATH_REJECTED');
                    process.exit(0);
                }}
                console.error('wrong error:', msg);
                process.exit(2);
            }}
        "#,
        path = js_str(outside_js.to_str().unwrap())
    );

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "--sandbox",
            "--allow-fs",
            &safe_dir.path().to_string_lossy(),
            "-e",
            &parent,
        ])
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("PATH_REJECTED"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("SHOULD_NEVER_RUN"),
        "child ran despite path rejection — SECURITY REGRESSION\nstdout:\n{stdout}"
    );
}

// ---------------------------------------------------------------------
// (5) manifold codec — narrowing-only round-trip
// ---------------------------------------------------------------------

/// Sealed manifold encodes as `--sandbox` (no grants) — narrowest.
#[test]
fn codec_sealed_emits_only_sandbox() {
    let m = Manifold::sealed();
    let args = manifold_to_cli_args(&m);
    assert_eq!(args, vec!["--sandbox".to_string()]);
}

/// Open manifold encodes as `[]` (CLI's implicit-open default).
#[test]
fn codec_open_emits_no_args() {
    let m = Manifold::open();
    let args = manifold_to_cli_args(&m);
    assert!(args.is_empty(), "expected empty, got {args:?}");
}

/// Narrowed FS — only the named root appears in the encoded args.
#[test]
fn codec_narrow_fs_root() {
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![PathBuf::from("/srv/app")]);
    let args = manifold_to_cli_args(&m);
    assert!(args.contains(&"--sandbox".to_string()));
    assert!(
        args.contains(&"--allow-fs=/srv/app".to_string()),
        "{args:?}"
    );
    // Must NOT include any other allow flags.
    for a in &args {
        assert!(
            !a.starts_with("--allow-net") && !a.starts_with("--allow-env"),
            "unexpected widening flag: {a}"
        );
    }
}

/// Narrowed net — wildcard-set encoded as `*` (matching the CLI's
/// own grammar). Must NOT promote to `--allow-fs`.
#[test]
fn codec_narrow_net_wildcard() {
    let mut m = Manifold::sealed();
    m.net = NetAccess::OutboundFull(None);
    let args = manifold_to_cli_args(&m);
    assert!(args.contains(&"--allow-net=*".to_string()), "{args:?}");
    for a in &args {
        assert!(
            !a.starts_with("--allow-fs") && !a.starts_with("--allow-env"),
            "unexpected widening flag: {a}"
        );
    }
}

/// Narrowed env — exactly the named keys.
#[test]
fn codec_narrow_env_allowlist() {
    let mut m = Manifold::sealed();
    m.env = EnvAccess::AllowList(vec!["HOME".into(), "PATH".into()]);
    let args = manifold_to_cli_args(&m);
    assert!(
        args.contains(&"--allow-env=HOME,PATH".to_string()),
        "{args:?}"
    );
}

/// EnvAccess::Full uses the wildcard.
#[test]
fn codec_full_env_wildcard() {
    let mut m = Manifold::sealed();
    m.env = EnvAccess::Full;
    let args = manifold_to_cli_args(&m);
    assert!(args.contains(&"--allow-env=*".to_string()), "{args:?}");
}

/// FS::ReadWrite with empty roots = open-FS shape; must encode as
/// `--allow-fs=*` (NOT as the empty-roots open-Manifold shorthand).
/// This protects against a partially-open Manifold collapsing into a
/// fully-open one when serialized.
#[test]
fn codec_open_fs_only_does_not_widen_to_open_manifold() {
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(Vec::new());
    let args = manifold_to_cli_args(&m);
    // Must include sandbox base (parent had narrow net+env).
    assert!(args.contains(&"--sandbox".to_string()), "{args:?}");
    assert!(args.contains(&"--allow-fs=*".to_string()), "{args:?}");
    // Must NOT promote net or env.
    for a in &args {
        assert!(
            !a.starts_with("--allow-net") && !a.starts_with("--allow-env"),
            "unexpected widening flag: {a}"
        );
    }
}
