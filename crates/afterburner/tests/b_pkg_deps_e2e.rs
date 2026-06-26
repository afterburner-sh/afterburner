// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! End-to-end coverage for package dependency management through the REAL
//! `burn` CLI binary: scaffold (JS + TS), declare deps, pack, and verify
//! the produced `.afb` is correct, JS-only, and fast to build.
//!
//! What this guards:
//!  * `burn new --ts` scaffolds a TypeScript package (entry `.ts`, tsconfig).
//!  * `burn package` on a TS package transpiles to JS at pack time - the
//!    published `.afb` contains `source/main.js` and NO `.ts` (the runtime
//!    never needs a transpiler).
//!  * dependencies are DECLARED in `afb.toml` (`[dependencies]`, `[npm]`)
//!    and are NOT packed into the `.afb` (cargo model - small artifacts).
//!  * native/C-ABI artifacts hand-committed under `source/` are rejected.
//!  * packing is fast (a cold pack of a fresh package well under a second of
//!    CPU - the artifact is a single content-addressed file, no per-dep
//!    network round-trips like npm's tarball waterfall).

#![cfg(feature = "bin")]

use std::process::Command;
use std::time::Instant;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run(args: &[&str], cwd: Option<&std::path::Path>) -> std::process::Output {
    let mut c = Command::new(BURN);
    c.env("BURN_QUIET", "1").args(args);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    c.output().expect("spawn burn")
}

/// Read the `source/` entries of a packed `.afb` (paths only).
fn afb_source_paths(bytes: &[u8]) -> Vec<String> {
    let afb = afterburner_afb::Afb::from_bytes(bytes).expect("parse .afb");
    afb.source.keys().cloned().collect()
}

#[test]
fn new_ts_scaffold_then_package_is_js_only() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("tspkg");

    let out = run(
        &[
            "init",
            dir.to_str().unwrap(),
            "--name",
            "thing",
            "--namespace",
            "nyquist",
            "--ts",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "new --ts failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.join("source/main.ts").exists(), "TS entry scaffolded");
    assert!(dir.join("tsconfig.json").exists(), "tsconfig scaffolded");
    assert!(
        !dir.join("source/main.js").exists(),
        "no JS entry for a TS package"
    );

    // Pack it.
    let out = run(
        &[
            "package",
            dir.to_str().unwrap(),
            "--out",
            dir.join("p.afb").to_str().unwrap(),
        ],
        None,
    );
    assert!(
        out.status.success(),
        "package failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = std::fs::read(dir.join("p.afb")).unwrap();
    let paths = afb_source_paths(&bytes);
    assert!(
        paths.iter().any(|p| p == "source/main.js"),
        "packed .afb must carry transpiled JS entry, got {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.ends_with(".ts")),
        "packed .afb must NOT carry any .ts (transpiled at pack), got {paths:?}"
    );

    // The manifest entry must point at the .js.
    let afb = afterburner_afb::Afb::from_bytes(&bytes).unwrap();
    assert_eq!(afb.manifest.package.entry, "source/main.js");
}

#[test]
fn new_js_scaffold_packs_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("jspkg");
    let out = run(
        &[
            "init",
            dir.to_str().unwrap(),
            "--name",
            "thing",
            "--namespace",
            "nyquist",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "new failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.join("source/main.js").exists());

    let out = run(
        &[
            "package",
            dir.to_str().unwrap(),
            "--out",
            dir.join("p.afb").to_str().unwrap(),
        ],
        None,
    );
    assert!(
        out.status.success(),
        "package failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let paths = afb_source_paths(&std::fs::read(dir.join("p.afb")).unwrap());
    assert!(paths.iter().any(|p| p == "source/main.js"));
}

#[test]
fn declared_deps_are_not_packed_into_afb() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("withdeps");
    let out = run(
        &[
            "init",
            dir.to_str().unwrap(),
            "--name",
            "app",
            "--namespace",
            "nyquist",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Declare an npm dep in afb.toml + drop a node_modules tree next to it.
    let afb_toml = dir.join("afb.toml");
    let mut t = std::fs::read_to_string(&afb_toml).unwrap();
    t.push_str("\n[npm]\nleftpad = \"^1.0.0\"\n");
    std::fs::write(&afb_toml, t).unwrap();
    std::fs::create_dir_all(dir.join("node_modules/leftpad")).unwrap();
    std::fs::write(
        dir.join("node_modules/leftpad/index.js"),
        "module.exports=1;",
    )
    .unwrap();

    let out = run(
        &[
            "package",
            dir.to_str().unwrap(),
            "--out",
            dir.join("p.afb").to_str().unwrap(),
        ],
        None,
    );
    assert!(
        out.status.success(),
        "package failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = std::fs::read(dir.join("p.afb")).unwrap();
    let paths = afb_source_paths(&bytes);
    assert!(
        !paths.iter().any(|p| p.contains("node_modules")),
        "node_modules must NOT be packed (cargo model), got {paths:?}"
    );
    // But the declaration round-trips in the manifest.
    let afb = afterburner_afb::Afb::from_bytes(&bytes).unwrap();
    assert_eq!(
        afb.manifest.npm.get("leftpad").map(String::as_str),
        Some("^1.0.0")
    );
}

#[test]
fn native_artifact_under_source_is_rejected_by_package() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("native");
    let out = run(
        &[
            "init",
            dir.to_str().unwrap(),
            "--name",
            "n",
            "--namespace",
            "nyquist",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::create_dir_all(dir.join("source/vendor")).unwrap();
    std::fs::write(dir.join("source/vendor/addon.node"), b"\0\0native").unwrap();

    let out = run(
        &[
            "package",
            dir.to_str().unwrap(),
            "--out",
            dir.join("p.afb").to_str().unwrap(),
        ],
        None,
    );
    assert!(
        !out.status.success(),
        "package must reject a native artifact"
    );
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        msg.to_lowercase().contains("native"),
        "error must name the native rejection: {msg}"
    );
}

#[test]
fn packing_is_fast() {
    // Cold pack of a fresh package: a single content-addressed file, no
    // per-dependency network round-trips (npm's tarball waterfall). The
    // wall budget here is generous (process spawn + cold caches dominate);
    // it exists to catch a pathological regression, not to microbenchmark.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("fast");
    assert!(
        run(
            &[
                "init",
                dir.to_str().unwrap(),
                "--name",
                "f",
                "--namespace",
                "nyquist"
            ],
            None
        )
        .status
        .success()
    );

    let t = Instant::now();
    let out = run(
        &[
            "package",
            dir.to_str().unwrap(),
            "--out",
            dir.join("p.afb").to_str().unwrap(),
        ],
        None,
    );
    let elapsed = t.elapsed();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed.as_secs() < 5,
        "packing took {elapsed:?} - far slower than expected for a single-file artifact"
    );
}

#[test]
fn burn_run_executes_package_entry_from_afb_toml() {
    // cargo-style: `burn run` with no FILE runs the entry declared in
    // afb.toml. The entry prints at top level so we can observe it ran.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("runnable");
    assert!(
        run(
            &[
                "init",
                dir.to_str().unwrap(),
                "--name",
                "r",
                "--namespace",
                "nyquist"
            ],
            None
        )
        .status
        .success()
    );
    std::fs::write(
        dir.join("source/main.js"),
        "console.log('ran:' + (typeof module.exports));\nmodule.exports = () => 1;",
    )
    .unwrap();

    // `burn run` from inside the package directory, no file argument.
    let out = run(&["run"], Some(&dir));
    assert!(
        out.status.success(),
        "burn run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ran:"),
        "entry should have executed, stdout: {stdout}"
    );
}

#[test]
fn burn_run_without_package_errors_clearly() {
    let tmp = tempfile::tempdir().unwrap();
    // empty dir: no afb.toml, no file argument
    let out = run(&["run"], Some(tmp.path()));
    assert!(!out.status.success(), "burn run with nothing must error");
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        msg.contains("afb.toml"),
        "error should mention afb.toml: {msg}"
    );
}

#[test]
fn burn_clean_removes_built_afb() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("c");
    assert!(
        run(
            &[
                "init",
                dir.to_str().unwrap(),
                "--name",
                "c",
                "--namespace",
                "nyquist"
            ],
            None
        )
        .status
        .success()
    );
    // build an artifact
    assert!(run(&["package"], Some(&dir)).status.success());
    let afb = dir.join("nyquist-c-0.1.0.afb");
    assert!(afb.exists(), "package built");
    // clean removes it
    let out = run(&["clean"], Some(&dir));
    assert!(
        out.status.success(),
        "clean: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!afb.exists(), "clean must remove the built .afb");
}
