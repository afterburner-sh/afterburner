// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! End-to-end coverage for the full registry-dependency RUNTIME workflow
//! through the REAL `burn` binary against a mock registry - the part the
//! dep-chain feature shipped without: an installed package must actually
//! be `require()`-able afterwards.
//!
//! What this guards (each was a live bug):
//!  * `burn install ns/pkg` in a bare directory links the package into
//!    `./node_modules/ns/pkg` (npm-style), so a standalone script's
//!    `require('ns/pkg')` resolves.
//!  * `burn thrust score.js` resolves registry deps - the UDF path used
//!    to have no entry dir at all, so EVERY bare require failed there.
//!  * package mode: `[dependencies]` install -> `burn run` resolves the
//!    dep through `node_modules/<ns>/<name>` -> extracted cache tree.
//!  * self-heal: deleting `node_modules` and running again re-links from
//!    `burn.lock` + the content cache with no network.

#![cfg(feature = "bin")]

use httpmock::prelude::*;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Run `burn` with an isolated cache + the mock registry.
fn run_in(
    args: &[&str],
    cwd: &std::path::Path,
    cache: &std::path::Path,
    registry: &str,
) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("XDG_CACHE_HOME", cache)
        .env("BURN_REGISTRY", registry)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn burn")
}

/// Pipe `stdin` into `burn thrust <file>` (same isolated env).
fn thrust_in(
    file: &str,
    stdin: &str,
    cwd: &std::path::Path,
    cache: &std::path::Path,
    registry: &str,
) -> std::process::Output {
    use std::io::Write;
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("XDG_CACHE_HOME", cache)
        .env("BURN_REGISTRY", registry)
        .args(["thrust", file])
        .current_dir(cwd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn burn thrust");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().expect("thrust output")
}

/// Build a real dependency `.afb` (scaffold-free: hand-rolled files +
/// `burn package`), returning its bytes + sha256 hex digest.
fn build_dep_afb(tmp: &std::path::Path) -> (Vec<u8>, String) {
    let pkg = tmp.join("depsrc");
    std::fs::create_dir_all(pkg.join("source")).unwrap();
    std::fs::write(
        pkg.join("afb.toml"),
        r#"[format]
version = "1.0"
[package]
description = "distance helpers"
entry = "source/main.js"
language = "js"
license = "Apache-2.0"
name = "phonetic"
namespace = "burnt"
version = "0.1.0"
[runtime]
min = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        pkg.join("manifold.json"),
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    )
    .unwrap();
    std::fs::write(
        pkg.join("source/main.js"),
        "module.exports = { tag: 'phonetic-loaded', double: (n) => n * 2 };\n",
    )
    .unwrap();

    let out_path = tmp.join("dep.afb");
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "package",
            pkg.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn package");
    assert!(
        out.status.success(),
        "burn package failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(&out_path).unwrap();
    let digest = afterburner_cloud::afterburner_afb::digest::hex(
        &afterburner_cloud::afterburner_afb::digest::digest(&bytes),
    );
    (bytes, digest)
}

/// Mock the three registry endpoints `burn install` resolves through.
fn mock_registry(server: &MockServer, afb: &[u8], digest: &str) {
    let digest_full = format!("sha256:{digest}");
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/packages/burnt/phonetic");
        then.status(200).json_body(serde_json::json!({
            "namespace": "burnt",
            "name": "phonetic",
            "latest": "0.1.0",
            "versions": [{ "version": "0.1.0", "digest": digest_full }],
        }));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/packages/burnt/phonetic/0.1.0");
        then.status(200).json_body(serde_json::json!({
            "namespace": "burnt",
            "name": "phonetic",
            "version": "0.1.0",
            "digest": digest_full,
            "dependencies": {},
        }));
    });
    let body = afb.to_vec();
    server.mock(move |when, then| {
        when.method(GET)
            .path("/api/v1/packages/burnt/phonetic/0.1.0/download");
        then.status(200).body(&body);
    });
}

#[test]
fn bare_install_links_node_modules_and_thrust_requires_the_dep() {
    let server = MockServer::start();
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();

    let (afb, digest) = build_dep_afb(tmp.path());
    mock_registry(&server, &afb, &digest);

    // The user flow that broke: bare dir, install by coordinate.
    let out = run_in(
        &["install", "burnt/phonetic"],
        &work,
        &cache,
        &server.base_url(),
    );
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let linked = work.join("node_modules/burnt/phonetic");
    assert!(
        linked.exists(),
        "install must link ./node_modules/<ns>/<name>"
    );
    assert!(
        linked.join("package.json").exists(),
        "extracted tree carries a generated package.json (main -> entry)"
    );

    // …then `burn thrust` on a standalone script requiring it.
    std::fs::write(
        work.join("score.js"),
        "const ph = require('burnt/phonetic');\nmodule.exports = (d) => ({ tag: ph.tag, n: ph.double(d.n) });\n",
    )
    .unwrap();
    let out = thrust_in("score.js", r#"{"n":21}"#, &work, &cache, &server.base_url());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("phonetic-loaded") && stdout.contains("42"),
        "thrust must resolve the installed dep.\nstdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `burn run` of a file in the same dir resolves it too.
    std::fs::write(
        work.join("use.js"),
        "console.log('RUN', require('burnt/phonetic').double(4));\n",
    )
    .unwrap();
    let out = run_in(&["use.js"], &work, &cache, &server.base_url());
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("RUN 8"),
        "run must resolve the installed dep: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn package_mode_dependency_installs_runs_and_self_heals() {
    let server = MockServer::start();
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    let pkg = tmp.path().join("app");
    std::fs::create_dir_all(pkg.join("source")).unwrap();

    let (afb, digest) = build_dep_afb(tmp.path());
    mock_registry(&server, &afb, &digest);

    std::fs::write(
        pkg.join("afb.toml"),
        r#"[format]
version = "1.0"
[package]
description = "consumer"
entry = "source/main.js"
language = "js"
license = "Apache-2.0"
name = "consumer"
namespace = "nyquist"
version = "0.1.0"
[runtime]
min = "0.1.0"
[dependencies]
"burnt/phonetic" = "*"
"#,
    )
    .unwrap();
    std::fs::write(
        pkg.join("manifold.json"),
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    )
    .unwrap();
    std::fs::write(
        pkg.join("source/main.js"),
        "console.log('GOT', require('burnt/phonetic').double(21));\n",
    )
    .unwrap();

    // install -> lockfile + node_modules link.
    let out = run_in(&["install"], &pkg, &cache, &server.base_url());
    assert!(
        out.status.success(),
        "package install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(pkg.join("burn.lock").exists(), "lockfile written");
    assert!(
        pkg.join("node_modules/burnt/phonetic").exists(),
        "dep linked next to the manifest"
    );

    // run resolves the dep.
    let out = run_in(&["run"], &pkg, &cache, &server.base_url());
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("GOT 42"),
        "package run must resolve the dep: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Self-heal: wipe node_modules; `burn run` re-links from the lock +
    // content cache - cargo builds on `cargo run`, burn links on `burn run`.
    std::fs::remove_dir_all(pkg.join("node_modules")).unwrap();
    let out = run_in(&["run"], &pkg, &cache, &server.base_url());
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("GOT 42"),
        "self-heal run must re-link from burn.lock: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        pkg.join("node_modules/burnt/phonetic").exists(),
        "node_modules re-materialized"
    );
}
