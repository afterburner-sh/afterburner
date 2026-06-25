// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Integration test: `burn compile` resolves transitive path dependencies
//! declared as `{ path = "../..." }` in `afb.toml`.
//!
//! Two-package fixture:
//!   leaf - no deps, exports a pure function
//!   root - depends on leaf via `{ path = "../leaf" }`, calls it
//!
//! `burn compile root` must produce an `.afb` with
//! `precompiled/wasm32-wasip1/main.wasm` present AND invoking it must return
//! the value computed through leaf's code (proving the closure was linked,
//! not just that a wasm member exists).
//!
//! Skips cleanly when `javy` is absent.

#![cfg(feature = "bin")]

use afterburner_afb::Afb;
use std::path::Path;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn write_file(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn javy_available() -> bool {
    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());
    std::process::Command::new(&javy)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Write the `leaf` package: exports a pure function `(x) => x * 7`.
fn scaffold_leaf(packages_dir: &Path) {
    let dir = packages_dir.join("leaf");
    write_file(
        &dir,
        "afb.toml",
        "[format]\nversion = \"1.0\"\n\
         [package]\nname = \"leaf\"\nnamespace = \"x\"\n\
         version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
         [runtime]\nmin = \"0.1.0\"\n",
    );
    write_file(
        &dir,
        "manifold.json",
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    );
    write_file(&dir, "source/main.js", "module.exports = (x) => x * 7;\n");
}

/// Write the `root` package: depends on leaf via a path dep and calls it.
fn scaffold_root(packages_dir: &Path) {
    let dir = packages_dir.join("root");
    write_file(
        &dir,
        "afb.toml",
        "[format]\nversion = \"1.0\"\n\
         [package]\nname = \"root\"\nnamespace = \"x\"\n\
         version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
         [runtime]\nmin = \"0.1.0\"\n\
         [dependencies]\n\"x/leaf\" = { path = \"../leaf\" }\n",
    );
    write_file(
        &dir,
        "manifold.json",
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    );
    // root requires leaf by its coordinate: leaf(n) = n * 7
    write_file(
        &dir,
        "source/main.js",
        "const leaf = require('x/leaf');\nmodule.exports = (input) => ({ result: leaf(input.n) });\n",
    );
}

#[test]
fn compile_with_path_dep_produces_precompiled_member() {
    if !javy_available() {
        eprintln!(
            "SKIP compile_with_path_dep_produces_precompiled_member: \
             `javy` not found on PATH; install javy 8.1.1 to run this test"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let packages_dir = tmp.path().join("packages");
    std::fs::create_dir_all(&packages_dir).unwrap();

    scaffold_leaf(&packages_dir);
    scaffold_root(&packages_dir);

    let root_dir = packages_dir.join("root");
    let out_afb = tmp.path().join("root.afb");

    // No --packages-dir flag: leaf is found via { path = "../leaf" } in afb.toml.
    let result = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "compile",
            root_dir.to_str().unwrap(),
            "-o",
            out_afb.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn compile");

    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success(),
        "burn compile with path dep failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Must NOT fall back to source-only (that note would appear on stderr).
    assert!(
        !stderr.contains("source-only"),
        "expected precompiled output, but got source-only fallback note: {stderr}"
    );

    let bytes = std::fs::read(&out_afb).expect("reading output .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing output .afb");

    // Precompiled member must be present and non-empty.
    let wasm_key = "precompiled/wasm32-wasip1/main.wasm";
    let wasm_bytes = afb
        .precompiled
        .get(wasm_key)
        .unwrap_or_else(|| panic!("{wasm_key} must be present when path deps are resolved"));
    assert!(!wasm_bytes.is_empty(), "precompiled wasm must be non-empty");

    // runtime.target must be set.
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1"),
        "runtime.target must be wasm32-wasip1"
    );

    // Correctness: invoke the precompiled wasm and confirm it returns a value
    // that depends on leaf's code (leaf(n) = n*7, so result should be 42 for n=6).
    use afterburner_core::{Combustor, FuelGauge};
    use afterburner_wasi::{WasmCombustor, WasmConfig};
    use serde_json::json;

    let engine = WasmCombustor::new(WasmConfig::default()).expect("WasmCombustor::new");
    let limits = FuelGauge::unlimited();

    let pre_id = engine
        .register_precompiled(wasm_bytes, "wasm32-wasip1")
        .expect("register_precompiled");
    let input = json!({ "n": 6 });
    let out = engine
        .thrust(&pre_id, &input, &limits)
        .expect("thrust precompiled");

    assert_eq!(
        out["result"],
        json!(42),
        "precompiled output must use leaf's multiply-by-7 logic: got {out}"
    );
}

#[test]
fn path_dep_missing_dir_errors_clearly() {
    // Root declares a path dep to a missing directory; burn compile must fail
    // with a clear error (not a panic or unhelpful message).
    let tmp = tempfile::tempdir().unwrap();
    let packages_dir = tmp.path().join("packages");
    std::fs::create_dir_all(&packages_dir).unwrap();

    let dir = packages_dir.join("root_missing");
    write_file(
        &dir,
        "afb.toml",
        "[format]\nversion = \"1.0\"\n\
         [package]\nname = \"root_missing\"\nnamespace = \"x\"\n\
         version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
         [runtime]\nmin = \"0.1.0\"\n\
         [dependencies]\n\"x/absent\" = { path = \"../absent\" }\n",
    );
    write_file(
        &dir,
        "manifold.json",
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    );
    write_file(
        &dir,
        "source/main.js",
        "const dep = require('x/absent');\nmodule.exports = () => dep();\n",
    );

    let out_afb = tmp.path().join("root_missing.afb");
    let result = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "compile",
            dir.to_str().unwrap(),
            "-o",
            out_afb.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn compile");

    // Either the compile falls back to source-only (exit 0, note on stderr)
    // or exits non-zero - either is acceptable. The important thing is that
    // stderr contains a descriptive message mentioning the missing path dep.
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("absent") || stderr.contains("missing") || stderr.contains("path"),
        "error message should mention the missing path dep: {stderr}"
    );
}
