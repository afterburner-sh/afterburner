// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Integration tests for `burn compile`.
//!
//! Three test groups:
//!
//! 1. `Manifold::is_sealed` unit coverage in afterburner-core is the
//!    canonical source; the predicate is also exercised here indirectly via
//!    the CLI path.
//!
//! 2. `burn compile` on a SEALED fixture package. This test shells to `javy`;
//!    when `javy` is absent it is SKIPPED with a clear message.
//!
//! 3. `burn compile` on a CAPABILITY fixture package. Does NOT shell to
//!    `javy`; confirms no `precompiled/` member, source present, and the
//!    stderr note.

#![cfg(feature = "bin")]

use afterburner_afb::Afb;
use std::path::Path;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

// ---- fixture helpers -------------------------------------------------------

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

/// Scaffold a minimal sealed package (no capability grants).
fn scaffold_sealed(dir: &Path) {
    write(
        dir,
        "afb.toml",
        "[format]\nversion = \"1.0\"\n\
         [package]\nname = \"probe\"\nnamespace = \"example\"\n\
         version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
         [runtime]\nmin = \"0.1.0\"\n",
    );
    // manifold.json: all defaults = sealed
    write(
        dir,
        "manifold.json",
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    );
    // A simple module.exports function - pure compute, no host capabilities.
    write(
        dir,
        "source/main.js",
        "module.exports = (input) => ({ ok: true, echo: input });\n",
    );
}

/// Scaffold a minimal capability-bearing package (crypto granted).
fn scaffold_capability(dir: &Path) {
    write(
        dir,
        "afb.toml",
        "[format]\nversion = \"1.0\"\n\
         [package]\nname = \"capprobe\"\nnamespace = \"example\"\n\
         version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
         [runtime]\nmin = \"0.1.0\"\n",
    );
    // manifold.json: crypto = true => NOT sealed
    write(
        dir,
        "manifold.json",
        r#"{"fs":"None","net":"None","crypto":true,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    );
    write(
        dir,
        "source/main.js",
        "module.exports = (input) => ({ ok: true });\n",
    );
}

/// Return true when `javy` is available on PATH (or JAVY env), false otherwise.
fn javy_available() -> bool {
    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());
    std::process::Command::new(&javy)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---- sealed package: precompiled member present ---------------------------

#[test]
fn compile_sealed_package_bundles_wasm() {
    if !javy_available() {
        eprintln!(
            "SKIP compile_sealed_package_bundles_wasm: \
             `javy` not found on PATH; install javy 8.1.1 to run this test"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("sealed");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    scaffold_sealed(&pkg_dir);

    let out_afb = tmp.path().join("out.afb");

    let result = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "compile",
            pkg_dir.to_str().unwrap(),
            "-o",
            out_afb.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn compile");

    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success(),
        "burn compile failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The output .afb must exist and be parseable.
    let bytes = std::fs::read(&out_afb).expect("reading output .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing output .afb");

    // Source must still be present.
    assert!(
        afb.source.contains_key("source/main.js"),
        "source/main.js must be present in compiled .afb"
    );

    // Precompiled member must be present and non-empty.
    let wasm_key = "precompiled/wasm32-wasip1/main.wasm";
    let wasm_bytes = afb
        .precompiled
        .get(wasm_key)
        .unwrap_or_else(|| panic!("{wasm_key} must be present in the compiled .afb"));
    assert!(!wasm_bytes.is_empty(), "precompiled wasm must be non-empty");

    // runtime.target must be set.
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1"),
        "runtime.target must be wasm32-wasip1"
    );
}

// ---- capability package: source-only, stderr note -------------------------

#[test]
fn compile_capability_package_produces_source_only_afb() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("cap");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    scaffold_capability(&pkg_dir);

    let out_afb = tmp.path().join("cap.afb");

    let result = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "compile",
            pkg_dir.to_str().unwrap(),
            "-o",
            out_afb.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn compile");

    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success(),
        "burn compile on capability package failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The stderr note must mention the limitation.
    assert!(
        stderr.contains("sealed-only") || stderr.contains("capability grants"),
        "expected a note on stderr about sealed-only precompilation, got: {stderr}"
    );

    // The output .afb must exist and be parseable.
    let bytes = std::fs::read(&out_afb).expect("reading output .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing output .afb");

    // Source must be present.
    assert!(
        afb.source.contains_key("source/main.js"),
        "source/main.js must be present"
    );

    // No precompiled member for a capability package.
    assert!(
        afb.precompiled.is_empty(),
        "precompiled must be empty for a capability package, got: {:?}",
        afb.precompiled.keys().collect::<Vec<_>>()
    );

    // runtime.target must NOT be set.
    assert_eq!(
        afb.manifest.runtime.target, None,
        "runtime.target must be absent for a source-only .afb"
    );
}

// ---- format-level: Builder with precompiled member round-trips ------------

#[test]
fn builder_precompiled_member_survives_pack_unpack() {
    use afterburner_afb::manifest::{Format, Package, Runtime};
    use afterburner_afb::pack::Builder;
    use afterburner_afb::{Manifest, Manifold};

    let manifest = Manifest {
        format: Format {
            version: "1.0".into(),
            min_reader: None,
        },
        package: Package {
            name: "probe".into(),
            namespace: "example".into(),
            version: "0.1.0".into(),
            language: "javascript".into(),
            entry: "source/main.js".into(),
            description: None,
            homepage: None,
            license: None,
            keywords: vec![],
        },
        runtime: Runtime {
            min: "0.1.0".into(),
            target: Some("wasm32-wasip1".into()),
        },
        dependencies: Default::default(),
        npm: Default::default(),
        signature: None,
        metadata: Default::default(),
        extra: Default::default(),
    };
    let manifold = Manifold::sealed();
    let fake_wasm = b"\x00asm\x01\x00\x00\x00".to_vec(); // minimal wasm magic

    let (bytes, _digest) = Builder::new(manifest, manifold)
        .source("source/main.js", b"module.exports = () => 1;".to_vec())
        .precompiled("precompiled/wasm32-wasip1/main.wasm", fake_wasm.clone())
        .build()
        .expect("build .afb");

    let afb = Afb::from_bytes(&bytes).expect("unpack .afb");

    // Source survives.
    assert!(afb.source.contains_key("source/main.js"));
    // Precompiled member survives.
    let wasm = afb
        .precompiled
        .get("precompiled/wasm32-wasip1/main.wasm")
        .expect("precompiled member must be present after round-trip");
    assert_eq!(wasm, &fake_wasm);
    // runtime.target survives.
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1")
    );
}
