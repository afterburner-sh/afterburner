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

// ---- capability package: dyn precompiled (javy present) or source-only ----

#[test]
fn compile_capability_package_produces_dyn_afb_or_source_only() {
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

    // The output .afb must exist and be parseable.
    let bytes = std::fs::read(&out_afb).expect("reading output .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing output .afb");

    // Source must always be present.
    assert!(
        afb.source.contains_key("source/main.js"),
        "source/main.js must be present"
    );

    if javy_available() {
        // When javy is present the capability package is compiled to a dyn module.
        let wasm_key = "precompiled/wasm32-wasip1-dyn/main.wasm";
        let wasm_bytes = afb
            .precompiled
            .get(wasm_key)
            .unwrap_or_else(|| panic!("{wasm_key} must be present in dyn .afb"));
        assert!(!wasm_bytes.is_empty(), "dyn wasm must be non-empty");
        assert_eq!(
            afb.manifest.runtime.target.as_deref(),
            Some("wasm32-wasip1-dyn"),
            "runtime.target must be wasm32-wasip1-dyn"
        );
    } else {
        // Without javy, fall back to source-only with a note.
        assert!(
            afb.precompiled.is_empty(),
            "precompiled must be empty for a source-only fallback, got: {:?}",
            afb.precompiled.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            afb.manifest.runtime.target, None,
            "runtime.target must be absent for a source-only fallback"
        );
    }
}

// ---- multi-file sealed package: sibling linked into precompiled wasm ------

/// Scaffold a multi-file sealed package.
/// entry: `source/main.js` requires `./util` which exports the real value.
fn scaffold_multifile_sealed(dir: &Path) {
    write(
        dir,
        "afb.toml",
        "[format]\nversion = \"1.0\"\n\
         [package]\nname = \"multiprobe\"\nnamespace = \"example\"\n\
         version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
         [runtime]\nmin = \"0.1.0\"\n",
    );
    write(
        dir,
        "manifold.json",
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    );
    // entry delegates to a sibling so both files must be linked for the WASM to work
    write(
        dir,
        "source/main.js",
        "const util = require('./util');\nmodule.exports = (input) => util.run(input);\n",
    );
    write(
        dir,
        "source/util.js",
        "module.exports = { run: (input) => ({ ok: true, doubled: (input.n || 0) * 2 }) };\n",
    );
}

#[test]
fn compile_multifile_sealed_sibling_linked() {
    if !javy_available() {
        eprintln!(
            "SKIP compile_multifile_sealed_sibling_linked: \
             `javy` not found on PATH; install javy 8.1.1 to run this test"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("multifile");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    scaffold_multifile_sealed(&pkg_dir);

    let out_afb = tmp.path().join("multi.afb");

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
        "burn compile (multi-file) failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = std::fs::read(&out_afb).expect("reading output .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing output .afb");

    // Both source files must be present.
    assert!(
        afb.source.contains_key("source/main.js"),
        "main.js must be in output .afb"
    );
    assert!(
        afb.source.contains_key("source/util.js"),
        "util.js must be in output .afb"
    );

    // Precompiled member must be present and non-empty.
    let wasm_key = "precompiled/wasm32-wasip1/main.wasm";
    let wasm_bytes = afb
        .precompiled
        .get(wasm_key)
        .unwrap_or_else(|| panic!("{wasm_key} must be present in compiled multi-file .afb"));
    assert!(!wasm_bytes.is_empty(), "precompiled wasm must be non-empty");

    // runtime.target must be set.
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1"),
        "runtime.target must be wasm32-wasip1"
    );

    // Correctness: the precompiled path must produce the same value as the
    // source (linked) path. This proves the sibling was linked into the wasm.
    use afterburner_core::{Combustor, FuelGauge};
    use afterburner_wasi::{WasmCombustor, WasmConfig};
    use serde_json::json;

    let engine = WasmCombustor::new(WasmConfig::default()).expect("WasmCombustor::new");
    let limits = FuelGauge::unlimited();
    let input = json!({ "n": 21 });

    // Source path: linked source through ignite.
    let linked_src = afb
        .linked_source(&[], &[])
        .expect("linked_source on compiled .afb");
    let src_id = engine.ignite(&linked_src).expect("ignite linked source");
    let src_out = engine
        .thrust(&src_id, &input, &limits)
        .expect("thrust source");

    // Precompiled path: register the wasm and thrust it.
    let pre_id = engine
        .register_precompiled(wasm_bytes, "wasm32-wasip1")
        .expect("register_precompiled");
    let pre_out = engine
        .thrust(&pre_id, &input, &limits)
        .expect("thrust precompiled");

    assert_eq!(
        pre_out, src_out,
        "precompiled output must equal source output for multi-file package\n  \
         precompiled: {pre_out}\n  source: {src_out}"
    );
}

// ---- dep-linked package: falls back to source-only, no precompiled member --

/// Scaffold a sealed package that declares an external afb dependency so that
/// `linked_source(&[], &[])` fails at compile time.
fn scaffold_dep_linked(dir: &Path) {
    // Use a fake digest: it only needs to look like a sha256 pin for the
    // manifest to parse. The dependency will never be resolved.
    let fake_pin = "sha256:".to_string() + &"a".repeat(64);
    write(
        dir,
        "afb.toml",
        &format!(
            "[format]\nversion = \"1.0\"\n\
             [package]\nname = \"depprobe\"\nnamespace = \"example\"\n\
             version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
             [runtime]\nmin = \"0.1.0\"\n\
             [dependencies]\n\"example/helper\" = \"{fake_pin}\"\n"
        ),
    );
    write(
        dir,
        "manifold.json",
        r#"{"fs":"None","net":"None","crypto":false,"child_process":false,"env":"None","allow_exit":false,"http_timeout_ms":null,"listen":"None"}"#,
    );
    write(
        dir,
        "source/main.js",
        "const h = require('example/helper');\nmodule.exports = (input) => h(input);\n",
    );
}

#[test]
fn compile_dep_linked_falls_back_to_source_only() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("deplinked");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    scaffold_dep_linked(&pkg_dir);

    let out_afb = tmp.path().join("dep.afb");

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
        "burn compile (dep-linked) must succeed with source-only fallback\n\
         stdout: {stdout}\nstderr: {stderr}"
    );

    // Stderr must carry the note about skipping precompiled.
    assert!(
        stderr.contains("dependency-linked") || stderr.contains("source-only"),
        "expected a note about dependency-linked fallback on stderr, got: {stderr}"
    );

    // The output .afb must be present and valid.
    let bytes = std::fs::read(&out_afb).expect("reading output .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing output .afb");

    // Source must be present.
    assert!(
        afb.source.contains_key("source/main.js"),
        "source/main.js must be present in source-only .afb"
    );

    // No precompiled member - a dep-linked package ships source only.
    assert!(
        afb.precompiled.is_empty(),
        "precompiled must be empty for a dep-linked fallback, got: {:?}",
        afb.precompiled.keys().collect::<Vec<_>>()
    );

    // runtime.target must NOT be set (no precompiled wasm).
    assert_eq!(
        afb.manifest.runtime.target, None,
        "runtime.target must be absent for a source-only dep-linked .afb"
    );
}

// ---- burn package --wasm-only (STEP 2 + STEP 3 CLI coverage) ---------------

/// `burn package --wasm-only` on a sealed package when javy is present:
/// the emitted `.afb` must have NO `source/` members and DOES have the
/// precompiled WASM member.
#[test]
fn package_wasm_only_sealed_no_source() {
    if !javy_available() {
        eprintln!(
            "SKIP package_wasm_only_sealed_no_source: \
             `javy` not found on PATH; install javy 8.1.1 to run this test"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("sealed_wasm_only");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    scaffold_sealed(&pkg_dir);

    let out_afb = tmp.path().join("wasm_only.afb");

    let result = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "package",
            pkg_dir.to_str().unwrap(),
            "--wasm-only",
            "-o",
            out_afb.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn package --wasm-only");

    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success(),
        "burn package --wasm-only failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = std::fs::read(&out_afb).expect("reading wasm-only .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing wasm-only .afb");

    // No source members.
    assert!(
        afb.source.is_empty(),
        "wasm-only .afb must have no source/ members, got: {:?}",
        afb.source.keys().collect::<Vec<_>>()
    );

    // Precompiled member must be present and non-empty.
    let wasm_key = "precompiled/wasm32-wasip1/main.wasm";
    let wasm_bytes = afb
        .precompiled
        .get(wasm_key)
        .unwrap_or_else(|| panic!("{wasm_key} must be present in wasm-only .afb"));
    assert!(!wasm_bytes.is_empty(), "precompiled wasm must be non-empty");

    // runtime.target set.
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1"),
    );
}

/// `burn package` (source-based, non-interactive default when stdin is not a
/// TTY) still includes source and no precompiled member.
#[test]
fn package_source_based_default_includes_source() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("sealed_src");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    scaffold_sealed(&pkg_dir);

    let out_afb = tmp.path().join("src.afb");

    // Run with stdin NOT a TTY (piped from /dev/null) so no prompt fires.
    let result = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "package",
            pkg_dir.to_str().unwrap(),
            "-o",
            out_afb.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn burn package (source-based)");

    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success(),
        "burn package (source-based) failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = std::fs::read(&out_afb).expect("reading source-based .afb");
    let afb = Afb::from_bytes(&bytes).expect("parsing source-based .afb");

    // Source must be present.
    assert!(
        afb.source.contains_key("source/main.js"),
        "source-based .afb must include source/main.js"
    );

    // No precompiled member in the plain source-based path.
    assert!(
        afb.precompiled.is_empty(),
        "source-based .afb must have no precompiled members, got: {:?}",
        afb.precompiled.keys().collect::<Vec<_>>()
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
