// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]

//! Polyglot compile -> run integration tests.
//!
//! Verifies that `burn compile` (via the Rust API) produces a valid `.afb`
//! for each supported native language, and that `EmbedderVm::run_command`
//! can execute the compiled WASM and produces the expected output.
//!
//! Tested languages:
//! - Rust (wasm32-wasip1 via `cargo build --release --target wasm32-wasip1`)
//! - Go   (wasm32-wasip1 via `GOOS=wasip1 GOARCH=wasm go build`)
//!
//! Both fixtures print `5050` (the sum 1+...+100) to stdout.
//!
//! The tests are skipped automatically when the required toolchain is absent
//! (no `cargo`/`go` on PATH, or missing `wasm32-wasip1` target). This
//! prevents CI red when the environment doesn't have the tools.

use afterburner_afb::Afb;
use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};
use std::path::Path;
use std::str::FromStr;

/// Compile the fixture at `dir` using `burn compile` logic and return the
/// produced `.afb` bytes. Returns `None` when the required toolchain is absent.
fn compile_fixture(dir: &Path) -> Option<Vec<u8>> {
    use afterburner_cloud::pkg::LocalPackage;

    let local = LocalPackage::load(dir).expect("loading fixture package");
    let lang = &local.manifest.package.language.clone();
    let entry = local.manifest.package.entry.clone();
    let pkg_dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let out = tempfile::NamedTempFile::new().expect("temp file");

    // Parse the language to detect native.
    use afterburner::cli::compile::lang::SourceLang;
    let source_lang = SourceLang::from_str(lang).expect("valid language");
    assert!(!source_lang.is_js_family(), "fixture must be a native lang");

    // Try native compile. Return None on toolchain-not-found errors.
    match afterburner::cli::compile::lang::compile_native(source_lang, &pkg_dir, &entry) {
        Ok(wasm_bytes) => {
            // Bundle into .afb.
            let afb_bytes =
                build_afb_with_wasm(local, wasm_bytes).expect("bundling wasm into .afb");
            std::fs::write(out.path(), &afb_bytes).expect("writing .afb");
            Some(std::fs::read(out.path()).expect("reading .afb back"))
        }
        Err(e) => {
            let msg = e.to_string();
            // Toolchain-not-found errors include "not found on PATH" or "wasm32-wasip1".
            if msg.contains("not found on PATH")
                || msg.contains("wasm32-wasip1 target may not be installed")
                || msg.contains("wasm32-wasip1` exited with code")
            {
                eprintln!("skipping {lang} compile test (toolchain absent): {msg}");
                None
            } else {
                panic!("unexpected compile error for {lang}: {e}");
            }
        }
    }
}

/// Compile the fixture at `dir` via `dispatch_compile` (the shared entry point
/// used by both `burn compile` and `burn package --compile`). Returns the
/// produced `.afb` bytes, or `None` when the required toolchain is absent.
fn dispatch_compile_fixture(dir: &Path, wasm_only: bool) -> Option<Vec<u8>> {
    use afterburner_cloud::pkg::LocalPackage;

    let local = LocalPackage::load(dir).expect("loading fixture package");
    let lang_str = local.manifest.package.language.clone();
    let out = tempfile::NamedTempFile::new().expect("temp file");

    match afterburner::cli::compile::dispatch_compile(dir, local, out.path(), wasm_only) {
        Ok(()) => Some(std::fs::read(out.path()).expect("reading .afb back")),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found on PATH")
                || msg.contains("wasm32-wasip1 target may not be installed")
                || msg.contains("wasm32-wasip1` exited with code")
            {
                eprintln!("skipping {lang_str} dispatch_compile test (toolchain absent): {msg}");
                None
            } else {
                panic!("unexpected dispatch_compile error for {lang_str}: {e}");
            }
        }
    }
}

/// Bundle a WASM binary and the local package's source into a `.afb`.
fn build_afb_with_wasm(
    local: afterburner_cloud::pkg::LocalPackage,
    wasm_bytes: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    use afterburner_afb::pack::Builder;

    let (source_bytes, _) = local.build()?;
    let afb = Afb::from_bytes(&source_bytes)?;

    let mut manifest = afb.manifest.clone();
    manifest.runtime.target = Some("wasm32-wasip1".into());

    let mut b = Builder::new(manifest, afb.manifold.clone());
    for (path, data) in &afb.source {
        b = b.source(path.clone(), data.clone());
    }
    b = b.precompiled("precompiled/wasm32-wasip1/main.wasm", wasm_bytes);
    let (bytes, _) = b.build()?;
    Ok(bytes)
}

/// Run the `.afb` bytes via `EmbedderVm::run_command` and return stdout as a String.
fn run_afb_bytes(afb_bytes: &[u8]) -> String {
    let afb = Afb::from_bytes(afb_bytes).expect("parsing .afb");
    let wasm = afb
        .precompiled
        .get("precompiled/wasm32-wasip1/main.wasm")
        .expect(".afb must contain precompiled/wasm32-wasip1/main.wasm");

    let vm = EmbedderVm::new().expect("creating EmbedderVm");
    let module = vm.compile(wasm, true, |_| Ok(())).expect("compiling WASM");
    let opts = WasiCommandOpts::new().args(["test"]);
    let out = vm.run_command(&module, opts, None).expect("running WASM");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fixtures_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn rust_sum_compile_and_run() {
    let dir = fixtures_dir().join("rust-sum");
    let Some(afb_bytes) = compile_fixture(&dir) else {
        return; // toolchain absent
    };

    // The .afb must parse and contain a WASM member.
    let afb = Afb::from_bytes(&afb_bytes).expect("parsing Rust .afb");
    assert!(
        afb.precompiled
            .contains_key("precompiled/wasm32-wasip1/main.wasm"),
        "Rust .afb must contain precompiled WASM"
    );
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1"),
        "runtime.target must be wasm32-wasip1"
    );

    // Run and check output.
    let stdout = run_afb_bytes(&afb_bytes);
    assert!(
        stdout.trim() == "5050",
        "Rust sum output must be 5050, got: {stdout:?}"
    );
}

#[test]
fn go_sum_compile_and_run() {
    let dir = fixtures_dir().join("go-sum");
    let Some(afb_bytes) = compile_fixture(&dir) else {
        return; // toolchain absent
    };

    let afb = Afb::from_bytes(&afb_bytes).expect("parsing Go .afb");
    assert!(
        afb.precompiled
            .contains_key("precompiled/wasm32-wasip1/main.wasm"),
        "Go .afb must contain precompiled WASM"
    );
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1"),
        "runtime.target must be wasm32-wasip1"
    );

    let stdout = run_afb_bytes(&afb_bytes);
    assert!(
        stdout.trim() == "5050",
        "Go sum output must be 5050, got: {stdout:?}"
    );
}

#[test]
fn python_compile_gives_honest_pending_error() {
    use afterburner::cli::compile::lang::SourceLang;
    let err = afterburner::cli::compile::lang::compile_native(
        SourceLang::Python,
        Path::new("/tmp"),
        "source/main.py",
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("pending") || msg.contains("not yet"),
        "Python compile must report pending state, got: {msg}"
    );
}

#[test]
fn js_package_still_compiles_via_js_engine_not_native_path() {
    // Regression: JS/TS packages must NOT go through compile_native().
    use afterburner::cli::compile::lang::SourceLang;
    let lang = SourceLang::from_str("js").unwrap();
    assert!(lang.is_js_family(), "js must be JS family");

    let lang_ts = SourceLang::from_str("typescript").unwrap();
    assert!(lang_ts.is_js_family(), "typescript must be JS family");
}

/// `dispatch_compile` on the rust-sum fixture with `wasm_only=false` must
/// produce a wasm `.afb` that runs and prints `5050`. This covers the path
/// that `burn compile` takes (and that `burn package --compile` now also uses).
#[test]
fn dispatch_compile_rust_sum_produces_runnable_wasm() {
    let dir = fixtures_dir().join("rust-sum");
    let Some(afb_bytes) = dispatch_compile_fixture(&dir, false) else {
        return; // toolchain absent
    };

    let afb = Afb::from_bytes(&afb_bytes).expect("parsing dispatched Rust .afb");
    assert!(
        afb.precompiled
            .contains_key("precompiled/wasm32-wasip1/main.wasm"),
        "dispatch_compile Rust .afb must contain precompiled WASM"
    );
    assert_eq!(
        afb.manifest.runtime.target.as_deref(),
        Some("wasm32-wasip1"),
        "runtime.target must be wasm32-wasip1"
    );
    // Source members must be present when wasm_only=false.
    assert!(
        !afb.source.is_empty(),
        "dispatch_compile with wasm_only=false must include source members"
    );

    let stdout = run_afb_bytes(&afb_bytes);
    assert!(
        stdout.trim() == "5050",
        "dispatch_compile Rust sum output must be 5050, got: {stdout:?}"
    );
}

/// `dispatch_compile` with `wasm_only=true` on the rust-sum fixture produces
/// an `.afb` with precompiled WASM and no `source/*` members. This is the
/// `burn package --wasm-only` path (FullWasm mode) for native languages.
#[test]
fn dispatch_compile_rust_sum_wasm_only_no_source() {
    let dir = fixtures_dir().join("rust-sum");
    let Some(afb_bytes) = dispatch_compile_fixture(&dir, true) else {
        return; // toolchain absent
    };

    let afb = Afb::from_bytes(&afb_bytes).expect("parsing wasm-only Rust .afb");
    assert!(
        afb.precompiled
            .contains_key("precompiled/wasm32-wasip1/main.wasm"),
        "wasm-only .afb must contain precompiled WASM"
    );
    assert!(
        afb.source.is_empty(),
        "wasm-only .afb must have no source members"
    );

    let stdout = run_afb_bytes(&afb_bytes);
    assert!(
        stdout.trim() == "5050",
        "wasm-only Rust sum output must be 5050, got: {stdout:?}"
    );
}

/// `burn package` (plain source-only mode) on a native language (Rust) must
/// return a clear error directing the user to `burn package --compile`. It
/// must never silently produce an unrunnable source-only `.afb`.
#[test]
fn native_lang_source_only_package_errors_clearly() {
    use afterburner_cloud::pkg::LocalPackage;

    let dir = fixtures_dir().join("rust-sum");
    let local = LocalPackage::load(&dir).expect("loading rust-sum");
    let out = tempfile::NamedTempFile::new().expect("temp file");

    // Simulate plain `burn package` with do_compile=false, wasm_only=false.
    // This must fail with a clear message since Rust is not interpretable.
    let err = afterburner::cli::registry::package(
        Some(&dir),
        Some(out.path()),
        false, // do_compile
        false, // wasm_only
    )
    .unwrap_err();

    let msg = err.to_string();
    // The error must mention the language and direct the user to --compile.
    assert!(
        msg.contains("rust") || msg.contains("Rust"),
        "error must name the language: {msg}"
    );
    assert!(
        msg.contains("--compile"),
        "error must suggest `burn package --compile`: {msg}"
    );
    assert!(
        msg.contains("source"),
        "error must mention source packaging: {msg}"
    );

    // The output file must NOT have been written (no silent unrunnable .afb).
    let out_len = std::fs::metadata(out.path()).map(|m| m.len()).unwrap_or(0);
    assert_eq!(
        out_len, 0,
        "no .afb must be written when native source-only packaging is rejected"
    );

    // Suppress the unused-variable warning from the explicit load above.
    drop(local);
}
