// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Colocated tests for [`run_afb_bytes`][super::run_afb_bytes], one pair per
//! language family (a compiled language via a real wasi-sdk `clang`, JS via a
//! real `javy`, and Ruby-source via the bundled CRuby interpreter): a normal
//! run asserting captured stdout and a non-zero exit code, and a bound-firing
//! run.
//!
//! Every test here boots a real toolchain or a real WASM/interpreter runtime,
//! so all of them are `#[ignore]`d (run with `cargo test --ignored`),
//! matching this crate's existing convention for runtime-touching tests (see
//! `tests/cross_language_parity.rs`). Each also self-skips with a printed
//! reason, rather than failing, on a machine that lacks the toolchain a
//! fixture needs - never a silent green from a test that did not run.

use super::*;
use afterburner_afb::manifest::{Format, Manifest, Package, Runtime};
use afterburner_afb::pack::Builder;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The smallest valid [`Manifest`] for a fixture package, mirroring
/// `afterburner_afb::resolve::minimal_manifest`'s exact field values (the
/// smallest manifest this crate's own unpacker already accepts).
fn minimal_manifest(language: &str, entry: &str, runtime_target: Option<&str>) -> Manifest {
    Manifest {
        format: Format {
            version: "1.0".into(),
            min_reader: None,
        },
        package: Package {
            name: "fixture".into(),
            namespace: "test".into(),
            version: "0.1.0".into(),
            language: language.into(),
            entry: entry.into(),
            description: None,
            homepage: None,
            license: None,
            keywords: vec![],
        },
        runtime: Runtime {
            min: "0.1.0".into(),
            target: runtime_target.map(str::to_owned),
        },
        dependencies: Default::default(),
        npm: Default::default(),
        pip: Default::default(),
        gem: Default::default(),
        signature: None,
        metadata: toml::Table::new(),
        extra: toml::Table::new(),
    }
}

/// Build a compiled-WASM fixture `.afb`: one precompiled
/// `precompiled/wasm32-wasip1/main.wasm` member, no source.
fn build_compiled_afb(language: &str, wasm_bytes: Vec<u8>) -> Vec<u8> {
    let manifest = minimal_manifest(language, "source/main", Some("wasm32-wasip1"));
    let (bytes, _digest) = Builder::new(manifest, Manifold::sealed())
        .precompiled(PRECOMPILED_WASM_MEMBER, wasm_bytes)
        .build()
        .expect("build compiled fixture .afb");
    bytes
}

/// Build a source-shipped fixture `.afb` (the Ruby/Python interpreted shape):
/// one `source/<entry>` member, no precompiled artifact.
fn build_source_afb(language: &str, entry: &str, source: &str) -> Vec<u8> {
    let manifest = minimal_manifest(language, entry, None);
    let (bytes, _digest) = Builder::new(manifest, Manifold::sealed())
        .source(entry, source.as_bytes().to_vec())
        .build()
        .expect("build source fixture .afb");
    bytes
}

// ---- compiled-language family (C via wasi-sdk clang) -----------------------

/// Locate the wasi-sdk's `wasm32-wasip1-clang` wrapper: `WASI_SDK_PATH/bin/…`
/// first (the canonical wasi-sdk convention), else the first
/// `~/.burn/wasi-sdk-*/bin/…` cache directory (the `burn compile` lazy-fetch
/// location). `None` when neither is present - the caller skips instead of
/// failing.
fn find_wasi_sdk_clang() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("WASI_SDK_PATH") {
        let p = PathBuf::from(dir).join("bin/wasm32-wasip1-clang");
        if p.is_file() {
            return Some(p);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let entries = std::fs::read_dir(PathBuf::from(home).join(".burn")).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("wasi-sdk-") {
            let p = entry.path().join("bin/wasm32-wasip1-clang");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// Compile `source` (a full C translation unit) to a `wasm32-wasip1` WASI
/// command module via the located `clang`.
fn compile_c(clang: &Path, source: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!(
        "afb-run-test-c-{}-{}",
        std::process::id(),
        NEXT_SCRATCH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src = dir.join("fixture.c");
    let wasm = dir.join("fixture.wasm");
    std::fs::write(&src, source).expect("write fixture.c");
    let status = std::process::Command::new(clang)
        .arg("-o")
        .arg(&wasm)
        .arg(&src)
        .status()
        .expect("spawn clang");
    assert!(
        status.success(),
        "clang exited non-zero compiling the fixture"
    );
    let bytes = std::fs::read(&wasm).expect("read fixture.wasm");
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

#[test]
#[ignore = "compiles a real C fixture via wasi-sdk clang and runs it through wasmtime; cargo test --ignored"]
fn compiled_family_normal_run_captures_stdout_and_exit_code() {
    let Some(clang) = find_wasi_sdk_clang() else {
        eprintln!(
            "skipping compiled_family_normal_run_captures_stdout_and_exit_code: \
             no wasi-sdk found (set WASI_SDK_PATH or install one under ~/.burn)"
        );
        return;
    };
    let wasm = compile_c(
        &clang,
        r#"#include <stdio.h>
int main(void) { printf("hello from c\n"); return 7; }
"#,
    );
    let afb = build_compiled_afb("c", wasm);

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(7));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from c"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
#[ignore = "compiles a real C fixture via wasi-sdk clang and runs it through wasmtime; cargo test --ignored"]
fn compiled_family_fuel_bound_fires() {
    let Some(clang) = find_wasi_sdk_clang() else {
        eprintln!(
            "skipping compiled_family_fuel_bound_fires: no wasi-sdk found (set WASI_SDK_PATH or install one under ~/.burn)"
        );
        return;
    };
    let wasm = compile_c(&clang, "int main(void) { while (1) {} return 0; }\n");
    let afb = build_compiled_afb("c", wasm);

    let request = AfbRunRequest {
        fuel: Some(50_000),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::OutOfFuel);
    assert_eq!(out.fuel_used, 50_000);
}

// ---- JS family (javy) -------------------------------------------------------

/// Whether a `javy` binary is on `PATH` and runnable. `None` (not `Err`) on
/// any failure to spawn it - the caller skips instead of failing.
fn javy_available() -> bool {
    std::process::Command::new("javy")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Compile `source` (already Javy.IO-shaped: no bare `console.log`, no
/// Node-isms) to a self-contained `wasm32-wasip1` WASI command module, using
/// the same sealed-build flags `cli::compile::mod::run_javy_sealed` invokes.
fn compile_js(source: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!(
        "afb-run-test-js-{}-{}",
        std::process::id(),
        NEXT_SCRATCH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src = dir.join("fixture.js");
    let wasm = dir.join("fixture.wasm");
    std::fs::write(&src, source).expect("write fixture.js");
    let status = std::process::Command::new("javy")
        .args([
            "build",
            "-J",
            "event-loop=y",
            "-J",
            "javy-stream-io=y",
            "-C",
            "deterministic=y",
        ])
        .arg(&src)
        .arg("-o")
        .arg(&wasm)
        .status()
        .expect("spawn javy");
    assert!(
        status.success(),
        "javy build exited non-zero compiling the fixture"
    );
    let bytes = std::fs::read(&wasm).expect("read fixture.wasm");
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

#[test]
#[ignore = "compiles a real JS fixture via javy and runs it through wasmtime; cargo test --ignored"]
fn js_family_normal_run_captures_stdout() {
    if !javy_available() {
        eprintln!("skipping js_family_normal_run_captures_stdout: no `javy` on PATH");
        return;
    }
    let wasm = compile_js(
        r#"
const enc = new TextEncoder();
Javy.IO.writeSync(1, enc.encode("hello from js\n"));
"#,
    );
    let afb = build_compiled_afb("js", wasm);

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from js"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Javy's runtime has no `process.exit` / POSIX-exit-code mechanism at all
/// (confirmed against `javy build -J help` / `-C help`: no such option
/// exists) - an uncaught JS exception is the only way a script signals
/// abnormal termination, and it traps (a WASM `unreachable`), not a process
/// exit code. So the JS family's "the guest failed and we said so honestly"
/// case is `Trapped`, not a fabricated `Exited(n)` - exactly the case
/// `AfbRunOutcome::Trapped` exists for. C and Ruby demonstrate a genuine
/// non-zero `Exited` elsewhere in this file; JS cannot produce one.
#[test]
#[ignore = "compiles a real JS fixture via javy and runs it through wasmtime; cargo test --ignored"]
fn js_family_uncaught_exception_traps_honestly() {
    if !javy_available() {
        eprintln!("skipping js_family_uncaught_exception_traps_honestly: no `javy` on PATH");
        return;
    }
    let wasm = compile_js(
        r#"
const enc = new TextEncoder();
Javy.IO.writeSync(1, enc.encode("about to throw\n"));
throw new Error("boom");
"#,
    );
    let afb = build_compiled_afb("js", wasm);

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert!(
        matches!(out.outcome, AfbRunOutcome::Trapped(_)),
        "expected Trapped, got {:?}",
        out.outcome
    );
}

#[test]
#[ignore = "compiles a real JS fixture via javy and runs it through wasmtime; cargo test --ignored"]
fn js_family_fuel_bound_fires() {
    if !javy_available() {
        eprintln!("skipping js_family_fuel_bound_fires: no `javy` on PATH");
        return;
    }
    let wasm = compile_js("while (true) {}\n");
    let afb = build_compiled_afb("js", wasm);

    let request = AfbRunRequest {
        fuel: Some(50_000),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::OutOfFuel);
    assert_eq!(out.fuel_used, 50_000);
}

// ---- interpreted-language family (Ruby source) ------------------------------

#[test]
#[ignore = "boots the bundled CRuby WASI interpreter (real runtime, seconds); cargo test --ignored"]
fn ruby_family_normal_run_captures_stdout_and_exit_code() {
    if afterburner_wasi::ruby_runner::resolve_ruby_runtime().is_err() {
        eprintln!(
            "skipping ruby_family_normal_run_captures_stdout_and_exit_code: \
             no Ruby runtime available (neither the bundled ~/.burn cache nor BURN_RUBY_RUNTIME)"
        );
        return;
    }
    let afb = build_source_afb("ruby", "source/main.rb", "puts 'hello from ruby'\nexit 5\n");

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(5));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from ruby"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
#[ignore = "boots the bundled CRuby WASI interpreter and lets it spin (bounded by a 15s timeout); cargo test --ignored"]
fn ruby_family_timeout_bound_fires() {
    if afterburner_wasi::ruby_runner::resolve_ruby_runtime().is_err() {
        eprintln!(
            "skipping ruby_family_timeout_bound_fires: \
             no Ruby runtime available (neither the bundled ~/.burn cache nor BURN_RUBY_RUNTIME)"
        );
        return;
    }
    // Ruby-source's fuel budget is a fixed multi-trillion-instruction
    // constant (RUBY_FUEL) that this API cannot currently tighten (see the
    // module doc's "known gaps"), so `timeout` - not `fuel` - is the bound
    // this family's test exercises. The infinite loop keeps running in the
    // background after this returns; see `AfbRunRequest::timeout`'s doc.
    let afb = build_source_afb("ruby", "source/main.rb", "loop {}\n");

    let request = AfbRunRequest {
        timeout: Some(Duration::from_secs(15)),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Timeout);
}
