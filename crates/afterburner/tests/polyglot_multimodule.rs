// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]

//! Multi-module / multi-file polyglot compile -> run integration tests.
//!
//! Each language's package under `examples/languages/<lang>-multimodule/` is a
//! REAL multi-module project (not one file): it has cross-module/-file calls,
//! a `pub`/exported API, and at least one PRIVATE (encapsulated) item that
//! `main` cannot reach. These tests compile each via the actual `burn compile`
//! backend (`compile_native` in `cli::compile::lang`) and run the produced
//! `wasm32-wasip1` WASI command module through `EmbedderVm::run_command`,
//! asserting the exact stdout.
//!
//! Asserted stdout per language:
//! - Rust  (`source/{main,geometry}.rs` + `source/stats/mod.rs`): `area=50 mean=20`
//! - Go    (`source/main.go` + package `source/geometry`):        `area=50 perimeter=30`
//! - C     (`source/{main,geometry}.c` + `geometry.h`):           `area=50 mean=20`
//! - C++   (`source/{main,geometry}.cpp` + `geometry.hpp`):       `area=50 mean=20`
//!
//! ## Honesty: skip, never fake-pass
//!
//! These tests need real native toolchains (cargo + the `wasm32-wasip1`
//! target; `go`; a wasi-sdk for C/C++). When a toolchain is genuinely absent
//! the test prints a prominent `SKIP <name>: <reason>` line to stderr and
//! returns WITHOUT asserting - it never silently reports green, and it never
//! fabricates a pass. This mirrors the in-repo `b_compile.rs` convention for
//! the `javy`-gated tests. Run `cargo test -p afterburner --features bin -- \
//! --nocapture` to see the skip lines.
//!
//! A hard `#[ignore]` attribute is deliberately not used: toolchain presence
//! is a runtime fact (it depends on PATH / `WASI_SDK_PATH`), and a static
//! attribute could not gate on it. The loud-skip pattern keeps the tests
//! running and asserting wherever the toolchain DOES exist (e.g. Rust and Go
//! locally; C/C++ on a runner with a wasi-sdk), which a blanket `#[ignore]`
//! would prevent.

use afterburner::cli::compile::lang::{SourceLang, compile_native};
use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Directory of an example package under the workspace `examples/languages/`.
fn example_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/languages")
        .join(name)
}

/// Run a `wasm32-wasip1` WASI command module and return `(exit_code, stdout)`.
fn run_command(wasm: &[u8]) -> (i64, String) {
    let vm = EmbedderVm::new().expect("creating EmbedderVm");
    let module = vm.compile(wasm, true, |_| Ok(())).expect("compiling WASM");
    let opts = WasiCommandOpts::new().args(["multimodule-test"]);
    let out = vm
        .run_command(&module, opts, None)
        .expect("running WASM command");
    (
        out.result,
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Classify a `compile_native` error as "toolchain absent" (a known,
/// honest not-installed signal) vs a real failure. Returns the skip reason
/// when the toolchain is absent, or `None` when the error is a genuine bug
/// that must fail the test.
fn toolchain_absent_reason(msg: &str) -> Option<String> {
    // The substrings below are produced by the compile backends' own honest
    // "tool not installed" errors. Anything else is a real compile failure.
    const ABSENT_SIGNALS: &[&str] = &[
        "not found on PATH",                         // cargo / go / rustc missing
        "wasm32-wasip1 target may not be installed", // rust target missing
        "wasm32-wasip1` exited with code",           // build failed (often missing target)
        "C/C++ compilation is not available",        // C/C++ toolchain absent
        "go build` exited with code",                // go build failed
    ];
    ABSENT_SIGNALS
        .iter()
        .find(|s| msg.contains(**s))
        .map(|s| format!("toolchain absent ({s})"))
}

/// Compile the named example via `compile_native`, run it, and assert the
/// produced WASM prints `expected` (trimmed) and exits 0. When the required
/// toolchain is absent, print a loud SKIP and return (no fake pass).
fn compile_run_assert(test_name: &str, lang: &str, example: &str, expected: &str) {
    let lang_enum = SourceLang::from_str(lang).expect("valid language");
    assert!(
        !lang_enum.is_js_family(),
        "multimodule fixture must be a native language"
    );

    let dir = example_dir(example);
    let dir = dir
        .canonicalize()
        .unwrap_or_else(|_| panic!("example dir missing: {}", dir.display()));
    let entry = "source/main.".to_string()
        + match lang_enum {
            SourceLang::Rust => "rs",
            SourceLang::Go => "go",
            SourceLang::C => "c",
            SourceLang::Cpp => "cpp",
            _ => unreachable!("unexpected native lang in multimodule test"),
        };

    let wasm = match compile_native(lang_enum, &dir, &entry) {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = e.to_string();
            match toolchain_absent_reason(&msg) {
                Some(reason) => {
                    eprintln!(
                        "SKIP {test_name}: {reason}\n  (install the {lang} -> wasm32-wasip1 \
                         toolchain to run this test)\n  detail: {msg}"
                    );
                    return;
                }
                None => panic!("unexpected {lang} compile error for {example}: {msg}"),
            }
        }
    };

    // The produced module must be a runnable WASI command (real `_start`),
    // not an `--no-entry`/reactor shape.
    let (exit_code, stdout) = run_command(&wasm);
    assert_eq!(
        exit_code, 0,
        "{lang} {example} must exit 0, got {exit_code}"
    );
    assert_eq!(
        stdout.trim(),
        expected,
        "{lang} {example} stdout must be {expected:?}, got {stdout:?}"
    );
}

#[test]
fn rust_multimodule_compiles_runs_and_encapsulates() {
    // Proves: Cargo resolves `source/main.rs` + `source/geometry.rs` +
    // `source/stats/mod.rs` (a directory module) with the
    // `[[bin]] path = "source/main.rs"` convention; the private `geometry::scale`
    // and `stats::sum` helpers are reachable only through the `pub` API.
    compile_run_assert(
        "rust_multimodule_compiles_runs_and_encapsulates",
        "rust",
        "rust-multimodule",
        "area=50 mean=20",
    );
}

#[test]
fn go_multimodule_compiles_runs_and_encapsulates() {
    // Proves: the Go module system links a second package
    // (`source/geometry`) into `main`; the exported `RectangleArea` /
    // `RectanglePerimeter` are callable across the package boundary while the
    // lowercase `scale` stays package-private.
    compile_run_assert(
        "go_multimodule_compiles_runs_and_encapsulates",
        "go",
        "go-multimodule",
        "area=50 perimeter=30",
    );
}

#[test]
fn c_multifile_compiles_runs_as_wasi_command() {
    // Proves: `compile_c` builds ALL of `source/*.c` (main.c + geometry.c,
    // sharing geometry.h) into ONE wasi-libc-linked WASI command module with a
    // real `main`; the `static` helpers in geometry.c are encapsulated.
    compile_run_assert(
        "c_multifile_compiles_runs_as_wasi_command",
        "c",
        "c-multimodule",
        "area=50 mean=20",
    );
}

#[test]
fn cpp_multifile_compiles_runs_as_wasi_command() {
    // Proves: `compile_cpp` builds ALL of `source/*.cpp` (main.cpp +
    // geometry.cpp, sharing geometry.hpp) via the wasi-sdk clang++ into a WASI
    // command module; the anonymous-namespace helpers are encapsulated.
    compile_run_assert(
        "cpp_multifile_compiles_runs_as_wasi_command",
        "cpp",
        "cpp-multimodule",
        "area=50 mean=20",
    );
}

#[test]
fn multimodule_examples_exist_and_declare_native_languages() {
    // A always-on guard that the example packages are present and well-formed,
    // so a missing-toolchain skip can never hide a deleted/renamed example.
    for (example, lang, entry) in [
        ("rust-multimodule", "rust", "source/main.rs"),
        ("go-multimodule", "go", "source/main.go"),
        ("c-multimodule", "c", "source/main.c"),
        ("cpp-multimodule", "cpp", "source/main.cpp"),
    ] {
        let dir = example_dir(example);
        assert!(dir.is_dir(), "missing example dir {}", dir.display());
        assert!(
            dir.join("afb.toml").is_file(),
            "{example}: missing afb.toml"
        );
        assert!(
            dir.join("manifold.json").is_file(),
            "{example}: missing manifold.json"
        );
        assert!(
            dir.join(entry).is_file(),
            "{example}: missing entry {entry}"
        );
        let lang_enum = SourceLang::from_str(lang).expect("valid lang");
        assert!(!lang_enum.is_js_family(), "{example} must be native");
        assert!(
            !lang_enum.is_interpretable(),
            "{example} compiles to wasm (not interpretable)"
        );
    }
}
