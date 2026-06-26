// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Integration tests against the real Pyodide 0.28 wasm binary.
//!
//! All tests are `#[ignore]` for two reasons:
//! 1. CPython static init takes ~200M Wasm instructions (minutes on first run).
//! 2. The binary at /tmp/pyodide-exnref.wasm is not committed to the repo;
//!    CI machines do not have it. Run these manually after translating the
//!    binary with wasm-opt as described in examples/pyodide028_probe.rs.
//!
//! To run on demand:
//!   cargo test -p afterburner-wasi --test pyodide_integration -- --ignored

use afterburner_wasi::pyodide_runner::boot_pyodide;

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";

fn pyodide_available() -> bool {
    std::path::Path::new(PYODIDE_WASM_PATH).exists()
}

// ---- boot ------------------------------------------------------------------

/// Pyodide 0.28 Wasm binary compiles and boots CPython through
/// `__wasm_call_ctors` without trapping.
#[test]
#[ignore]
fn pyodide_boots_without_trap() {
    if !pyodide_available() {
        eprintln!(
            "[pyodide_integration] SKIP: {} not found",
            PYODIDE_WASM_PATH
        );
        return;
    }
    let out = boot_pyodide(PYODIDE_WASM_PATH, PYTHON_STDLIB_ZIP_PATH)
        .expect("Pyodide should boot through __wasm_call_ctors without trap");
    // Not asserting specific stdout content - just that the boot did not trap.
    let _ = out;
}

// ---- determinism -----------------------------------------------------------

/// Two back-to-back boots of the same binary produce byte-identical stdout.
#[test]
#[ignore]
fn pyodide_boot_is_deterministic() {
    if !pyodide_available() {
        eprintln!(
            "[pyodide_integration] SKIP: {} not found",
            PYODIDE_WASM_PATH
        );
        return;
    }
    let out1 = boot_pyodide(PYODIDE_WASM_PATH, PYTHON_STDLIB_ZIP_PATH).expect("first boot");
    let out2 = boot_pyodide(PYODIDE_WASM_PATH, PYTHON_STDLIB_ZIP_PATH).expect("second boot");
    assert_eq!(
        out1.stdout, out2.stdout,
        "two identical boots must produce byte-identical stdout"
    );
}

// ---- compile only ----------------------------------------------------------

/// The translated binary compiles with the deterministic engine without
/// needing to boot CPython. This is a fast sanity check (no fuel consumed).
#[test]
#[ignore]
fn pyodide_binary_compiles() {
    if !pyodide_available() {
        eprintln!(
            "[pyodide_integration] SKIP: {} not found",
            PYODIDE_WASM_PATH
        );
        return;
    }
    let wasm_bytes = std::fs::read(PYODIDE_WASM_PATH).expect("read wasm");
    let engine =
        afterburner_wasi::embedder_vm::deterministic_engine().expect("deterministic engine");
    wasmtime::Module::new(&engine, &wasm_bytes)
        .expect("Pyodide binary must compile with the deterministic engine");
}
