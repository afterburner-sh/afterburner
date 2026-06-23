// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Polyglot demo: five source languages, one Wasmtime engine.
//!
//! Loads each language's committed `.wasm` artifact, runs it on
//! [`EmbedderVm`], captures stdout, and prints a results table.
//!
//! Every module is a standard WASI command module: it exports `_start`,
//! writes one line to fd 1 (stdout), and exits. The runner uses
//! [`EmbedderVm::run_command`] for all five languages.
//!
//! Expected stdout from each module:
//! ```
//! rust:   rust: sum(1..=100)=5050 fib(20)=6765
//! go:     go: sum(1..=100)=5050 fib(20)=6765
//! python: python: sum(1..=100)=5050 fib(20)=6765   (skipped if wasm absent)
//! js:     js: sum(1..=100)=5050 fib(20)=6765
//! ts:     ts: sum(1..=100)=5050 fib(20)=6765
//! ```
//!
//! # Usage
//!
//!   cargo run -p afterburner-wasi --example polyglot
//!
//! The Python row reads `$PYTHON_WASM` (default `/tmp/python.wasm`). If the
//! file is absent, the row prints `SKIPPED` and the example still exits 0.
//! All other rows use prebuilt artifacts committed at
//! `examples/languages/{rust,go,js,ts}/<lang>.wasm`.

use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};
use std::{path::Path, process};

/// Fuel budget: generous for startup-heavy runtimes (Go GC, QuickJS init).
/// vertexia: global budget; per-tenant limits if throughput matters.
const FUEL: u64 = 50_000_000_000;

/// A single polyglot row.
struct Row {
    lang: &'static str,
    /// Path to the .wasm artifact, relative to the workspace root.
    wasm_path: String,
    /// Expected substring in the module's stdout.
    expected: &'static str,
    /// When true, skip (print SKIPPED) rather than fail if the file is absent.
    optional: bool,
}

fn artifact_dir() -> String {
    // Locate the examples/languages dir relative to this source file's
    // manifest. CARGO_MANIFEST_DIR is set by cargo when running examples.
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/examples/languages")
}

fn main() {
    let art = artifact_dir();
    let python_wasm = std::env::var("PYTHON_WASM").unwrap_or_else(|_| "/tmp/python.wasm".into());

    let rows: Vec<Row> = vec![
        Row {
            lang: "rust",
            wasm_path: format!("{art}/rust/rust.wasm"),
            expected: "5050",
            optional: false,
        },
        Row {
            lang: "go",
            wasm_path: format!("{art}/go/go.wasm"),
            expected: "5050",
            optional: false,
        },
        Row {
            lang: "python",
            wasm_path: python_wasm,
            expected: "5050",
            optional: true,
        },
        Row {
            lang: "js",
            wasm_path: format!("{art}/js/js.wasm"),
            expected: "5050",
            optional: false,
        },
        Row {
            lang: "ts",
            wasm_path: format!("{art}/ts/ts.wasm"),
            expected: "5050",
            optional: false,
        },
    ];

    let vm = EmbedderVm::new().unwrap_or_else(|e| {
        eprintln!("EmbedderVm::new failed: {e}");
        process::exit(1);
    });

    println!();
    println!("afterburner polyglot demo - five languages, one Wasmtime engine");
    println!("{:-<66}", "");
    println!("{:<10} {:<8} output", "language", "status");
    println!("{:-<66}", "");

    let mut any_fail = false;

    for row in &rows {
        let path = Path::new(&row.wasm_path);

        if !path.exists() {
            if row.optional {
                println!(
                    "{:<10} {:<8} (wasm not found at {})",
                    row.lang, "SKIPPED", row.wasm_path
                );
            } else {
                println!(
                    "{:<10} {:<8} wasm not found: {}",
                    row.lang, "FAIL", row.wasm_path
                );
                any_fail = true;
            }
            continue;
        }

        let wasm_bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                println!("{:<10} {:<8} read error: {e}", row.lang, "FAIL");
                any_fail = true;
                continue;
            }
        };

        let module = match vm.compile(&wasm_bytes, true, |_| Ok(())) {
            Ok(m) => m,
            Err(e) => {
                println!("{:<10} {:<8} compile error: {e}", row.lang, "FAIL");
                any_fail = true;
                continue;
            }
        };

        // Python needs argv so CPython's argument parser finds a -c command.
        // All other modules ignore argv entirely.
        // The fib function is expressed as a lambda chain to fit in one -c line.
        let opts = if row.lang == "python" {
            WasiCommandOpts::new().args([
                "python",
                "-c",
                concat!(
                    "fib=lambda n:(lambda f:f(f,n))(lambda s,x:x if x<2 else s(s,x-1)+s(s,x-2));",
                    "print(f'python: sum(1..=100)={sum(range(1,101))} fib(20)={fib(20)}')"
                ),
            ])
        } else {
            WasiCommandOpts::new()
        };

        match vm.run_command(&module, opts, Some(FUEL)) {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let trimmed = text.trim_end();
                let status = if trimmed.contains(row.expected) {
                    "OK"
                } else {
                    "FAIL"
                };
                println!("{:<10} {:<8} {}", row.lang, status, trimmed);
                if status == "FAIL" {
                    any_fail = true;
                }
            }
            Err(e) => {
                println!("{:<10} {:<8} run error: {e}", row.lang, "FAIL");
                any_fail = true;
            }
        }
    }

    println!("{:-<66}", "");
    println!();

    if any_fail {
        eprintln!("one or more languages failed");
        process::exit(1);
    }
}
