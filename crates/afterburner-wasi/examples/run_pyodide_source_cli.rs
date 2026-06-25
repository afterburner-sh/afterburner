// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Drive the PRODUCTION `pyodide_runner::run_pyodide_source` path directly.
//!
//! Unlike the bring-up probes (which re-implement the boot wiring inline), this
//! goes through the exact production entry point `burn run` uses, so it verifies
//! the fix on the shipping code path rather than a probe replica.
//!
//! # Usage
//!
//!   BURN_PYTHON_STDLIB_VER=3.14 \
//!     cargo run -p afterburner-wasi --example run_pyodide_source_cli -- \
//!       <pyodide-exnref.wasm> <python_stdlib.zip> '<python source>'

use afterburner_wasi::pyodide_runner::run_pyodide_source;
use std::{env, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: run_pyodide_source_cli <pyodide-exnref.wasm> <python_stdlib.zip> '<source>'"
        );
        process::exit(2);
    }
    let wasm = &args[1];
    let stdlib = &args[2];
    let source = &args[3];

    match run_pyodide_source(wasm, stdlib, source) {
        Ok(out) => {
            print!("{}", String::from_utf8_lossy(&out.stdout));
            eprintln!("[run_pyodide_source_cli] exit_code={}", out.exit_code);
            process::exit(out.exit_code);
        }
        Err(e) => {
            eprintln!("[run_pyodide_source_cli] ERROR: {e}");
            process::exit(1);
        }
    }
}
