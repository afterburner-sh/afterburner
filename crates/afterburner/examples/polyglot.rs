// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Unified polyglot `run_source` facade example.
//!
//! Shows the same one-line API for JavaScript, Python, and Ruby.
//! Python and Ruby are guarded so the example compiles without those
//! runtimes being present; the JS case runs unconditionally (no external
//! dependency).
//!
//! Run: `cargo run -p afterburner --example polyglot`

use afterburner::{Afterburner, Language};

fn main() -> Result<(), afterburner::AfterburnerError> {
    let ab = Afterburner::new()?;

    // ---- JavaScript (always available) ----------------------------------------

    let js_out = ab.run_source(Language::Js, "console.log('hello from js')")?;
    println!(
        "[js]     ok={} stdout={:?}",
        js_out.ok,
        js_out.stdout_str().trim()
    );
    assert!(
        js_out.stdout_str().contains("hello from js"),
        "js stdout: {:?}",
        js_out.stdout_str()
    );

    // ---- Python (requires wasm feature + bundled Pyodide runtime) -------------

    #[cfg(feature = "wasm")]
    {
        match ab.run_source(Language::Python, "print('hello from python')") {
            Ok(py_out) => {
                println!(
                    "[python] ok={} stdout={:?}",
                    py_out.ok,
                    py_out.stdout_str().trim()
                );
            }
            Err(e) => {
                // No runtime available (cold build without BURN_PYTHON_RUNTIME).
                // Honest skip, never a fake pass.
                println!("[python] skip - runtime not available: {e}");
            }
        }
    }
    #[cfg(not(feature = "wasm"))]
    println!("[python] skip - wasm feature not enabled");

    // ---- Ruby (requires wasm feature + bundled ruby.wasm runtime) -------------

    #[cfg(feature = "wasm")]
    {
        match ab.run_source(Language::Ruby, "puts 'hello from ruby'") {
            Ok(rb_out) => {
                println!(
                    "[ruby]   ok={} stdout={:?}",
                    rb_out.ok,
                    rb_out.stdout_str().trim()
                );
            }
            Err(e) => {
                // No runtime available (cold build without BURN_RUBY_RUNTIME).
                println!("[ruby]   skip - runtime not available: {e}");
            }
        }
    }
    #[cfg(not(feature = "wasm"))]
    println!("[ruby]   skip - wasm feature not enabled");

    // ---- Compiled languages: honest unsupported message ----------------------

    let rust_result = ab.run_source(Language::Rust, "fn main() { println!(\"hi\"); }");
    assert!(
        rust_result.is_err(),
        "Rust run_source must return Err (no source interpreter)"
    );
    let msg = rust_result.unwrap_err().to_string();
    assert!(
        msg.contains("register_precompiled"),
        "Rust error must mention register_precompiled: {msg}"
    );
    println!("[rust]   correctly rejected: pre-compile required");

    Ok(())
}
