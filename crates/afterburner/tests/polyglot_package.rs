// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]

//! End-to-end `burn compile` -> `burn run <pkg.afb>` tests for the interpreted
//! languages (Python, Ruby), packed as SOURCE and run on the bundled runtime.
//!
//! Each test drives the real `burn` binary on a REAL multi-module package under
//! `examples/languages/<lang>-multimodule/` (the entry imports/requires a
//! sibling module), exercising the whole path:
//! `burn compile` (source `.afb`, no precompiled WASM) -> `burn run <pkg.afb>`
//! (unpack -> mount the source tree -> run the entry on the bundled CPython /
//! CRuby interpreter with siblings on the module search path) -> stdout.
//!
//! The package directory is the multimodule fixture; the asserted stdout proves
//! the sibling import resolved:
//! - Python (`source/main.py` imports `source/helper.py`): `python-mm: fib(10)=55 square(7)=49`
//! - Ruby   (`source/main.rb` requires `source/helper.rb`): `ruby-mm: fib(10)=55 square(7)=49`
//!
//! ## Honesty: skip, never fake-pass
//!
//! The bundled interpreter is assembled at build time (it needs `wasm-opt` /
//! network for Pyodide, network for ruby.wasm). When it is genuinely absent the
//! test prints a prominent `SKIP <name>: <reason>` to stderr and returns
//! WITHOUT asserting the output - it never silently reports green. The skip is
//! gated on the honest "runtime not found" message the resolver emits, so a
//! real run failure (a wrong import path, a trap) still fails the test. This
//! mirrors the `polyglot_repl.rs` / `polyglot_multimodule.rs` conventions.
//!
//! No `BURN_*` env is set: the test exercises the zero-config bundled runtime,
//! exactly as a user gets it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the compiled `burn` binary (populated by Cargo for the crate that
/// declares the binary).
const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Directory of an example package under the workspace `examples/languages/`.
fn example_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/languages")
        .join(name)
}

/// Whether `stderr` shows the honest "runtime not assembled in this build"
/// signal for an interpreted language. When true, the caller LOUD-SKIPs.
fn runtime_absent(stderr: &str) -> bool {
    stderr.contains("python runtime not found") || stderr.contains("ruby runtime not found")
}

/// Run `burn` with `args`, no `BURN_*` env, and return `(exit_ok, stdout, stderr)`.
///
/// Every `BURN_*` override is explicitly removed so the run uses the zero-config
/// bundled runtime - a stray env var in the test shell cannot mask a real
/// regression in the default path.
fn run_burn(args: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(BURN);
    cmd.args(args).env("NO_COLOR", "1").env("BURN_QUIET", "1");
    // Strip any interpreter-runtime overrides: test the bundled default.
    for (k, _) in std::env::vars() {
        if k.starts_with("BURN_PYTHON") || k.starts_with("BURN_RUBY") || k == "BURN_WHEELS" {
            cmd.env_remove(k);
        }
    }
    let out = cmd.output().expect("spawn burn");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Compile the named multimodule example to a `.afb`, then run that `.afb`, and
/// assert the produced stdout equals `expected` (trimmed). LOUD-SKIP (no
/// assertion) when the bundled interpreter is absent in this build.
fn compile_run_assert(test_name: &str, example: &str, expected: &str) {
    let dir = example_dir(example);
    assert!(dir.is_dir(), "missing example dir {}", dir.display());

    let out_afb = std::env::temp_dir().join(format!("burn-test-{example}.afb"));
    let _ = std::fs::remove_file(&out_afb);
    let out_afb_str = out_afb.to_string_lossy().into_owned();

    // Step 1: `burn compile <dir> -o <out.afb>` packs the source `.afb`.
    let (compile_ok, compile_stdout, compile_stderr) =
        run_burn(&["compile", dir.to_str().unwrap(), "-o", &out_afb_str]);
    assert!(
        compile_ok,
        "{test_name}: `burn compile` failed\n  stdout={compile_stdout}\n  stderr={compile_stderr}"
    );
    assert!(
        out_afb.is_file(),
        "{test_name}: `burn compile` did not write {}",
        out_afb.display()
    );

    // Step 2: `burn run <out.afb>` unpacks + runs on the bundled interpreter.
    let (run_ok, run_stdout, run_stderr) = run_burn(&["run", &out_afb_str]);

    let _ = std::fs::remove_file(&out_afb);

    if runtime_absent(&run_stderr) {
        eprintln!(
            "SKIP {test_name}: bundled interpreter not assembled in this build\n  \
             (the .afb compiled fine; running it needs the bundled runtime)\n  detail: {run_stderr}"
        );
        return;
    }

    assert!(
        run_ok,
        "{test_name}: `burn run <pkg.afb>` failed\n  stdout={run_stdout}\n  stderr={run_stderr}"
    );
    assert_eq!(
        run_stdout.trim(),
        expected,
        "{test_name}: stdout must be {expected:?}\n  got stdout={run_stdout:?}\n  stderr={run_stderr:?}"
    );
}

#[test]
fn python_multimodule_compiles_to_afb_and_runs_with_sibling_import() {
    // Proves: `burn compile` packs `source/main.py` + `source/helper.py` into a
    // source `.afb`, and `burn run <pkg.afb>` mounts the tree so `from helper
    // import fib, square` resolves the sibling on the bundled CPython runtime.
    compile_run_assert(
        "python_multimodule_compiles_to_afb_and_runs_with_sibling_import",
        "python-multimodule",
        "python-mm: fib(10)=55 square(7)=49",
    );
}

#[test]
fn ruby_multimodule_compiles_to_afb_and_runs_with_sibling_require() {
    // Proves: `burn compile` packs `source/main.rb` + `source/helper.rb` into a
    // source `.afb`, and `burn run <pkg.afb>` mounts the tree + adds it to
    // `$LOAD_PATH` so `require 'helper'` resolves the sibling on the bundled
    // CRuby runtime.
    compile_run_assert(
        "ruby_multimodule_compiles_to_afb_and_runs_with_sibling_require",
        "ruby-multimodule",
        "ruby-mm: fib(10)=55 square(7)=49",
    );
}

#[test]
fn interpreted_multimodule_examples_exist_and_declare_interpreted_languages() {
    // Always-on guard: the example packages are present and well-formed, so a
    // missing-runtime skip can never hide a deleted/renamed example. Mirrors
    // `polyglot_multimodule::multimodule_examples_exist_*`.
    use afterburner::cli::compile::lang::SourceLang;
    use std::str::FromStr;

    for (example, lang, entry, helper) in [
        (
            "python-multimodule",
            "python",
            "source/main.py",
            "source/helper.py",
        ),
        (
            "ruby-multimodule",
            "ruby",
            "source/main.rb",
            "source/helper.rb",
        ),
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
        assert!(
            dir.join(helper).is_file(),
            "{example}: missing sibling module {helper}"
        );
        let lang_enum = SourceLang::from_str(lang).expect("valid lang");
        assert!(
            lang_enum.is_interpretable(),
            "{example} must be an interpreted language"
        );
        assert!(!lang_enum.is_js_family(), "{example} is not JS/TS family");
    }
}
