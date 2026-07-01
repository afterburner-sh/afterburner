// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Integration tests for the unified polyglot `run_source` / `run_file` facade.
//!
//! Tests run against default features (wasm + native + thrust + embed-ruby).
//! Python and Ruby cases are guarded: when no runtime is available (a cold build
//! with no BURN_PYTHON_RUNTIME / BURN_RUBY_RUNTIME), the test LOUD-SKIPs with an
//! honest explanation rather than failing or silently passing. JS runs always.

use afterburner::{Afterburner, Language, Outcome, OutputValue};

// ---- Language::from_extension -----------------------------------------------

#[test]
fn from_extension_maps_all_supported() {
    assert_eq!(Language::from_extension("js"), Some(Language::Js));
    assert_eq!(Language::from_extension("ts"), Some(Language::Ts));
    assert_eq!(Language::from_extension("py"), Some(Language::Python));
    assert_eq!(Language::from_extension("rb"), Some(Language::Ruby));
    assert_eq!(Language::from_extension("rs"), Some(Language::Rust));
    assert_eq!(Language::from_extension("go"), Some(Language::Go));
    assert_eq!(Language::from_extension("c"), Some(Language::C));
    assert_eq!(Language::from_extension("cc"), Some(Language::Cpp));
    assert_eq!(Language::from_extension("cpp"), Some(Language::Cpp));
    assert_eq!(Language::from_extension("haskell"), None);
    assert_eq!(Language::from_extension(""), None);
}

#[test]
fn from_extension_is_case_insensitive() {
    assert_eq!(Language::from_extension("JS"), Some(Language::Js));
    assert_eq!(Language::from_extension("PY"), Some(Language::Python));
    assert_eq!(Language::from_extension("RB"), Some(Language::Ruby));
}

// ---- Outcome From conversions -----------------------------------------------

#[test]
fn outcome_from_script_outcome_ok() {
    let so = afterburner::ScriptOutcome {
        stdout: b"hello\n".to_vec(),
        stderr: b"".to_vec(),
        exit_code: 0,
    };
    let out = Outcome::from(so);
    assert_eq!(out.stdout_str(), "hello\n");
    assert_eq!(out.stderr_str(), "");
    assert!(out.ok);
    assert_eq!(out.output, OutputValue::Json(serde_json::Value::Null));
}

#[test]
fn outcome_from_script_outcome_nonzero_exit() {
    let so = afterburner::ScriptOutcome {
        stdout: b"partial\n".to_vec(),
        stderr: b"boom\n".to_vec(),
        exit_code: 1,
    };
    let out = Outcome::from(so);
    assert!(!out.ok);
    assert_eq!(out.stderr_str(), "boom\n");
}

// ---- run_source: JavaScript -------------------------------------------------

#[test]
fn run_source_js_hello() {
    let ab = Afterburner::new().expect("build ab");
    let out = ab
        .run_source(Language::Js, "console.log('hello from js')")
        .expect("run_source js");
    assert!(out.ok, "exit 0; stderr={:?}", out.stderr_str());
    assert!(
        out.stdout_str().contains("hello from js"),
        "stdout must contain greeting: {:?}",
        out.stdout_str()
    );
}

#[test]
fn run_source_js_returns_outcome_not_json() {
    let ab = Afterburner::new().expect("build ab");
    let out = ab
        .run_source(Language::Js, "console.log(42)")
        .expect("run_source js");
    assert!(out.ok);
    assert!(out.stdout_str().contains("42"));
    // no return value surfaced for a script-mode run -> Json(Null) sentinel
    assert_eq!(out.output, OutputValue::Json(serde_json::Value::Null));
}

#[test]
fn run_source_js_nonzero_exit_is_ok_not_err() {
    // An uncaught exception -> exit 1, but run_source returns Ok, not Err.
    let ab = Afterburner::new().expect("build ab");
    let result = ab.run_source(Language::Js, "throw new Error('boom')");
    let out = result.expect("run_source must return Ok even on user exception");
    assert!(!out.ok, "exit 1 expected");
}

// ---- run_source: TypeScript -------------------------------------------------

// TypeScript stripping requires the `ts` cargo feature (oxc dependency).
// Without it, run_source(Ts) returns a clear typed error pointing at --features ts.
#[test]
#[cfg(feature = "ts")]
fn run_source_ts_strips_types_and_runs() {
    let ab = Afterburner::new().expect("build ab");
    let source = "const msg: string = 'hello ts'; console.log(msg);";
    let out = ab.run_source(Language::Ts, source).expect("run_source ts");
    assert!(out.ok, "stderr={:?}", out.stderr_str());
    assert!(
        out.stdout_str().contains("hello ts"),
        "stdout must contain greeting: {:?}",
        out.stdout_str()
    );
}

#[test]
#[cfg(not(feature = "ts"))]
fn run_source_ts_without_ts_feature_is_typed_error() {
    let ab = Afterburner::new().expect("build ab");
    let err = ab
        .run_source(Language::Ts, "const x: number = 1")
        .expect_err("Ts without ts feature must return Err");
    assert!(
        err.to_string().contains("ts") || err.to_string().contains("TypeScript"),
        "error must mention the ts feature: {}",
        err
    );
}

// ---- run_source: compiled languages (honest rejection) ----------------------

#[test]
fn run_source_rust_returns_typed_error_with_register_precompiled_hint() {
    let ab = Afterburner::new().expect("build ab");
    let err = ab
        .run_source(Language::Rust, "fn main() {}")
        .expect_err("Rust must return Err (no source interpreter)");
    let msg = err.to_string();
    assert!(
        msg.contains("register_precompiled"),
        "error must mention register_precompiled: {msg}"
    );
}

#[test]
fn run_source_go_returns_typed_error() {
    let ab = Afterburner::new().expect("build ab");
    let err = ab
        .run_source(Language::Go, "package main\nfunc main() {}")
        .expect_err("Go must return Err (no source interpreter)");
    assert!(err.to_string().contains("register_precompiled"));
}

#[test]
fn run_source_c_returns_typed_error() {
    let ab = Afterburner::new().expect("build ab");
    let err = ab
        .run_source(Language::C, "int main() { return 0; }")
        .expect_err("C must return Err (no source interpreter)");
    assert!(err.to_string().contains("register_precompiled"));
}

#[test]
fn run_source_cpp_returns_typed_error() {
    let ab = Afterburner::new().expect("build ab");
    let err = ab
        .run_source(Language::Cpp, "int main() { return 0; }")
        .expect_err("C++ must return Err (no source interpreter)");
    assert!(err.to_string().contains("register_precompiled"));
}

// ---- run_file: language detection -------------------------------------------

#[test]
fn run_file_detects_js_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hello.js");
    std::fs::write(&path, "console.log('hi from file')").expect("write");
    let ab = Afterburner::new().expect("build ab");
    let out = ab.run_file(&path).expect("run_file js");
    assert!(out.ok, "stderr={:?}", out.stderr_str());
    assert!(
        out.stdout_str().contains("hi from file"),
        "stdout={:?}",
        out.stdout_str()
    );
}

#[test]
fn run_file_unknown_extension_is_typed_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hello.haskell");
    std::fs::write(&path, "main = putStrLn \"hi\"").expect("write");
    let ab = Afterburner::new().expect("build ab");
    let err = ab.run_file(&path).expect_err("unknown ext must error");
    let msg = err.to_string();
    assert!(
        msg.contains("haskell") || msg.contains("unsupported"),
        "error must name the bad extension: {msg}"
    );
}

#[test]
fn run_file_missing_file_is_typed_error() {
    let ab = Afterburner::new().expect("build ab");
    let err = ab
        .run_file(std::path::Path::new("/nonexistent/path/hello.js"))
        .expect_err("missing file must error");
    assert!(
        err.to_string().contains("nonexistent"),
        "error must name the path: {}",
        err
    );
}

// ---- run_source: Python (skip when runtime absent) --------------------------

#[test]
#[cfg(feature = "wasm")]
fn run_source_python_hello_or_skip() {
    let ab = Afterburner::new().expect("build ab");
    match ab.run_source(Language::Python, "print('hello from python')") {
        Ok(out) => {
            assert!(out.ok, "python must exit 0; stderr={:?}", out.stderr_str());
            assert!(
                out.stdout_str().contains("hello from python"),
                "stdout must contain greeting: {:?}",
                out.stdout_str()
            );
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("python runtime not found")
                    || msg.contains("BURN_PYTHON_RUNTIME")
                    || msg.contains("not found"),
                "error must be honest runtime-missing, not a silent fail: {msg}"
            );
            eprintln!("SKIP python run_source (runtime absent): {msg}");
        }
    }
}

// ---- run_source: Ruby (skip when runtime absent) ----------------------------

#[test]
#[cfg(feature = "wasm")]
fn run_source_ruby_hello_or_skip() {
    let ab = Afterburner::new().expect("build ab");
    match ab.run_source(Language::Ruby, "puts 'hello from ruby'") {
        Ok(out) => {
            assert!(out.ok, "ruby must exit 0; stderr={:?}", out.stderr_str());
            assert!(
                out.stdout_str().contains("hello from ruby"),
                "stdout must contain greeting: {:?}",
                out.stdout_str()
            );
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("ruby runtime not found")
                    || msg.contains("BURN_RUBY_RUNTIME")
                    || msg.contains("not found"),
                "error must be honest runtime-missing, not a silent fail: {msg}"
            );
            eprintln!("SKIP ruby run_source (runtime absent): {msg}");
        }
    }
}
