// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Unified polyglot facade: one entry point for every language.
//!
//! All language-level entry points (`run_script`, `run_python`, `run_ruby`,
//! `register_precompiled + run`) are bridged behind the two methods
//! [`Language`] + [`run_source`](crate::Afterburner::run_source) /
//! [`run_file`](crate::Afterburner::run_file), which return a single
//! [`Outcome`] type regardless of the language being run.
//!
//! The per-language entry points remain and are unchanged - this module is
//! an additive facade, not a replacement.

use std::path::Path;

use afterburner_core::{AfterburnerError, Result, ScriptOutcome};
use serde_json::Value;

/// A source language supported by the afterburner runtime.
///
/// Used with [`crate::Afterburner::run_source`] and
/// [`crate::Afterburner::run_file`] to select the execution path.
/// Construct via `Language::from_extension` (from a file extension) or
/// use the variants directly.
///
/// # Compile-to-WASM languages
///
/// `Rust`, `Go`, `C`, and `Cpp` do not have a source-interpreter path.
/// Calling `run_source` with one of these variants returns a typed error
/// directing the caller to `register_precompiled`. Pre-compiled WASM
/// modules should be registered via
/// [`Afterburner::register_precompiled`](crate::Afterburner::register_precompiled).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// JavaScript source, run via the JS/WASM engine.
    Js,
    /// TypeScript source, stripped to JS then run via the JS/WASM engine.
    Ts,
    /// Rust source. No source-interpreter; use `register_precompiled` with
    /// a pre-compiled `wasm32-wasip1` module.
    Rust,
    /// Go source. No source-interpreter; use `register_precompiled` with a
    /// pre-compiled `wasm32-wasip1` module.
    Go,
    /// C source. No source-interpreter; use `register_precompiled` with a
    /// pre-compiled `wasm32-wasip1` module.
    C,
    /// C++ source. No source-interpreter; use `register_precompiled` with a
    /// pre-compiled `wasm32-wasip1` module.
    Cpp,
    /// Python source, run via the bundled Pyodide/CPython-WASI runtime.
    /// Requires the `wasm` feature.
    Python,
    /// Ruby source, run via the bundled ruby.wasm/CRuby-WASI runtime.
    /// Requires the `wasm` feature.
    Ruby,
}

impl Language {
    /// Detect the language from a file extension (lowercased, without the dot).
    ///
    /// | Extension      | Language     |
    /// |----------------|--------------|
    /// | `rb`           | `Ruby`       |
    /// | `py`           | `Python`     |
    /// | `js`           | `Js`         |
    /// | `ts`           | `Ts`         |
    /// | `rs`           | `Rust`       |
    /// | `go`           | `Go`         |
    /// | `c`            | `C`          |
    /// | `cc`, `cpp`    | `Cpp`        |
    ///
    /// Returns `None` for any other extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.trim().to_ascii_lowercase().as_str() {
            "rb" => Some(Self::Ruby),
            "py" => Some(Self::Python),
            "js" => Some(Self::Js),
            "ts" => Some(Self::Ts),
            "rs" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "c" => Some(Self::C),
            "cc" | "cpp" => Some(Self::Cpp),
            _ => None,
        }
    }
}

/// Unified output from [`crate::Afterburner::run_source`] and
/// [`crate::Afterburner::run_file`].
///
/// Maps from the per-language output types (`ScriptOutcome`,
/// `PyodideRunOutput`, `RubyRunOutput`) into a single consistent shape.
///
/// `ok` is `true` when the program exited with code 0 (success). A
/// non-zero exit code (an uncaught exception, a runtime error) sets `ok`
/// to `false` but does NOT produce an `Err` - the program ran to
/// completion. `Err` is reserved for infrastructural failures (runtime not
/// found, compile failure, WASM trap, I/O error reading the source file).
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Text written to stdout during the run (captured, not printed).
    pub stdout: String,
    /// Text written to stderr during the run (captured). Empty on a clean run.
    pub stderr: String,
    /// The script's return value, when the language surfaces one.
    /// Currently `None` for all languages: script-mode runs capture text
    /// output, not structured return values.
    ///
    /// vertexia: future per-language value extraction (e.g. JSON last-expr
    /// for JS) goes here; add Language-specific From impls when available.
    pub value: Option<Value>,
    /// `true` when the program exited with code 0.
    pub ok: bool,
}

impl From<ScriptOutcome> for Outcome {
    fn from(s: ScriptOutcome) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&s.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&s.stderr).into_owned(),
            value: None,
            ok: s.exit_code == 0,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<afterburner_wasi::pyodide_runner::PyodideRunOutput> for Outcome {
    fn from(p: afterburner_wasi::pyodide_runner::PyodideRunOutput) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&p.stdout).into_owned(),
            stderr: String::new(),
            value: None,
            ok: p.exit_code == 0,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<afterburner_wasi::ruby_runner::RubyRunOutput> for Outcome {
    fn from(r: afterburner_wasi::ruby_runner::RubyRunOutput) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&r.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&r.stderr).into_owned(),
            value: None,
            ok: r.exit_code == 0,
        }
    }
}

/// Internal dispatch: route source to the appropriate runner.
///
/// Called by `Afterburner::run_source`. Separated here to keep `builder.rs`
/// free of per-language imports.
pub(crate) fn dispatch_run_source(
    ab: &crate::Afterburner,
    lang: Language,
    source: &str,
) -> Result<Outcome> {
    match lang {
        Language::Js => {
            let outcome = ab.run_script(source)?;
            Ok(Outcome::from(outcome))
        }

        #[cfg(feature = "ts")]
        Language::Ts => {
            // Strip TypeScript annotations before handing to the JS engine.
            let js = crate::ts::transpile(source, Path::new("<run_source>.ts"))
                .map_err(|e| AfterburnerError::Engine(format!("TypeScript transpile: {e}")))?;
            let outcome = ab.run_script(&js)?;
            Ok(Outcome::from(outcome))
        }

        #[cfg(not(feature = "ts"))]
        Language::Ts => Err(AfterburnerError::Engine(
            "TypeScript requires the `ts` cargo feature \
             (rebuild with `--features ts`)."
                .into(),
        )),

        #[cfg(feature = "wasm")]
        Language::Python => {
            let out = afterburner_wasi::pyodide_runner::run_python(source)?;
            Ok(Outcome::from(out))
        }

        #[cfg(not(feature = "wasm"))]
        Language::Python => Err(AfterburnerError::Engine(
            "Python requires the `wasm` feature to be enabled".into(),
        )),

        #[cfg(feature = "wasm")]
        Language::Ruby => {
            let out = afterburner_wasi::ruby_runner::run_ruby(source)?;
            Ok(Outcome::from(out))
        }

        #[cfg(not(feature = "wasm"))]
        Language::Ruby => Err(AfterburnerError::Engine(
            "Ruby requires the `wasm` feature to be enabled".into(),
        )),

        Language::Rust | Language::Go | Language::C | Language::Cpp => {
            Err(AfterburnerError::Engine(format!(
                "{lang:?} does not have a source-interpreter path. \
                 Compile the source to a wasm32-wasip1 module with the \
                 appropriate toolchain, then use \
                 `Afterburner::register_precompiled` to register and run it."
            )))
        }
    }
}

/// Detect language from a `Path`'s extension, returning a typed error when
/// the extension is absent or unrecognized.
pub(crate) fn language_for_path(path: &Path) -> Result<Language> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    Language::from_extension(ext).ok_or_else(|| {
        AfterburnerError::Engine(format!(
            "cannot detect language for {:?}: unsupported extension {:?}. \
             Supported extensions: rb, py, js, ts, rs, go, c, cc, cpp.",
            path.display(),
            ext
        ))
    })
}
