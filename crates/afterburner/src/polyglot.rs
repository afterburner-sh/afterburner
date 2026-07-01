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

use afterburner_core::{AfterburnerError, OutputValue, Result, ScriptOutcome};

/// A source language supported by the afterburner runtime.
///
/// Re-exported from `afterburner-core` so the facade and every substrate
/// contract name the same one enum. Used with
/// [`crate::Afterburner::run_source`] and [`crate::Afterburner::run_file`] to
/// select the execution path. `Rust` / `Go` / `C` / `Cpp` have no
/// source-interpreter path: `run_source` with one of them returns a typed
/// error directing the caller to `register_precompiled`.
pub use afterburner_core::Language;

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
///
/// Binary-first: `stdout` / `stderr` are raw bytes (a run may emit invalid
/// UTF-8 or NULs; multimodal payloads are byte-exact) and are never passed
/// through a lossy conversion at capture time. Use [`Outcome::stdout_str`] /
/// [`Outcome::stderr_str`] for a lossy `String` view when text is what you
/// want.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Bytes written to stdout during the run (captured, not printed),
    /// byte-exact.
    pub stdout: Vec<u8>,
    /// Bytes written to stderr during the run (captured), byte-exact. Empty
    /// on a clean run.
    pub stderr: Vec<u8>,
    /// The run's typed return value. `OutputValue::Json(Value::Null)` means
    /// no return value was surfaced (a plain script-mode run that only wrote
    /// stdout - the current state for every language until per-substrate
    /// value capture lands).
    pub output: OutputValue,
    /// `true` when the program exited with code 0.
    pub ok: bool,
}

impl Outcome {
    /// A lossy `String` view of [`stdout`](Self::stdout), for callers that
    /// want text. Back-compat shim for the pre-binary `stdout: String` field;
    /// invalid UTF-8 becomes the replacement character.
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// A lossy `String` view of [`stderr`](Self::stderr). See
    /// [`stdout_str`](Self::stdout_str).
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// The "no return value surfaced" sentinel: `OutputValue::Json(Value::Null)`.
fn no_output() -> OutputValue {
    OutputValue::Json(serde_json::Value::Null)
}

impl From<ScriptOutcome> for Outcome {
    fn from(s: ScriptOutcome) -> Self {
        Self {
            stdout: s.stdout,
            stderr: s.stderr,
            output: no_output(),
            ok: s.exit_code == 0,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<afterburner_wasi::pyodide_runner::PyodideRunOutput> for Outcome {
    fn from(p: afterburner_wasi::pyodide_runner::PyodideRunOutput) -> Self {
        Self {
            stdout: p.stdout,
            stderr: p.stderr,
            output: p.output,
            ok: p.exit_code == 0,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<afterburner_wasi::ruby_runner::RubyRunOutput> for Outcome {
    fn from(r: afterburner_wasi::ruby_runner::RubyRunOutput) -> Self {
        Self {
            stdout: r.stdout,
            stderr: r.stderr,
            output: r.output,
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
