// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Resolver for the self-contained Pyodide 0.28.3 payload that the build script
//! assembles (see `build.rs` + `pyodide_payload.rs`).
//!
//! The build script fetches the stock Pyodide 0.28.3 main wasm, the stdlib, and
//! the pandas dependency closure (numpy, six, python-dateutil, pytz, pandas),
//! exnref-translates the wasm and each wheel `.so` with `wasm-opt`, and caches
//! the result under the workspace target, with a `manifest.txt` listing the
//! files. The dir path is baked in at compile time as
//! `AFTERBURNER_PYODIDE_BUNDLE_DIR`.
//!
//! This module reads that manifest at runtime and returns the resolved paths,
//! so `burn run x.py` (and the REPL) run numpy + pandas with NO env vars and NO
//! runtime download. `BURN_PYTHON_RUNTIME` / `BURN_WHEELS` remain optional
//! OVERRIDES. When the bundle is absent (a build where `wasm-opt` or the network
//! was unavailable), `resolve` returns `None` and the caller falls back to the
//! env-var path with an honest error.

use std::path::{Path, PathBuf};

/// Compile-time path to the cache dir the build script populates. Always set
/// (the build script emits it unconditionally); the dir may or may not be
/// populated depending on whether `wasm-opt` and the network were available.
const BUNDLE_DIR: &str = env!("AFTERBURNER_PYODIDE_BUNDLE_DIR");

/// A resolved, ready-to-run Pyodide payload: absolute paths to the exnref main
/// wasm, the stdlib zip, the wheels (in dependency order), and the interpreter
/// `X.Y` version the stdlib + wheels were built for.
#[derive(Debug, Clone)]
pub struct BundledRuntime {
    /// The exnref-translated `pyodide.asm.wasm`.
    pub wasm_path: PathBuf,
    /// `python_stdlib.zip`.
    pub stdlib_path: PathBuf,
    /// Wheel paths in dependency (load) order. Empty for a stdlib-only bundle.
    pub wheels: Vec<PathBuf>,
    /// Interpreter `X.Y`, e.g. `"3.13"`, for the stdlib mount + soabi tag.
    pub python_xy: String,
}

/// Resolve the bundled Pyodide payload from the build-time cache, or `None` if
/// it was not assembled (so the caller falls back to `BURN_PYTHON_RUNTIME`).
///
/// Validates that the manifest exists and every file it lists is present; a
/// half-populated cache resolves to `None` rather than a broken run.
pub fn resolve() -> Option<BundledRuntime> {
    let dir = Path::new(BUNDLE_DIR);
    let manifest = dir.join("manifest.txt");
    let text = std::fs::read_to_string(&manifest).ok()?;

    let mut wasm_path = None;
    let mut stdlib_path = None;
    let mut wheels = Vec::new();
    let mut python_xy = String::from("3.13");

    for line in text.lines() {
        let (key, val) = line.split_once('=')?;
        match key {
            "python" => python_xy = val.to_owned(),
            "wasm" => wasm_path = Some(dir.join(val)),
            "stdlib" => stdlib_path = Some(dir.join(val)),
            "wheel" => wheels.push(dir.join(val)),
            _ => {}
        }
    }

    let wasm_path = wasm_path?;
    let stdlib_path = stdlib_path?;
    // Every listed file must exist; otherwise the cache is partial.
    if !wasm_path.exists() || !stdlib_path.exists() || wheels.iter().any(|w| !w.exists()) {
        return None;
    }

    Some(BundledRuntime {
        wasm_path,
        stdlib_path,
        wheels,
        python_xy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compile-time bundle dir env is always set by the build script.
    #[test]
    fn bundle_dir_env_is_set() {
        assert!(
            !BUNDLE_DIR.is_empty(),
            "AFTERBURNER_PYODIDE_BUNDLE_DIR must be baked in by build.rs"
        );
    }

    /// `resolve` never panics: it returns `Some` when the cache is fully
    /// populated (the normal dev/CI path, wasm-opt present) and `None` when it
    /// is absent. Either is a valid, honest outcome.
    #[test]
    fn resolve_is_total() {
        match resolve() {
            Some(rt) => {
                assert!(rt.wasm_path.exists(), "resolved wasm must exist");
                assert!(rt.stdlib_path.exists(), "resolved stdlib must exist");
                assert!(
                    rt.python_xy.starts_with("3."),
                    "python xy looks wrong: {}",
                    rt.python_xy
                );
                for w in &rt.wheels {
                    assert!(w.exists(), "resolved wheel must exist: {}", w.display());
                }
            }
            None => { /* bundle not assembled in this build; acceptable */ }
        }
    }
}
