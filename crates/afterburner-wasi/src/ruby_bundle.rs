// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Resolver for the self-contained ruby.wasm payload that the build script
//! assembles (see `build.rs` + `ruby_payload.rs`).
//!
//! The build script fetches the stock `ruby-3.4-wasm32-unknown-wasip1-full`
//! tarball, extracts the standalone interpreter (`usr/local/bin/ruby`, a pure
//! WASI command module) and its stdlib tree (kept under `usr/local/lib/ruby`),
//! and caches them under the workspace target with a `manifest.txt`. The dir
//! path is baked in at compile time as `AFTERBURNER_RUBY_BUNDLE_DIR`.
//!
//! This module reads that manifest at runtime and returns the resolved paths,
//! so `burn run x.rb` (and the REPL) run with NO env vars and NO runtime
//! download. `BURN_RUBY_RUNTIME` remains an optional OVERRIDE. When the bundle
//! is absent (a build where the network was unavailable), `resolve` returns
//! `None` and the caller falls back to the env-var path with an honest error.

use std::path::{Path, PathBuf};

/// Compile-time path to the cache dir the build script populates. Always set
/// (the build script emits it unconditionally); the dir may or may not be
/// populated depending on whether the network was available at build time.
const BUNDLE_DIR: &str = env!("AFTERBURNER_RUBY_BUNDLE_DIR");

/// A resolved, ready-to-run ruby.wasm payload: absolute paths to the standalone
/// interpreter and the `usr` tree to mount, plus the Ruby `X.Y.Z` ABI the
/// stdlib was built for.
#[derive(Debug, Clone)]
pub struct BundledRubyRuntime {
    /// The standalone `ruby.wasm` (a WASI command module).
    pub wasm_path: PathBuf,
    /// The cached `usr` tree (`<dir>/usr`), holding `local/lib/ruby/<abi>/...`.
    /// It is mounted read-only at guest `/usr` so CRuby's compiled-in load path
    /// (`/usr/local/lib/ruby/<abi>`) and every intermediate dir resolve.
    pub usr_dir: PathBuf,
    /// Ruby ABI, e.g. `"3.4.0"`, for the load-path mount.
    pub ruby_abi: String,
}

/// Resolve the bundled ruby.wasm payload from the build-time cache, or `None` if
/// it was not assembled (so the caller falls back to `BURN_RUBY_RUNTIME`).
///
/// Validates that the manifest exists and the files it lists are present; a
/// half-populated cache resolves to `None` rather than a broken run.
pub fn resolve() -> Option<BundledRubyRuntime> {
    let dir = Path::new(BUNDLE_DIR);
    let text = std::fs::read_to_string(dir.join("manifest.txt")).ok()?;

    let mut wasm_path = None;
    let mut usr_dir = None;
    let mut ruby_abi = String::from("3.4.0");

    for line in text.lines() {
        let (key, val) = line.split_once('=')?;
        match key {
            "ruby" => ruby_abi = val.to_owned(),
            "wasm" => wasm_path = Some(dir.join(val)),
            "usr" => usr_dir = Some(dir.join(val)),
            _ => {}
        }
    }

    let wasm_path = wasm_path?;
    let usr_dir = usr_dir?;
    // Both must exist; the `usr` tree must carry the versioned stdlib dir.
    if !wasm_path.exists() || !usr_dir.join("local/lib/ruby").join(&ruby_abi).exists() {
        return None;
    }

    Some(BundledRubyRuntime {
        wasm_path,
        usr_dir,
        ruby_abi,
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
            "AFTERBURNER_RUBY_BUNDLE_DIR must be baked in by build.rs"
        );
    }

    /// `resolve` never panics: it returns `Some` when the cache is fully
    /// populated (the normal dev/CI path with network) and `None` when it is
    /// absent. Either is a valid, honest outcome.
    #[test]
    fn resolve_is_total() {
        match resolve() {
            Some(rt) => {
                assert!(rt.wasm_path.exists(), "resolved wasm must exist");
                assert!(
                    rt.usr_dir
                        .join("local/lib/ruby")
                        .join(&rt.ruby_abi)
                        .exists(),
                    "resolved usr tree must carry the versioned ABI dir"
                );
                assert!(
                    rt.ruby_abi.starts_with("3.") || rt.ruby_abi.starts_with("4."),
                    "ruby abi looks wrong: {}",
                    rt.ruby_abi
                );
            }
            None => { /* bundle not assembled in this build; acceptable */ }
        }
    }
}
