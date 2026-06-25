// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Resolver for the self-contained Ruby runtime payload, fetched lazily into
//! `~/.burn` on first use.
//!
//! On a miss, [`crate::bundle::ensure_ruby_bundle`] downloads the stock
//! `ruby-3.4-wasm32-unknown-wasip1-full` tarball from its pinned, sha256-checked
//! source, extracts the standalone interpreter (`usr/local/bin/ruby`, a pure
//! WASI command module) and its stdlib tree (kept under `usr/local/lib/ruby`),
//! and populates `~/.burn/ruby-<release>/` atomically with a `manifest.txt`. A
//! populated bundle is a cache hit (no network). This module reads that manifest
//! and returns the resolved paths, so `burn run x.rb` (and the REPL) run with NO
//! env vars beyond the first-use download.
//!
//! `BURN_RUBY_RUNTIME` remains an optional OVERRIDE handled one level up in
//! [`crate::ruby_runner::resolve_ruby_runtime`]; this resolver is the default
//! path. When the fetch fails (no network), `resolve` returns `None` and the
//! caller falls back to the env-var path with an honest error.

use std::path::{Path, PathBuf};

/// A resolved, ready-to-run Ruby payload: absolute paths to the standalone
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

/// Resolve the Ruby payload, fetching it into `~/.burn` on a miss, or `None`
/// when neither the fetch nor a populated bundle is available (so the caller
/// falls back to `BURN_RUBY_RUNTIME`).
///
/// Ensures the bundle (a cache hit is a no-op; a miss downloads with the gradient
/// bar), then validates that the files the manifest lists are present; a
/// half-populated bundle resolves to `None` rather than a broken run.
pub fn resolve() -> Option<BundledRubyRuntime> {
    // Fetch into `~/.burn` on a miss (no-op on a hit). A failure (no network) is
    // reported by the caller's honest fallback error, so swallow it to `None`.
    let dir = crate::bundle::ensure_ruby_bundle().ok()?;
    resolve_dir(&dir)
}

/// Parse the manifest in a populated bundle `dir` into resolved paths, returning
/// `None` when the manifest is absent, malformed, or the stdlib tree is missing.
/// Pure (no network, no env): the fetch happened in [`resolve`].
fn resolve_dir(dir: &Path) -> Option<BundledRubyRuntime> {
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

    /// Write a complete fixture bundle under `dir`, exercising `resolve_dir`
    /// without a network fetch or env mutation (parallel-safe).
    fn write_fixture(dir: &Path) {
        std::fs::create_dir_all(dir.join("usr/local/lib/ruby/3.4.0")).unwrap();
        std::fs::write(dir.join("ruby.wasm"), b"wasm").unwrap();
        std::fs::write(
            dir.join("manifest.txt"),
            "release=2.9.4\nruby=3.4.0\nwasm=ruby.wasm\nusr=usr\n",
        )
        .unwrap();
    }

    /// A complete bundle dir resolves to the interpreter + `usr` tree.
    #[test]
    fn resolves_a_complete_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path());
        let rt = resolve_dir(tmp.path()).expect("a complete bundle resolves");
        assert!(rt.wasm_path.exists());
        assert!(
            rt.usr_dir
                .join("local/lib/ruby")
                .join(&rt.ruby_abi)
                .exists()
        );
        assert_eq!(rt.ruby_abi, "3.4.0");
    }

    /// A bundle missing the versioned stdlib ABI dir resolves to `None`.
    #[test]
    fn partial_bundle_resolves_none() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path());
        std::fs::remove_dir_all(tmp.path().join("usr/local/lib/ruby/3.4.0")).unwrap();
        assert!(resolve_dir(tmp.path()).is_none());
    }

    /// An absent manifest resolves to `None`, never a panic.
    #[test]
    fn missing_manifest_resolves_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(resolve_dir(tmp.path()).is_none());
    }
}
