// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Build-time assembly of the self-contained ruby.wasm payload.
//!
//! Fetches the stock `ruby-3.4-wasm32-unknown-wasip1-full` tarball from the
//! official `ruby/ruby.wasm` GitHub release (sha256-pinned), extracts the
//! standalone interpreter (`usr/local/bin/ruby`, a plain WASI command module
//! that imports only `wasi_snapshot_preview1`) and its stdlib tree
//! (`usr/local/lib/ruby`), and writes them into a stable cache dir under the
//! workspace target. No translation, no dynamic linking, no `wasm-opt` - the
//! binary runs as-is through `EmbedderVm::run_command`.
//!
//! The runtime reads `AFTERBURNER_RUBY_BUNDLE_DIR` (a `cargo:rustc-env` emitted
//! here) plus a `manifest.txt` the dir contains. Nothing is committed to git
//! and nothing is downloaded at runtime. The fetch SKIPS cleanly (a
//! `cargo:warning`, never a panic) when the network is unreachable; the runtime
//! then falls back to `BURN_RUBY_RUNTIME` with an honest error.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::sha256_hex;

/// ruby.wasm release the bundled payload tracks: the official `ruby/ruby.wasm`
/// GitHub release `2.9.4`, CRuby 3.4 built for `wasm32-unknown-wasip1`.
const RUBY_WASM_RELEASE: &str = "2.9.4";

/// Ruby `X.Y.Z` ABI dir the stdlib lives under inside the tarball
/// (`usr/local/lib/ruby/<RUBY_ABI>`), recorded in the manifest so the runtime
/// mounts the matching tree without a hardcode in the runner.
const RUBY_ABI: &str = "3.4.0";

/// Stock release tarball: the `full` build, which ships the standalone
/// `usr/local/bin/ruby` plus the complete stdlib under `usr/local/lib/ruby`.
const TARBALL: &str = "ruby-3.4-wasm32-unknown-wasip1-full.tar.gz";

/// sha256 of the STOCK tarball download (GitHub release asset, immutable).
const TARBALL_SHA256: &str = "ccda86a375a4fe09849846d3b03a370172a4902a0c571087f48457388a2762c7";

/// Top-level dir name inside the tarball; stripped so the cache keeps the
/// `usr/...` sub-tree (mounted at guest `/usr`).
const TARBALL_ROOT: &str = "ruby-3.4-wasm32-unknown-wasip1-full/";

/// The standalone interpreter path inside the tarball (a pure-WASI command
/// module). Extracted verbatim into the cache as `ruby.wasm`.
const BIN_RUBY: &str = "ruby-3.4-wasm32-unknown-wasip1-full/usr/local/bin/ruby";

/// The stdlib tree prefix inside the tarball. Everything under here is copied
/// into the cache PRESERVING the `usr/local/lib/ruby/...` path, then the cache's
/// `usr` dir is mounted read-only at guest `/usr`. The full `/usr` prefix must
/// resolve (CRuby's `gem_prelude` calls `realpath` on the load-path roots up to
/// `/usr` at startup), so mounting the stdlib alone at `/usr/local/lib/ruby`
/// would fail with `realpath_rec - /usr (Errno::ENOENT)`; mounting at `/usr`
/// lets every intermediate dir resolve.
const LIB_PREFIX: &str = "ruby-3.4-wasm32-unknown-wasip1-full/usr/local/lib/ruby/";

/// Cache-relative path of the versioned stdlib ABI dir, used to detect a
/// complete extraction.
const STDLIB_ABI_REL: &str = "usr/local/lib/ruby";

/// `cargo build` entry point: populate (or reuse) the ruby.wasm bundle cache and
/// export its dir so the runtime can resolve it.
pub(crate) fn build() {
    let dir = bundle_dir();
    // Always export the dir so the runtime knows where to look, even if this
    // build can't populate it (the runtime then falls back honestly).
    println!(
        "cargo:rustc-env=AFTERBURNER_RUBY_BUNDLE_DIR={}",
        dir.display()
    );
    println!("cargo:rerun-if-changed=ruby_payload.rs");
    // An explicit opt-out for offline/minimal builds that don't want Ruby.
    println!("cargo:rerun-if-env-changed=AFTERBURNER_SKIP_RUBY_BUNDLE");
    if std::env::var_os("AFTERBURNER_SKIP_RUBY_BUNDLE").is_some() {
        println!("cargo:warning=AFTERBURNER_SKIP_RUBY_BUNDLE set; skipping ruby.wasm payload");
        return;
    }

    let manifest = dir.join("manifest.txt");
    if manifest.exists() && manifest_complete(&dir, &manifest) {
        // Cache hit: the wasm and the stdlib root are present. No network.
        return;
    }

    if let Err(e) = std::fs::create_dir_all(&dir) {
        println!(
            "cargo:warning=ruby bundle: cannot create {}: {e}",
            dir.display()
        );
        return;
    }

    if let Err(e) = assemble(&dir) {
        println!(
            "cargo:warning=ruby bundle: {e}; `burn run x.rb` will fall back to BURN_RUBY_RUNTIME."
        );
    }
}

/// Fetch the stock tarball, extract `bin/ruby` + the stdlib into `dir`, and
/// write the manifest. Returns `Err` (a single actionable string) on any
/// failure so the caller can warn-and-skip without a panic.
fn assemble(dir: &Path) -> Result<(), String> {
    let wasm_out = dir.join("ruby.wasm");
    let abi_dir = dir.join(STDLIB_ABI_REL).join(RUBY_ABI);
    // Re-extract only when either half of the cache is missing.
    if !wasm_out.exists() || !abi_dir.exists() {
        let tar_gz = fetch()?;
        extract(&tar_gz, &wasm_out, dir)?;
    }

    let lines = [
        format!("release={RUBY_WASM_RELEASE}"),
        format!("ruby={RUBY_ABI}"),
        "wasm=ruby.wasm".to_string(),
        // The dir mounted read-only at guest `/usr`.
        "usr=usr".to_string(),
    ];
    std::fs::write(dir.join("manifest.txt"), lines.join("\n") + "\n")
        .map_err(|e| format!("writing manifest: {e}"))
}

/// Download the stock release tarball and verify its pinned sha256.
fn fetch() -> Result<Vec<u8>, String> {
    let url = format!(
        "https://github.com/ruby/ruby.wasm/releases/download/{RUBY_WASM_RELEASE}/{TARBALL}"
    );
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body {url}: {e}"))?;
    let got = sha256_hex(&buf);
    if got != TARBALL_SHA256 {
        return Err(format!(
            "{TARBALL} sha256 mismatch: expected {TARBALL_SHA256}, got {got} (release changed?)"
        ));
    }
    Ok(buf)
}

/// Extract the standalone `bin/ruby` to `wasm_out` and every stdlib file under
/// `LIB_PREFIX` into `<dir>/usr/local/lib/ruby/...`, preserving the tree shape
/// (so the cached `usr` mounts at guest `/usr`). Skips the 22 MB
/// `libruby-static.a` and the rest of the build sysroot, which the runtime
/// never touches.
fn extract(tar_gz: &[u8], wasm_out: &Path, dir: &Path) -> Result<(), String> {
    let gz = flate2::read::GzDecoder::new(tar_gz);
    let mut ar = tar::Archive::new(gz);
    let mut found_bin = false;
    let mut stdlib_count = 0usize;

    let entries = ar.entries().map_err(|e| format!("read tar entries: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        // The entry path is borrowed from the entry; copy it out so the
        // mutable read below does not conflict with the borrow.
        let path = entry
            .path()
            .map_err(|e| format!("tar entry path: {e}"))?
            .to_string_lossy()
            .into_owned();

        if path == BIN_RUBY {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| format!("read {BIN_RUBY}: {e}"))?;
            write_atomic(wasm_out, &bytes)?;
            found_bin = true;
        } else if path.starts_with(LIB_PREFIX) {
            // Keep the `usr/local/lib/ruby/...` sub-tree (strip only the
            // top-level tarball dir) so the cache's `usr` mounts at `/usr` with
            // every intermediate path resolvable.
            let rel = path.strip_prefix(TARBALL_ROOT).unwrap_or(&path);
            let dest = dir.join(rel);
            // Directory entries (trailing `/`) carry no bytes; mkdir and move on.
            if path.ends_with('/') {
                std::fs::create_dir_all(&dest)
                    .map_err(|e| format!("mkdir {}: {e}", dest.display()))?;
                continue;
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
            }
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| format!("read stdlib {rel}: {e}"))?;
            write_atomic(&dest, &bytes)?;
            stdlib_count += 1;
        }
        // Everything else (libruby-static.a, headers, bin/* scripts) is skipped.
    }

    if !found_bin {
        return Err(format!("{BIN_RUBY} not found in {TARBALL}"));
    }
    if stdlib_count == 0 {
        return Err(format!(
            "no stdlib files found under {LIB_PREFIX} in {TARBALL}"
        ));
    }
    Ok(())
}

/// Write `bytes` to `path` via a sibling temp file + rename, so a half-written
/// file from an interrupted build never reads back as a complete cache entry.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("building");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

/// A manifest is complete when the wasm and the versioned stdlib dir it lists
/// both exist (so a half-populated cache re-extracts).
fn manifest_complete(dir: &Path, manifest: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(manifest) else {
        return false;
    };
    let mut wasm_ok = false;
    let mut stdlib_ok = false;
    for line in text.lines() {
        let Some((key, rel)) = line.split_once('=') else {
            continue;
        };
        match key {
            "wasm" => wasm_ok = dir.join(rel).exists(),
            // The mounted `usr` tree must contain the versioned ABI dir, not
            // just an empty parent (so a half-extracted cache re-extracts).
            "usr" => {
                let _ = rel;
                stdlib_ok = dir.join(STDLIB_ABI_REL).join(RUBY_ABI).exists();
            }
            _ => {}
        }
    }
    wasm_ok && stdlib_ok
}

/// The cache dir: `<target>/ruby-bundle/<release>`. Under the target dir so
/// `cargo clean` clears it and it never lands in git, but stable across normal
/// rebuilds (unlike `OUT_DIR`). Honors `CARGO_TARGET_DIR`; otherwise the
/// workspace `target`. Mirrors the Pyodide bundle dir scheme.
fn bundle_dir() -> PathBuf {
    let target = if let Some(t) = std::env::var_os("CARGO_TARGET_DIR") {
        PathBuf::from(t)
    } else {
        // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out. Walk up to <target>.
        let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set in build script"));
        out.ancestors()
            .nth(4)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| out.clone())
    };
    target.join("ruby-bundle").join(RUBY_WASM_RELEASE)
}
