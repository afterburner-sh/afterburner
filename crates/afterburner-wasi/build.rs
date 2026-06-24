// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Build-time work for afterburner-wasi: three independent jobs.
//!
//! Job one, the plugin drift gate: make sure the committed plugin binary
//! matches the current polyfill bundle, so editing a polyfill without
//! rebuilding the plugin can never silently ship a stale binary.
//!
//! Job two, the self-contained Pyodide payload: fetch the stock Pyodide 0.28.3
//! main wasm, the stdlib, and the pandas-closure wheels from the jsDelivr CDN,
//! exnref-translate the wasm and each wheel `.so` with `wasm-opt`, and cache the
//! result in a stable dir under the workspace target so `burn run x.py` (numpy +
//! pandas) works with no env vars and no runtime download. The dir is exported
//! as `AFTERBURNER_PYODIDE_BUNDLE_DIR`; the runtime loads from there by default.
//! See `pyodide_payload.rs` (build side) and `src/pyodide_bundle.rs` (runtime).
//!
//! Honesty: `wasm-opt` is a BUILD-time dependency for the exnref translation
//! (not a runtime dependency). When it is absent, or the CDN is unreachable,
//! the payload step SKIPS cleanly (a `cargo:warning`, never a panic) and the
//! runtime falls back to `BURN_PYTHON_RUNTIME` with an honest error - exactly
//! as the plugin gate skips on a fresh checkout.
//!
//! Job three, the self-contained ruby.wasm payload: fetch the stock
//! `ruby-3.4-wasm32-unknown-wasip1-full` tarball from the `ruby/ruby.wasm`
//! GitHub release (sha256-pinned), extract the standalone interpreter (a plain
//! WASI command module) and its stdlib, and cache the result under the target
//! so `burn run x.rb` works with no env vars and no runtime download. No
//! `wasm-opt` and no translation: the binary imports only
//! `wasi_snapshot_preview1`. Skips cleanly (a `cargo:warning`) when the network
//! is unreachable; the runtime then falls back to `BURN_RUBY_RUNTIME`. See
//! `ruby_payload.rs` (build side) and `src/ruby_bundle.rs` (runtime).
//!
//! Job four, the self-contained C/C++ toolchain payload: fetch the stock
//! `WebAssembly/wasi-sdk` release for the host platform (sha256-pinned per
//! platform), unpack the toolchain tree (the `clang`/`clang++` drivers, their
//! resource dir, and the WASI sysroot) under the target so `burn run x.c` /
//! `burn run x.cpp` compile with no env vars and no runtime download. Skips
//! cleanly (a `cargo:warning`) on an unsupported host or when the network is
//! unreachable; the C/C++ compile then falls back to `WASI_SDK_PATH`. See
//! `wasi_sdk_payload.rs` (build side) and `src/wasi_sdk_bundle.rs` (runtime).

use std::path::{Path, PathBuf};
use std::process::Command;

mod pyodide_payload;
mod ruby_payload;
mod wasi_sdk_payload;

fn main() {
    plugin_drift_gate();
    pyodide_payload::build();
    ruby_payload::build();
    wasi_sdk_payload::build();
}

// ---- 1. plugin drift gate --------------------------------------------------

fn plugin_drift_gate() {
    // CARGO_MANIFEST_DIR = <repo>/crates/afterburner-wasi.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Walk up two parents to reach the repo root for the sibling-crate
    // bundle path. The plugin sidecar lives INSIDE this crate so it
    // ships unmodified through `cargo publish`.
    let root = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();
    let bundle_path = root.join("crates/afterburner-node-compat/generated/plenum_bundle.js");
    let sidecar_path = manifest.join("plugin/afterburner_plugin.wasm.bundle-sha256");

    println!("cargo:rerun-if-changed={}", bundle_path.display());
    println!("cargo:rerun-if-changed={}", sidecar_path.display());

    let bundle = match std::fs::read(&bundle_path) {
        Ok(b) => b,
        Err(_) => return, // bundle not yet generated - fresh workspace checkout
    };
    let current_hash = sha256_hex(&bundle);

    let committed_hash = match std::fs::read_to_string(&sidecar_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            // No recorded hash yet - first-time plugin build; record it
            // rather than fail. Normal CI/dev flow writes this via the
            // plugin's build.sh.
            let _ = std::fs::write(&sidecar_path, format!("{current_hash}\n"));
            return;
        }
    };

    if current_hash != committed_hash {
        panic!(
            "\n\n\
             afterburner-plugin <-> plenum bundle drift detected.\n\
             \n\
                 Committed plugin hash: {committed_hash}\n\
                 Current bundle hash:   {current_hash}\n\
             \n\
             Somebody edited a polyfill without rebuilding the plugin.\n\
             To fix:\n\
             \n\
                 AFTERBURNER_REBUILD_PLENUM=1 cargo build -p afterburner-node-compat\n\
                 bash crates/afterburner-plugin/build.sh\n\
             \n\
             (plugin builds require `rustup target add wasm32-wasip1` and a `javy` CLI\n\
             at build time only; neither is needed at runtime.)\n\n"
        );
    }
}

// ---- shared helpers (used by the payload module too) -----------------------

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Locate `wasm-opt`: PATH first, then the emsdk fallback Pyodide builds ship.
/// Returns `None` when neither is present (the payload step then skips).
pub(crate) fn find_wasm_opt() -> Option<PathBuf> {
    if let Ok(out) = Command::new("wasm-opt").arg("--version").output()
        && out.status.success()
    {
        return Some(PathBuf::from("wasm-opt"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = Path::new(&home).join("emsdk/upstream/bin/wasm-opt");
        if p.exists() {
            return Some(p);
        }
    }
    None
}
