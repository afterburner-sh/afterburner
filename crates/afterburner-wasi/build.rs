// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Build-time gate: make sure the committed plugin binary matches the
//! current polyfill bundle. Without this check, editing a polyfill and
//! forgetting to rerun `crates/afterburner-plugin/build.sh` silently ships a
//! stale plugin that behaves differently from what the source says.

use std::fs;
use std::path::PathBuf;

fn main() {
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

    let bundle = match fs::read(&bundle_path) {
        Ok(b) => b,
        Err(_) => return, // bundle not yet generated — fresh workspace checkout
    };
    let current_hash = sha256_hex(&bundle);

    let committed_hash = match fs::read_to_string(&sidecar_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            // No recorded hash yet — first-time plugin build; record it
            // rather than fail. Normal CI/dev flow writes this via the
            // plugin's build.sh.
            let _ = fs::write(&sidecar_path, format!("{current_hash}\n"));
            return;
        }
    };

    if current_hash != committed_hash {
        panic!(
            "\n\n\
             afterburner-plugin ↔ plenum bundle drift detected.\n\
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let bytes = h.finalize();
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
