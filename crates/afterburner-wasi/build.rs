// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Build-time work for afterburner-wasi: two jobs.
//!
//! Job one, the plugin drift gate: make sure the committed plugin binary
//! matches the current polyfill bundle, so editing a polyfill without
//! rebuilding the plugin can never silently ship a stale binary.
//!
//! Job two, the OPTIONAL runtime-bundle prefetch. By DEFAULT this build does no
//! network work: the language runtimes (the Python runtime, the C/C++
//! toolchain, the Ruby runtime) are fetched LAZILY into `~/.burn` on first use
//! by the runtime resolvers (see `src/bundle.rs` + `bundle_fetch.rs`). When
//! `BURN_PREFETCH=1` is set, this build calls the SAME `bundle_fetch` engine to
//! populate `~/.burn` ahead of time, so a packaged binary ships with the
//! bundles already in place. There is exactly one fetch+verify+translate+cache
//! engine (`bundle_fetch.rs`, `#[path]`-included into both this build script and
//! `src/lib.rs`), so a build-time prefetch and a lazy runtime fetch produce a
//! byte-identical bundle - no drift. The prefetch skips cleanly (a
//! `cargo:warning`, never a panic) when the network or `wasm-opt` is
//! unavailable; the runtime then fetches on first use exactly as the default
//! path does.

use std::path::PathBuf;

/// The shared bundle engine, `#[path]`-included so the optional `BURN_PREFETCH`
/// prefetch uses the identical fetch+verify+translate+cache logic the runtime
/// does. Only the `ensure_*` + `burn_home` entry points are used here.
#[path = "bundle_fetch.rs"]
mod bundle_fetch;

fn main() {
    plugin_drift_gate();
    prefetch_bundles_if_requested();
    assemble_embed_core_if_enabled();
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
    let current_hash = bundle_fetch::sha256_hex_pub(&bundle);

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

// ---- 2. optional ~/.burn prefetch (BURN_PREFETCH=1) ------------------------

/// Populate `~/.burn` at build time when `BURN_PREFETCH=1`, via the SAME engine
/// the runtime uses. Off by default: the runtime fetches lazily on first use.
/// Every failure is a `cargo:warning`, never a build failure, since the lazy
/// path is the real guarantee and a build host may have no network.
fn prefetch_bundles_if_requested() {
    println!("cargo:rerun-if-env-changed=BURN_PREFETCH");
    if std::env::var_os("BURN_PREFETCH").is_none_or(|v| v.is_empty() || v == "0") {
        return;
    }

    let Some(home) = bundle_fetch::burn_home() else {
        println!(
            "cargo:warning=BURN_PREFETCH=1 set but neither BURN_HOME nor HOME is set; \
             skipping prefetch (the runtime will fetch lazily on first use)."
        );
        return;
    };

    // A build-time prefetch renders nothing (no TTY on a build host); the lazy
    // runtime fetch is where the gradient bar shows.
    let prog = bundle_fetch::NoProgress;
    for (label, result) in [
        ("Python runtime", bundle_fetch::ensure_pyodide(&home, &prog)),
        (
            "C/C++ toolchain",
            bundle_fetch::ensure_wasi_sdk(&home, &prog),
        ),
        ("Ruby runtime", bundle_fetch::ensure_ruby(&home, &prog)),
    ] {
        if let Err(e) = result {
            println!(
                "cargo:warning=BURN_PREFETCH: {label} not prefetched ({e}); \
                 the runtime will fetch it lazily on first use."
            );
        }
    }
}

// ---- 3. embed-core: bake the Python core into the binary -------------------

/// Under the `embed-core` feature, assemble JUST the Python core (the exnref
/// main wasm + the stdlib zip, no wheels) into `OUT_DIR/embed-core` and export
/// its path as `AFTERBURNER_EMBED_CORE_DIR`, so `src/pyodide_embed.rs` can
/// `include_bytes!` it. This needs `wasm-opt` + network AT BUILD TIME; if either
/// is missing the build FAILS (unlike the optional prefetch), because a binary
/// built `--features embed-core` that silently shipped without the core would be
/// a dishonest "offline Python" promise. The wheels and the C/C++ toolchain are
/// NOT embedded - they still fetch lazily into `~/.burn`.
fn assemble_embed_core_if_enabled() {
    // Cargo sets CARGO_FEATURE_<NAME> for each enabled feature of THIS crate.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EMBED_CORE");
    if std::env::var_os("CARGO_FEATURE_EMBED_CORE").is_none() {
        return;
    }

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set in build script"));
    let core_dir = out_dir.join("embed-core");

    // A populated core is a cache hit: skip the fetch + translate.
    let manifest = core_dir.join("manifest.txt");
    let core_present = manifest.exists()
        && core_dir.join("pyodide-exnref.wasm").exists()
        && core_dir.join("python_stdlib.zip").exists();

    if !core_present
        && let Err(e) = bundle_fetch::assemble_pyodide_core(&core_dir, &bundle_fetch::NoProgress)
    {
        panic!(
            "embed-core: could not assemble the Python core ({e}).\n\
             Building with `--features embed-core` requires `wasm-opt` (Binaryen) on PATH and \
             network access at build time to fetch + translate the core. Install Binaryen and \
             build online, or drop the `embed-core` feature to use the default lazy ~/.burn fetch."
        );
    }

    println!(
        "cargo:rustc-env=AFTERBURNER_EMBED_CORE_DIR={}",
        core_dir.display()
    );
}
