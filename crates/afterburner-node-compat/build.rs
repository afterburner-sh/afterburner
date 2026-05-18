// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Plenum bundle builder.
//!
//! Default behavior (CI, normal `cargo build`): use the pre-built
//! `generated/plenum_bundle.js` that ships with the crate. This keeps
//! builds reproducible and node/npm-free.
//!
//! Regeneration: set `AFTERBURNER_REBUILD_PLENUM=1`. The build script
//! concatenates every file under `polyfills/` (and, once we pull them in
//! from npm, runs `esbuild` on the tree) and writes the result to
//! `generated/plenum_bundle.js`. The developer commits the file.
//!
//! The in-tree generator is intentionally minimal for Phase 1 — Phase 2
//! swaps in a proper bundler once we import npm polyfills.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let polyfills_dir = manifest.join("polyfills");
    let out_path = manifest.join("generated/plenum_bundle.js");

    println!("cargo:rerun-if-env-changed=AFTERBURNER_REBUILD_PLENUM");
    println!("cargo:rerun-if-changed={}", polyfills_dir.display());

    let rebuild = env::var("AFTERBURNER_REBUILD_PLENUM").ok().as_deref() == Some("1");
    let missing = !out_path.exists();

    if !(rebuild || missing) {
        return;
    }

    let mut bundle = String::new();
    bundle.push_str("// GENERATED — do not edit. Source: afterburner-node-compat/polyfills/\n");
    bundle.push_str(
        "// Rebuild with: AFTERBURNER_REBUILD_PLENUM=1 cargo build -p afterburner-node-compat\n\n",
    );

    // Always lead with the require resolver so later polyfills can
    // assume `__register_module` is installed.
    append_file(&mut bundle, &polyfills_dir.join("require.js"));

    // Walk the rest of the polyfill files in sorted order so the output
    // is deterministic across machines.
    let mut others: Vec<PathBuf> = fs::read_dir(&polyfills_dir)
        .expect("polyfills dir should exist")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|s| s.to_str()) == Some("js")
                && p.file_name() != Some(std::ffi::OsStr::new("require.js"))
                && p.file_name() != Some(std::ffi::OsStr::new("entry.js"))
        })
        .collect();
    others.sort();

    for p in others {
        append_file(&mut bundle, &p);
    }

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create generated dir");
    }
    fs::write(&out_path, bundle).expect("write plenum bundle");
}

fn append_file(buf: &mut String, path: &Path) {
    let contents =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    buf.push_str(&format!(
        "// ---- {} ----\n",
        path.file_name().unwrap().to_string_lossy()
    ));
    buf.push_str(&contents);
    if !contents.ends_with('\n') {
        buf.push('\n');
    }
    buf.push('\n');
}
