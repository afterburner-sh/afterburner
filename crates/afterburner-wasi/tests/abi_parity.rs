// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! ABI drift gate. Host imports are declared in three places:
//!
//! 1. `crates/afterburner-plugin/src/host_api.rs` — `extern "C" { fn host_foo(...) }`.
//! 2. `crates/afterburner-wasi/src/host_imports.rs` — `linker.func_wrap(NS, "host_foo", ...)`.
//! 3. `docs/wit/afterburner-host.wit` — the shape contract (docs).
//!
//! The `extern` declaration and the `func_wrap` registration MUST name
//! the same imports — a missing entry on either side manifests as a
//! link error at Wasmtime instantiation time with a message like
//! "unknown import". This test catches the drift at `cargo test` time
//! instead.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/afterburner-wasi → walk up to <repo>.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

/// Extract `host_xxx` names from string literals inside `func_wrap`
/// registrations in host_imports.rs.
fn wasi_imports() -> BTreeSet<String> {
    let src =
        fs::read_to_string(workspace_root().join("crates/afterburner-wasi/src/host_imports.rs"))
            .expect("read host_imports.rs");
    let mut out = BTreeSet::new();
    for line in src.lines() {
        let line = line.trim();
        // func_wrap takes the name as a string literal; also the zlib /
        // cipher loops register via tuple entries like `("host_foo", ...)`.
        if let Some(name) = extract_host_literal(line) {
            out.insert(name);
        }
    }
    out
}

/// Extract `host_xxx` names from `extern "C"` declarations in the
/// plugin. The plugin block looks like:
///
/// ```ignore
/// extern "C" {
///     pub fn host_foo(...);
/// }
/// ```
///
/// Lives in `afterburner-plugin/src/host_api.rs` since the lib.rs
/// split (B0 / §4.7).
fn plugin_imports() -> BTreeSet<String> {
    let src =
        fs::read_to_string(workspace_root().join("crates/afterburner-plugin/src/host_api.rs"))
            .expect("read plugin/src/host_api.rs");
    let mut out = BTreeSet::new();
    let mut in_extern = false;
    for line in src.lines() {
        let trimmed = line.trim();
        // The plugin uses `unsafe extern "C" {` with a
        // `#[link(wasm_import_module = ...)]` attribute above. Treat
        // either form as the start of the extern block.
        if trimmed.contains("extern \"C\"") && trimmed.ends_with('{') {
            in_extern = true;
            continue;
        }
        if !in_extern {
            continue;
        }
        if trimmed == "}" {
            in_extern = false;
            continue;
        }
        // After the split, declarations are `pub fn host_foo(...)`.
        // The pre-split form was `fn host_foo(...)`. Accept both so
        // the test stays robust if visibility is ever tightened.
        let stripped = trimmed
            .strip_prefix("pub fn host_")
            .or_else(|| trimmed.strip_prefix("fn host_"));
        if let Some(rest) = stripped
            && let Some(open) = rest.find('(')
        {
            let name = format!("host_{}", &rest[..open]);
            out.insert(name);
        }
    }
    out
}

fn extract_host_literal(line: &str) -> Option<String> {
    // Look for `"host_xxx_yyy"` as a substring — simple but effective
    // because the plugin doesn't emit random `host_` string literals
    // outside of the import-naming spots.
    let start = line.find("\"host_")? + 1;
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Manifest of every host import burn ships, kept at
/// `docs/wit/host-imports.txt`. Single source of truth: when a new
/// host import is added or removed, this file is the authoritative
/// place to mirror the change. abi_parity then enforces that plugin
/// + wasi sides agree with the manifest.
fn manifest_imports() -> BTreeSet<String> {
    let src = fs::read_to_string(workspace_root().join("docs/wit/host-imports.txt"))
        .expect("read docs/wit/host-imports.txt");
    src.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

#[test]
fn plugin_and_wasi_host_imports_match() {
    let wasi = wasi_imports();
    let plugin = plugin_imports();

    let only_plugin: BTreeSet<_> = plugin.difference(&wasi).collect();
    let only_wasi: BTreeSet<_> = wasi.difference(&plugin).collect();

    assert!(
        only_plugin.is_empty() && only_wasi.is_empty(),
        "ABI drift between afterburner-plugin and afterburner-wasi:\n\
         - only in plugin (extern but no linker wiring): {only_plugin:?}\n\
         - only in wasi   (linker wiring but no extern): {only_wasi:?}\n\
         Every host import must be declared in BOTH crates/afterburner-plugin/src/host_api.rs \
         and crates/afterburner-wasi/src/host_imports.rs. Update docs/wit/host-imports.txt + \
         docs/wit/afterburner-host.wit too."
    );
}

#[test]
fn manifest_matches_plugin_and_wasi() {
    // The manifest at docs/wit/host-imports.txt is the SSOT. Both the
    // plugin's extern decls and the wasi linker registrations must
    // list exactly the names the manifest does — no more, no less.
    // This catches:
    //   1. Adding an import without recording it in the manifest.
    //   2. Removing an import without pulling the manifest entry.
    //   3. Renaming an import without updating the manifest (would
    //      surface as a removal + addition pair).
    //
    // The pure plugin/wasi parity test above is still useful because
    // it gives a sharper diagnosis when ONLY one side is missing —
    // here we'd see both sides differ from the manifest equally.
    let manifest = manifest_imports();
    let plugin = plugin_imports();
    let wasi = wasi_imports();

    let plugin_extra: BTreeSet<_> = plugin.difference(&manifest).collect();
    let plugin_missing: BTreeSet<_> = manifest.difference(&plugin).collect();
    let wasi_extra: BTreeSet<_> = wasi.difference(&manifest).collect();
    let wasi_missing: BTreeSet<_> = manifest.difference(&wasi).collect();

    assert!(
        plugin_extra.is_empty()
            && plugin_missing.is_empty()
            && wasi_extra.is_empty()
            && wasi_missing.is_empty(),
        "Manifest drift between docs/wit/host-imports.txt and the live ABI:\n\
         - in plugin extern decls but NOT manifest: {plugin_extra:?}\n\
         - in manifest but NOT plugin extern decls: {plugin_missing:?}\n\
         - in wasi linker but NOT manifest:        {wasi_extra:?}\n\
         - in manifest but NOT wasi linker:        {wasi_missing:?}\n\
         Adding a host import is now a four-place change:\n\
           1. docs/wit/host-imports.txt\n\
           2. crates/afterburner-plugin/src/host_api.rs (extern decl)\n\
           3. crates/afterburner-wasi/src/host_imports.rs (linker)\n\
           4. crates/afterburner-plugin/src/globals/* (JS bridge)\n\
         (And docs/wit/afterburner-host.wit for the typed contract.)"
    );
}
