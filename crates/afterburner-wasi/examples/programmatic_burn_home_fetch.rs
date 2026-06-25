// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Programmatic (library-embed) proof that the `~/.burn` lazy fetch fires off
//! the CLI: this binary calls `resolve_runtime()` + `run_pyodide_with()`
//! directly - no `burn` CLI, no env vars - and on a cold `~/.burn` it downloads
//! the Python runtime (into `~/.burn/pyodide-<ver>`) before running.
//!
//! Run it against a cold cache to see the fetch:
//!
//! ```text
//! rm -rf ~/.burn
//! cargo run -p afterburner-wasi --example programmatic_burn_home_fetch
//! ```
//!
//! It prints the resolved wasm path (under `~/.burn` when the bundle was
//! fetched) and the program's stdout (`42`). The fetch renders no progress bar
//! here: a library embed installs no progress reporter, so the engine's silent
//! default is used (the colorful bar is the `burn` CLI's, injected at its
//! boundary). The default sink is the right behavior for an embedded consumer.

use afterburner_wasi::pyodide_runner::{resolve_runtime, run_pyodide_with};

fn main() {
    // Resolve the runtime the same way a library consumer would: no CLI, no env
    // overrides set here. On a cold `~/.burn` this triggers the download +
    // exnref-translate into `~/.burn/pyodide-<ver>` via the shared resolve path.
    let rt = match resolve_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("resolve_runtime failed: {e}");
            std::process::exit(2);
        }
    };

    // Show where the runtime resolved from. After a cold fetch this is under
    // the user's `~/.burn`, proving the programmatic path populated it.
    println!("resolved wasm: {}", rt.wasm_path.display());
    let in_burn_home = std::env::var_os("HOME")
        .map(|h| {
            rt.wasm_path
                .starts_with(std::path::Path::new(&h).join(".burn"))
        })
        .unwrap_or(false);
    println!("under ~/.burn: {in_burn_home}");

    let out = match run_pyodide_with(&rt, "print(6 * 7)") {
        Ok(out) => out,
        Err(e) => {
            eprintln!("run_pyodide_with failed: {e}");
            std::process::exit(3);
        }
    };

    let text = String::from_utf8_lossy(&out.stdout);
    print!("program stdout: {text}");
    if !text.contains("42") {
        eprintln!("unexpected program output (wanted 42): {text:?}");
        std::process::exit(4);
    }
}
