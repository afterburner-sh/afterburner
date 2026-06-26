// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! Python -> self-contained emscripten-pyodide bundle compile+run, driving the real CLI.
//!
//! Heavy: the compile path fetches the Pyodide Python runtime (network on first use,
//! then cached in `~/.burn`). `#[ignore]`d so CI stays fast and offline; run locally
//! with `cargo test -p afterburner --features bin -- --ignored python`.
//!
//! Dogfoods the CLI end to end: `burn new` scaffolds the package, then `burn compile`
//! and `burn run`. The environment is scrubbed (no `BURN_PYTHON_*`) so it exercises the
//! zero-configuration path a real user hits.

use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// A `burn` command with every runtime/override env var removed, so the test proves
/// the zero-configuration path (auto-fetch, nothing set).
fn burn() -> Command {
    let mut c = Command::new(BURN);
    for v in [
        "WASI_VFS",
        "BURN_RUBY_RUNTIME",
        "BURN_RUBY_USR",
        "BURN_PYTHON_RUNTIME",
        "BURN_PYTHON_STDLIB_ZIP",
        "BURN_PYTHON_STDLIB_VER",
        "BURN_WHEELS",
    ] {
        c.env_remove(v);
    }
    c
}

#[test]
#[ignore = "fetches Pyodide runtime; run locally with --ignored"]
fn python_compiles_to_standalone_wasm_blob() {
    let work = std::env::temp_dir().join(format!("burn-python-compile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("mkdir work");

    // Dogfood: scaffold through the real `burn new`, not a hand-written fixture.
    let new = burn()
        .current_dir(&work)
        .args(["new", "test/pyc", "--lang", "python"])
        .output()
        .expect("spawn burn new");
    assert!(
        new.status.success(),
        "burn new failed:\n{}",
        String::from_utf8_lossy(&new.stderr)
    );

    let pkg = work.join("pyc");
    std::fs::write(pkg.join("source/main.py"), "print('python-wasm-blob-ok')\n")
        .expect("write main.py");

    let afb = work.join("out.afb");
    let compile = burn()
        .args([
            "compile",
            pkg.to_str().unwrap(),
            "-o",
            afb.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn compile");
    assert!(
        compile.status.success(),
        "compile failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(afb.exists(), "no .afb produced");

    let run = burn()
        .args(["run", afb.to_str().unwrap()])
        .output()
        .expect("spawn burn run");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    let _ = std::fs::remove_dir_all(&work);
    assert!(
        stdout.contains("python-wasm-blob-ok"),
        "blob did not run standalone:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
