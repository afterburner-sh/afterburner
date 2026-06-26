// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! Python -> self-contained emscripten-pyodide bundle compile+run integration.
//!
//! Heavy: the compile path fetches the Pyodide Python runtime (network on
//! first use, then cached in `~/.burn`). `#[ignore]`d so CI stays fast and
//! offline; run locally with:
//!
//!   cargo test -p afterburner --features bin -- --ignored python
//!
//! The environment is scrubbed (`BURN_PYTHON_RUNTIME` removed) so this
//! exercises the zero-configuration path a real user hits: nothing set,
//! everything auto-fetched from the bundle cache.

use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

#[test]
#[ignore = "fetches Pyodide Python runtime; run locally with --ignored"]
fn python_compiles_to_standalone_wasm_blob() {
    let dir = std::env::temp_dir().join(format!("burn-python-compile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("source")).expect("mkdir source");
    std::fs::write(dir.join("source/main.py"), "print('python-wasm-blob-ok')\n")
        .expect("write main.py");
    std::fs::write(
        dir.join("afb.toml"),
        "[format]\nversion = \"1.0\"\n\n[package]\nname = \"pyc\"\nnamespace = \"test\"\n\
         version = \"0.1.0\"\nlanguage = \"python\"\nentry = \"source/main.py\"\n\n\
         [runtime]\nmin = \"0.1.0\"\n",
    )
    .expect("write afb.toml");
    std::fs::write(
        dir.join("manifold.json"),
        r#"{"fs":"None","net":"None","env":"None","crypto":false,"child_process":false}"#,
    )
    .expect("write manifold.json");

    let afb = dir.join("out.afb");

    // Scrubbed env: exercises the zero-config auto-fetch path.
    let compile = Command::new(BURN)
        .env_remove("BURN_PYTHON_RUNTIME")
        .env_remove("BURN_PYTHON_STDLIB_ZIP")
        .env_remove("BURN_WHEELS")
        .env_remove("BURN_PYTHON_STDLIB_VER")
        .env_remove("WASI_VFS")
        .env_remove("BURN_RUBY_RUNTIME")
        .args([
            "compile",
            dir.to_str().unwrap(),
            "-o",
            afb.to_str().unwrap(),
        ])
        .output()
        .expect("spawn burn compile");

    assert!(
        compile.status.success(),
        "compile failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(afb.exists(), "no .afb produced at {}", afb.display());

    // burn run on the compiled artifact - no runtime env vars, no network.
    let run = Command::new(BURN)
        .env_remove("BURN_PYTHON_RUNTIME")
        .env_remove("BURN_PYTHON_STDLIB_ZIP")
        .env_remove("BURN_WHEELS")
        .env_remove("BURN_PYTHON_STDLIB_VER")
        .env_remove("WASI_VFS")
        .env_remove("BURN_RUBY_RUNTIME")
        .args(["run", afb.to_str().unwrap()])
        .output()
        .expect("spawn burn run");

    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        stdout.contains("python-wasm-blob-ok"),
        "blob did not run standalone:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
