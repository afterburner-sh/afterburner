// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! Ruby -> self-contained wasm compile+run integration.
//!
//! Heavy: the compile path fetches `wasi-vfs` and the stock `ruby.wasm` (network on
//! first use, then cached in `~/.burn`). `#[ignore]`d so CI stays fast and offline;
//! run locally with `cargo test -p afterburner --features bin -- --ignored ruby`.
//!
//! The environment is scrubbed (`WASI_VFS` / `BURN_RUBY_*` removed) so this exercises
//! the zero-configuration path a real user hits: nothing set, everything auto-fetched.

use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

#[test]
#[ignore = "fetches wasi-vfs + ruby.wasm; run locally with --ignored"]
fn ruby_compiles_to_standalone_wasm_blob() {
    let dir = std::env::temp_dir().join(format!("burn-ruby-compile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("source")).expect("mkdir source");
    std::fs::write(dir.join("source/main.rb"), "puts 'ruby-wasm-blob-ok'\n")
        .expect("write main.rb");
    std::fs::write(
        dir.join("afb.toml"),
        "[format]\nversion = \"1.0\"\n\n[package]\nname = \"rbc\"\nnamespace = \"test\"\n\
         version = \"0.1.0\"\nlanguage = \"ruby\"\nentry = \"source/main.rb\"\n\n\
         [runtime]\nmin = \"0.1.0\"\n",
    )
    .expect("write afb.toml");
    std::fs::write(
        dir.join("manifold.json"),
        r#"{"fs":"None","net":"None","env":"None","crypto":false,"child_process":false}"#,
    )
    .expect("write manifold.json");

    let afb = dir.join("out.afb");
    // Scrubbed env: the zero-config auto-fetch path, not the WASI_VFS override.
    let compile = Command::new(BURN)
        .env_remove("WASI_VFS")
        .env_remove("BURN_RUBY_RUNTIME")
        .env_remove("BURN_RUBY_USR")
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
        "compile failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(afb.exists(), "no .afb produced");

    let run = Command::new(BURN)
        .env_remove("WASI_VFS")
        .env_remove("BURN_RUBY_RUNTIME")
        .env_remove("BURN_RUBY_USR")
        .args(["run", afb.to_str().unwrap()])
        .output()
        .expect("spawn burn run");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        stdout.contains("ruby-wasm-blob-ok"),
        "blob did not run standalone:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
