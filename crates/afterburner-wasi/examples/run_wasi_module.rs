// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Run an arbitrary WASI command module through [`EmbedderVm`].
//!
//! # Usage
//!
//!   cargo run -p afterburner-wasi --example run_wasi_module -- \
//!       <path-to.wasm> [--preopen HOST_PATH:GUEST_PATH]... [-- <argv>...]
//!
//! # CPython example
//!
//!   cargo run -p afterburner-wasi --example run_wasi_module -- \
//!       /tmp/python.wasm -- python -c "print(sum(range(100)))"
//!
//! The module bytes are read from disk at runtime; nothing is baked into
//! the binary. stdout captured from the guest is printed to the host stdout.

use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};
use std::{env, fs, process};

fn usage() -> ! {
    eprintln!(
        "usage: run_wasi_module <module.wasm> [--preopen HOST:GUEST]... [-- argv0 argv1 ...]"
    );
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let wasm_path = &args[1];
    let mut preopens: Vec<(String, String)> = Vec::new();
    let mut argv: Vec<String> = Vec::new();

    let mut i = 2usize;
    while i < args.len() {
        match args[i].as_str() {
            "--preopen" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--preopen requires HOST_PATH:GUEST_PATH");
                    process::exit(1);
                }
                let spec = &args[i];
                // Split on the first ':' only so Windows drive letters survive.
                let colon = spec.find(':').unwrap_or_else(|| {
                    eprintln!("--preopen value must be HOST_PATH:GUEST_PATH, got {spec:?}");
                    process::exit(1);
                });
                let host = spec[..colon].to_owned();
                let guest = spec[colon + 1..].to_owned();
                preopens.push((host, guest));
            }
            "--" => {
                argv = args[i + 1..].to_vec();
                break;
            }
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
        i += 1;
    }

    let wasm_bytes = fs::read(wasm_path).unwrap_or_else(|e| {
        eprintln!("failed to read {wasm_path}: {e}");
        process::exit(1);
    });
    eprintln!(
        "[run_wasi_module] loaded {} ({} bytes)",
        wasm_path,
        wasm_bytes.len()
    );

    let vm = EmbedderVm::new().unwrap_or_else(|e| {
        eprintln!("EmbedderVm::new: {e}");
        process::exit(1);
    });

    // Compile with WASI enabled; no custom host imports needed for standard
    // WASI command modules (all imports come from the WASI linker).
    let module = vm
        .compile(&wasm_bytes, true, |_| Ok(()))
        .unwrap_or_else(|e| {
            eprintln!("compile failed: {e}");
            process::exit(1);
        });
    eprintln!("[run_wasi_module] compiled OK");

    let mut opts = WasiCommandOpts::new();
    if !argv.is_empty() {
        opts = opts.args(argv);
    }
    for (host, guest) in preopens {
        opts = opts.preopen(host, guest);
    }

    // Use a generous fuel cap; CPython startup is instruction-heavy.
    // vertexia: global fuel cap; per-tenant budget if throughput matters.
    let fuel: u64 = 50_000_000_000;

    match vm.run_command(&module, opts, Some(fuel)) {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            print!("{text}");
            eprintln!("[run_wasi_module] exit code: {}", out.result);
            process::exit(out.result as i32);
        }
        Err(e) => {
            eprintln!("[run_wasi_module] error: {e}");
            process::exit(1);
        }
    }
}
