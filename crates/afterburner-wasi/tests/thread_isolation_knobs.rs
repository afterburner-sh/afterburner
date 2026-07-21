// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Proof that `WasmConfig::parallel_compilation` and
//! `WasmConfig::spawn_epoch_ticker` each independently control whether
//! `WasmCombustor` touches a thread beyond the caller's own.
//!
//! Linux-only: thread enumeration reads `/proc/self/task`, the only
//! zero-dependency way to get ground-truth OS thread counts/names. This
//! is an integration test file so it is its own process (Cargo compiles
//! every `tests/*.rs` file to a separate binary) - required for a sound
//! "no thread was spawned" claim, because `rayon`'s global worker pool
//! is process-global and lazily initialized exactly once: if any other
//! test in the same process had already triggered a parallel compile
//! first, an in-process assertion here would be order-dependent and
//! flaky. Each phase below instead asserts a *delta* against a baseline
//! captured at the top of this test, so the claim holds regardless of
//! what (if anything) ran before it in this process - which, being a
//! dedicated single-test integration binary, is nothing.
#![cfg(target_os = "linux")]

use afterburner_wasi::{WasmCombustor, WasmConfig};

/// Zero-import WAT module, several exported functions so a real compile
/// has more than a single trivial unit of work to (not) parallelize.
/// `register_precompiled` only compiles + type-checks it here; it is
/// never instantiated, so it needs no WASI plumbing.
const FRESH_WAT: &str = r#"(module
  (func (export "f0") (result i32) i32.const 0)
  (func (export "f1") (result i32) i32.const 1)
  (func (export "f2") (result i32) i32.const 2)
  (func (export "f3") (result i32) i32.const 3)
  (func (export "f4") (result i32) i32.const 4)
  (func (export "f5") (result i32) i32.const 5)
  (func (export "f6") (result i32) i32.const 6)
  (func (export "f7") (result i32) i32.const 7)
)"#;

fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .count()
}

fn thread_names() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("comm")).ok())
        .map(|name| name.trim().to_string())
        .collect()
}

#[test]
fn parallel_compilation_and_epoch_ticker_are_independently_attributable() {
    let baseline = thread_count();

    // ---- Phase 1: both knobs off -----------------------------------
    // A real fresh compile (register_precompiled never disk-caches, so
    // this always exercises Cranelift) must add zero threads: no rayon
    // worker pool, no epoch ticker.
    {
        let combustor = WasmCombustor::new(WasmConfig {
            parallel_compilation: Some(false),
            spawn_epoch_ticker: Some(false),
            ..Default::default()
        })
        .unwrap();
        combustor
            .register_precompiled(FRESH_WAT.as_bytes(), "wasm32-wasip1")
            .unwrap();
        assert_eq!(
            thread_count(),
            baseline,
            "parallel_compilation(false) + spawn_epoch_ticker(false) must add zero threads; \
             names={:?}",
            thread_names()
        );
    }
    assert_eq!(
        thread_count(),
        baseline,
        "thread count must return to baseline once the combustor is dropped"
    );

    // ---- Phase 2: epoch ticker on alone (parallel_compilation off) --
    // Isolates the ticker's contribution: exactly one thread appears,
    // and it is the one named by `WasmCombustor::new`'s ticker spawn.
    {
        let combustor = WasmCombustor::new(WasmConfig {
            parallel_compilation: Some(false),
            spawn_epoch_ticker: Some(true),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            thread_count(),
            baseline + 1,
            "spawn_epoch_ticker(true) alone must add exactly one thread; names={:?}",
            thread_names()
        );
        assert!(
            thread_names()
                .iter()
                .any(|name| name.starts_with("afterburner-epo")),
            "the added thread must be the named epoch ticker; names={:?}",
            thread_names()
        );
        drop(combustor);
        // `Drop for WasmCombustor` joins the ticker synchronously.
        assert_eq!(
            thread_count(),
            baseline,
            "dropping the combustor must join the ticker thread back out"
        );
    }

    // ---- Phase 3: parallel_compilation on alone (ticker off) --------
    // Isolates rayon's contribution. Skipped on a single-core host,
    // where rayon's global pool has no extra worker to spawn.
    let available_parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if available_parallelism > 1 {
        let combustor = WasmCombustor::new(WasmConfig {
            parallel_compilation: Some(true),
            spawn_epoch_ticker: Some(false),
            ..Default::default()
        })
        .unwrap();
        combustor
            .register_precompiled(FRESH_WAT.as_bytes(), "wasm32-wasip1")
            .unwrap();
        assert!(
            thread_count() > baseline,
            "parallel_compilation(true) must spawn at least one rayon worker thread on a \
             {available_parallelism}-core host; before={baseline} after={}",
            thread_count()
        );
    }
}
