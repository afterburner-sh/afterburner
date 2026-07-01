// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Integration proof for SUBSTRATE B R1 (+ the R4 host threading): the
//! effect-wrapped `clock_time_get` / `random_get` preview1 shims, driven
//! through the public [`EmbedderVm::run_command_with_host`] path with a real
//! recording / replaying [`HostContext`].
//!
//! No language runtime is needed: a hand-written WASI-command module (WAT,
//! which `compile` accepts directly) calls the two wrapped imports and streams
//! the produced random bytes to stdout via the *stock* `fd_write`, so the test
//! can assert both what the host recorded and what reached guest memory.

use std::sync::Mutex;

use afterburner_core::{
    EffectKind, EffectStatus, HostContext, HostEffect, HostEffectRecord, content_hash,
};
use afterburner_wasi::effect_wasi::wire_effect_wrapped_wasi;
use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};
use afterburner_wasi::emscripten_abi::VIRTUAL_EPOCH_NS;

/// A WASI-command module that calls `random_get(buf=0, len=16)`,
/// `clock_time_get(realtime, 0, time_out=64)`, then streams `memory[0..16]`
/// (the random bytes) to stdout via the stock `fd_write`, and exits 0.
const CALLS_CLOCK_AND_RANDOM: &str = r#"
(module
  (import "wasi_snapshot_preview1" "random_get"
    (func $rand (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get"
    (func $clock (param i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    ;; random_get(buf=0, len=16)
    (drop (call $rand (i32.const 0) (i32.const 16)))
    ;; clock_time_get(id=realtime=0, precision=0, time_out=64)
    (drop (call $clock (i32.const 0) (i64.const 0) (i32.const 64)))
    ;; iovec at 80: {buf=0, len=16}
    (i32.store (i32.const 80) (i32.const 0))
    (i32.store (i32.const 84) (i32.const 16))
    ;; fd_write(fd=1 stdout, iovs=80, iovs_len=1, nwritten=88)  [stock impl]
    (drop (call $write (i32.const 1) (i32.const 80) (i32.const 1) (i32.const 88)))
    (call $exit (i32.const 0))))
"#;

/// Records every effect handed to it (original-run / record mode: `on_host_call`
/// stays the default `None`).
#[derive(Default)]
struct Recorder {
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for Recorder {
    fn record_host_effect(&self, record: HostEffectRecord) {
        self.log.lock().unwrap().push(record);
    }
    fn get_effect_log(&self) -> Vec<HostEffectRecord> {
        self.log.lock().unwrap().clone()
    }
}

/// Serves a fixed 16-byte random fill and 8-byte clock value (replay mode:
/// `on_host_call` returns `Some`, so the real deterministic producer never
/// runs and these bytes land in guest memory).
struct Replayer {
    random: Vec<u8>,
    clock: Vec<u8>,
}

impl HostContext for Replayer {
    fn on_host_call(&self, effect: &HostEffect) -> Option<HostEffectRecord> {
        let output = match effect.kind {
            EffectKind::Random => self.random.clone(),
            EffectKind::Clock => self.clock.clone(),
            _ => return None,
        };
        Some(HostEffectRecord::new(
            effect.clone(),
            output,
            0,
            EffectStatus::Ok {
                code: 0,
                rows: None,
            },
        ))
    }
}

#[test]
fn records_clock_and_random_effects_on_original_run() {
    let vm = EmbedderVm::new().expect("vm");
    let module = vm
        .compile(
            CALLS_CLOCK_AND_RANDOM.as_bytes(),
            true,
            wire_effect_wrapped_wasi,
        )
        .expect("compile");

    let host: std::sync::Arc<dyn HostContext> = std::sync::Arc::new(Recorder::default());
    let out = vm
        .run_command_with_host(&module, WasiCommandOpts::new(), None, Some(host.clone()))
        .expect("run");
    assert_eq!(out.result, 0, "clean exit; stderr={:?}", out.stderr);

    let log = host.get_effect_log();
    assert_eq!(log.len(), 2, "one Random + one Clock effect: {log:?}");

    let random = log
        .iter()
        .find(|r| r.effect.kind == EffectKind::Random)
        .expect("random effect recorded");
    assert_eq!(random.effect.target, "random::getrandom");
    assert_eq!(random.output.len(), 16, "16 bytes requested and recorded");
    assert!(
        random.output.iter().any(|&b| b != 0),
        "deterministic fill is not all zero"
    );
    // The record's output_hash is self-consistent (constructor computes it).
    assert_eq!(random.output_hash, content_hash(&random.output));
    // The bytes the host recorded are exactly the bytes that reached guest
    // memory and were streamed to stdout by the stock fd_write.
    assert_eq!(
        out.stdout, random.output,
        "recorded random bytes == bytes delivered to the guest"
    );

    let clock = log
        .iter()
        .find(|r| r.effect.kind == EffectKind::Clock)
        .expect("clock effect recorded");
    assert_eq!(clock.effect.target, "clock::realtime");
    assert_eq!(clock.output.len(), 8);
    assert_eq!(
        u64::from_le_bytes(clock.output[..8].try_into().unwrap()),
        VIRTUAL_EPOCH_NS,
        "sealed clock is the shared virtual epoch"
    );
}

#[test]
fn replays_recorded_random_into_guest_memory() {
    let vm = EmbedderVm::new().expect("vm");
    let module = vm
        .compile(
            CALLS_CLOCK_AND_RANDOM.as_bytes(),
            true,
            wire_effect_wrapped_wasi,
        )
        .expect("compile");

    // A distinctive fill the deterministic producer would never emit.
    let replay_random = vec![0xABu8; 16];
    let host: std::sync::Arc<dyn HostContext> = std::sync::Arc::new(Replayer {
        random: replay_random.clone(),
        clock: 42u64.to_le_bytes().to_vec(),
    });

    let out = vm
        .run_command_with_host(&module, WasiCommandOpts::new(), None, Some(host))
        .expect("run");
    assert_eq!(out.result, 0, "clean exit; stderr={:?}", out.stderr);
    // The replayed bytes (not the deterministic fill) reached guest memory.
    assert_eq!(
        out.stdout, replay_random,
        "replay substitutes the recorded random bytes into guest memory"
    );
}

#[test]
fn sealed_run_without_host_is_deterministic_and_repeatable() {
    let vm = EmbedderVm::new().expect("vm");
    let module = vm
        .compile(
            CALLS_CLOCK_AND_RANDOM.as_bytes(),
            true,
            wire_effect_wrapped_wasi,
        )
        .expect("compile");

    // No host: the wrappers still produce deterministic bytes (sealed posture),
    // and two runs of the same module agree byte-for-byte.
    let a = vm
        .run_command_with_host(&module, WasiCommandOpts::new(), None, None)
        .expect("run a");
    let b = vm
        .run_command(&module, WasiCommandOpts::new(), None)
        .expect("run b");
    assert_eq!(a.result, 0);
    assert_eq!(a.stdout.len(), 16);
    assert_eq!(a.stdout, b.stdout, "deterministic across runs");
}
