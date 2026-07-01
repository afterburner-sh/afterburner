// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Integration proof for the WASI-command **filesystem** capture increment: the
//! effect-wrapped wasip1 `path_open` / `fd_write` / `fd_read` / `fd_close`
//! shadows (see [`afterburner_wasi::effect_wasi_fs`]), driven through the public
//! [`EmbedderVm::run_command_with_host`] path with a real recording / replaying
//! [`HostContext`].
//!
//! No language runtime is needed: a hand-written WASI-command module (WAT, which
//! `compile` accepts directly) issues exactly the wasip1 sequence a
//! `File.binwrite` + `File.binread` lowers to, over a **binary** payload
//! (embedded NULs, `0xFF`, and the invalid-UTF-8 pair `0xC3 0x28`), so the test
//! asserts both what the host recorded and what round-tripped through the
//! in-memory FS back into guest memory. The sealed clock/random setup
//! ([`wire_effect_wrapped_wasi`]) is exercised too, to prove the fs variant did
//! not disturb it.

use std::sync::Mutex;

use afterburner_core::{
    EffectKind, EffectStatus, FileOp, HostContext, HostEffect, HostEffectRecord, content_hash,
    fs_target,
};
use afterburner_wasi::effect_wasi::wire_effect_wrapped_wasi;
use afterburner_wasi::effect_wasi_fs::wire_effect_wrapped_wasi_fs;
use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};

/// A 32-byte **binary** payload: embedded NUL (`0x00`), `0xFF`, and the pair
/// `0xC3 0x28` (an invalid UTF-8 sequence: a lead byte followed by a
/// non-continuation byte). If any capture step lossily decoded to a `String`
/// this blob would not survive byte-exact.
const PAYLOAD: [u8; 32] = [
    0x00, 0xFF, 0xC3, 0x28, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0xFF,
    0x80, 0x7F, 0x00, 0xC3, 0x28, 0x41, 0x42, 0x43, 0x00, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
];

/// The guest path the module writes then reads: `/f.bin` under the preopen root
/// (fd 3 -> `/`).
const GUEST_PATH: &str = "/f.bin";

/// A WASI-command module that lowers `File.binwrite("/f.bin", PAYLOAD)` +
/// `File.binread("/f.bin")` -> stdout to wasip1:
///
/// Write leg: `path_open(dirfd=3, "/f.bin", oflags=CREAT|TRUNC=0x9,
/// rights=FD_WRITE=0x40)` -> one iovec `{buf=payload, len=32}` -> `fd_write` ->
/// `fd_close`.
/// Read leg: `path_open(dirfd=3, "/f.bin", oflags=0, rights=FD_READ=0x2)` ->
/// one iovec `{buf=readbuf, len=32}` -> `fd_read` -> `fd_write(fd=1)` echoing
/// the read-back bytes to stdout -> `fd_close` -> `proc_exit(0)`.
///
/// The binary payload lives at memory offset 0; `/f.bin` at 64; the read buffer
/// at 256.
const WRITE_READ_BINARY: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close"
    (func $fd_close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0)
    "\00\ff\c3\28\de\ad\be\ef\00\01\02\03\fc\fd\fe\ff\80\7f\00\c3\28\41\42\43\00\ff\10\20\30\40\50\60")
  (data (i32.const 64) "/f.bin")
  (func (export "_start")
    (local $fd i32)
    ;; --- write leg: create (CREAT|TRUNC) + write the 32-byte payload ---
    (drop (call $path_open
      (i32.const 3) (i32.const 0) (i32.const 64) (i32.const 6)
      (i32.const 0x9) (i64.const 0x40) (i64.const 0) (i32.const 0) (i32.const 128)))
    (local.set $fd (i32.load (i32.const 128)))
    ;; write iovec @136: { buf=0, len=32 }
    (i32.store (i32.const 136) (i32.const 0))
    (i32.store (i32.const 140) (i32.const 32))
    (drop (call $fd_write (local.get $fd) (i32.const 136) (i32.const 1) (i32.const 144)))
    (drop (call $fd_close (local.get $fd)))
    ;; --- read leg: reopen read-only + read the payload back ---
    (drop (call $path_open
      (i32.const 3) (i32.const 0) (i32.const 64) (i32.const 6)
      (i32.const 0) (i64.const 0x2) (i64.const 0) (i32.const 0) (i32.const 148)))
    (local.set $fd (i32.load (i32.const 148)))
    ;; read iovec @160: { buf=256, len=32 }
    (i32.store (i32.const 160) (i32.const 256))
    (i32.store (i32.const 164) (i32.const 32))
    (drop (call $fd_read (local.get $fd) (i32.const 160) (i32.const 1) (i32.const 168)))
    ;; echo read-back bytes to stdout: iovec @176 = { buf=256, len=nread@168 }
    (i32.store (i32.const 176) (i32.const 256))
    (i32.store (i32.const 180) (i32.load (i32.const 168)))
    (drop (call $fd_write (i32.const 1) (i32.const 176) (i32.const 1) (i32.const 184)))
    (drop (call $fd_close (local.get $fd)))
    (call $proc_exit (i32.const 0))))
"#;

/// A minimal clock/random module used only to prove the sealed
/// [`wire_effect_wrapped_wasi`] setup is unchanged by the fs increment.
const CALLS_RANDOM: &str = r#"
(module
  (import "wasi_snapshot_preview1" "random_get"
    (func $rand (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (drop (call $rand (i32.const 0) (i32.const 16)))
    (i32.store (i32.const 80) (i32.const 0))
    (i32.store (i32.const 84) (i32.const 16))
    (drop (call $write (i32.const 1) (i32.const 80) (i32.const 1) (i32.const 88)))
    (call $exit (i32.const 0))))
"#;

/// Records every effect (original / record run: `on_host_call` returns `None`).
#[derive(Default)]
struct Recorder {
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for Recorder {
    fn on_host_call(&self, _effect: &HostEffect) -> Option<HostEffectRecord> {
        None
    }
    fn record_host_effect(&self, record: HostEffectRecord) {
        self.log.lock().unwrap().push(record);
    }
    fn get_effect_log(&self) -> Vec<HostEffectRecord> {
        self.log.lock().unwrap().clone()
    }
}

/// Serves a distinctive substitute (`0xAB` x 32) for the `Fs(Read)` effect and
/// records everything else (replay direction). The read serve proves bytes are
/// substituted with no real in-memory-FS read; `path_open`'s Create still
/// journals (it is record-only by construction), so the log carries the Create
/// but never a Read.
struct ReadReplayer {
    served: Vec<u8>,
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for ReadReplayer {
    fn on_host_call(&self, effect: &HostEffect) -> Option<HostEffectRecord> {
        if effect.kind == EffectKind::Fs(FileOp::Read) {
            Some(HostEffectRecord::new(
                effect.clone(),
                self.served.clone(),
                0,
                EffectStatus::Ok {
                    code: 0,
                    rows: None,
                },
            ))
        } else {
            None
        }
    }
    fn record_host_effect(&self, record: HostEffectRecord) {
        self.log.lock().unwrap().push(record);
    }
    fn get_effect_log(&self) -> Vec<HostEffectRecord> {
        self.log.lock().unwrap().clone()
    }
}

fn compile_write_read(vm: &EmbedderVm) -> afterburner_wasi::embedder_vm::EmbedderModule {
    vm.compile(
        WRITE_READ_BINARY.as_bytes(),
        true,
        wire_effect_wrapped_wasi_fs,
    )
    .expect("write/read binary module compiles")
}

#[test]
fn record_run_captures_create_write_read_with_blake3_parity_over_binary() {
    let vm = EmbedderVm::new().expect("vm");
    let module = compile_write_read(&vm);

    let host: std::sync::Arc<dyn HostContext> = std::sync::Arc::new(Recorder::default());
    let out = vm
        .run_command_with_host(
            &module,
            WasiCommandOpts::new().args(["conf"]),
            None,
            Some(host.clone()),
        )
        .expect("record run");
    assert_eq!(out.result, 0, "clean proc_exit(0); stderr={:?}", out.stderr);

    // The bytes read back out of the InMemFs reached the guest byte-exact and
    // were echoed to stdout: the full binary round-trip through capture.
    assert_eq!(
        out.stdout,
        PAYLOAD.to_vec(),
        "binary payload round-tripped guest -> InMemFs -> guest byte-exact"
    );

    let log = host.get_effect_log();
    assert_eq!(
        log.len(),
        3,
        "Create (path_open) + Write (fd_write) + Read (fd_read); seek/close/stdout not journalled: {log:?}"
    );

    // 1. Create at file::/f.bin (record-only).
    let create = &log[0];
    assert_eq!(create.effect.kind, EffectKind::Fs(FileOp::Create));
    assert_eq!(create.effect.target, fs_target(GUEST_PATH));

    // 2. Write: the request input carries the payload verbatim; output empty.
    let write = &log[1];
    assert_eq!(write.effect.kind, EffectKind::Fs(FileOp::Write));
    assert_eq!(write.effect.target, fs_target(GUEST_PATH));
    assert_eq!(
        write.effect.input,
        PAYLOAD.to_vec(),
        "write input == payload"
    );
    assert!(write.output.is_empty(), "a write carries no output content");

    // 3. Read: the result output carries the payload verbatim.
    let read = &log[2];
    assert_eq!(read.effect.kind, EffectKind::Fs(FileOp::Read));
    assert_eq!(read.effect.target, fs_target(GUEST_PATH));
    assert_eq!(read.output, PAYLOAD.to_vec(), "read output == payload");

    // BLAKE3 parity: the write's input and the read's output content-address to
    // the same hash, and both equal content_hash(payload) (the record/replay
    // parity crux).
    let want = content_hash(&PAYLOAD);
    assert_eq!(
        write.effect.input_hash, want,
        "write input hash == H(payload)"
    );
    assert_eq!(read.output_hash, want, "read output hash == H(payload)");
    assert_eq!(
        write.effect.input_hash, read.output_hash,
        "write in == read out"
    );

    // Self-consistency: each hash agrees with the bytes it addresses.
    assert_eq!(write.effect.input_hash, content_hash(&write.effect.input));
    assert_eq!(read.output_hash, content_hash(&read.output));

    // Binary-safety: the recorded bytes still hold the NUL and the invalid
    // UTF-8 pair, proving no lossy String decode on the capture path.
    assert!(write.effect.input.contains(&0x00), "NUL preserved");
    assert!(
        write.effect.input.windows(2).any(|w| w == [0xC3, 0x28]),
        "invalid-UTF-8 pair 0xC3 0x28 preserved"
    );
}

#[test]
fn record_run_is_deterministic_across_two_runs() {
    let vm = EmbedderVm::new().expect("vm");
    let module = compile_write_read(&vm);

    let run = || {
        let host = std::sync::Arc::new(Recorder::default());
        vm.run_command_with_host(
            &module,
            WasiCommandOpts::new().args(["conf"]),
            None,
            Some(host.clone()),
        )
        .expect("record run");
        host.get_effect_log()
    };

    let a = run();
    let b = run();
    assert_eq!(a.len(), b.len(), "same number of effects");
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.effect, y.effect, "same request identity");
        assert_eq!(x.output_hash, y.output_hash, "same output content-address");
        assert_eq!(x.status, y.status, "same status/code");
    }
}

#[test]
fn replay_serves_recorded_read_bytes_without_touching_the_fs() {
    let vm = EmbedderVm::new().expect("vm");
    let module = compile_write_read(&vm);

    // A distinctive fill the guest never wrote: 32 x 0xAB.
    let substitute = vec![0xABu8; 32];
    let host = std::sync::Arc::new(ReadReplayer {
        served: substitute.clone(),
        log: Mutex::new(Vec::new()),
    });

    let out = vm
        .run_command_with_host(
            &module,
            WasiCommandOpts::new().args(["conf"]),
            None,
            Some(host.clone()),
        )
        .expect("replay run");
    assert_eq!(out.result, 0, "clean exit; stderr={:?}", out.stderr);

    // The guest wrote PAYLOAD to the InMemFs, but the served read substitutes
    // 0xAB x 32 into guest memory: the read went through the seam's serve path,
    // NOT a real InMemFs read (which would have echoed PAYLOAD).
    assert_eq!(out.stdout, substitute, "served read bytes substituted");
    assert_ne!(
        out.stdout,
        PAYLOAD.to_vec(),
        "the real on-disk bytes were bypassed"
    );

    // The Read was served, so it is NOT journalled; `path_open`'s Create is
    // record-only by construction and still appears. No second Read record.
    let log = host.get_effect_log();
    assert!(
        log.iter()
            .all(|r| r.effect.kind != EffectKind::Fs(FileOp::Read)),
        "a served read journals no Read record: {log:?}"
    );
}

#[test]
fn sealed_no_host_is_byte_identical_and_round_trips_the_binary() {
    let vm = EmbedderVm::new().expect("vm");
    let module = compile_write_read(&vm);

    // No host: the fs shadows still run over an empty InMemFs, journalling
    // nothing, and two runs agree byte-for-byte.
    let a = vm
        .run_command_with_host(&module, WasiCommandOpts::new().args(["conf"]), None, None)
        .expect("sealed run a");
    let b = vm
        .run_command(&module, WasiCommandOpts::new().args(["conf"]), None)
        .expect("sealed run b");
    assert_eq!(a.result, 0);
    assert_eq!(
        a.stdout,
        PAYLOAD.to_vec(),
        "binary round-trips with no host"
    );
    assert_eq!(a.stdout, b.stdout, "deterministic across sealed runs");
}

#[test]
fn sealed_clock_random_setup_is_undisturbed_by_the_fs_variant() {
    // The production sealed setup (clock + random shadows, stock fs) still
    // compiles and runs the clock/random module unchanged: the fs increment is
    // a second, opt-in compile variant and does not perturb this path.
    let vm = EmbedderVm::new().expect("vm");
    let module = vm
        .compile(CALLS_RANDOM.as_bytes(), true, wire_effect_wrapped_wasi)
        .expect("clock/random module compiles under the sealed setup");
    let a = vm
        .run_command(&module, WasiCommandOpts::new(), None)
        .expect("sealed run a");
    let b = vm
        .run_command(&module, WasiCommandOpts::new(), None)
        .expect("sealed run b");
    assert_eq!(a.result, 0);
    assert_eq!(
        a.stdout.len(),
        16,
        "16 deterministic random bytes to stdout"
    );
    assert_eq!(a.stdout, b.stdout, "deterministic across runs");
}
