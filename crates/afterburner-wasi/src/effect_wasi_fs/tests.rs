// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Conformance tests for the effect-wrapped wasip1 filesystem shadows.
//!
//! A hand-written WAT command module creates its own file, writes `hello` to
//! it, seeks back to 0, reads it, and echoes the read-back bytes to stdout. It
//! needs no host stdlib, so the sealed `InMemFs` backing is proven directly.
//! The record run drives `path_open` -> `fd_write` -> `fd_read` through the
//! shared [`FsSeam`](crate::emscripten_syscall) and the replay run proves the
//! served read substitutes recorded bytes without touching the FS.

use std::sync::Mutex;

use afterburner_core::{
    EffectKind, EffectStatus, FileOp, HostContext, HostEffect, HostEffectRecord, content_hash,
    fs_target,
};

use super::*;
use crate::embedder_vm::{EmbedderVm, WasiCommandOpts};

/// A WASI command module that:
/// 1. `path_open`s `test.txt` under the preopen root (fd 3) with O_CREAT + write,
/// 2. `fd_write`s `hello` to the returned fd,
/// 3. `fd_seek`s back to offset 0,
/// 4. `fd_read`s 5 bytes,
/// 5. echoes the read-back bytes to stdout (fd 1),
/// 6. `fd_close`s and `proc_exit(0)`s.
const CONFORMANCE_WAT: &[u8] = br#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_seek"
    (func $fd_seek (param i32 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close"
    (func $fd_close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "test.txt")
  (data (i32.const 16) "hello")
  (func (export "_start")
    (local $fd i32)
    ;; path_open(dirfd=3, dirflags=0, path=0, path_len=8, oflags=1 (O_CREAT),
    ;;   rights_base=0x42 (FD_READ|FD_WRITE), rights_inh=0, fdflags=0, out=32)
    (drop (call $path_open
      (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 8)
      (i32.const 1) (i64.const 0x42) (i64.const 0) (i32.const 0) (i32.const 32)))
    (local.set $fd (i32.load (i32.const 32)))
    ;; write iovec @48: { buf=16, len=5 }
    (i32.store (i32.const 48) (i32.const 16))
    (i32.store (i32.const 52) (i32.const 5))
    (drop (call $fd_write (local.get $fd) (i32.const 48) (i32.const 1) (i32.const 56)))
    ;; seek to offset 0 (whence SET)
    (drop (call $fd_seek (local.get $fd) (i64.const 0) (i32.const 0) (i32.const 64)))
    ;; read iovec @80: { buf=128, len=5 }
    (i32.store (i32.const 80) (i32.const 128))
    (i32.store (i32.const 84) (i32.const 5))
    (drop (call $fd_read (local.get $fd) (i32.const 80) (i32.const 1) (i32.const 88)))
    ;; echo the read-back bytes to stdout: iovec @96 = { buf=128, len=nread@88 }
    (i32.store (i32.const 96) (i32.const 128))
    (i32.store (i32.const 100) (i32.load (i32.const 88)))
    (drop (call $fd_write (i32.const 1) (i32.const 96) (i32.const 1) (i32.const 104)))
    (drop (call $fd_close (local.get $fd)))
    (call $proc_exit (i32.const 0))
  )
)
"#;

/// A recording host: `on_host_call` returns `None` for every effect (record
/// mode) and appends each `record_host_effect` in call order.
#[derive(Default)]
struct RecordHost {
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for RecordHost {
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

/// A replay host: serves a canned `Read` result (`WORLD`) for any `Fs(Read)`
/// effect, and records everything else (so the create + write still happen).
struct ReplayReadHost {
    served: Vec<u8>,
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for ReplayReadHost {
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

fn compile_conformance(vm: &EmbedderVm) -> crate::embedder_vm::EmbedderModule {
    vm.compile(CONFORMANCE_WAT, true, wire_effect_wrapped_wasi_fs)
        .expect("conformance module compiles")
}

#[test]
fn record_run_captures_create_write_read_with_content_parity() {
    let vm = EmbedderVm::new().unwrap();
    let module = compile_conformance(&vm);
    let host = std::sync::Arc::new(RecordHost::default());

    let out = vm
        .run_command_with_host(
            &module,
            WasiCommandOpts::new().args(["conf"]),
            None,
            Some(host.clone()),
        )
        .expect("conformance run succeeds");

    assert_eq!(out.result, 0, "clean proc_exit(0)");
    // stdout is the bytes read back from the InMemFs.
    assert_eq!(out.stdout, b"hello", "read-back echoed to stdout");

    let log = host.get_effect_log();
    assert_eq!(
        log.len(),
        3,
        "create (path_open) + write (fd_write) + read (fd_read); fd_seek/fd_close/stdout are not journalled"
    );

    // 1. Create at file::/test.txt (record-only; code = allocated fd = 4).
    assert_eq!(log[0].effect.kind, EffectKind::Fs(FileOp::Create));
    assert_eq!(log[0].effect.target, fs_target("/test.txt"));
    assert_eq!(
        log[0].status,
        EffectStatus::Ok {
            code: 4,
            rows: None
        },
        "first file lands at fd 4 (0/1/2 reserved, 3 = preopen root)"
    );

    // 2. Write: input carries the payload; output empty.
    assert_eq!(log[1].effect.kind, EffectKind::Fs(FileOp::Write));
    assert_eq!(log[1].effect.target, fs_target("/test.txt"));
    assert_eq!(log[1].effect.input, b"hello");
    assert_eq!(log[1].effect.input_hash, content_hash(b"hello"));
    assert!(log[1].output.is_empty(), "a write has no output content");
    assert_eq!(
        log[1].status,
        EffectStatus::Ok {
            code: 5,
            rows: None
        }
    );

    // 3. Read: output carries the bytes read.
    assert_eq!(log[2].effect.kind, EffectKind::Fs(FileOp::Read));
    assert_eq!(log[2].effect.target, fs_target("/test.txt"));
    assert_eq!(log[2].output, b"hello");
    assert_eq!(log[2].output_hash, content_hash(b"hello"));

    // Cross-op content parity: the write's input and the read's output
    // content-address to the same BLAKE3 (the record/replay parity crux).
    assert_eq!(log[1].effect.input_hash, log[2].output_hash);
}

#[test]
fn record_run_is_deterministic_across_two_runs() {
    let vm = EmbedderVm::new().unwrap();
    let module = compile_conformance(&vm);

    let run = || {
        let host = std::sync::Arc::new(RecordHost::default());
        vm.run_command_with_host(
            &module,
            WasiCommandOpts::new().args(["conf"]),
            None,
            Some(host.clone()),
        )
        .unwrap();
        host.get_effect_log()
    };

    let a = run();
    let b = run();
    // Byte-identical effect logs: same targets, same hashes, same codes.
    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.effect, y.effect, "same request identity");
        assert_eq!(x.output_hash, y.output_hash, "same output content-address");
        assert_eq!(x.status, y.status, "same status/code");
    }
}

#[test]
fn replay_serves_recorded_read_bytes_without_touching_the_fs() {
    let vm = EmbedderVm::new().unwrap();
    let module = compile_conformance(&vm);
    let host = std::sync::Arc::new(ReplayReadHost {
        served: b"WORLD".to_vec(),
        log: Mutex::new(Vec::new()),
    });

    let out = vm
        .run_command_with_host(
            &module,
            WasiCommandOpts::new().args(["conf"]),
            None,
            Some(host.clone()),
        )
        .expect("replay run succeeds");

    // The guest wrote `hello`, but the served read substitutes `WORLD`, proving
    // the read went through the seam's serve path and not the real InMemFs.
    assert_eq!(out.stdout, b"WORLD", "served read bytes substituted");
}

#[test]
fn sealed_no_host_run_is_byte_identical_and_zero_effect() {
    // With no recording host, the fs shadows still function (over an empty
    // InMemFs) but journal nothing and touch no host state.
    let vm = EmbedderVm::new().unwrap();
    let module = compile_conformance(&vm);
    let out = vm
        .run_command(&module, WasiCommandOpts::new().args(["conf"]), None)
        .expect("sealed run succeeds");
    assert_eq!(out.result, 0);
    assert_eq!(out.stdout, b"hello", "read-back echoed to stdout, no host");
}

// ---- pure-unit tests for the two load-bearing translations ------------------

#[test]
fn em2wasi_maps_every_documented_errno() {
    assert_eq!(em2wasi(ENOENT), ERRNO_NOENT); // -2  -> 44
    assert_eq!(em2wasi(EBADF), ERRNO_BADF); // -9  -> 8
    assert_eq!(em2wasi(EACCES), ERRNO_ACCES); // -13 -> 2
    assert_eq!(em2wasi(ENOTDIR), ERRNO_NOTDIR); // -20 -> 54
    assert_eq!(em2wasi(EISDIR), ERRNO_ISDIR); // -21 -> 31
    assert_eq!(em2wasi(EINVAL), ERRNO_INVAL); // -22 -> 28
    assert_eq!(em2wasi(-5), ERRNO_INVAL, "unmapped errno -> EINVAL");
}

#[test]
fn open_flags_translates_oflags_and_rights() {
    // O_CREAT bit only.
    assert_eq!(open_flags(OFLAGS_CREAT, 0), EM_O_CREAT);
    // O_CREAT | O_TRUNC | write right.
    assert_eq!(
        open_flags(OFLAGS_CREAT | OFLAGS_TRUNC, RIGHTS_FD_WRITE),
        EM_O_CREAT | EM_O_TRUNC | EM_O_RDWR
    );
    // Read-only open: no flags.
    assert_eq!(open_flags(0, 0), 0);
}

#[test]
fn filestat_writer_lays_out_ino_type_size_and_pinned_times() {
    let b = write_filestat(0x1122, 4, 0xABCD);
    assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 0x1122);
    assert_eq!(b[16], 4, "filetype at offset 16");
    assert_eq!(
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
        1,
        "nlink"
    );
    assert_eq!(u64::from_le_bytes(b[32..40].try_into().unwrap()), 0xABCD);
    assert_eq!(
        u64::from_le_bytes(b[40..48].try_into().unwrap()),
        VIRTUAL_EPOCH_NS,
        "atim pinned to the virtual epoch"
    );
}
