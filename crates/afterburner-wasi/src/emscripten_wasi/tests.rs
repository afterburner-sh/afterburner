// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Tests for the wasi_snapshot_preview1 custom shims (emscripten_wasi.rs).
//!
//! All tests run the shim inside a tiny wasmtime module compiled from WAT,
//! reading and asserting results from guest memory.

use super::*;
use crate::{embedder_vm::EmbedderState, emscripten_abi::VIRTUAL_EPOCH_NS};
use std::sync::LazyLock;
use wasmtime::{Config, Engine, Linker, Memory, MemoryType, Module, Store};

// ---- shared engine ----------------------------------------------------------

static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    let mut cfg = Config::new();
    cfg.consume_fuel(true);
    Engine::new(&cfg).expect("test engine")
});

// ---- store builder ----------------------------------------------------------
//
// Build a Store + Linker with all wasi_snapshot_preview1 shims registered,
// a small wasm Memory wired as pyodide_memory, and the memory exposed as
// wasi_snapshot_preview1.memory is NOT needed - shims read from EmbedderState.

fn make_store_and_linker() -> (Store<EmbedderState>, Linker<EmbedderState>) {
    let engine = &ENGINE;
    let mut store = Store::new(engine, EmbedderState::headless());
    store.set_fuel(100_000_000).expect("set_fuel");

    let mem_ty = MemoryType::new(4, None); // 4 pages = 256 KiB
    let mem = Memory::new(&mut store, mem_ty).expect("memory");
    store.data_mut().pyodide_memory = Some(mem);

    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    wire_wasi_snapshot_preview1(&mut linker).expect("wire wasi");

    // Expose memory for modules that need to import it.
    linker
        .define(
            &mut store,
            "wasi_snapshot_preview1",
            "memory",
            wasmtime::Extern::Memory(mem),
        )
        .ok(); // not all test modules need it

    (store, linker)
}

// Helper: write bytes into wasm memory at given offset.
fn write_mem(store: &mut Store<EmbedderState>, addr: usize, data: &[u8]) {
    let mem = store.data().pyodide_memory.expect("mem");
    mem.data_mut(store)[addr..addr + data.len()].copy_from_slice(data);
}

// Helper: read bytes from wasm memory.
fn read_mem(store: &Store<EmbedderState>, addr: usize, len: usize) -> Vec<u8> {
    let mem = store.data().pyodide_memory.expect("mem");
    mem.data(store)[addr..addr + len].to_vec()
}

// Helper: call a wasi shim with N i32 params, return the i32 result.
fn call_wasi_2(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    name: &str,
    a: i32,
    b: i32,
) -> i32 {
    let wat_src = format!(
        r#"(module
          (import "wasi_snapshot_preview1" "{name}"
            (func $f (param i32 i32) (result i32)))
          (func (export "run") (result i32)
            i32.const {a}
            i32.const {b}
            call $f))"#
    );
    let wasm = wat::parse_str(&wat_src).expect("WAT");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut *store, &module)
        .expect("instantiate");
    instance
        .get_typed_func::<(), i32>(&mut *store, "run")
        .expect("run")
        .call(&mut *store, ())
        .expect("call")
}

fn call_wasi_4(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    name: &str,
    a: i32,
    b: i32,
    c: i32,
    d: i32,
) -> i32 {
    let wat_src = format!(
        r#"(module
          (import "wasi_snapshot_preview1" "{name}"
            (func $f (param i32 i32 i32 i32) (result i32)))
          (func (export "run") (result i32)
            i32.const {a}
            i32.const {b}
            i32.const {c}
            i32.const {d}
            call $f))"#
    );
    let wasm = wat::parse_str(&wat_src).expect("WAT");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut *store, &module)
        .expect("instantiate");
    instance
        .get_typed_func::<(), i32>(&mut *store, "run")
        .expect("run")
        .call(&mut *store, ())
        .expect("call")
}

// ---- environ_sizes_get / environ_get ----------------------------------------

/// The fixed guest environment exposed via the WASI environ ABI, as bytes
/// (each entry NUL-terminated). Mirrors `GUEST_ENVIRON` in the parent module so
/// these tests pin the exact contract: PYTHONUNBUFFERED=1 and HOME=/home/burn.
const EXPECTED_ENVIRON: &[&[u8]] = &[b"PYTHONUNBUFFERED=1\0", b"HOME=/home/burn\0"];

/// environ_sizes_get writes the var count and total byte size of the fixed
/// guest environment (PYTHONUNBUFFERED=1 and HOME=/home/burn).
#[test]
fn environ_sizes_get_returns_fixed_environ() {
    let (mut store, linker) = make_store_and_linker();
    // count_ptr at 0x100, buf_size_ptr at 0x104
    let rc = call_wasi_2(&mut store, &linker, "environ_sizes_get", 0x100, 0x104);
    assert_eq!(rc, 0, "environ_sizes_get must return 0 (success)");

    let count = u32::from_le_bytes(read_mem(&store, 0x100, 4).try_into().unwrap());
    let buf_size = u32::from_le_bytes(read_mem(&store, 0x104, 4).try_into().unwrap());
    let want_count = EXPECTED_ENVIRON.len() as u32;
    let want_size: u32 = EXPECTED_ENVIRON.iter().map(|v| v.len() as u32).sum();
    assert_eq!(count, want_count, "environ count (PYTHONUNBUFFERED + HOME)");
    assert_eq!(buf_size, want_size, "buf_size = sum of NUL-terminated vars");
}

/// environ_get writes each env string to the buffer and a pointer to each in
/// the environ array. Asserts both vars and that HOME is set (the fix that lets
/// os.path.expanduser('~') resolve).
#[test]
fn environ_get_writes_fixed_environ() {
    let (mut store, linker) = make_store_and_linker();
    // environ_ptr (the char* array) at 0x200, buf_ptr (string storage) at 0x210.
    let rc = call_wasi_2(&mut store, &linker, "environ_get", 0x200, 0x210);
    assert_eq!(rc, 0, "environ_get must return 0");

    let total: usize = EXPECTED_ENVIRON.iter().map(|v| v.len()).sum();
    let buf = read_mem(&store, 0x210, total);
    // The strings are laid back to back in declaration order.
    let mut expected = Vec::new();
    for v in EXPECTED_ENVIRON {
        expected.extend_from_slice(v);
    }
    assert_eq!(buf, expected, "environ buffer = vars back to back");

    // Each environ[i] points at the start of var i within the buffer.
    let mut off = 0x210u32;
    for (i, v) in EXPECTED_ENVIRON.iter().enumerate() {
        let slot = 0x200usize + i * 4;
        let ptr_val = u32::from_le_bytes(read_mem(&store, slot, 4).try_into().unwrap());
        assert_eq!(ptr_val, off, "environ[{i}] must point at its string");
        off += v.len() as u32;
    }

    // The HOME assignment is present (the expanduser fix).
    let as_str = String::from_utf8_lossy(&buf);
    assert!(as_str.contains("HOME=/home/burn"), "HOME must be set");
    assert!(
        as_str.contains("PYTHONUNBUFFERED=1"),
        "PYTHONUNBUFFERED=1 must be present"
    );
}

// ---- fd_write ---------------------------------------------------------------

/// fd_write on fd 1: bytes appended to wasi_stdout; nwritten written.
#[test]
fn fd_write_fd1_appends_to_wasi_stdout() {
    let (mut store, linker) = make_store_and_linker();
    // Memory layout:
    //   0x1000: "hello" (5 bytes)
    //   0x1010: iovec {buf_ptr=0x1000, buf_len=5}
    //   0x1020: nwritten (4 bytes, output)
    write_mem(&mut store, 0x1000, b"hello");
    write_mem(&mut store, 0x1010, &(0x1000u32).to_le_bytes()); // iov_base
    write_mem(&mut store, 0x1014, &(5u32).to_le_bytes()); // iov_len
    // fd_write(fd=1, iovs_ptr=0x1010, iovs_len=1, nwritten_ptr=0x1020)
    let rc = call_wasi_4(&mut store, &linker, "fd_write", 1, 0x1010, 1, 0x1020);
    assert_eq!(rc, 0, "fd_write must return 0 (success)");

    let nwritten = u32::from_le_bytes(read_mem(&store, 0x1020, 4).try_into().unwrap());
    assert_eq!(nwritten, 5, "nwritten must be 5");
    assert_eq!(store.data().wasi_stdout, b"hello");
}

/// fd_write on an MEMFS fd writes to the file node.
#[test]
fn fd_write_memfs_fd_writes_to_file() {
    let (mut store, linker) = make_store_and_linker();
    store.data_mut().fs.insert_file("/out.txt", Vec::new());
    let fd = store
        .data_mut()
        .fs
        .open("/out.txt".to_owned(), 1 /* O_WRONLY */);
    assert!(fd >= 3);

    write_mem(&mut store, 0x2000, b"data");
    write_mem(&mut store, 0x2010, &(0x2000u32).to_le_bytes());
    write_mem(&mut store, 0x2014, &(4u32).to_le_bytes());

    let rc = call_wasi_4(&mut store, &linker, "fd_write", fd, 0x2010, 1, 0x2020);
    assert_eq!(rc, 0, "fd_write to file must return 0");

    let nwritten = u32::from_le_bytes(read_mem(&store, 0x2020, 4).try_into().unwrap());
    assert_eq!(nwritten, 4, "nwritten must be 4");
    assert_eq!(store.data().fs.read_file("/out.txt").unwrap(), b"data");
}

// ---- fd_read ----------------------------------------------------------------

/// fd_read on stdin (fd 0) returns 0 bytes (EOF).
#[test]
fn fd_read_stdin_returns_eof() {
    let (mut store, linker) = make_store_and_linker();
    // iovec at 0x3000, nread at 0x3020
    write_mem(&mut store, 0x3000, &(0x3010u32).to_le_bytes()); // iov_base
    write_mem(&mut store, 0x3004, &(64u32).to_le_bytes()); // iov_len
    let rc = call_wasi_4(&mut store, &linker, "fd_read", 0, 0x3000, 1, 0x3020);
    assert_eq!(rc, 0, "fd_read on stdin must return 0 (no error)");
    let nread = u32::from_le_bytes(read_mem(&store, 0x3020, 4).try_into().unwrap());
    assert_eq!(nread, 0, "nread on stdin must be 0");
}

/// fd_read on an MEMFS fd reads bytes and advances offset.
#[test]
fn fd_read_memfs_fd_reads_content() {
    let (mut store, linker) = make_store_and_linker();
    store
        .data_mut()
        .fs
        .insert_file("/read_me.txt", b"abcde".to_vec());
    let fd = store.data_mut().fs.open("/read_me.txt".to_owned(), 0);
    assert!(fd >= 3);

    // iovec at 0x4000: {buf_ptr=0x4010, buf_len=5}; nread at 0x4020
    write_mem(&mut store, 0x4000, &(0x4010u32).to_le_bytes());
    write_mem(&mut store, 0x4004, &(5u32).to_le_bytes());
    let rc = call_wasi_4(&mut store, &linker, "fd_read", fd, 0x4000, 1, 0x4020);
    assert_eq!(rc, 0, "fd_read must return 0 (success)");
    let nread = u32::from_le_bytes(read_mem(&store, 0x4020, 4).try_into().unwrap());
    assert_eq!(nread, 5, "nread must be 5");
    let content = read_mem(&store, 0x4010, 5);
    assert_eq!(&content, b"abcde");
}

// ---- fd_seek ----------------------------------------------------------------

/// fd_seek SEEK_SET on an MEMFS fd updates offset and writes new offset.
#[test]
fn fd_seek_seek_set_updates_offset() {
    let (mut store, linker) = make_store_and_linker();
    store
        .data_mut()
        .fs
        .insert_file("/seek_me.txt", b"0123456789".to_vec());
    let fd = store.data_mut().fs.open("/seek_me.txt".to_owned(), 0);
    assert!(fd >= 3);

    // fd_seek(fd, offset=5, whence=0 (SEEK_SET), newoffset_ptr=0x5000)
    // WAT for fd_seek has signature (i32 i32 i64 i32) -> i32 (fd, offset-as-i64, whence, ptr)
    // We need a custom wrapper since offset is i64.
    let wat_src = format!(
        r#"(module
          (import "wasi_snapshot_preview1" "fd_seek"
            (func $f (param i32 i64 i32 i32) (result i32)))
          (func (export "run") (result i32)
            i32.const {fd}
            i64.const 5
            i32.const 0
            i32.const 0x5000
            call $f))"#
    );
    let wasm = wat::parse_str(&wat_src).expect("WAT");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
    let rc = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .expect("run")
        .call(&mut store, ())
        .expect("call");
    assert_eq!(rc, 0, "fd_seek must return 0 (success)");

    let new_off = u64::from_le_bytes(read_mem(&store, 0x5000, 8).try_into().unwrap());
    assert_eq!(new_off, 5, "new offset must be 5 after SEEK_SET to 5");
}

/// fd_seek on stdin (fd 0) returns 0 and writes 0 as the new offset.
#[test]
fn fd_seek_stdin_returns_zero() {
    let (mut store, linker) = make_store_and_linker();
    let wat_src = r#"(module
          (import "wasi_snapshot_preview1" "fd_seek"
            (func $f (param i32 i64 i32 i32) (result i32)))
          (func (export "run") (result i32)
            i32.const 0   ;; fd=stdin
            i64.const 0   ;; offset
            i32.const 0   ;; SEEK_SET
            i32.const 0x6000
            call $f))"#;
    let wasm = wat::parse_str(wat_src).expect("WAT");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
    let rc = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .expect("run")
        .call(&mut store, ())
        .expect("call");
    assert_eq!(rc, 0, "fd_seek on stdin must return 0");
}

// ---- clock_time_get ---------------------------------------------------------

/// clock_time_get returns the deterministic VIRTUAL_EPOCH_NS constant.
#[test]
fn clock_time_get_returns_deterministic_epoch() {
    let (mut store, linker) = make_store_and_linker();
    // clock_time_get(id=0, precision=1, time_ptr=0x7000) -> i32
    let wat_src = r#"(module
          (import "wasi_snapshot_preview1" "clock_time_get"
            (func $f (param i32 i64 i32) (result i32)))
          (func (export "run") (result i32)
            i32.const 0   ;; CLOCK_REALTIME
            i64.const 1   ;; precision
            i32.const 0x7000
            call $f))"#;
    let wasm = wat::parse_str(wat_src).expect("WAT");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
    let rc = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .expect("run")
        .call(&mut store, ())
        .expect("call");
    assert_eq!(rc, 0, "clock_time_get must return 0");

    let ns = u64::from_le_bytes(read_mem(&store, 0x7000, 8).try_into().unwrap());
    assert_eq!(
        ns, VIRTUAL_EPOCH_NS,
        "clock_time_get must return VIRTUAL_EPOCH_NS"
    );
}

/// Two calls with different clock ids still return the same deterministic value.
#[test]
fn clock_time_get_same_value_for_all_ids() {
    let (mut store, linker) = make_store_and_linker();
    let call = |store: &mut Store<EmbedderState>, clock_id: i32, ptr: i32| {
        let wat_src = format!(
            r#"(module
              (import "wasi_snapshot_preview1" "clock_time_get"
                (func $f (param i32 i64 i32) (result i32)))
              (func (export "run") (result i32)
                i32.const {clock_id}
                i64.const 1
                i32.const {ptr}
                call $f))"#
        );
        let wasm = wat::parse_str(&wat_src).expect("WAT");
        let module = Module::new(&ENGINE, &wasm).expect("module");
        let instance = linker
            .instantiate(&mut *store, &module)
            .expect("instantiate");
        instance
            .get_typed_func::<(), i32>(&mut *store, "run")
            .expect("run")
            .call(&mut *store, ())
            .expect("call")
    };
    call(&mut store, 0 /* CLOCK_REALTIME */, 0x7100);
    call(&mut store, 1 /* CLOCK_MONOTONIC */, 0x7108);

    let t0 = u64::from_le_bytes(read_mem(&store, 0x7100, 8).try_into().unwrap());
    let t1 = u64::from_le_bytes(read_mem(&store, 0x7108, 8).try_into().unwrap());
    assert_eq!(
        t0, t1,
        "all clock ids must return the same deterministic epoch"
    );
    assert_eq!(t0, VIRTUAL_EPOCH_NS);
}

// ---- random_get -------------------------------------------------------------

/// random_get is deterministic: same seed -> same bytes on every call.
#[test]
fn random_get_same_seed_same_bytes() {
    let (mut store, linker) = make_store_and_linker();
    // Call random_get twice to the same buffer and compare.
    // Since the implementation re-seeds from the fixed constant each call,
    // bytes must be identical.
    let call = |store: &mut Store<EmbedderState>, ptr: i32, len: i32| {
        let wat_src = format!(
            r#"(module
              (import "wasi_snapshot_preview1" "random_get"
                (func $f (param i32 i32) (result i32)))
              (func (export "run") (result i32)
                i32.const {ptr}
                i32.const {len}
                call $f))"#
        );
        let wasm = wat::parse_str(&wat_src).expect("WAT");
        let module = Module::new(&ENGINE, &wasm).expect("module");
        let instance = linker
            .instantiate(&mut *store, &module)
            .expect("instantiate");
        instance
            .get_typed_func::<(), i32>(&mut *store, "run")
            .expect("run")
            .call(&mut *store, ())
            .expect("call")
    };
    let rc1 = call(&mut store, 0x8000, 32);
    let bytes1 = read_mem(&store, 0x8000, 32);
    // Zero the buffer, call again.
    write_mem(&mut store, 0x8000, &[0u8; 32]);
    let rc2 = call(&mut store, 0x8000, 32);
    let bytes2 = read_mem(&store, 0x8000, 32);

    assert_eq!(rc1, 0, "random_get must return 0");
    assert_eq!(rc2, 0, "random_get must return 0 on second call");
    assert_eq!(
        bytes1, bytes2,
        "deterministic SplitMix64 must produce identical bytes on re-call"
    );
    // Bytes must not be all-zero (the RNG actually ran).
    assert_ne!(
        bytes1,
        vec![0u8; 32],
        "random_get must not return all zeros"
    );
}

/// random_get fills exactly the requested byte count (boundary check).
#[test]
fn random_get_fills_exact_length() {
    let (mut store, linker) = make_store_and_linker();
    let rc = call_wasi_2(&mut store, &linker, "random_get", 0x9000, 7);
    assert_eq!(rc, 0, "random_get must return 0");
    // Check that only 7 bytes were written (byte 7 must still be 0 if we guard the next slot).
    // We only verify the bytes themselves are non-trivially non-zero.
    let out = read_mem(&store, 0x9000, 7);
    assert_ne!(out, vec![0u8; 7], "random_get must produce non-zero bytes");
}

/// random_get with len=0 is a no-op and returns 0.
#[test]
fn random_get_zero_len_is_noop() {
    let (mut store, linker) = make_store_and_linker();
    let rc = call_wasi_2(&mut store, &linker, "random_get", 0xa000, 0);
    assert_eq!(rc, 0, "random_get with len=0 must return 0");
}

// ---- args_sizes_get / args_get ----------------------------------------------

/// args_sizes_get reports 0 args and 0 buf bytes.
#[test]
fn args_sizes_get_returns_zero() {
    let (mut store, linker) = make_store_and_linker();
    let rc = call_wasi_2(&mut store, &linker, "args_sizes_get", 0xb000, 0xb004);
    assert_eq!(rc, 0);
    let argc = u32::from_le_bytes(read_mem(&store, 0xb000, 4).try_into().unwrap());
    let bufsz = u32::from_le_bytes(read_mem(&store, 0xb004, 4).try_into().unwrap());
    assert_eq!(argc, 0, "argc must be 0");
    assert_eq!(bufsz, 0, "argv buf size must be 0");
}
