// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Tests for the __syscall_* filesystem shims (emscripten_syscall.rs).
//!
//! All tests: write test bytes into a small wasm Memory, call the shim via
//! a linker-wired WAT module, and assert captured or returned results.

use super::*;
use crate::{embedder_vm::EmbedderState, emscripten_runtime::MechCallLog};
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
// Build a Store with EmbedderState::headless(), a 2-page wasm Memory wired as
// pyodide_memory, and all __syscall_* shims registered in the linker.

fn make_store_and_linker() -> (Store<EmbedderState>, Linker<EmbedderState>) {
    let engine = &ENGINE;
    let mut store = Store::new(engine, EmbedderState::headless());
    store.set_fuel(100_000_000).expect("set_fuel");

    // 2-page memory (128 KiB) - more than enough for all test offsets.
    let mem_ty = MemoryType::new(2, None);
    let mem = Memory::new(&mut store, mem_ty).expect("memory");
    store.data_mut().pyodide_memory = Some(mem);

    let mech_log = MechCallLog::new();
    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    wire_fs_env_funcs(&mut linker, mech_log).expect("wire");

    // Expose the memory as env.memory so modules can import it.
    linker
        .define(&mut store, "env", "memory", wasmtime::Extern::Memory(mem))
        .expect("define memory");

    (store, linker)
}

// Helper: write bytes into the wasm memory at offset `addr`.
fn write_mem(store: &mut Store<EmbedderState>, addr: usize, data: &[u8]) {
    let mem = store.data().pyodide_memory.expect("mem");
    mem.data_mut(store)[addr..addr + data.len()].copy_from_slice(data);
}

// Helper: read bytes from wasm memory at offset `addr`, length `len`.
fn read_mem(store: &Store<EmbedderState>, addr: usize, len: usize) -> Vec<u8> {
    let mem = store.data().pyodide_memory.expect("mem");
    mem.data(store)[addr..addr + len].to_vec()
}

fn call_shim_2(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    name: &str,
    a: i32,
    b: i32,
) -> i32 {
    let wat_src = format!(
        r#"(module
          (import "env" "memory" (memory 1))
          (import "env" "{name}" (func $f (param i32 i32) (result i32)))
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
    let f = instance
        .get_typed_func::<(), i32>(&mut *store, "run")
        .expect("run");
    f.call(&mut *store, ()).expect("call")
}

fn call_shim_3(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    name: &str,
    a: i32,
    b: i32,
    c: i32,
) -> i32 {
    let wat_src = format!(
        r#"(module
          (import "env" "memory" (memory 1))
          (import "env" "{name}" (func $f (param i32 i32 i32) (result i32)))
          (func (export "run") (result i32)
            i32.const {a}
            i32.const {b}
            i32.const {c}
            call $f))"#
    );
    let wasm = wat::parse_str(&wat_src).expect("WAT");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut *store, &module)
        .expect("instantiate");
    let f = instance
        .get_typed_func::<(), i32>(&mut *store, "run")
        .expect("run");
    f.call(&mut *store, ()).expect("call")
}

fn call_shim_4(
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
          (import "env" "memory" (memory 1))
          (import "env" "{name}" (func $f (param i32 i32 i32 i32) (result i32)))
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
    let f = instance
        .get_typed_func::<(), i32>(&mut *store, "run")
        .expect("run");
    f.call(&mut *store, ()).expect("call")
}

// ---- __syscall_write --------------------------------------------------------

/// fd 1 (stdout): bytes go to wasi_stdout.
#[test]
fn syscall_write_fd1_appends_to_wasi_stdout() {
    let (mut store, linker) = make_store_and_linker();
    // Write "hi" at offset 0x100
    write_mem(&mut store, 0x100, b"hi");
    // call __syscall_write(fd=1, buf=0x100, count=2)
    let rc = call_shim_3(&mut store, &linker, "__syscall_write", 1, 0x100, 2);
    assert_eq!(rc, 2, "write should return byte count");
    assert_eq!(store.data().wasi_stdout, b"hi");
}

/// fd 2 (stderr) also routes to wasi_stdout buffer.
#[test]
fn syscall_write_fd2_appends_to_wasi_stdout() {
    let (mut store, linker) = make_store_and_linker();
    write_mem(&mut store, 0x200, b"err");
    let rc = call_shim_3(&mut store, &linker, "__syscall_write", 2, 0x200, 3);
    assert_eq!(rc, 3);
    assert_eq!(store.data().wasi_stdout, b"err");
}

/// File fd: bytes written to the MEMFS node.
#[test]
fn syscall_write_file_fd_appends_to_fs() {
    let (mut store, linker) = make_store_and_linker();
    // Create a file in the FS first.
    store.data_mut().fs.insert_file("/tmp/out.txt", Vec::new());
    // Open it (flags: O_WRONLY=1 | O_CREAT=64 -> 65, but file exists so 1 suffices)
    let fd = store
        .data_mut()
        .fs
        .open("/tmp/out.txt".to_owned(), 1 /* O_WRONLY */);
    assert!(fd >= 3, "expected valid fd, got {fd}");

    write_mem(&mut store, 0x300, b"world");
    let rc = call_shim_3(&mut store, &linker, "__syscall_write", fd, 0x300, 5);
    assert_eq!(rc, 5, "write to file fd should return 5");

    // Verify the FS node contains the written bytes.
    let contents = store.data().fs.read_file("/tmp/out.txt").expect("file");
    assert_eq!(contents, b"world");
}

/// Invalid fd returns EBADF (-9).
#[test]
fn syscall_write_bad_fd_returns_ebadf() {
    let (mut store, linker) = make_store_and_linker();
    write_mem(&mut store, 0x400, b"x");
    let rc = call_shim_3(&mut store, &linker, "__syscall_write", 42, 0x400, 1);
    assert_eq!(rc, -9, "bad fd must return EBADF=-9");
}

// ---- __syscall_writev -------------------------------------------------------

/// writev over fd 1 concatenates two iovecs into wasi_stdout.
#[test]
fn syscall_writev_fd1_concatenates_iovecs() {
    let (mut store, linker) = make_store_and_linker();
    // Memory layout:
    //   0x1000: "foo" (3 bytes)
    //   0x1010: "bar" (3 bytes)
    //   0x1020: iovec[0] = {buf_ptr=0x1000, buf_len=3} (8 bytes)
    //   0x1028: iovec[1] = {buf_ptr=0x1010, buf_len=3} (8 bytes)
    write_mem(&mut store, 0x1000, b"foo");
    write_mem(&mut store, 0x1010, b"bar");
    // iovec[0]
    write_mem(&mut store, 0x1020, &(0x1000u32).to_le_bytes());
    write_mem(&mut store, 0x1024, &(3u32).to_le_bytes());
    // iovec[1]
    write_mem(&mut store, 0x1028, &(0x1010u32).to_le_bytes());
    write_mem(&mut store, 0x102c, &(3u32).to_le_bytes());

    let rc = call_shim_3(&mut store, &linker, "__syscall_writev", 1, 0x1020, 2);
    assert_eq!(rc, 6, "writev should return total byte count");
    assert_eq!(store.data().wasi_stdout, b"foobar");
}

// ---- __syscall_openat -------------------------------------------------------

/// O_CREAT creates a new file and returns a valid fd.
#[test]
fn syscall_openat_o_creat_returns_valid_fd() {
    let (mut store, linker) = make_store_and_linker();
    // Write path "/newfile.txt\0" at offset 0x500
    let path = b"/newfile.txt\0";
    write_mem(&mut store, 0x500, path);
    // dirfd=-100 (AT_FDCWD), pathptr=0x500, flags=O_CREAT(64)|O_WRONLY(1)=65, mode=0
    let fd = call_shim_4(&mut store, &linker, "__syscall_openat", -100, 0x500, 65, 0);
    assert!(fd >= 3, "openat O_CREAT must return fd >= 3, got {fd}");
    // Confirm the file now exists in the FS.
    assert!(store.data().fs.exists("/newfile.txt"));
}

/// Opening a non-existent file without O_CREAT returns ENOENT (-2).
#[test]
fn syscall_openat_missing_file_returns_enoent() {
    let (mut store, linker) = make_store_and_linker();
    let path = b"/nonexistent.txt\0";
    write_mem(&mut store, 0x600, path);
    // flags=0 (no O_CREAT)
    let rc = call_shim_4(&mut store, &linker, "__syscall_openat", -100, 0x600, 0, 0);
    assert_eq!(rc, -2, "missing file without O_CREAT must return ENOENT=-2");
}

// ---- __syscall_fstat64 ------------------------------------------------------

/// fstat64 on a valid file fd fills the stat buffer: st_size at offset 24.
#[test]
fn syscall_fstat64_fills_stat_buf_st_size() {
    let (mut store, linker) = make_store_and_linker();
    store
        .data_mut()
        .fs
        .insert_file("/fstat_test.txt", b"hello world".to_vec());
    let fd = store.data_mut().fs.open("/fstat_test.txt".to_owned(), 0);
    assert!(fd >= 3);

    // stat buffer at offset 0x700 (need 112 bytes)
    let stat_ptr = 0x700i32;
    let rc = call_shim_2(&mut store, &linker, "__syscall_fstat64", fd, stat_ptr);
    assert_eq!(rc, 0, "fstat64 must return 0 on success");

    // st_size is at offset 24 (i64 LE) in the Emscripten stat layout.
    let buf = read_mem(&store, 0x700, 112);
    let st_size = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    assert_eq!(st_size, 11, "st_size must be 11 (len of 'hello world')");

    // st_mode at offset 4: S_IFREG bit (0o100000) must be set.
    let st_mode = i32::from_le_bytes(buf[4..8].try_into().unwrap());
    assert!(
        st_mode & 0o100_000 != 0,
        "st_mode must have S_IFREG bit set, got 0o{st_mode:o}"
    );
}

/// fstat64 on an invalid fd returns EBADF.
#[test]
fn syscall_fstat64_bad_fd_returns_ebadf() {
    let (mut store, linker) = make_store_and_linker();
    let rc = call_shim_2(&mut store, &linker, "__syscall_fstat64", 42, 0x800);
    assert_eq!(rc, -9, "fstat64 on bad fd must return EBADF=-9");
}

// ---- __syscall_stat64 -------------------------------------------------------

/// stat64 on an existing path fills st_mode with S_IFREG.
#[test]
fn syscall_stat64_regular_file_has_s_ifreg() {
    let (mut store, linker) = make_store_and_linker();
    store
        .data_mut()
        .fs
        .insert_file("/stat_me.txt", b"abc".to_vec());

    let path = b"/stat_me.txt\0";
    write_mem(&mut store, 0x900, path);
    let stat_ptr = 0xa00i32;
    let rc = call_shim_2(&mut store, &linker, "__syscall_stat64", 0x900, stat_ptr);
    assert_eq!(rc, 0, "stat64 must return 0 for existing file");

    let buf = read_mem(&store, 0xa00, 112);
    let st_mode = i32::from_le_bytes(buf[4..8].try_into().unwrap());
    assert!(st_mode & 0o100_000 != 0, "S_IFREG bit must be set");
    let st_size = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    assert_eq!(st_size, 3, "st_size must be 3");
}

/// stat64 on a missing path returns ENOENT.
#[test]
fn syscall_stat64_missing_path_returns_enoent() {
    let (mut store, linker) = make_store_and_linker();
    let path = b"/no_such_file.txt\0";
    write_mem(&mut store, 0xb00, path);
    let rc = call_shim_2(&mut store, &linker, "__syscall_stat64", 0xb00, 0xc00);
    assert_eq!(rc, -2, "stat64 on missing path must return ENOENT=-2");
}

// ---- __syscall_getdents64 ---------------------------------------------------

/// getdents64 on a directory with children: first call returns > 0 bytes,
/// second call returns 0 (EOF).
#[test]
fn syscall_getdents64_records_and_eof() {
    let (mut store, linker) = make_store_and_linker();
    store.data_mut().fs.insert_file("/dir/a.py", b"".to_vec());
    store.data_mut().fs.insert_file("/dir/b.py", b"".to_vec());

    let fd = store.data_mut().fs.open("/dir".to_owned(), 0);
    assert!(fd >= 3, "expected valid fd");

    // dirp at offset 0xd00, count = 4096
    let dirp = 0xd00i32;
    let count = 4096i32;

    // First call: must return > 0 (dot entries + children).
    let n1 = call_shim_3(&mut store, &linker, "__syscall_getdents64", fd, dirp, count);
    assert!(n1 > 0, "first getdents64 call must return > 0, got {n1}");

    // Second call with large buffer: must eventually reach 0 (EOF).
    // Loop to drain remaining entries (in case single call didn't fit all).
    let mut remaining = true;
    let mut iterations = 0u32;
    while remaining {
        let n = call_shim_3(&mut store, &linker, "__syscall_getdents64", fd, dirp, count);
        assert!(n >= 0, "getdents64 must not return negative, got {n}");
        if n == 0 {
            remaining = false;
        }
        iterations += 1;
        assert!(iterations < 100, "getdents64 never reached EOF");
    }

    // One more call: must still return 0 (cursor stays at end).
    let n_extra = call_shim_3(&mut store, &linker, "__syscall_getdents64", fd, dirp, count);
    assert_eq!(n_extra, 0, "cursor must stay at EOF after exhaustion");
}

/// getdents64 on a bad fd returns a negative error.
#[test]
fn syscall_getdents64_bad_fd_returns_error() {
    let (mut store, linker) = make_store_and_linker();
    let rc = call_shim_3(
        &mut store,
        &linker,
        "__syscall_getdents64",
        99,
        0x1000,
        4096,
    );
    assert!(rc < 0, "bad fd must return negative errno, got {rc}");
}

// ---- __syscall_getcwd -------------------------------------------------------

/// getcwd writes "/" into guest memory and returns 2.
#[test]
fn syscall_getcwd_writes_root() {
    let (mut store, linker) = make_store_and_linker();
    let buf = 0x2000i32;
    let size = 64i32;
    let rc = call_shim_2(&mut store, &linker, "__syscall_getcwd", buf, size);
    assert_eq!(rc, 2, "getcwd must return 2 (bytes written including NUL)");
    let out = read_mem(&store, 0x2000, 2);
    assert_eq!(&out, b"/\0");
}
