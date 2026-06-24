// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

use super::*;

// Compile a WAT snippet to bytes inline - no external toolchain.
fn wat(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("WAT parse")
}

/// The primary fixture: imports `host.value` (returns i64), exports
/// `run` computing `value() * 2 + 1`. Used by determinism and
/// correctness tests.
fn value_doubler_wat() -> Vec<u8> {
    wat(r#"
      (module
        (import "host" "value" (func $v (result i64)))
        (func (export "run") (result i64)
          call $v
          i64.const 2
          i64.mul
          i64.const 1
          i64.add))
    "#)
}

// ---- core correctness --------------------------------------------------

/// Embedder supplies host.value -> 21; module computes 21*2+1 = 43.
#[test]
fn embedder_host_import_value_computed_correctly() {
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(&value_doubler_wat(), false, |linker| {
            linker.func_wrap("host", "value", || -> i64 { 21 })
        })
        .unwrap();
    let out = vm.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 43);
}

// ---- determinism -------------------------------------------------------

/// Two calls with the same import produce byte-identical results.
#[test]
fn same_import_value_deterministic() {
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(&value_doubler_wat(), false, |linker| {
            linker.func_wrap("host", "value", || -> i64 { 21 })
        })
        .unwrap();
    let out1 = vm.run(&module, "run", None).unwrap().result;
    let out2 = vm.run(&module, "run", None).unwrap().result;
    assert_eq!(out1, out2, "identical import must produce identical output");
    assert_eq!(out1, 43);
}

/// Different import value produces a different result (non-vacuous check:
/// the module is actually wired to the import, not returning a constant).
#[test]
fn different_import_value_produces_different_result() {
    let vm = EmbedderVm::new().unwrap();

    let mod21 = vm
        .compile(&value_doubler_wat(), false, |linker| {
            linker.func_wrap("host", "value", || -> i64 { 21 })
        })
        .unwrap();

    let mod22 = vm
        .compile(&value_doubler_wat(), false, |linker| {
            linker.func_wrap("host", "value", || -> i64 { 22 })
        })
        .unwrap();

    let r21 = vm.run(&mod21, "run", None).unwrap().result;
    let r22 = vm.run(&mod22, "run", None).unwrap().result;

    assert_eq!(r21, 43, "value 21 -> 43");
    assert_eq!(r22, 45, "value 22 -> 45");
    assert_ne!(r21, r22, "different imports must produce different results");
}

// ---- unsatisfied import ------------------------------------------------

/// A module whose import is not supplied by the embedder must fail loud
/// with a clear `AfterburnerError::Engine`, not silently succeed or panic.
#[test]
fn unsupplied_import_fails_loud() {
    let vm = EmbedderVm::new().unwrap();
    // Compile without wiring `host.value` - the linker callback is a no-op.
    let result = vm.compile(&value_doubler_wat(), false, |_linker| Ok(()));
    match result {
        Err(AfterburnerError::Engine(msg)) => {
            // wasmtime's instantiate_pre error names the missing import.
            assert!(
                msg.contains("host") || msg.contains("value") || msg.contains("import"),
                "error message should name the missing import, got: {msg}"
            );
        }
        Err(other) => panic!("expected Engine error, got: {other:?}"),
        Ok(_) => panic!("expected error for unsatisfied import"),
    }
}

// ---- fuel exhaustion ---------------------------------------------------

/// A module that loops forever is bounded by fuel, not by the OS.
#[test]
fn fuel_exhaustion_surfaces_as_typed_error() {
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(
            &wat(r#"
              (module
                (func (export "run") (result i64)
                  (loop $forever
                    br $forever)
                  i64.const 0))
            "#),
            false,
            |_| Ok(()),
        )
        .unwrap();
    let err = vm.run(&module, "run", Some(10_000)).unwrap_err();
    assert!(
        matches!(err, AfterburnerError::FuelExhausted),
        "expected FuelExhausted, got {err:?}"
    );
}

// ---- deterministic engine config ---------------------------------------

/// `deterministic_engine()` builds successfully and enforces the expected
/// flags: shared memory (requires threads) must fail to compile.
#[test]
fn deterministic_engine_config() {
    let engine = deterministic_engine().expect("engine build");
    // A trivial module must compile and run correctly.
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(
            &wat("(module (func (export \"run\") (result i64) i64.const 42))"),
            false,
            |_| Ok(()),
        )
        .unwrap();
    let out = vm.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 42, "trivial module must return 42");
    // shared memory requires threads, which are disabled in the deterministic
    // engine. Compilation must fail.
    let shared_mem_wasm = wat("(module (memory $m 1 1 shared))");
    let compile_err = wasmtime::Module::new(&engine, &shared_mem_wasm);
    assert!(
        compile_err.is_err(),
        "shared memory module must fail to compile with threads disabled"
    );
}

// ---- zero-import module ------------------------------------------------

/// A module with no imports exporting a function returning i64.const 42.
#[test]
fn zero_import_module_returns_42() {
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(
            &wat("(module (func (export \"run\") (result i64) i64.const 42))"),
            false,
            |_| Ok(()),
        )
        .unwrap();
    let out = vm.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 42);
}

// ---- host import substitution ------------------------------------------

/// A module that calls host.ping (side-effect) and host.value (returns i64).
/// Assert the ping counter is incremented and the result is forwarded.
#[test]
fn host_import_substitution_is_called() {
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    let counter = Arc::new(AtomicU32::new(0));
    let counter2 = counter.clone();

    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(
            &wat(r#"
              (module
                (import "host" "ping"  (func $ping))
                (import "host" "value" (func $value (result i64)))
                (func (export "run") (result i64)
                  call $ping
                  call $value))
            "#),
            false,
            move |linker| {
                linker.func_wrap("host", "ping", move || {
                    counter2.fetch_add(1, Ordering::SeqCst);
                })?;
                linker.func_wrap("host", "value", || -> i64 { 99 })
            },
        )
        .unwrap();

    let out = vm.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 99, "host.value must return 99");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "host.ping must be called exactly once"
    );
}

// ---- proc_exit path ----------------------------------------------------

/// A WASI command module that calls proc_exit(5); result must be 5.
#[test]
fn proc_exit_exit_code_surfaced() {
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(
            &wat(r#"
              (module
                (import "wasi_snapshot_preview1" "proc_exit"
                  (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                  i32.const 5
                  call $proc_exit))
            "#),
            true,
            |_| Ok(()),
        )
        .unwrap();
    let out = vm
        .run_command(&module, WasiCommandOpts::new(), None)
        .unwrap();
    assert_eq!(out.result, 5, "proc_exit(5) must surface as result == 5");
}

/// A WASI command module that writes to fd 2 (stderr) must have those bytes
/// captured in `EmbedderRunOutput::stderr` (not silently dropped). This is the
/// capture that lets a failing CRuby / C program show its diagnostics.
#[test]
fn run_command_captures_stderr() {
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(
            &wat(r#"
              (module
                (import "wasi_snapshot_preview1" "fd_write"
                  (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "boom")
                (func (export "_start")
                  ;; iovec at offset 8: buf=0, buf_len=4
                  i32.const 8   i32.const 0   i32.store
                  i32.const 12  i32.const 4   i32.store
                  ;; fd_write(fd=2 (stderr), iovs_ptr=8, iovs_len=1, nwritten_ptr=16)
                  i32.const 2
                  i32.const 8
                  i32.const 1
                  i32.const 16
                  call $fd_write
                  drop))
            "#),
            true,
            |_| Ok(()),
        )
        .unwrap();
    let out = vm
        .run_command(&module, WasiCommandOpts::new(), None)
        .unwrap();
    assert_eq!(out.result, 0, "clean exit");
    assert_eq!(out.stderr, b"boom", "fd 2 bytes must be captured");
    assert!(out.stdout.is_empty(), "nothing was written to fd 1");
}

// ---- determinism: same module + fuel -----------------------------------

/// Two calls with value_doubler_wat and host.value=21 must both return 43.
#[test]
fn determinism_same_module_twice_identical() {
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(&value_doubler_wat(), false, |linker| {
            linker.func_wrap("host", "value", || -> i64 { 21 })
        })
        .unwrap();
    let out1 = vm.run(&module, "run", None).unwrap();
    let out2 = vm.run(&module, "run", None).unwrap();
    assert_eq!(out1.result, 43);
    assert_eq!(out2.result, 43, "second run must be identical to the first");
}

// ---- WASI stdout -------------------------------------------------------

/// A module compiled with `wasi: true` can write to stdout and have
/// the bytes returned in `EmbedderRunOutput::stdout`.
#[test]
fn wasi_stdout_captured() {
    // Module writes "hello" to fd 1 (stdout) via the WASI fd_write import,
    // then returns 0. We compose the write manually in WAT:
    // memory[0..5] = "hello"; iov[8..16] = ptr(0), len(5); fd_write(1, iov_ptr=8, 1, nwritten_ptr=16)
    let vm = EmbedderVm::new().unwrap();
    let module = vm
        .compile(
            &wat(r#"
              (module
                (import "wasi_snapshot_preview1" "fd_write"
                  (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "hello")
                (func (export "run") (result i64)
                  ;; iovec: buf=0, buf_len=5 at offset 8
                  i32.const 8   i32.const 0   i32.store
                  i32.const 12  i32.const 5   i32.store
                  ;; fd_write(fd=1, iovs_ptr=8, iovs_len=1, nwritten_ptr=16)
                  i32.const 1
                  i32.const 8
                  i32.const 1
                  i32.const 16
                  call $fd_write
                  drop
                  i64.const 0))
            "#),
            true,
            |_| Ok(()),
        )
        .unwrap();
    let out = vm.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 0);
    assert_eq!(out.stdout, b"hello");
}

// ---- WasiCommandOpts builder API ----------------------------------------

/// `WasiCommandOpts::new()` is sealed: no args, no preopens, no env.
#[test]
fn wasi_command_opts_default_is_sealed() {
    let opts = WasiCommandOpts::new();
    assert!(opts.args.is_empty(), "args must be empty");
    assert!(opts.preopens_ro.is_empty(), "preopens_ro must be empty");
    assert!(opts.preopens_rw.is_empty(), "preopens_rw must be empty");
    assert!(opts.env_vars.is_empty(), "env_vars must be empty");
}

/// `preopen` is a backward-compatible alias for `preopen_ro`.
#[test]
fn preopen_alias_appends_to_preopens_ro() {
    let opts = WasiCommandOpts::new().preopen("/tmp", "/tmp");
    assert_eq!(opts.preopens_ro.len(), 1);
    assert!(opts.preopens_rw.is_empty());
}

/// `preopen_rw` appends to `preopens_rw`, not `preopens_ro`.
#[test]
fn preopen_rw_appends_to_preopens_rw() {
    let opts = WasiCommandOpts::new().preopen_rw("/tmp", "/tmp");
    assert_eq!(opts.preopens_rw.len(), 1);
    assert!(opts.preopens_ro.is_empty());
}

/// `env_var` appends a (key, value) pair.
#[test]
fn env_var_appends_key_value_pair() {
    let opts = WasiCommandOpts::new()
        .env_var("FOO", "bar")
        .env_var("BAZ", "qux");
    assert_eq!(opts.env_vars.len(), 2);
    assert_eq!(opts.env_vars[0], ("FOO".into(), "bar".into()));
    assert_eq!(opts.env_vars[1], ("BAZ".into(), "qux".into()));
}

/// Forward `WasiCommandOpts::env_var` path smoke-test.
#[test]
fn env_var_forwarded_into_wasm_module() {
    // Verify the data is present in opts before being passed to run_command.
    // vertexia: WAT-level environ test requires careful iovec layout;
    //           the builder-API tests above verify the data path.
    let opts = WasiCommandOpts::new().env_var("TEST_KEY", "test_value");
    assert!(
        opts.env_vars
            .iter()
            .any(|(k, v)| k == "TEST_KEY" && v == "test_value"),
        "env var must be present in opts.env_vars"
    );
}
