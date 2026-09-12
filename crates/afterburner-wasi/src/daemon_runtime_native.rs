// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `NativeDaemonRuntime` - the non-JS counterpart to
//! [`crate::daemon_runtime::DaemonRuntime`]: a long-lived `Store` that
//! persists a compiled Rust / Go / C / C++ guest's own state (heap,
//! globals) across many `afterburner_daemon_dispatch` invocations.
//!
//! Full design and rationale: `docs/wasi-daemon-abi.md`. Short version: a
//! WASI *command* module exports only `_start` and is one-shot by
//! construction. A daemon-capable native guest additionally exports four
//! `i32`-only functions - `afterburner_alloc`, `afterburner_dealloc`,
//! `afterburner_daemon_init`, `afterburner_daemon_dispatch` - that the host
//! calls as many times as it wants, passing JSON envelopes as byte buffers
//! through the guest's own linear memory. [`daemon_shape`] decides,
//! purely from a compiled module's exports, whether it is daemon-shaped;
//! [`NativeDaemonRuntime`] owns the long-lived `Store` once it is.
//!
//! Deliberately independent of [`crate::embedder_vm::EmbedderVm`] /
//! `EmbedderState`: that type carries a large amount of Pyodide/Emscripten-
//! only state (side-module registries, FFI closure tables, syscall shims)
//! that a plain Rust/Go/C/C++ reactor has no use for. This file reuses the
//! pieces that generalize - [`crate::embedder_vm::deterministic_engine`],
//! [`crate::embedder_vm::WasiCommandOpts`], and `daemon_runtime`'s
//! (private) `map_daemon_trap` - and nothing else.

use crate::daemon_runtime::map_daemon_trap;
use crate::embedder_vm::{WasiCommandOpts, deterministic_engine};
use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Instance, Linker, Memory, Module, Store, StoreLimits, TypedFunc};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{WasiP1Ctx, add_to_linker_sync};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};

/// Fuel budget applied fresh before every `afterburner_daemon_init` /
/// `afterburner_daemon_dispatch` call. Matches
/// [`crate::embedder_vm`]'s `DEFAULT_FUEL` for one-shot native runs: a
/// daemon handler gets the same per-call compute budget the same code
/// would get running once. Reset (not accumulated) per call - see
/// `docs/wasi-daemon-abi.md`'s "Fuel, memory, timeout" section for why a
/// fixed one-time budget would starve every request after the first few.
pub const NATIVE_DAEMON_FUEL_PER_CALL: u64 = 100_000_000;

/// The four exports a daemon-capable native guest must provide, and their
/// required `i32`-only signatures. Order matches the calling convention
/// doc: allocate, free, init, dispatch.
const REQUIRED_EXPORTS: &[(&str, usize, usize)] = &[
    ("afterburner_alloc", 1, 1),
    ("afterburner_dealloc", 2, 0),
    ("afterburner_daemon_init", 2, 1),
    ("afterburner_daemon_dispatch", 2, 1),
];

/// A port a daemon-shaped guest's `afterburner_daemon_init` response asked
/// the host to bind. See `docs/wasi-daemon-abi.md`'s "How the guest asks
/// the host to listen" - there is no `.listen()` host import in this ABI;
/// the guest declares intent in the init response instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeListenSpec {
    pub port: u16,
}

/// Outcome of inspecting a compiled module's exports for the daemon ABI.
#[derive(Debug)]
pub enum NativeDaemonShape {
    /// None of the four required exports are present - a plain one-shot
    /// WASI command module. The existing `run_command` path is unchanged.
    OneShot,
    /// All four required exports are present with the expected
    /// `i32`-only signatures.
    Daemon,
    /// Some but not all of the four exports are present, or one is
    /// present with a mismatched signature. Almost certainly a build the
    /// author got wrong (a typo'd export name, a missing
    /// `afterburner_alloc`); `burn` refuses to guess and fails loudly
    /// naming exactly what is missing or mismatched, rather than silently
    /// falling back to one-shot.
    Malformed(String),
}

/// Compile `wasm` and classify it per [`NativeDaemonShape`], without
/// instantiating it. The CLI's `run` dispatch calls this up front to
/// decide between the native daemon driver and the existing one-shot
/// `run_command` path *before* committing to either - the two paths
/// build `Store`s with different lifetimes and neither should pay for
/// the other's setup. Compiling twice (once here, once more inside
/// [`NativeDaemonRuntime::instantiate`] when the answer is `Daemon`) is
/// deliberate: `deterministic_engine`'s on-disk compile cache (see its
/// own doc) makes the second compile of the same bytes a cache hit, and
/// avoiding it would mean threading a compiled `Module` through the CLI's
/// existing one-shot call sites, which is a larger, riskier change than
/// this one-time, cache-absorbed extra compile.
/// `// vertexia: double-compile on the daemon-detect path, cache-absorbed;
/// threading the already-compiled Module through instead is the upgrade
/// path if the cache ever proves insufficient.`
pub fn probe(wasm: &[u8]) -> Result<NativeDaemonShape> {
    let engine = deterministic_engine()?;
    let module = Module::new(&engine, wasm)
        .map_err(|e| AfterburnerError::CompileFailed(format!("native daemon probe: {e}")))?;
    Ok(daemon_shape(&module))
}

/// Inspect `module`'s exports and classify it per [`NativeDaemonShape`].
/// Pure static introspection - no instantiation, no side effects.
pub fn daemon_shape(module: &Module) -> NativeDaemonShape {
    let mut present: Vec<&str> = Vec::new();
    let mut mismatched: Vec<String> = Vec::new();

    for &(name, want_params, want_results) in REQUIRED_EXPORTS {
        let Some(export) = module.exports().find(|e| e.name() == name) else {
            continue;
        };
        present.push(name);
        let Some(func_ty) = export.ty().func().cloned() else {
            mismatched.push(format!("{name} (not a function export)"));
            continue;
        };
        let params_ok = func_ty.params().len() == want_params
            && func_ty
                .params()
                .all(|p| matches!(p, wasmtime::ValType::I32));
        let results_ok = func_ty.results().len() == want_results
            && func_ty
                .results()
                .all(|r| matches!(r, wasmtime::ValType::I32));
        if !params_ok || !results_ok {
            mismatched.push(format!(
                "{name} (expected {want_params} i32 param(s) / {want_results} i32 result(s), \
                 got {} param(s) / {} result(s))",
                func_ty.params().len(),
                func_ty.results().len()
            ));
        }
    }

    if present.is_empty() {
        return NativeDaemonShape::OneShot;
    }
    if !mismatched.is_empty() || present.len() < REQUIRED_EXPORTS.len() {
        let missing: Vec<&str> = REQUIRED_EXPORTS
            .iter()
            .map(|&(name, _, _)| name)
            .filter(|name| !present.contains(name))
            .collect();
        let mut reasons = Vec::new();
        if !missing.is_empty() {
            reasons.push(format!("missing export(s): {}", missing.join(", ")));
        }
        if !mismatched.is_empty() {
            reasons.push(format!("mismatched export(s): {}", mismatched.join(", ")));
        }
        return NativeDaemonShape::Malformed(format!(
            "this module exports some but not all of the daemon ABI \
             (afterburner_alloc, afterburner_dealloc, afterburner_daemon_init, \
             afterburner_daemon_dispatch): {}. Export all four with i32-only \
             signatures to run as a daemon, or none of them to run as a \
             one-shot program.",
            reasons.join("; ")
        ));
    }
    NativeDaemonShape::Daemon
}

/// Per-call store state: plain WASI preview-1 context plus an optional
/// memory cap. Nothing else - a daemon-capable native guest imports no
/// afterburner-specific host functions at all (see the module doc).
struct NativeDaemonState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// Long-lived handle to a daemon-shaped native guest instance. Owns the
/// `Store`, the four typed exports, and the guest's `memory` export.
pub struct NativeDaemonRuntime {
    store: Store<NativeDaemonState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    dealloc: TypedFunc<(i32, i32), ()>,
    daemon_init: TypedFunc<(i32, i32), i32>,
    daemon_dispatch: TypedFunc<(i32, i32), i32>,
    stdout: MemoryOutputPipe,
    stderr: MemoryOutputPipe,
}

impl std::fmt::Debug for NativeDaemonRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeDaemonRuntime")
            .finish_non_exhaustive()
    }
}

impl NativeDaemonRuntime {
    /// Compile `wasm`, instantiate it, run its entry point (if any -
    /// `_start` for a command module, `_initialize` for a reactor, or
    /// nothing for a Rust `#![no_main]` cdylib), and return a handle ready
    /// for [`Self::call_init`]. Fails if `wasm` is not daemon-shaped
    /// (callers should check [`daemon_shape`] first) or if the entry
    /// point traps / exits non-zero.
    pub fn instantiate(wasm: &[u8], opts: WasiCommandOpts) -> Result<Self> {
        let engine = deterministic_engine()?;
        let module = Module::new(&engine, wasm)
            .map_err(|e| AfterburnerError::CompileFailed(format!("native daemon compile: {e}")))?;

        if let NativeDaemonShape::Malformed(reason) = daemon_shape(&module) {
            return Err(AfterburnerError::Engine(reason));
        }

        let mut linker: Linker<NativeDaemonState> = Linker::new(&engine);
        add_to_linker_sync(&mut linker, |s: &mut NativeDaemonState| &mut s.wasi)
            .map_err(|e| AfterburnerError::Engine(format!("native daemon wasi linker: {e}")))?;

        let stdout = MemoryOutputPipe::new(4 * 1024 * 1024);
        let stderr = MemoryOutputPipe::new(4 * 1024 * 1024);

        let mut builder = WasiCtxBuilder::new();
        builder.stdout(stdout.clone()).stderr(stderr.clone());
        if let Some(bytes) = &opts.stdin {
            builder.stdin(MemoryInputPipe::new(bytes.clone()));
        }
        if !opts.args.is_empty() {
            builder.args(&opts.args);
        }
        for (key, val) in &opts.env_vars {
            builder.env(key, val);
        }
        for (host_path, guest_path) in &opts.preopens_ro {
            builder
                .preopened_dir(
                    host_path,
                    guest_path,
                    wasmtime_wasi::DirPerms::READ,
                    wasmtime_wasi::FilePerms::READ,
                )
                .map_err(|e| {
                    AfterburnerError::Engine(format!(
                        "native daemon preopen-ro {}: {e}",
                        host_path.display()
                    ))
                })?;
        }
        for (host_path, guest_path) in &opts.preopens_rw {
            builder
                .preopened_dir(
                    host_path,
                    guest_path,
                    wasmtime_wasi::DirPerms::all(),
                    wasmtime_wasi::FilePerms::all(),
                )
                .map_err(|e| {
                    AfterburnerError::Engine(format!(
                        "native daemon preopen-rw {}: {e}",
                        host_path.display()
                    ))
                })?;
        }

        let limits = opts
            .max_memory_bytes
            .map(|max| wasmtime::StoreLimitsBuilder::new().memory_size(max).build())
            .unwrap_or_default();
        let state = NativeDaemonState {
            wasi: builder.build_p1(),
            limits,
        };

        let mut store = Store::new(&engine, state);
        if opts.max_memory_bytes.is_some() {
            store.limiter(|s: &mut NativeDaemonState| &mut s.limits);
        }
        store
            .set_fuel(NATIVE_DAEMON_FUEL_PER_CALL)
            .map_err(|e| AfterburnerError::Engine(format!("native daemon set_fuel: {e}")))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| AfterburnerError::Engine(format!("native daemon instantiate: {e}")))?;

        Self::run_entry_point(&mut store, &instance)?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| AfterburnerError::Engine("native daemon: no `memory` export".into()))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "afterburner_alloc")
            .map_err(|e| AfterburnerError::Engine(format!("afterburner_alloc lookup: {e}")))?;
        let dealloc = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "afterburner_dealloc")
            .map_err(|e| AfterburnerError::Engine(format!("afterburner_dealloc lookup: {e}")))?;
        let daemon_init = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "afterburner_daemon_init")
            .map_err(|e| {
                AfterburnerError::Engine(format!("afterburner_daemon_init lookup: {e}"))
            })?;
        let daemon_dispatch = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "afterburner_daemon_dispatch")
            .map_err(|e| {
                AfterburnerError::Engine(format!("afterburner_daemon_dispatch lookup: {e}"))
            })?;

        Ok(Self {
            store,
            memory,
            alloc,
            dealloc,
            daemon_init,
            daemon_dispatch,
            stdout,
            stderr,
        })
    }

    /// Run the module's entry point exactly once, before any daemon
    /// export is called. See `docs/wasi-daemon-abi.md`'s "Instance
    /// lifecycle" for the full per-case rationale; short version,
    /// confirmed by direct testing against real Rust/C/Go builds:
    ///
    /// * `_start` present (a command module - normal Rust/C/C++ `main()`,
    ///   or Go's `//go:wasmexport` reactor mode): call it. A clean return,
    ///   or a trap carrying `I32Exit(0)`, is success (Go's reactor mode
    ///   always signals completion via `I32Exit(0)`; Rust/C's `main()`
    ///   returning is a plain return). `I32Exit(n)` for `n != 0` or any
    ///   other trap fails instantiate.
    /// * Else `_initialize` present (a C/C++ reactor built with
    ///   `-mexec-model=reactor`): call it; any trap fails instantiate.
    /// * Else (a Rust `#![no_main]` cdylib): nothing to call.
    fn run_entry_point(store: &mut Store<NativeDaemonState>, instance: &Instance) -> Result<()> {
        if let Some(start) = instance.get_func(&mut *store, "_start") {
            let typed = start
                .typed::<(), ()>(&*store)
                .map_err(|e| AfterburnerError::Engine(format!("_start signature: {e}")))?;
            match typed.call(&mut *store, ()) {
                Ok(()) => {}
                Err(e) => {
                    let mapped = map_daemon_trap("native daemon entry (_start)", e);
                    match mapped {
                        AfterburnerError::ProcessExit(0) => {}
                        other => return Err(other),
                    }
                }
            }
        } else if let Some(init) = instance.get_func(&mut *store, "_initialize") {
            let typed = init
                .typed::<(), ()>(&*store)
                .map_err(|e| AfterburnerError::Engine(format!("_initialize signature: {e}")))?;
            typed
                .call(&mut *store, ())
                .map_err(|e| map_daemon_trap("native daemon entry (_initialize)", e))?;
        }
        Ok(())
    }

    /// Write `bytes` into a freshly `afterburner_alloc`'d guest buffer and
    /// return its `(ptr, len)`.
    fn write_buffer(&mut self, bytes: &[u8]) -> Result<(i32, i32)> {
        let len = bytes.len() as i32;
        let ptr = self
            .alloc
            .call(&mut self.store, len)
            .map_err(|e| map_daemon_trap("afterburner_alloc", e))?;
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .map_err(|e| {
                AfterburnerError::Engine(format!("native daemon: writing guest memory: {e}"))
            })?;
        Ok((ptr, len))
    }

    /// Read the 8-byte response header at `header_ptr`
    /// (`[result_ptr: u32 LE][result_len: u32 LE]`), then the response
    /// bytes it points at, then free both the header and the response
    /// buffer via `afterburner_dealloc` - the host is responsible for
    /// freeing every guest-allocated buffer it consumes, per the ABI's
    /// ownership rule (see `docs/wasi-daemon-abi.md`).
    fn read_and_free_response(&mut self, header_ptr: i32) -> Result<Vec<u8>> {
        let mut header = [0u8; 8];
        self.memory
            .read(&self.store, header_ptr as usize, &mut header)
            .map_err(|e| {
                AfterburnerError::Engine(format!("native daemon: reading response header: {e}"))
            })?;
        let result_ptr = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let result_len = u32::from_le_bytes(header[4..8].try_into().unwrap());

        let mut result = vec![0u8; result_len as usize];
        self.memory
            .read(&self.store, result_ptr as usize, &mut result)
            .map_err(|e| {
                AfterburnerError::Engine(format!("native daemon: reading response body: {e}"))
            })?;

        // Best-effort frees: a guest that mis-sized its own allocation
        // (freeing more or fewer bytes than it allocated) is a guest bug,
        // but it must never take down an otherwise-successful response -
        // the response bytes are already copied out above.
        let _ = self
            .dealloc
            .call(&mut self.store, (result_ptr as i32, result_len as i32));
        let _ = self.dealloc.call(&mut self.store, (header_ptr, 8));

        Ok(result)
    }

    /// Shared body of [`Self::call_init`] / [`Self::call_dispatch`]:
    /// replenish fuel, write `envelope` into guest memory, call `func`,
    /// free the request buffer, and read + free the response.
    fn call_native(
        &mut self,
        func: TypedFunc<(i32, i32), i32>,
        phase: &'static str,
        envelope: &[u8],
    ) -> Result<Vec<u8>> {
        self.store
            .set_fuel(NATIVE_DAEMON_FUEL_PER_CALL)
            .map_err(|e| AfterburnerError::Engine(format!("native daemon set_fuel: {e}")))?;

        let (req_ptr, req_len) = self.write_buffer(envelope)?;
        let header_ptr = func
            .call(&mut self.store, (req_ptr, req_len))
            .map_err(|e| map_daemon_trap(phase, e))?;
        let _ = self.dealloc.call(&mut self.store, (req_ptr, req_len));

        self.read_and_free_response(header_ptr)
    }

    /// Call `afterburner_daemon_init` once with the init envelope
    /// (`{"mode":"daemon-init","argv":[...],"env":{...},"cwd":"..."}`).
    /// Returns the raw JSON response bytes; the caller parses it with
    /// [`crate::daemon_envelopes::parse_native_init_response`].
    pub fn call_init(&mut self, envelope: &[u8]) -> Result<Vec<u8>> {
        let f = self.daemon_init.clone();
        self.call_native(f, "native daemon-init", envelope)
    }

    /// Call `afterburner_daemon_dispatch` once with a request envelope
    /// (the same shape [`crate::daemon_envelopes::http_event_to_envelope`]
    /// produces for the JS path). Returns the raw JSON response bytes; the
    /// caller parses it with
    /// [`crate::daemon_envelopes::parse_native_dispatch_response`].
    ///
    /// A trap here is fatal to the instance (see `docs/wasi-daemon-abi.md`'s
    /// "A trap mid-request") - the caller should reply 500 to the
    /// in-flight request and shut the daemon down rather than issuing
    /// another call against `self`.
    pub fn call_dispatch(&mut self, envelope: &[u8]) -> Result<Vec<u8>> {
        let f = self.daemon_dispatch.clone();
        self.call_native(f, "native daemon-dispatch", envelope)
    }

    /// Snapshot of captured stdout so far. Cumulative, same posture as
    /// [`crate::daemon_runtime::DaemonRuntime::drain_stdout`]: WASI
    /// command-module stdio (`printf`, `fmt.Println`, `println!`) is
    /// typically userspace-buffered by the guest's own libc/runtime and
    /// only reaches this pipe when the guest flushes it, so a guest that
    /// wants its diagnostic output visible per-request should flush
    /// explicitly inside `afterburner_daemon_dispatch`.
    pub fn drain_stdout(&self) -> Vec<u8> {
        self.stdout.contents().to_vec()
    }

    /// Stderr counterpart to [`Self::drain_stdout`].
    pub fn drain_stderr(&self) -> Vec<u8> {
        self.stderr.contents().to_vec()
    }

    /// Tail-only counterpart to [`Self::drain_stdout`]: only the bytes
    /// captured after `from` (the caller's high-water mark), so a
    /// per-request flush copies just the new tail instead of the whole
    /// cumulative buffer. Mirrors
    /// [`crate::daemon_runtime::DaemonRuntime::drain_stdout_from`].
    pub fn drain_stdout_from(&self, from: usize) -> Vec<u8> {
        self.stdout
            .contents()
            .get(from..)
            .unwrap_or_default()
            .to_vec()
    }

    /// Stderr counterpart to [`Self::drain_stdout_from`].
    pub fn drain_stderr_from(&self, from: usize) -> Vec<u8> {
        self.stderr
            .contents()
            .get(from..)
            .unwrap_or_default()
            .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(wat_or_wasm: &[u8]) -> Module {
        let engine = deterministic_engine().unwrap();
        Module::new(&engine, wat_or_wasm).unwrap()
    }

    #[test]
    fn one_shot_module_has_no_daemon_shape() {
        let wat = br#"(module (func (export "_start")))"#;
        let module = compile(wat);
        assert!(matches!(daemon_shape(&module), NativeDaemonShape::OneShot));
    }

    #[test]
    fn fully_shaped_module_is_daemon() {
        let wat = br#"(module
            (memory (export "memory") 1)
            (func (export "afterburner_alloc") (param i32) (result i32) (i32.const 0))
            (func (export "afterburner_dealloc") (param i32 i32))
            (func (export "afterburner_daemon_init") (param i32 i32) (result i32) (i32.const 0))
            (func (export "afterburner_daemon_dispatch") (param i32 i32) (result i32) (i32.const 0))
        )"#;
        let module = compile(wat);
        assert!(matches!(daemon_shape(&module), NativeDaemonShape::Daemon));
    }

    #[test]
    fn partial_shape_is_malformed_not_silently_one_shot() {
        let wat = br#"(module
            (memory (export "memory") 1)
            (func (export "afterburner_alloc") (param i32) (result i32) (i32.const 0))
            (func (export "afterburner_daemon_dispatch") (param i32 i32) (result i32) (i32.const 0))
        )"#;
        let module = compile(wat);
        match daemon_shape(&module) {
            NativeDaemonShape::Malformed(msg) => {
                assert!(
                    msg.contains("afterburner_dealloc"),
                    "must name the missing export: {msg}"
                );
                assert!(
                    msg.contains("afterburner_daemon_init"),
                    "must name the missing export: {msg}"
                );
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_signature_is_malformed() {
        let wat = br#"(module
            (memory (export "memory") 1)
            (func (export "afterburner_alloc") (result i32) (i32.const 0))
            (func (export "afterburner_dealloc") (param i32 i32))
            (func (export "afterburner_daemon_init") (param i32 i32) (result i32) (i32.const 0))
            (func (export "afterburner_daemon_dispatch") (param i32 i32) (result i32) (i32.const 0))
        )"#;
        let module = compile(wat);
        match daemon_shape(&module) {
            NativeDaemonShape::Malformed(msg) => {
                assert!(
                    msg.contains("afterburner_alloc"),
                    "must name the mismatch: {msg}"
                );
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_init_and_dispatch_persist_state() {
        // A tiny reactor (no _start/_initialize) with a global counter:
        // dispatch echoes back the running call count, proving Store
        // state survives across calls exactly as the design doc claims.
        let wat = br#"(module
            (memory (export "memory") 2)
            (global $counter (mut i32) (i32.const 0))
            (global $next_ptr (mut i32) (i32.const 65536))
            (func (export "afterburner_alloc") (param $len i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $next_ptr))
                (global.set $next_ptr (i32.add (global.get $next_ptr) (local.get $len)))
                (local.get $p))
            (func (export "afterburner_dealloc") (param i32 i32))
            (func (export "afterburner_daemon_init") (param i32 i32) (result i32)
                (i32.store (i32.const 128) (i32.const 200))
                (i32.store (i32.const 132) (i32.const 0))
                (i32.const 128))
            (func (export "afterburner_daemon_dispatch") (param i32 i32) (result i32)
                (global.set $counter (i32.add (global.get $counter) (i32.const 1)))
                (i32.store (i32.const 128) (i32.const 300))
                (i32.store8 (i32.const 300) (i32.add (i32.const 48) (global.get $counter)))
                (i32.store (i32.const 132) (i32.const 1))
                (i32.const 128))
        )"#;
        let opts = WasiCommandOpts::new();
        let mut rt = NativeDaemonRuntime::instantiate(wat, opts).unwrap();

        let init_resp = rt.call_init(b"{}").unwrap();
        assert_eq!(init_resp.len(), 0);

        let d1 = rt.call_dispatch(b"{}").unwrap();
        let d2 = rt.call_dispatch(b"{}").unwrap();
        let d3 = rt.call_dispatch(b"{}").unwrap();
        assert_eq!(d1, b"1");
        assert_eq!(d2, b"2");
        assert_eq!(d3, b"3");
    }

    #[test]
    fn fuel_is_replenished_not_accumulated_across_many_dispatches() {
        // Every dispatch burns a real, measured amount of fuel (a tight
        // counted loop; empirically 5 fuel units per iteration on this
        // wasmtime version, so 500_000 iterations = 2_500_000 fuel, ~2.5%
        // of NATIVE_DAEMON_FUEL_PER_CALL) - proving this test would
        // actually catch a "budget set once, never replenished"
        // regression, not just a guest that does no work. If fuel were a
        // fixed one-time budget instead of reset before every call (see
        // docs/wasi-daemon-abi.md's "Fuel, memory, timeout"), it would be
        // exhausted well before the 40th call; with per-call replenishment
        // every one of 100 calls starts from a near-full budget.
        let wat = br#"(module
            (memory (export "memory") 2)
            (global $next_ptr (mut i32) (i32.const 65536))
            (func (export "afterburner_alloc") (param $len i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $next_ptr))
                (global.set $next_ptr (i32.add (global.get $next_ptr) (local.get $len)))
                (local.get $p))
            (func (export "afterburner_dealloc") (param i32 i32))
            (func (export "afterburner_daemon_init") (param i32 i32) (result i32)
                (i32.store (i32.const 128) (i32.const 200))
                (i32.store (i32.const 132) (i32.const 0))
                (i32.const 128))
            (func $burn (param $n i32)
                (loop $l
                    (br_if $l (local.tee $n (i32.sub (local.get $n) (i32.const 1))))))
            (func (export "afterburner_daemon_dispatch") (param i32 i32) (result i32)
                (call $burn (i32.const 500000))
                (i32.store (i32.const 128) (i32.const 200))
                (i32.store (i32.const 132) (i32.const 0))
                (i32.const 128))
        )"#;
        let opts = WasiCommandOpts::new();
        let mut rt = NativeDaemonRuntime::instantiate(wat, opts).unwrap();
        rt.call_init(b"{}").unwrap();

        let mut min_remaining = u64::MAX;
        for i in 0..100 {
            rt.call_dispatch(b"{}")
                .unwrap_or_else(|e| panic!("call {i} of 100 failed: {e}"));
            let remaining = rt.store.get_fuel().expect("fuel metering is always on");
            min_remaining = min_remaining.min(remaining);
            assert!(
                remaining > NATIVE_DAEMON_FUEL_PER_CALL / 2,
                "call {i}: only {remaining} fuel left out of a \
                 {NATIVE_DAEMON_FUEL_PER_CALL}-unit per-call budget after \
                 replenishment - fuel is accumulating across calls instead \
                 of being reset before each one"
            );
        }
        // The loop must have burned a real, non-trivial amount of fuel each
        // call - otherwise this test would pass even with no
        // replenishment at all (a no-op guest never exhausts anything).
        assert!(
            min_remaining < NATIVE_DAEMON_FUEL_PER_CALL,
            "the dispatch loop burned no fuel; this test would not catch a \
             missing-replenishment regression"
        );
    }

    #[test]
    fn memory_cap_applies_for_the_whole_instance_lifetime() {
        // `docs/wasi-daemon-abi.md`'s "Fuel, memory, timeout": unlike fuel,
        // the memory cap is set once at construction and NEVER reset -
        // memory is exactly the state a daemon is supposed to keep across
        // requests, so capping it per-call would defeat the point. Each
        // dispatch here calls `memory.grow` directly and reports the
        // result (the previous page count on success, -1 on a cap
        // denial) - a real WASM growth attempt, not a simulated one.
        let wat = br#"(module
            (memory (export "memory") 2)
            (func (export "afterburner_alloc") (param $len i32) (result i32) (i32.const 128))
            (func (export "afterburner_dealloc") (param i32 i32))
            (func (export "afterburner_daemon_init") (param i32 i32) (result i32)
                (i32.store (i32.const 128) (i32.const 200))
                (i32.store (i32.const 132) (i32.const 0))
                (i32.const 128))
            (func (export "afterburner_daemon_dispatch") (param $ptr i32) (param i32) (result i32)
                (i32.store (i32.const 300) (memory.grow (i32.load (local.get $ptr))))
                (i32.store (i32.const 128) (i32.const 300))
                (i32.store (i32.const 132) (i32.const 4))
                (i32.const 128))
        )"#;
        // Cap at 256 KiB (4 pages); the module starts at 2 pages.
        let opts = WasiCommandOpts::new().max_memory_bytes(256 * 1024);
        let mut rt = NativeDaemonRuntime::instantiate(wat, opts).unwrap();
        rt.call_init(b"{}").unwrap();

        // `call_dispatch`'s (ptr, len) args feed straight into
        // `memory.grow` here - grow by 1 page (well under the cap) first.
        let one_page = 1i32.to_le_bytes();
        let resp = rt.call_dispatch(&one_page).unwrap();
        let grown = i32::from_le_bytes(resp[0..4].try_into().unwrap());
        assert_eq!(
            grown, 2,
            "growing within the cap must succeed (returns the prior page count)"
        );

        // Now grow by 2000 pages (~128 MiB) - far past the 256 KiB cap.
        let many_pages = 2000i32.to_le_bytes();
        let resp = rt.call_dispatch(&many_pages).unwrap();
        let grown = i32::from_le_bytes(resp[0..4].try_into().unwrap());
        assert_eq!(
            grown, -1,
            "growing past max_memory_bytes must be denied (memory.grow returns -1), \
             on the SAME instance that just grew successfully above - proving the \
             cap persists across calls rather than resetting"
        );
    }
}
