// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Host state threaded through the Wasmtime `Store`. Holds the WASI
//! preview1 context, bounded stdin/stdout/stderr memory pipes, the
//! per-store memory limiter, and the active [`Manifold`] plus a
//! last-error slot consulted by `afterburner:host` imports.

use afterburner_core::{HostContext, Manifold, SharedStateStore};
use afterburner_node_compat::hash_handles::HashHandleStore;
use afterburner_node_compat::sign_handles::SignHandleStore;
use std::sync::Arc;
use std::time::Instant;
use wasmtime::{ResourceLimiter, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};

use crate::capture::CapturePipe;

/// Host-managed timer entry. Lives in `HostState::timers` and is
/// manipulated by the `__host_timer_*` imports. The CLI event loop
/// drains expired entries via `DaemonRuntime::drain_expired_timers`.
#[derive(Debug, Clone)]
pub struct TimerSlot {
    pub id: i32,
    pub fire_at: Instant,
    /// `None` = one-shot (`setTimeout`); `Some(ms)` = repeating
    /// (`setInterval`). On fire the host re-arms with a new `fire_at`.
    pub interval_ms: Option<u64>,
    /// Ref'd timers keep the daemon event loop alive. `unref()` clears
    /// this; `ref()` re-sets it. Matches Node's `timer.unref()`.
    pub is_ref: bool,
}

/// Framing of `HostState::pending_input`, read by the guest through
/// the `host_input_format` import (as the discriminant value). One
/// compiled invoke wrapper serves both framings - the guest-side input
/// getter branches on this flag per invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum InputFormat {
    /// JSON text (`serde_json::to_vec` of the call's input value); the
    /// invoke wrapper materializes a JS string and `JSON.parse`s it.
    #[default]
    Json = 0,
    /// Opaque bytes; the invoke wrapper hands the module a
    /// `Uint8Array` directly. Used by the `thrust_raw` fast path.
    Raw = 1,
}

/// Per-`thrust` host state. A fresh instance is created for every call so
/// invocations are fully isolated (no shared JS globals, no stdout leak
/// between calls).
pub struct HostState {
    pub wasi: WasiP1Ctx,
    /// Result / stdout capture: grows on demand, hard-capped at
    /// [`Self::output_ceiling`]. Overflow is recorded on the pipe and
    /// surfaced by the host as `AfterburnerError::OutputTooLarge`.
    pub stdout: CapturePipe,
    pub stderr: MemoryOutputPipe,
    /// Per-call output ceiling (`FuelGauge::output_ceiling()` at
    /// `HostState` build time). Bounds the stdout capture and the
    /// `host_raw_output` reply alike.
    pub output_ceiling: usize,
    pub limits: StoreLimits,
    /// Capability profile consulted by every `afterburner:host` import.
    pub manifold: Manifold,
    /// Cross-invocation key/value store, read by `afterburner:state`.
    pub state_store: SharedStateStore,
    /// Optional embedder-provided host context for read_column / emit_row.
    pub host_context: Option<Arc<dyn HostContext>>,
    /// Per-store streaming sign/verify handle store. Lives for the
    /// thrust's duration and is dropped with the `Store`.
    pub sign_handles: SignHandleStore,
    /// Per-store streaming createHash / createHmac handle store. Same
    /// lifetime as `sign_handles`.
    pub hash_handles: HashHandleStore,
    /// Detailed message for the last failed host call. The plugin reads
    /// this via the `host_last_error` import when a syscall returned a
    /// negative error code, and the JS glue surfaces it to the user.
    pub last_error: String,
    /// Input bytes for the bytecode-cache invoke path. Plugin reads
    /// this via the `host_get_input` import; lets us skip the
    /// per-thrust preamble compile that would otherwise publish the
    /// input as a JS global. Empty if the call uses the legacy
    /// envelope. Framing is described by [`Self::input_format`].
    pub pending_input: Vec<u8>,
    /// Framing of [`Self::pending_input`], surfaced to the guest via
    /// the `host_input_format` import. [`InputFormat::Json`] (the
    /// default) means JSON text the invoke wrapper `JSON.parse`s;
    /// [`InputFormat::Raw`] means opaque bytes the wrapper hands the
    /// module as a `Uint8Array` - the large-payload fast path that
    /// skips guest-side string materialization and `JSON.parse`
    /// entirely (both are O(n) fuel-metered work).
    pub input_format: InputFormat,
    /// JSON-serialized envelope for the daemon path's `daemon_step`
    /// re-entry. Separate from `pending_input` because daemon mode
    /// re-uses the same Store across many calls and we don't want one
    /// channel's state to leak into the other. Host sets this before
    /// each `daemon_step` invocation; plugin reads via the
    /// `host_get_envelope` import.
    pub pending_envelope: Vec<u8>,
    /// Set by the columnar-invoke plugin mode via the
    /// `host_columnar_reply` import after the user UDF returns.
    /// Carries the result blob the host then decodes via
    /// [`crate::columnar::decode_batch`] in `thrust_columnar`. `None`
    /// means the call hasn't completed (or wasn't a columnar call).
    pub pending_columnar_reply: Option<Vec<u8>>,
    /// Optional daemon HTTP coordinator. `Some` only in daemon mode -
    /// owns the axum listeners + per-req reply channels. `None` for
    /// all one-shot thrust paths so UDF/script callers don't pay the
    /// coordinator's startup cost.
    pub daemon_http: Option<Arc<crate::daemon_http::DaemonHttp>>,
    /// Optional `worker_threads` coordinator. `Some` in daemon mode
    /// (parent role) and inside `burn run --internal-worker` (child
    /// role); `None` everywhere else - `new Worker(...)` then surfaces
    /// a clear "not in daemon mode" error rather than silently
    /// spawning a process from the library API.
    pub daemon_workers: Option<Arc<crate::daemon_workers::DaemonWorkers>>,
    /// Optional `net` (raw TCP) coordinator. `Some` in daemon mode;
    /// `None` everywhere else - `net.connect` / `net.createServer`
    /// then surface a clear "requires daemon mode" error rather than
    /// silently spawning sockets from the library API. Gated behind
    /// the `daemon` feature because the coordinator is tokio-backed.
    #[cfg(feature = "daemon")]
    pub daemon_net: Option<Arc<crate::daemon_net::DaemonNet>>,
    /// Optional `tls` coordinator. Same lifecycle/posture as
    /// `daemon_net`; gated behind `daemon` because it's also
    /// tokio-backed (and pulls in `tokio-rustls`).
    #[cfg(feature = "daemon")]
    pub daemon_tls: Option<Arc<crate::daemon_tls::DaemonTls>>,
    /// Optional `dgram` (UDP) coordinator. Same lifecycle as
    /// `daemon_net` - installed only by the CLI's daemon path
    /// (`http.createServer().listen()` etc.); the library API never
    /// installs one so dgram polyfill calls cleanly error in non-daemon
    /// mode. Gated behind `daemon` because it's tokio-backed.
    #[cfg(feature = "daemon")]
    pub daemon_dgram: Option<Arc<crate::daemon_dgram::DaemonDgram>>,
    /// Optional AF_UNIX socket coordinator. Same lifecycle as
    /// `daemon_dgram` - installed only by the CLI's daemon path so
    /// `net.connect({path})` / `net.createServer({path})` work in
    /// daemon mode and cleanly error in library mode.
    #[cfg(all(feature = "daemon", unix))]
    pub daemon_unix: Option<Arc<crate::daemon_unix::DaemonUnix>>,
    /// Outbound HTTP coordinator - async per-shard. JS calls
    /// `http.request` end up here (via `__host_http_request_async`),
    /// the request runs on the daemon's Tokio runtime, and the
    /// response comes back through the shard's event loop. Library
    /// callers without a daemon Store (one-shot script mode) fall
    /// back to the synchronous `__host_http_request` path so simple
    /// fire-and-forget scripts still work.
    #[cfg(feature = "daemon")]
    pub daemon_http_outbound: Option<Arc<crate::daemon_http_outbound::DaemonHttpOutbound>>,
    /// Optional inspector / Chrome DevTools Protocol coordinator.
    /// Set when the JS side calls `inspector.open(port)` (axum-backed
    /// HTTP+WebSocket listener); `None` everywhere else so the
    /// in-process `Session.post` path stays usable without paying for
    /// a listener.
    #[cfg(feature = "daemon")]
    pub daemon_inspector: Option<Arc<crate::daemon_inspector::DaemonInspector>>,
    /// Raw result bytes posted by the guest via the `host_raw_output`
    /// import when the module returned a `Uint8Array` / `ArrayBuffer`.
    /// The output-side mirror of `pending_input`'s raw framing: the
    /// invoke wrapper branches on the module's return type, and a
    /// bytes-shaped return crosses here instead of JSON-over-stdout.
    /// `None` means the call produced a JSON result (or nothing).
    pub pending_raw_output: Option<Vec<u8>>,
    /// Set by `host_raw_output` when the posted reply exceeded
    /// [`Self::output_ceiling`] - the raw-path twin of the stdout
    /// pipe's overflow flag, consulted by
    /// [`Self::output_overflowed`].
    pub raw_output_overflow: bool,
    /// Cross-process `SharedArrayBuffer` + `Atomics.wait`/`notify`
    /// coordinator. Always present (cheap to construct - no listener
    /// or socket) so the JS side's `new SharedArrayBuffer(...)` and
    /// `Atomics.{wait,notify}` work uniformly across UDF, script,
    /// and daemon modes.
    pub daemon_sab: Arc<crate::daemon_sab::DaemonSab>,
    /// Per-thrust SQLite shadow registry. Each opened
    /// `new sqlite3.Database(...)` runs in its own worker thread
    /// owned by this store; the field is just the lookup table that
    /// maps db ids to per-conn command senders. Always-present (no
    /// Option wrapper) because the registry is cheap to construct
    /// and the host import paths can return a clean "unknown id"
    /// error without coordinator-presence checks.
    #[cfg(feature = "shadow-sqlite3")]
    pub sqlite3_shadow: Arc<afterburner_node_compat::shadows::sqlite3::SqliteShadow>,
    /// Sub-runner for `WebAssembly.compile` / `instantiate`. Always
    /// present - wasmtime is already a workspace-wide dep, so the
    /// loader is cheap to construct and the API is part of the
    /// Node 20.x LTS surface (`globalThis.WebAssembly`).
    pub wasm_loader: Arc<crate::wasm_loader::WasmLoader>,
    /// Host-managed timers registered by `setTimeout`/`setInterval` in
    /// daemon mode via the `__host_timer_set` import. Empty for one-shot
    /// UDF / script paths.
    pub timers: Vec<TimerSlot>,
    /// Monotonically increasing timer id counter. Starts at 1 so JS
    /// can use `0` as "no timer".
    pub next_timer_id: i32,
    /// Optional hook for transpiling JS-flavoured source (TS, ESM)
    /// to plain CJS-shaped JS at require-time. Wired by the CLI
    /// when built with the `ts` feature so `require('./x.ts')` and
    /// `require('./x.mjs')` lower to runnable CJS before the require
    /// resolver wraps the source in `new Function(...)`. `None`
    /// disables the hook - any non-`.js`/`.json` file loaded via
    /// `require` surfaces a "TS support requires `ts` feature"-style
    /// error downstream.
    pub transpile_hook: Option<TranspileFn>,
}

/// Signature of the transpile hook. Takes `(source, path)` and
/// returns the transpiled JS or a string error message.
pub type TranspileFn = Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>;

impl HostState {
    /// Build a `HostState` with the given input JSON piped to stdin, a
    /// growable ceiling-bounded stdout capture, and a bounded stderr
    /// buffer.
    pub fn new(
        input: &[u8],
        memory_bytes: Option<usize>,
        output_ceiling: usize,
        manifold: Manifold,
        state_store: SharedStateStore,
        host_context: Option<Arc<dyn HostContext>>,
    ) -> Self {
        let stdin = MemoryInputPipe::new(input.to_vec());
        let stdout = CapturePipe::new(output_ceiling);
        // Stderr is bounded too - preserving it unbounded is a memory-
        // exhaustion vector. Surfaced to the caller via WasmTrap on error.
        let stderr = MemoryOutputPipe::new(64 * 1024);

        let wasi = wasmtime_wasi::WasiCtxBuilder::new()
            .stdin(stdin)
            .stdout(stdout.clone())
            .stderr(stderr.clone())
            .build_p1();

        let limits = match memory_bytes {
            Some(max) => StoreLimitsBuilder::new().memory_size(max).build(),
            None => StoreLimitsBuilder::new().build(),
        };

        Self {
            wasi,
            stdout,
            stderr,
            output_ceiling,
            limits,
            manifold,
            state_store,
            host_context,
            sign_handles: SignHandleStore::new(),
            hash_handles: HashHandleStore::new(),
            last_error: String::new(),
            pending_input: Vec::new(),
            input_format: InputFormat::Json,
            pending_envelope: Vec::new(),
            pending_columnar_reply: None,
            pending_raw_output: None,
            raw_output_overflow: false,
            daemon_http: None,
            daemon_workers: None,
            #[cfg(feature = "daemon")]
            daemon_net: None,
            #[cfg(feature = "daemon")]
            daemon_tls: None,
            #[cfg(feature = "daemon")]
            daemon_dgram: None,
            #[cfg(all(feature = "daemon", unix))]
            daemon_unix: None,
            #[cfg(feature = "daemon")]
            daemon_http_outbound: None,
            #[cfg(feature = "daemon")]
            daemon_inspector: None,
            daemon_sab: crate::daemon_sab::DaemonSab::new(),
            #[cfg(feature = "shadow-sqlite3")]
            sqlite3_shadow: Arc::new(
                afterburner_node_compat::shadows::sqlite3::SqliteShadow::new(),
            ),
            wasm_loader: Arc::new(crate::wasm_loader::WasmLoader::new()),
            timers: Vec::new(),
            next_timer_id: 1,
            transpile_hook: None,
        }
    }

    /// Like `new` but pre-populates `pending_input` for the bytecode-
    /// cache invoke path. The plugin reads the bytes via
    /// `host_get_input` and their framing via `host_input_format`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_input(
        envelope: &[u8],
        input: Vec<u8>,
        input_format: InputFormat,
        memory_bytes: Option<usize>,
        output_ceiling: usize,
        manifold: Manifold,
        state_store: SharedStateStore,
        host_context: Option<Arc<dyn HostContext>>,
    ) -> Self {
        let mut s = Self::new(
            envelope,
            memory_bytes,
            output_ceiling,
            manifold,
            state_store,
            host_context,
        );
        s.pending_input = input;
        s.input_format = input_format;
        s
    }

    pub fn limiter(&mut self) -> &mut dyn ResourceLimiter {
        &mut self.limits
    }

    /// `true` when this call's output exceeded [`Self::output_ceiling`]
    /// on either delivery channel (stdout capture or raw-output
    /// reply). The chamber and the script-mode path map a set flag to
    /// `AfterburnerError::OutputTooLarge` - a structured error in the
    /// existing taxonomy, never a bare trap.
    pub fn output_overflowed(&self) -> bool {
        self.raw_output_overflow || self.stdout.overflowed()
    }
}
