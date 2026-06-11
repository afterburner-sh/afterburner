// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `DaemonRuntime` — long-lived `Store<HostState>` that persists JS
//! state across many `daemon_step` invocations.
//!
//! Daemon mode is what lets `burn server.js` run real Node HTTP
//! servers: after the user code registers handlers via
//! `http.createServer(cb).listen(port)`, the Store sticks around so
//! subsequent incoming HTTP requests (dispatched via
//! [`DaemonRuntime::dispatch_event`]) hit the same JS state — same
//! globals, same handler table, same plenum caches.
//!
//! This is an intentional break from the fresh-per-thrust invariant
//! that every other combustor path enforces: daemon mode is opt-in
//! (CLI-only by default per the plan's Q2-A locked decision), and
//! the library API's `Afterburner::run_script` never auto-enters it.

use crate::daemon_http::DaemonHttp;
#[cfg(feature = "daemon")]
use crate::daemon_net::DaemonNet;
#[cfg(feature = "daemon")]
use crate::daemon_tls::DaemonTls;
use crate::daemon_workers::DaemonWorkers;
use crate::host::HostState;
use afterburner_core::{
    AfterburnerError, HostContext, InMemoryStateStore, Manifold, Result, ScriptInvocation,
    SharedStateStore,
};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wasmtime::{Engine, InstancePre, Store, Trap, TypedFunc};
use wasmtime_wasi::I32Exit;

/// Cumulative stdout-capture ceiling for the daemon's long-lived
/// Store. Matches the engine-wide default
/// (`FuelGauge::DEFAULT_OUTPUT_BYTES`) so daemon-mode scripts don't
/// get a surprise capacity shift versus the one-shot paths. B2.4
/// routes daemon stdout to the real process stdout, which removes
/// this accumulation entirely.
const DAEMON_STDOUT_CAPACITY: usize = afterburner_core::FuelGauge::DEFAULT_OUTPUT_BYTES;

/// Handle to a long-lived plugin instance. Owns the Store, the
/// typed `daemon_step` function, and a reference to the HTTP
/// coordinator shared with the axum listeners the script registers.
pub struct DaemonRuntime {
    store: Store<HostState>,
    daemon_step: TypedFunc<(), ()>,
    daemon_http: Arc<DaemonHttp>,
}

impl std::fmt::Debug for DaemonRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonRuntime")
            .field("daemon_http", &self.daemon_http)
            .finish_non_exhaustive()
    }
}

impl DaemonRuntime {
    /// Spawn a daemon runtime from a prepared `InstancePre` and the
    /// user's source. Runs `daemon_step` once with the daemon-init
    /// envelope — that evaluates the user source, which typically
    /// installs HTTP handlers onto `globalThis.__ab_http_handlers`
    /// and binds listeners via `__host_http_listen`.
    ///
    /// Returns a handle the caller drives via [`dispatch_event`]
    /// and [`drain_stdout`] / [`drain_stderr`].
    pub fn new(
        engine: &Engine,
        instance_pre: &InstancePre<HostState>,
        source: &str,
        manifold: Manifold,
        state_store: Option<SharedStateStore>,
        host_context: Option<Arc<dyn HostContext>>,
        daemon_http: Arc<DaemonHttp>,
    ) -> Result<Self> {
        let mut d = Self::instantiate(
            engine,
            instance_pre,
            manifold,
            state_store,
            host_context,
            daemon_http,
            None,
        )?;
        d.run_init(source, &ScriptInvocation::default())?;
        Ok(d)
    }

    /// Variant that threads a [`ScriptInvocation`] (argv + env) into
    /// `daemon-init`. The CLI uses this so `process.argv` /
    /// `process.env` match what the user expected when they wrote
    /// `burn server.js arg1 arg2`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_invocation(
        engine: &Engine,
        instance_pre: &InstancePre<HostState>,
        source: &str,
        invocation: &ScriptInvocation,
        manifold: Manifold,
        state_store: Option<SharedStateStore>,
        host_context: Option<Arc<dyn HostContext>>,
        daemon_http: Arc<DaemonHttp>,
    ) -> Result<Self> {
        let mut d = Self::instantiate(
            engine,
            instance_pre,
            manifold,
            state_store,
            host_context,
            daemon_http,
            None,
        )?;
        d.run_init(source, invocation)?;
        Ok(d)
    }

    /// Build the long-lived Store + plugin instance WITHOUT running
    /// daemon-init. Callers that need to inspect partial output on
    /// init failure use `instantiate()` + [`run_init`] separately
    /// instead of the convenience constructors.
    #[allow(clippy::too_many_arguments)]
    pub fn instantiate(
        engine: &Engine,
        instance_pre: &InstancePre<HostState>,
        manifold: Manifold,
        state_store: Option<SharedStateStore>,
        host_context: Option<Arc<dyn HostContext>>,
        daemon_http: Arc<DaemonHttp>,
        transpile_hook: Option<crate::host::TranspileFn>,
    ) -> Result<Self> {
        let state_store = state_store.unwrap_or_else(InMemoryStateStore::shared);
        let mut state = HostState::new(
            b"",
            None,
            DAEMON_STDOUT_CAPACITY,
            manifold,
            state_store,
            host_context,
        );
        state.daemon_http = Some(daemon_http.clone());
        state.transpile_hook = transpile_hook;

        let mut store = Store::new(engine, state);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(u64::MAX)
            .map_err(|e| AfterburnerError::Engine(format!("set_fuel: {e}")))?;
        store.set_epoch_deadline(u64::MAX / 2);

        let instance = instance_pre
            .instantiate(&mut store)
            .map_err(|e| AfterburnerError::Engine(format!("daemon instantiate: {e}")))?;
        let daemon_step = instance
            .get_typed_func::<(), ()>(&mut store, "daemon_step")
            .map_err(|e| AfterburnerError::Engine(format!("daemon_step lookup: {e}")))?;

        Ok(Self {
            store,
            daemon_step,
            daemon_http,
        })
    }

    /// Evaluate the user source as daemon-init. On success, JS state
    /// (handler tables, plenum caches, globals) persists in the
    /// Store. On failure, `self` is still valid — callers can call
    /// [`drain_stdout`] / [`drain_stderr`] to retrieve whatever the
    /// script wrote before it threw.
    pub fn run_init(&mut self, source: &str, invocation: &ScriptInvocation) -> Result<()> {
        let envelope = serde_json::json!({
            "mode": "daemon-init",
            "source": source,
            "argv": invocation.argv,
            "env": invocation.env,
            "cwd": invocation.cwd,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)?;
        self.store.data_mut().pending_envelope = envelope_bytes;
        self.daemon_step
            .call(&mut self.store, ())
            .map_err(|trap| map_daemon_trap("daemon-init", trap))
    }

    /// Same as [`Self::run_init`] but invokes pre-compiled bytecode
    /// produced by [`crate::WasmCombustor::compile_daemon_init_bytecode`].
    /// The wrap + compile happened on the host side; this just hands
    /// the bytes to the plugin's `daemon-init` mode for invoke.
    ///
    /// Use case: when the same user app needs to load into multiple
    /// daemon Stores (e.g. a multi-shard pool), pre-compile once and
    /// run init with bytecode N times — each Store skips the per-
    /// launch source parse + wrap + compile and just runs the
    /// already-baked image.
    ///
    /// JS state (`process.argv`, `process.env`, `__host_cwd`) is
    /// already baked into the bytecode via the script-mode envelope
    /// the host applied at compile time. Re-running this method on
    /// the same Store re-evaluates the script, which is a behavioral
    /// no-op for typical daemon scripts (idempotent module init) but
    /// could double-register handlers — same caveat as calling
    /// [`Self::run_init`] twice.
    pub fn run_init_with_bytecode(&mut self, bytecode: &[u8]) -> Result<()> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytecode);
        let envelope = serde_json::json!({
            "mode": "daemon-init",
            "bytecode_b64": b64,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)?;
        self.store.data_mut().pending_envelope = envelope_bytes;
        self.daemon_step
            .call(&mut self.store, ())
            .map_err(|trap| map_daemon_trap("daemon-init", trap))
    }

    /// Dispatch one event to the running daemon. Event shape:
    /// `{ kind: "http-request", server_id, req_id, req: {...} }` —
    /// the plugin's `daemon_event` mode looks the handler up on
    /// `globalThis.__ab_http_handlers[server_id]` and invokes it.
    pub fn dispatch_event(&mut self, event: Value) -> Result<()> {
        let envelope = serde_json::json!({
            "mode": "daemon-event",
            "event": event,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)?;
        self.store.data_mut().pending_envelope = envelope_bytes;
        self.daemon_step
            .call(&mut self.store, ())
            .map_err(|trap| map_daemon_trap("daemon-event", trap))?;
        Ok(())
    }

    /// Snapshot of captured stdout. Cumulative — the caller is
    /// responsible for tracking a high-water mark if it wants
    /// per-event deltas. B2.4 will route stdout to the real process
    /// in the long-running CLI case.
    pub fn drain_stdout(&self) -> Vec<u8> {
        self.store.data().stdout.contents().to_vec()
    }

    /// Snapshot of captured stderr. Same cumulative semantics.
    pub fn drain_stderr(&self) -> Vec<u8> {
        self.store.data().stderr.contents().to_vec()
    }

    /// Access the HTTP coordinator — B2.4 uses this to register axum
    /// listener sockets keyed to the `server_id`s the script
    /// produced during daemon-init.
    pub fn http(&self) -> &Arc<DaemonHttp> {
        &self.daemon_http
    }

    /// `true` if the script installed at least one HTTP listener via
    /// `.listen(port)`. The CLI uses this to decide between exiting
    /// cleanly after daemon-init (no listener → script was one-shot)
    /// and entering the event loop.
    pub fn has_listeners(&self) -> bool {
        self.daemon_http.listener_count() > 0
    }

    /// `true` if the daemon has anything keeping it alive — HTTP
    /// listeners, ref'd timers, alive worker_threads children, or
    /// alive `net` connections / listeners. B7 extends the rule to
    /// raw TCP: while any socket is open or any listener is bound,
    /// the daemon stays up so events can flow.
    pub fn has_refs(&self) -> bool {
        if self.daemon_http.listener_count() > 0 {
            return true;
        }
        if self.store.data().timers.iter().any(|t| t.is_ref) {
            return true;
        }
        if let Some(w) = &self.store.data().daemon_workers
            && w.has_alive_workers()
        {
            return true;
        }
        #[cfg(feature = "daemon")]
        if let Some(n) = &self.store.data().daemon_net
            && n.has_refs()
        {
            return true;
        }
        #[cfg(feature = "daemon")]
        if let Some(t) = &self.store.data().daemon_tls
            && t.has_refs()
        {
            return true;
        }
        #[cfg(feature = "daemon")]
        if let Some(d) = &self.store.data().daemon_dgram
            && d.has_refs()
        {
            return true;
        }
        // Outbound HTTP keeps the daemon alive while a request is in
        // flight — without this the script-mode wrapper would exit
        // the moment the synchronous user fn returns, even though
        // the response Promise hasn't resolved yet.
        #[cfg(feature = "daemon")]
        if let Some(o) = &self.store.data().daemon_http_outbound
            && o.has_refs()
        {
            return true;
        }
        false
    }

    /// Install a worker_threads coordinator on this daemon's Store.
    /// Called by the CLI before `run_init` so user code that calls
    /// `new Worker(...)` during top-level evaluation already sees the
    /// host import wired. Idempotent — second call replaces the slot.
    pub fn install_workers(&mut self, workers: Arc<DaemonWorkers>) {
        self.store.data_mut().daemon_workers = Some(workers);
    }

    /// Pop the next worker event for the event-loop to dispatch.
    /// `None` when the queue is empty. Returns nothing in non-worker
    /// configurations (the slot is `None`).
    pub fn try_recv_worker_event(&self) -> Option<crate::daemon_workers::WorkerEvent> {
        self.store.data().daemon_workers.as_ref()?.try_recv_event()
    }

    /// Drop the active-handle entry for `worker_id` after dispatching
    /// `Exit` to JS. The reaper-on-Drop path catches anything we miss.
    pub fn reap_worker(&self, worker_id: i32) {
        if let Some(w) = &self.store.data().daemon_workers {
            w.mark_reaped(worker_id);
        }
    }

    /// Child-mode signal: the parent closed our stdin (or sent
    /// `terminate`). Used by the worker child's event loop to know it
    /// can exit cleanly when no other refs remain.
    pub fn parent_closed_signaled(&self) -> bool {
        self.store
            .data()
            .daemon_workers
            .as_ref()
            .map(|w| w.parent_closed_signaled())
            .unwrap_or(false)
    }

    /// Install a net (raw TCP) coordinator on this daemon's Store.
    /// Called by the CLI (parent + worker) before `run_init` so user
    /// code that calls `net.connect(...)` / `net.createServer(...)`
    /// during top-level evaluation already sees the host imports.
    #[cfg(feature = "daemon")]
    pub fn install_net(&mut self, net: Arc<DaemonNet>) {
        self.store.data_mut().daemon_net = Some(net);
    }

    #[cfg(feature = "daemon")]
    pub fn try_recv_net_event(&self) -> Option<crate::daemon_net::NetEvent> {
        self.store.data().daemon_net.as_ref()?.try_recv_event()
    }

    /// Drop the registry entry for `conn_id` after dispatching `Close`
    /// to JS — same role as `reap_worker` for `worker_threads`.
    #[cfg(feature = "daemon")]
    pub fn mark_net_closed(&self, conn_id: i32) {
        if let Some(n) = &self.store.data().daemon_net {
            n.mark_closed(conn_id);
        }
    }

    /// Install a tls coordinator on this daemon's Store. Same posture
    /// as `install_net`: parent + worker call this before `run_init`.
    #[cfg(feature = "daemon")]
    pub fn install_tls(&mut self, tls: Arc<DaemonTls>) {
        self.store.data_mut().daemon_tls = Some(tls);
    }

    #[cfg(feature = "daemon")]
    pub fn try_recv_tls_event(&self) -> Option<crate::daemon_tls::TlsEvent> {
        self.store.data().daemon_tls.as_ref()?.try_recv_event()
    }

    #[cfg(feature = "daemon")]
    pub fn mark_tls_closed(&self, conn_id: i32) {
        if let Some(t) = &self.store.data().daemon_tls {
            t.mark_closed(conn_id);
        }
    }

    /// Install a dgram (UDP) coordinator. Same lifecycle as
    /// `install_net` / `install_tls`.
    #[cfg(feature = "daemon")]
    pub fn install_dgram(&mut self, dgram: Arc<crate::daemon_dgram::DaemonDgram>) {
        self.store.data_mut().daemon_dgram = Some(dgram);
    }

    #[cfg(feature = "daemon")]
    pub fn try_recv_dgram_event(&self) -> Option<crate::daemon_dgram::DgramEvent> {
        self.store.data().daemon_dgram.as_ref()?.try_recv_event()
    }

    /// Install the inspector / Chrome DevTools Protocol coordinator
    /// on this daemon's Store. The CLI's daemon path wires this; the
    /// JS side then unblocks `inspector.open(port)` calls that need
    /// the host listener.
    #[cfg(feature = "daemon")]
    pub fn install_inspector(&mut self, coord: Arc<crate::daemon_inspector::DaemonInspector>) {
        self.store.data_mut().daemon_inspector = Some(coord);
    }

    #[cfg(feature = "daemon")]
    pub fn try_recv_inspector_event(&self) -> Option<crate::daemon_inspector::InspectorEvent> {
        self.store
            .data()
            .daemon_inspector
            .as_ref()?
            .try_recv_event()
    }

    /// Install the outbound HTTP coordinator on this daemon's Store.
    /// Same lifecycle as the other `install_*` methods — parent +
    /// worker call this before `run_init` so user code that calls
    /// `http.request` / `https.request` / `fetch` during top-level
    /// evaluation already sees the async host import.
    #[cfg(feature = "daemon")]
    pub fn install_http_outbound(
        &mut self,
        coord: Arc<crate::daemon_http_outbound::DaemonHttpOutbound>,
    ) {
        self.store.data_mut().daemon_http_outbound = Some(coord);
    }

    #[cfg(feature = "daemon")]
    pub fn try_recv_http_outbound_response(
        &self,
    ) -> Option<crate::daemon_http_outbound::HttpOutboundResponseEvent> {
        self.store
            .data()
            .daemon_http_outbound
            .as_ref()?
            .try_recv_response()
    }

    /// Drain timers whose `fire_at` has passed. Returns the ids that
    /// fired. One-shot timers are removed; repeating timers are re-
    /// armed with a fresh `fire_at`.
    pub fn drain_expired_timers(&mut self) -> Vec<i32> {
        let now = Instant::now();
        let timers = &mut self.store.data_mut().timers;
        let mut fired = Vec::new();
        let mut i = 0;
        while i < timers.len() {
            if timers[i].fire_at <= now {
                fired.push(timers[i].id);
                if let Some(interval) = timers[i].interval_ms {
                    timers[i].fire_at = now + Duration::from_millis(interval);
                    i += 1;
                } else {
                    timers.swap_remove(i);
                }
            } else {
                i += 1;
            }
        }
        fired
    }

    /// Earliest fire-time among all registered timers, if any. The
    /// event loop uses this to bound its poll sleep so timers fire
    /// with reasonable granularity.
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        self.store.data().timers.iter().map(|t| t.fire_at).min()
    }
}

// wasmtime 44 returns its own `wasmtime::Error` from store / typed-func
// calls; it mirrors anyhow's downcast / chain API, so the body below
// is unchanged besides the parameter type.
fn map_daemon_trap(phase: &'static str, trap: wasmtime::Error) -> AfterburnerError {
    // WASI `proc_exit(N)` propagates as I32Exit. `__host_process_exit`
    // triggers this via the host import that returns `Err(I32Exit(n))`.
    // Surface it as `ProcessExit` so the CLI can `std::process::exit`.
    if let Some(exit) = trap.downcast_ref::<I32Exit>() {
        return AfterburnerError::ProcessExit(exit.0);
    }
    if let Some(t) = trap.downcast_ref::<Trap>() {
        match t {
            Trap::Interrupt => return AfterburnerError::Timeout,
            Trap::OutOfFuel => return AfterburnerError::FuelExhausted,
            other => return AfterburnerError::WasmTrap(format!("{phase}: {other}")),
        }
    }
    // Fall through: bundle the chain so the caller can see what
    // actually went wrong (often a JS-side exception that propagated
    // back through `invoke`).
    let chain: Vec<String> = trap.chain().map(|e| format!("{e}")).collect();
    AfterburnerError::WasmTrap(format!("{phase}: {}", chain.join(" => ")))
}
