// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `DaemonShardPool` - N independent `DaemonRuntime` instances, each
//! served from a dedicated OS thread. The shared `DaemonHttp`
//! coordinator binds one TCP listener per port; the pool's
//! dispatcher task drains the central event channel and round-robins
//! each request to a shard's mailbox. Per-shard event sources
//! (timers, worker_threads, net, tls, dgram) are polled by each
//! shard's own loop on its own daemon - events can't smuggle across
//! shard boundaries.
//!
//! Sandbox boundary preserved per-shard: every shard owns its own
//! `Manifold` clone (`Manifold` is a pure value type with no shared
//! mutex, so the clone is behaviourally equal). Capability gates
//! (`fs`, `net`, `env`, `crypto`, `child_process`) apply per-Store
//! identically. Wasmtime guarantees per-Store memory isolation, so
//! a buggy or hostile script in one shard cannot read another
//! shard's heap.
//!
//! Resource budget surfaced at pool spawn: with `N` shards and a
//! `BURN_MAX_LINEAR_MEMORY` per-Store cap of `M`, the worst-case
//! linear-memory usage is `N × M`. Same multiplier applies to the
//! `worker_threads` budget (`N × WorkerConfig::max_concurrent`).
//! Operators size the container (CPU + memory) at the deployment
//! layer - `available_parallelism()` honours cgroup CPU quotas, so
//! `docker run --cpus=4` produces 4 shards automatically.
//!
//! Shard panic isolation: every dispatch call is wrapped in
//! `catch_unwind`. A panicking shard's reply is dropped (HTTP 500
//! at the axum layer); the pool keeps serving from surviving
//! shards. The pool's `shards_alive()` reports liveness for tests
//! and ops.
//!
//! Lock-free arbitration: shards' `app.listen(port)` calls converge
//! on a single bound socket via `kovan_map::HopscotchMap::
//! get_or_insert` (CAS-based, no Mutex). Per-request dispatch uses
//! an `AtomicUsize` round-robin counter; the per-shard mailbox is a
//! bounded `tokio::sync::mpsc` channel.

#![cfg(feature = "daemon")]

use crate::daemon_dgram::DaemonDgram;
use crate::daemon_envelopes::{
    dgram_event_to_envelope, http_event_to_envelope, net_event_to_envelope, tls_event_to_envelope,
    worker_event_to_envelope,
};
use crate::daemon_http::{DaemonEvent, DaemonHttp};
use crate::daemon_net::DaemonNet;
use crate::daemon_port_claims::SharedPortClaims;
use crate::daemon_runtime::DaemonRuntime;
use crate::daemon_tls::DaemonTls;
use crate::daemon_workers::{DaemonWorkers, WorkerConfig};
use crate::host::TranspileFn;
use afterburner_core::{
    AfterburnerError, HostContext, Manifold, Result, ScriptInvocation, SharedStateStore,
};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use wasmtime::{Engine, InstancePre};

/// Default per-shard mailbox depth. Bounded so a stalled shard
/// can't accumulate unbounded HTTP request memory; deep enough to
/// absorb a ~300 ms burst on the user's box.
pub const DEFAULT_SHARD_QUEUE_DEPTH: usize = 256;

/// Hard ceiling on shard count. Pinned to match Wasmtime's
/// `POOL_TOTAL_MEMORIES = 128` (set in `wasm_engine.rs`) - the
/// pooling allocator pre-allocates that many instance slots, and
/// each shard claims one. Exceeding the pool would fail
/// `instance_pre.instantiate()` on shards 128+ with
/// "no available memory slot" errors. `available_parallelism()`
/// rarely returns more than 128 even on Threadripper-class
/// hardware; the cap also keeps a misconfiguration from spawning
/// thousands of OS threads.
pub const MAX_SHARDS: usize = 128;

/// Configuration for spawning a `DaemonShardPool`.
pub struct ShardPoolConfig {
    /// Maximum number of shards to spawn. The pool may spawn FEWER
    /// than this if shard 0's init does not bind an HTTP listener
    /// (see `expand_only_for_http_listener`). `1` reduces to the
    /// legacy single-runtime semantics; `≥2` enables cluster-
    /// mode-style per-shard JS state for HTTP daemons.
    pub shard_count: usize,
    /// When `true` (the default), the pool only multi-shards when
    /// shard 0's daemon-init bound at least one HTTP listener.
    /// Non-HTTP daemons (timer-only scripts, raw `net`/`tls`/
    /// `dgram` servers, scripts that just open outbound clients)
    /// stay single-shard so init-time side effects (`net.connect`,
    /// `setInterval`, `fetch`, etc.) don't multiply by N.
    ///
    /// Set to `false` for the legacy "always multi-shard" behavior
    /// - useful for benchmarks where init is intentionally trivial
    /// and the amplification doesn't matter.
    pub expand_only_for_http_listener: bool,
    pub engine: Engine,
    pub instance_pre: Arc<InstancePre<crate::host::HostState>>,
    /// Pre-compiled daemon-init bytecode (B4). Shared via `Arc`
    /// so all `N` shards skip the per-launch source compile and
    /// run init from the same bytecode buffer.
    pub init_bytecode: Arc<Vec<u8>>,
    pub manifold: Manifold,
    pub state_store: Option<SharedStateStore>,
    pub host_context: Option<Arc<dyn HostContext>>,
    /// Shared HTTP coordinator. The pool flips `enable_shared_listeners()`
    /// on this so per-shard `app.listen(port)` calls converge on a
    /// single bound socket. Callers must not flip this themselves
    /// before passing it in.
    pub daemon_http: Arc<DaemonHttp>,
    pub transpile_hook: Option<TranspileFn>,
    pub worker_config: WorkerConfig,
    pub tokio_handle: tokio::runtime::Handle,
    pub invocation: ScriptInvocation,
    pub shutdown: Arc<AtomicBool>,
    /// Override for the per-shard mailbox depth. `None` → default.
    pub queue_depth_per_shard: Option<usize>,
}

/// Pool of N daemon runtime shards.
pub struct DaemonShardPool {
    shards: Vec<ShardHandle>,
    daemon_http: Arc<DaemonHttp>,
    /// The dispatcher task that drains `daemon_http`'s event channel
    /// and routes each event to a shard. Lives for the pool's
    /// lifetime; abort on `Drop`.
    dispatcher_task: Option<tokio::task::JoinHandle<()>>,
    /// Per-shard init outcomes - collected during spawn().
    init_results: Vec<InitResult>,
}

struct ShardHandle {
    /// Mailbox for HTTP events dispatched from the dispatcher to
    /// this shard.
    http_tx: mpsc::Sender<DaemonEvent>,
    /// Thread join handle; `None` after the pool's `Drop` joins.
    join: Option<JoinHandle<()>>,
    /// Per-shard alive flag; cleared when the shard thread exits
    /// (cleanly or via panic).
    alive: Arc<AtomicBool>,
    /// Per-shard `has_refs` mirror; cleared by the shard's loop on
    /// natural exit (no listeners + no ref'd timers + no alive
    /// workers).
    has_refs: Arc<AtomicBool>,
    /// Per-shard request counter; incremented before each HTTP
    /// dispatch, decremented after. Tests use this to verify
    /// round-robin distribution.
    requests_handled: Arc<AtomicUsize>,
}

/// Per-shard daemon-init outcome. Stdout/stderr captured so the
/// caller can flush them in deterministic shard order rather than
/// interleaved across N threads.
#[derive(Debug)]
pub struct InitResult {
    pub shard_idx: usize,
    pub has_refs: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

enum InitOutcome {
    Ok(InitResult),
    Err {
        shard_idx: usize,
        /// The original error preserved as-is so the CLI can
        /// match on `AfterburnerError::ProcessExit(code)` and
        /// propagate the right exit code (instead of collapsing
        /// every init error to `exit(1)`).
        error: AfterburnerError,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

impl DaemonShardPool {
    /// Spawn the pool. Each shard runs its daemon-init synchronously
    /// (via `run_init_with_bytecode`) and reports outcome before
    /// `spawn` returns. If any shard's init fails, all shards are
    /// torn down and the failure is surfaced.
    pub fn spawn(cfg: ShardPoolConfig) -> Result<Self> {
        if cfg.shard_count < 1 {
            return Err(AfterburnerError::Engine("shard_count must be ≥ 1".into()));
        }
        if cfg.shard_count > MAX_SHARDS {
            return Err(AfterburnerError::Engine(format!(
                "shard_count must be ≤ {MAX_SHARDS} (got {})",
                cfg.shard_count
            )));
        }

        // Flip the shared-listener arbitration on. Multi-shard or
        // not, we're going through the pool, and the contract is
        // that shards' `app.listen(port)` calls converge on a single
        // bound socket. Single-shard mode (N=1) still gets correct
        // behavior because there's no second shard to race with.
        cfg.daemon_http.enable_shared_listeners();

        // Build a shared port-claim arbiter for the non-HTTP
        // coordinators (DaemonNet / DaemonTls / DaemonDgram). HTTP
        // uses its own embedded arbiter inside DaemonHttp; the rest
        // share this one. See `daemon_port_claims` for the contract.
        let shared_claims = SharedPortClaims::new();

        let queue_depth = cfg
            .queue_depth_per_shard
            .unwrap_or(DEFAULT_SHARD_QUEUE_DEPTH);
        let (init_tx, init_rx) = std::sync::mpsc::channel::<InitOutcome>();
        let mut shards = Vec::with_capacity(cfg.shard_count);
        let mut init_results: Vec<InitResult> = Vec::with_capacity(cfg.shard_count);
        let mut first_failure: Option<(usize, AfterburnerError, Vec<u8>, Vec<u8>)> = None;

        // Helper to spawn a single shard. Used twice: once eagerly
        // for shard 0 (so we can probe the post-init state before
        // committing to N), and again for shards 1..N-1 if we
        // decide to expand.
        let spawn_one = |shard_idx: usize, shards: &mut Vec<ShardHandle>| -> Result<()> {
            let (http_tx, http_rx) = mpsc::channel::<DaemonEvent>(queue_depth);
            let alive = Arc::new(AtomicBool::new(true));
            let has_refs = Arc::new(AtomicBool::new(false));
            let requests_handled = Arc::new(AtomicUsize::new(0));

            let args = ShardThreadArgs {
                shard_idx,
                engine: cfg.engine.clone(),
                instance_pre: cfg.instance_pre.clone(),
                bytecode: Arc::clone(&cfg.init_bytecode),
                manifold: cfg.manifold.clone(),
                state_store: cfg.state_store.clone(),
                host_context: cfg.host_context.clone(),
                daemon_http: Arc::clone(&cfg.daemon_http),
                shared_claims: Arc::clone(&shared_claims),
                transpile_hook: cfg.transpile_hook.clone(),
                worker_config: cfg.worker_config.clone(),
                tokio_handle: cfg.tokio_handle.clone(),
                http_rx,
                shutdown: Arc::clone(&cfg.shutdown),
                init_tx: init_tx.clone(),
                alive: Arc::clone(&alive),
                has_refs: Arc::clone(&has_refs),
                requests_handled: Arc::clone(&requests_handled),
            };

            let join = std::thread::Builder::new()
                .name(format!("burn-shard-{shard_idx}"))
                .spawn(move || {
                    shard_main(args);
                })
                .map_err(|e| AfterburnerError::Engine(format!("spawn shard {shard_idx}: {e}")))?;

            shards.push(ShardHandle {
                http_tx,
                join: Some(join),
                alive,
                has_refs,
                requests_handled,
            });
            Ok(())
        };

        // Phase 1: spawn shard 0 only, wait for its init outcome.
        // This lets us inspect post-init state (specifically: did
        // user code bind an HTTP listener?) BEFORE committing to N
        // shards. The motivation is correctness, not perf: if init
        // does `net.connect(api)` or `setInterval(refresh, 1000)`
        // at the top level, we don't want to multiply those side
        // effects N times. HTTP daemons are the multi-shard sweet
        // spot - the bound listener is the dispatch boundary, and
        // every shard needs its own JS state to handle requests in
        // parallel. Non-HTTP daemons stay single-shard.
        spawn_one(0, &mut shards)?;
        let shard0_outcome = init_rx
            .recv()
            .map_err(|_| AfterburnerError::Engine("shard 0 dropped before init".into()))?;
        match shard0_outcome {
            InitOutcome::Ok(r) => init_results.push(r),
            InitOutcome::Err {
                shard_idx,
                error,
                stdout,
                stderr,
            } => {
                first_failure = Some((shard_idx, error, stdout, stderr));
            }
        }

        // Phase 2: decide whether to expand. Only multi-shard if
        // shard 0 succeeded AND its init bound an HTTP listener
        // AND the caller actually wanted > 1 shard AND the
        // expansion gate is enabled (set false to force the
        // legacy "always multi-shard" behavior).
        let should_expand = first_failure.is_none()
            && cfg.shard_count > 1
            && (!cfg.expand_only_for_http_listener || cfg.daemon_http.listener_count() > 0);

        if should_expand {
            for shard_idx in 1..cfg.shard_count {
                if let Err(e) = spawn_one(shard_idx, &mut shards) {
                    first_failure = Some((shard_idx, e, Vec::new(), Vec::new()));
                    break;
                }
            }
        }

        // Drop the original sender so init_rx terminates after the
        // remaining shards (if any) report.
        drop(init_tx);

        // Phase 3: drain remaining init outcomes. If we expanded,
        // there are shard_count - 1 more to receive. If we didn't,
        // init_tx has already been fully released (only shard 0's
        // clone existed and fired) and recv loop terminates
        // immediately.
        while let Ok(outcome) = init_rx.recv() {
            match outcome {
                InitOutcome::Ok(r) => init_results.push(r),
                InitOutcome::Err {
                    shard_idx,
                    error,
                    stdout,
                    stderr,
                } => {
                    if first_failure.is_none() {
                        first_failure = Some((shard_idx, error, stdout, stderr));
                    } else {
                        // Subsequent failures are usually the same
                        // cause (every shard runs the same init); log
                        // briefly without verbatim repeat.
                        eprintln!("burn: shard {shard_idx} init also failed");
                    }
                }
            }
        }

        if let Some((shard_idx, error, stdout, stderr)) = first_failure {
            // Init failure: signal shutdown so all shards exit, drop
            // pool, propagate error. ProcessExit passes through
            // unchanged so the CLI can `std::process::exit(code)`
            // with the user's intended code instead of collapsing
            // to 1.
            cfg.shutdown.store(true, Ordering::Release);
            // Surface init's stdout/stderr to the user - useful for
            // diagnosing init failures (TS compile errors, missing
            // modules, etc.). For ProcessExit suppress the stderr
            // because there's nothing wrong - the user's script
            // intentionally exited.
            let _ = std::io::stdout().write_all(&stdout);
            if !matches!(error, AfterburnerError::ProcessExit(_)) {
                let _ = std::io::stderr().write_all(&stderr);
            }
            // Drop senders so any surviving shards' loops exit.
            drop(shards);
            return Err(match error {
                AfterburnerError::ProcessExit(code) => AfterburnerError::ProcessExit(code),
                other => AfterburnerError::Engine(format!("shard {shard_idx} init: {other}")),
            });
        }

        // Sort results by shard idx so callers see deterministic order.
        init_results.sort_by_key(|r| r.shard_idx);

        // Spawn the dispatcher task on the tokio runtime. It drains
        // `daemon_http.event_rx` and RR-sends each event to a shard.
        let shard_senders: Vec<mpsc::Sender<DaemonEvent>> =
            shards.iter().map(|s| s.http_tx.clone()).collect();
        let shard_alives: Vec<Arc<AtomicBool>> =
            shards.iter().map(|s| Arc::clone(&s.alive)).collect();
        let shard_request_counters: Vec<Arc<AtomicUsize>> = shards
            .iter()
            .map(|s| Arc::clone(&s.requests_handled))
            .collect();
        let coord = Arc::clone(&cfg.daemon_http);
        let shutdown_disp = Arc::clone(&cfg.shutdown);

        let dispatcher_task = cfg.tokio_handle.spawn(async move {
            run_dispatcher(
                coord,
                shard_senders,
                shard_alives,
                shard_request_counters,
                shutdown_disp,
            )
            .await;
        });

        Ok(Self {
            shards,
            daemon_http: cfg.daemon_http,
            dispatcher_task: Some(dispatcher_task),
            init_results,
        })
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Number of shard threads still running. A panicking shard sets
    /// its `alive` to false; tests use this to verify isolation.
    pub fn shards_alive(&self) -> usize {
        self.shards
            .iter()
            .filter(|s| s.alive.load(Ordering::Acquire))
            .count()
    }

    /// `true` if any shard reports refs (listener bound, ref'd timer,
    /// alive worker_threads child). The CLI uses this to decide
    /// whether to wait on the event loop or exit cleanly after init.
    pub fn any_has_refs(&self) -> bool {
        self.shards
            .iter()
            .any(|s| s.has_refs.load(Ordering::Acquire))
    }

    /// Per-shard init outcomes. Sorted by shard index.
    pub fn init_results(&self) -> &[InitResult] {
        &self.init_results
    }

    /// Per-shard request counters (`requests_handled[i]`). Tests use
    /// this to verify round-robin fairness.
    pub fn request_counts(&self) -> Vec<usize> {
        self.shards
            .iter()
            .map(|s| s.requests_handled.load(Ordering::Acquire))
            .collect()
    }

    pub fn daemon_http(&self) -> &Arc<DaemonHttp> {
        &self.daemon_http
    }

    /// Block until all shards exit naturally. Used by the CLI's
    /// shutdown path to drain in-flight requests. Does NOT signal
    /// shutdown - the caller must set the shutdown flag (or close
    /// listeners and clear timers) separately.
    pub fn join_all(&mut self) {
        for shard in &mut self.shards {
            if let Some(join) = shard.join.take() {
                let _ = join.join();
            }
        }
    }
}

impl Drop for DaemonShardPool {
    fn drop(&mut self) {
        // Drop the http_tx senders, then join the threads. Each
        // shard's `recv()` returns `None` when its sender drops, so
        // the loop exits naturally. The shutdown flag (if set) also
        // breaks out of the per-shard event loops.
        for shard in &mut self.shards {
            if let Some(join) = shard.join.take() {
                let _ = join.join();
            }
        }
        if let Some(task) = self.dispatcher_task.take() {
            task.abort();
        }
    }
}

// ----- per-shard thread -----

struct ShardThreadArgs {
    shard_idx: usize,
    engine: Engine,
    instance_pre: Arc<InstancePre<crate::host::HostState>>,
    bytecode: Arc<Vec<u8>>,
    manifold: Manifold,
    state_store: Option<SharedStateStore>,
    host_context: Option<Arc<dyn HostContext>>,
    daemon_http: Arc<DaemonHttp>,
    /// Process-shared port arbiter for raw TCP / TLS / UDP
    /// listeners. Same `Arc` is handed to every shard so
    /// `net.createServer().listen(p)` (or the TLS / dgram
    /// equivalent) converges on a single owner without
    /// EADDRINUSE on followers.
    shared_claims: Arc<SharedPortClaims>,
    transpile_hook: Option<TranspileFn>,
    worker_config: WorkerConfig,
    tokio_handle: tokio::runtime::Handle,
    http_rx: mpsc::Receiver<DaemonEvent>,
    shutdown: Arc<AtomicBool>,
    init_tx: std::sync::mpsc::Sender<InitOutcome>,
    alive: Arc<AtomicBool>,
    has_refs: Arc<AtomicBool>,
    requests_handled: Arc<AtomicUsize>,
}

fn shard_main(args: ShardThreadArgs) {
    let shard_idx = args.shard_idx;
    let alive = Arc::clone(&args.alive);
    // Wrap the entire shard body in catch_unwind so a panic inside
    // user code (or our event loop) doesn't poison the pool.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        shard_main_inner(args);
    }));
    if let Err(panic) = result {
        eprintln!("burn: shard {shard_idx} thread panicked: {panic:?}");
    }
    alive.store(false, Ordering::Release);
}

fn shard_main_inner(args: ShardThreadArgs) {
    let ShardThreadArgs {
        shard_idx,
        engine,
        instance_pre,
        bytecode,
        manifold,
        state_store,
        host_context,
        daemon_http,
        shared_claims,
        transpile_hook,
        worker_config,
        tokio_handle,
        mut http_rx,
        shutdown,
        init_tx,
        alive: _alive,
        has_refs,
        requests_handled,
    } = args;

    // Step 1: instantiate the daemon Store on this thread.
    let mut daemon = match DaemonRuntime::instantiate(
        &engine,
        &instance_pre,
        manifold.clone(),
        state_store,
        host_context,
        Arc::clone(&daemon_http),
        transpile_hook,
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = init_tx.send(InitOutcome::Err {
                shard_idx,
                error: e,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
            return;
        }
    };

    // Step 2: install per-shard coordinators. Each gets the
    // shard's own Manifold clone (capability gates apply per-Store)
    // AND a reference to the same `shared_claims` arbiter so
    // `net.createServer().listen(p)` etc. converge on a single
    // owner across shards instead of fighting for the kernel-level
    // bind. See `daemon_port_claims` for the owner / follower
    // contract.
    let workers = DaemonWorkers::new_parent(manifold.clone(), worker_config);
    daemon.install_workers(Arc::clone(&workers));
    let net = DaemonNet::new_with_claims(
        tokio_handle.clone(),
        manifold.clone(),
        Arc::clone(&shared_claims),
    );
    daemon.install_net(Arc::clone(&net));
    let tls = DaemonTls::new_with_claims(
        tokio_handle.clone(),
        manifold.clone(),
        Arc::clone(&shared_claims),
    );
    daemon.install_tls(Arc::clone(&tls));
    let dgram = DaemonDgram::new_with_claims(tokio_handle.clone(), manifold, shared_claims);
    daemon.install_dgram(Arc::clone(&dgram));

    // Outbound HTTP coordinator - async per-shard. JS calls to
    // `http.request` / `https.request` / `fetch` go through this
    // coord, which spawns the actual round-trip on the same Tokio
    // runtime that drives axum / net / tls. Responses come back
    // through a per-shard channel that the dispatch loop polls each
    // tick (added below alongside the other event sources).
    let http_outbound = crate::daemon_http_outbound::DaemonHttpOutbound::new(tokio_handle.clone());
    daemon.install_http_outbound(Arc::clone(&http_outbound));

    // Inspector / Chrome DevTools Protocol coordinator. Cheap to
    // construct (no listener until `inspector.open(port)`); installed
    // unconditionally so the JS side's `__host_inspector_open` host
    // import lights up the moment user code enables the inspector.
    let inspector = crate::daemon_inspector::DaemonInspector::new(tokio_handle.clone());
    daemon.install_inspector(Arc::clone(&inspector));

    // Step 3: run init from precompiled bytecode. The shared
    // `daemon_http` is in shared-listeners mode so this shard's
    // `app.listen(port)` either binds the real socket (first shard)
    // or rejoins the existing id (later shards), fully lock-free.
    if let Err(e) = daemon.run_init_with_bytecode(&bytecode) {
        let stdout = daemon.drain_stdout();
        let stderr = daemon.drain_stderr();
        let _ = init_tx.send(InitOutcome::Err {
            shard_idx,
            error: e,
            stdout,
            stderr,
        });
        return;
    }

    // Step 4: report init success + initial state.
    let stdout = daemon.drain_stdout();
    let stderr = daemon.drain_stderr();
    // Per-shard stdout/stderr high-water marks initialised to the
    // post-init lengths so the event-loop flush doesn't re-emit
    // init output. Only shard 0's init output is surfaced to the
    // user (via init_results); other shards' identical init output
    // is suppressed at flush time.
    let mut stdout_hw: usize = stdout.len();
    let mut stderr_hw: usize = stderr.len();
    let initial_has_refs = daemon.has_refs();
    has_refs.store(initial_has_refs, Ordering::Release);
    let _ = init_tx.send(InitOutcome::Ok(InitResult {
        shard_idx,
        has_refs: initial_has_refs,
        stdout,
        stderr,
    }));
    drop(init_tx); // close this end so the pool's recv loop terminates
    // after all N shards report

    // Step 5: enter the per-shard event loop.
    shard_event_loop(
        shard_idx,
        &mut daemon,
        &mut http_rx,
        &shutdown,
        &has_refs,
        &requests_handled,
        &mut stdout_hw,
        &mut stderr_hw,
    );
}

#[allow(clippy::too_many_arguments)]
fn shard_event_loop(
    shard_idx: usize,
    daemon: &mut DaemonRuntime,
    http_rx: &mut mpsc::Receiver<DaemonEvent>,
    shutdown: &Arc<AtomicBool>,
    has_refs: &Arc<AtomicBool>,
    requests_handled: &Arc<AtomicUsize>,
    stdout_hw: &mut usize,
    stderr_hw: &mut usize,
) {
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        if !daemon.has_refs() {
            // Event loop drained - emit Node's shutdown lifecycle
            // before tearing the shard down so `process.on('beforeExit')`
            // / `process.on('exit')` handlers run. npm (and many CLIs)
            // buffer ALL their output and flush it from an 'exit'
            // handler - without this the script that completed by
            // draining the loop (rather than calling `process.exit()`)
            // prints nothing and never finalizes. A 'beforeExit' handler
            // may schedule new work (a timer / async I/O); if it does,
            // `has_refs()` flips back true and we keep looping (Node
            // re-fires 'beforeExit' each time the loop empties). 'exit'
            // fires exactly once, right before we break.
            emit_lifecycle(shard_idx, daemon, "beforeExit", stdout_hw, stderr_hw);
            if daemon.has_refs() {
                continue;
            }
            emit_lifecycle(shard_idx, daemon, "exit", stdout_hw, stderr_hw);
            has_refs.store(false, Ordering::Release);
            break;
        }
        has_refs.store(true, Ordering::Release);

        let mut did_work = false;

        // ---- HTTP events from this shard's mailbox ----
        // Drain a bounded batch per loop tick so a chatty mailbox
        // doesn't starve the local event sources.
        for _ in 0..32 {
            match http_rx.try_recv() {
                Ok(event) => {
                    did_work = true;
                    requests_handled.fetch_add(1, Ordering::Relaxed);
                    let envelope = http_event_to_envelope(&event);
                    dispatch_with_panic_isolation(
                        shard_idx, daemon, envelope, "http", stdout_hw, stderr_hw,
                    );
                    let _ = flush_streams(daemon, stdout_hw, stderr_hw);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Pool dropped its sender; HTTP requests can no
                    // longer reach this shard. Other event sources
                    // may still keep refs alive (timers, workers).
                    break;
                }
            }
        }

        // ---- Timers ----
        let fired = daemon.drain_expired_timers();
        for timer_id in fired {
            did_work = true;
            let envelope = serde_json::json!({
                "kind": "timer-fire",
                "timer_id": timer_id,
            });
            dispatch_with_panic_isolation(
                shard_idx, daemon, envelope, "timer", stdout_hw, stderr_hw,
            );
            let _ = flush_streams(daemon, stdout_hw, stderr_hw);
        }

        // ---- Worker events ----
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_worker_event() else {
                break;
            };
            did_work = true;
            let (envelope, reap_id) = worker_event_to_envelope(&evt);
            dispatch_with_panic_isolation(
                shard_idx, daemon, envelope, "worker", stdout_hw, stderr_hw,
            );
            let _ = flush_streams(daemon, stdout_hw, stderr_hw);
            if let Some(id) = reap_id {
                daemon.reap_worker(id);
            }
        }

        // ---- Net events ----
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_net_event() else {
                break;
            };
            did_work = true;
            let (envelope, reap_id) = net_event_to_envelope(&evt);
            dispatch_with_panic_isolation(shard_idx, daemon, envelope, "net", stdout_hw, stderr_hw);
            let _ = flush_streams(daemon, stdout_hw, stderr_hw);
            if let Some(id) = reap_id {
                daemon.mark_net_closed(id);
            }
        }

        // ---- Outbound HTTP responses ----
        // Each shard owns its outbound coordinator; responses for
        // requests this shard issued land here. Drain a generous
        // batch per tick - npm install fans out 50+ concurrent
        // requests during dependency resolution, and stalling on
        // queue drain stretches install wall time.
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_http_outbound_response() else {
                break;
            };
            did_work = true;
            let envelope = crate::daemon_envelopes::http_outbound_response_to_envelope(&evt);
            dispatch_with_panic_isolation(
                shard_idx,
                daemon,
                envelope,
                "http-response",
                stdout_hw,
                stderr_hw,
            );
            let _ = flush_streams(daemon, stdout_hw, stderr_hw);
        }

        // ---- TLS events ----
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_tls_event() else {
                break;
            };
            did_work = true;
            let (envelope, reap_id) = tls_event_to_envelope(&evt);
            dispatch_with_panic_isolation(shard_idx, daemon, envelope, "tls", stdout_hw, stderr_hw);
            let _ = flush_streams(daemon, stdout_hw, stderr_hw);
            if let Some(id) = reap_id {
                daemon.mark_tls_closed(id);
            }
        }

        // ---- dgram events ----
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_dgram_event() else {
                break;
            };
            did_work = true;
            let envelope = dgram_event_to_envelope(&evt);
            dispatch_with_panic_isolation(
                shard_idx, daemon, envelope, "dgram", stdout_hw, stderr_hw,
            );
            let _ = flush_streams(daemon, stdout_hw, stderr_hw);
        }

        // ---- inspector / CDP events ----
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_inspector_event() else {
                break;
            };
            did_work = true;
            if let Some(envelope) = crate::daemon_envelopes::inspector_event_to_envelope(&evt) {
                dispatch_with_panic_isolation(
                    shard_idx,
                    daemon,
                    envelope,
                    "inspector",
                    stdout_hw,
                    stderr_hw,
                );
                let _ = flush_streams(daemon, stdout_hw, stderr_hw);
            }
        }

        if !did_work {
            // No events processed this iteration - sleep briefly,
            // bounded by the next timer's fire-time. Same shape as
            // the legacy single-shard run loop.
            let max_sleep = Duration::from_millis(5);
            let sleep_dur = daemon
                .next_timer_deadline()
                .map(|d| d.saturating_duration_since(Instant::now()).min(max_sleep))
                .unwrap_or(max_sleep);
            std::thread::sleep(sleep_dur);
        }
    }

    has_refs.store(false, Ordering::Release);
}

/// Wrap one `dispatch_event` call in `catch_unwind`. A panic inside
/// the JS handler (or any host import called from it) doesn't
/// propagate up the shard thread; we log + carry on with the next
/// event. The HTTP reply (if any) was registered as a pending slot
/// in `DaemonHttp.pending` - when the panicked dispatch fails to
/// call `__host_http_reply`, axum's `recv_async` waits forever on
/// that req_id. To prevent this, we cancel the pending slot on
/// dispatch error.
///
/// On `ProcessExit`, flushes the shard's stdout/stderr before
/// calling `std::process::exit(code)` - otherwise the user's
/// `console.log` immediately preceding `process.exit()` gets lost
/// in the shard's MemoryOutputPipe.
fn dispatch_with_panic_isolation(
    shard_idx: usize,
    daemon: &mut DaemonRuntime,
    envelope: serde_json::Value,
    kind: &'static str,
    stdout_hw: &mut usize,
    stderr_hw: &mut usize,
) {
    // Pull req_id out of the envelope BEFORE handing it off, so we
    // can cancel the pending reply slot if dispatch traps. (HTTP-
    // event envelopes carry req_id at the top level.)
    let req_id_for_cancel: Option<i64> = if kind == "http" {
        envelope.get("req_id").and_then(|v| v.as_i64())
    } else {
        None
    };

    let coord = Arc::clone(daemon.http());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        daemon.dispatch_event(envelope)
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // Dispatch returned an error (Trap, fuel exhaust, exit).
            // For ProcessExit, flush captured stdout/stderr from
            // this shard so the user's `console.log` immediately
            // before `process.exit()` reaches the host pipe before
            // we tear down the process.
            if let AfterburnerError::ProcessExit(code) = &e {
                let _ = flush_streams(daemon, stdout_hw, stderr_hw);
                std::process::exit(*code);
            }
            eprintln!("burn: shard {shard_idx} {kind} dispatch error: {e}");
            if let Some(rid) = req_id_for_cancel {
                cancel_pending_reply(&coord, rid);
            }
        }
        Err(panic) => {
            eprintln!("burn: shard {shard_idx} {kind} dispatch panicked: {panic:?}");
            if let Some(rid) = req_id_for_cancel {
                cancel_pending_reply(&coord, rid);
            }
        }
    }
}

/// Synthesise a 500 response into a pending reply slot so the axum
/// task isn't stuck forever waiting on `__host_http_reply`. Idempotent
/// - `take_reply` returns `None` if the JS already replied.
fn cancel_pending_reply(coord: &Arc<DaemonHttp>, req_id: i64) {
    if let Some(pending) = coord.take_reply(req_id) {
        // Best-effort send of an empty 500. The axum side just sees
        // a generic internal-error response.
        pending.sender.send(crate::daemon_http::ReplyEnvelope {
            status: 500,
            headers: Vec::new(),
            body: b"burn: shard dispatch failed".to_vec(),
        });
    }
}

/// Emit a Node process lifecycle event ('beforeExit' / 'exit') into the
/// shard's JS Store, then flush whatever the handler printed. Routed
/// through the same panic-isolated dispatch as timers/HTTP so a throwing
/// handler can't take down the shard thread, and so a `process.exit()`
/// from inside a handler still propagates as `ProcessExit`. This is what
/// makes `process.on('exit')` flushers (npm buffers all its output there)
/// actually run when a script finishes by draining the event loop rather
/// than calling `process.exit()`.
fn emit_lifecycle(
    shard_idx: usize,
    daemon: &mut DaemonRuntime,
    event_name: &'static str,
    stdout_hw: &mut usize,
    stderr_hw: &mut usize,
) {
    let envelope = serde_json::json!({
        "kind": "lifecycle",
        "event_name": event_name,
    });
    dispatch_with_panic_isolation(
        shard_idx,
        daemon,
        envelope,
        "lifecycle",
        stdout_hw,
        stderr_hw,
    );
    let _ = flush_streams(daemon, stdout_hw, stderr_hw);
}

fn flush_streams(
    daemon: &mut DaemonRuntime,
    stdout_hw: &mut usize,
    stderr_hw: &mut usize,
) -> std::io::Result<()> {
    let stdout = daemon.drain_stdout();
    let stderr = daemon.drain_stderr();
    // Explicit per-shard high-water marks. Each shard's loop owns
    // its own pair of usize and passes them in by &mut. The shard
    // never re-emits already-flushed bytes; stdout from different
    // shards interleaves at line boundaries (best-effort, matches
    // Node's cluster module).
    if stdout.len() > *stdout_hw {
        let mut so = std::io::stdout().lock();
        so.write_all(&stdout[*stdout_hw..])?;
        so.flush()?;
        *stdout_hw = stdout.len();
    }
    if stderr.len() > *stderr_hw {
        let mut se = std::io::stderr().lock();
        se.write_all(&stderr[*stderr_hw..])?;
        se.flush()?;
        *stderr_hw = stderr.len();
    }
    Ok(())
}

// ----- dispatcher task -----

/// Drain `DaemonHttp.event_rx` in an async loop, RR-route each event
/// to a shard's mailbox. Lives on the tokio runtime; aborted by
/// the pool's `Drop`.
async fn run_dispatcher(
    coord: Arc<DaemonHttp>,
    shard_senders: Vec<mpsc::Sender<DaemonEvent>>,
    shard_alives: Vec<Arc<AtomicBool>>,
    shard_request_counters: Vec<Arc<AtomicUsize>>,
    shutdown: Arc<AtomicBool>,
) {
    let n = shard_senders.len();
    if n == 0 {
        return;
    }
    let next = AtomicUsize::new(0);

    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        // The kovan_channel `try_recv` is non-blocking; we yield
        // briefly when empty so the scheduler can pick this task
        // up promptly when an event arrives without burning CPU
        // here on idle.
        match coord.try_recv_event() {
            Some(event) => {
                let start = next.fetch_add(1, Ordering::Relaxed) % n;
                let mut sent = false;
                for offset in 0..n {
                    let idx = (start + offset) % n;
                    if !shard_alives[idx].load(Ordering::Acquire) {
                        continue;
                    }
                    match shard_senders[idx].try_send(event.clone()) {
                        Ok(()) => {
                            // Counter increments inside the shard's
                            // own loop on receipt; we don't double-
                            // count here.
                            let _ = &shard_request_counters; // keep alive
                            sent = true;
                            break;
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => continue,
                        Err(mpsc::error::TrySendError::Closed(_)) => continue,
                    }
                }
                if !sent {
                    // All shards full or down - fall back to async
                    // send on the originally-chosen shard so we
                    // backpressure rather than drop.
                    let idx = start;
                    if shard_alives[idx].load(Ordering::Acquire) {
                        let _ = shard_senders[idx].send(event).await;
                    }
                    // If all are down: silently drop. Caller's axum
                    // task observes a stuck reply slot and times out.
                }
            }
            None => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
}
