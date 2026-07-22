// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! `afterburner-thrust` - multi-threaded scheduler for afterburner.
//!
//! Turns the single-threaded `WasmCombustor` into an N-worker pool with
//! per-worker kovan-channel queues, hash-based script → worker affinity
//! (uses pooled Wasmtime slots), steal-when-idle, token-bucket
//! admission per tenant, and a dirty pool for blocking host calls.
//!
//! `thrust()` picks a worker via `hash(script_id) % num_workers` and
//! pushes the job onto that worker's queue. A shared
//! `Arc<WasmCombustor>` handles execution; fan-out wins parallelism
//! across distinct scripts without duplicating the wasmtime engine or
//! plugin module.

#![deny(missing_debug_implementations)]

mod admission;
mod numa;

use admission::TokenBucketAdmission;
use afterburner_core::governance::{ThreadGovernance, spawn_governed};
use afterburner_core::ledger::{LedgerClass, MemoryLedger};
use afterburner_core::{AfterburnerError, Combustor, FuelGauge, OutputValue, Result, ScriptId};
use afterburner_wasi::{WasmCombustor, WasmConfig};
use kovan_channel::flavors::unbounded::{Receiver, Sender};
use kovan_channel::unbounded;
use kovan_queue::array_queue::ArrayQueue;
use numa::{NumaTopology, pin_current_thread_to_worker};
use serde_json::Value;
use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────
// Shutdown signaling (3-state)
// ─────────────────────────────────────────────────────────────────────────
//
// Runtime states the worker loop checks. `Drop` walks Run → Drain →
// Force, giving up to `config.shutdown_drain_deadline` for in-flight
// queues to drain naturally before forcing immediate exit.

const STATE_RUN: u8 = 0;
const STATE_DRAIN: u8 = 1;
const STATE_FORCE: u8 = 2;

// ─────────────────────────────────────────────────────────────────────────
// Tenant identity
// ─────────────────────────────────────────────────────────────────────────

/// Opaque tenant identifier used by the admission layer (§5, T4). A small
/// integer keyed into a lock-free map - callers pick the mapping.
///
/// `None` at the `thrust` call site means the caller is *trusted*: the
/// token bucket is skipped entirely and the thrust enters the queue at
/// wire speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(pub NonZeroU32);

impl TenantId {
    /// `None` if `id == 0`.
    #[inline]
    pub const fn new(id: u32) -> Option<Self> {
        match NonZeroU32::new(id) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// Raw integer, for logging / error payloads.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tenant#{}", self.0.get())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Engine configuration
// ─────────────────────────────────────────────────────────────────────────

/// `ThrustEngineConfig` is the full knob surface of the scheduler.
///
/// **Clone is required** (usability-plan §8 commitment): the facade crate
/// stores a builder snapshot, then hands it to `ThrustEngine::new`, which
/// itself clones a copy into each worker.
///
/// `Debug` is implemented manually below - `WasmConfig` embeds an
/// `Option<Arc<dyn HostContext>>` which isn't `Debug`, so the derive
/// doesn't carry over.
#[derive(Clone)]
pub struct ThrustEngineConfig {
    /// Compute workers. `0` → auto-probe via
    /// [`std::thread::available_parallelism`] (which is logical CPUs,
    /// SMT-inclusive; a future refinement is to fall back to a
    /// physical-core count per plan §14).
    pub compute_workers: usize,

    /// I/O pool size. `0` disables dirty-scheduler offload (T6).
    pub io_workers: usize,

    /// Per-tenant token-bucket refill rate (tokens/sec). `None` = no
    /// admission control. See T4.
    pub admission_tokens_per_sec: Option<u64>,

    /// Token-bucket burst cap. Ignored when `admission_tokens_per_sec` is
    /// `None`.
    pub admission_burst_tokens: u64,

    /// Soft cap on a worker's local backlog before `thrust()` falls
    /// through to the global injector. Plan §5.1 baseline is 256
    /// (covers ~12 ms of 50 µs work). `0` falls back to that default.
    pub local_queue_capacity: usize,

    /// Hard cap on the global injector before `thrust()` returns
    /// `AfterburnerError::Overloaded`. Sized at 16× the per-worker cap
    /// by default - represents the system-wide in-flight ceiling that
    /// keeps the pooling-allocator + reply-channel memory growth
    /// bounded under burst.
    pub injector_capacity: usize,

    /// Maximum time `Drop` waits for workers to drain queued jobs
    /// before flipping to a force-exit. `Duration::ZERO` skips drain
    /// entirely (workers exit on the next iteration). Default 5 s
    /// covers a backlog of ~2500 thrusts at 200/sec/worker; production
    /// clusters with sticky long-tail jobs may bump this.
    pub shutdown_drain_deadline: Duration,

    /// WasmCombustor configuration shared across every worker. Cloned per
    /// worker construction; each worker adds its own `HostState` per call.
    pub wasm_config: WasmConfig,

    /// Governance (nice / affinity / name prefix) applied to every
    /// compute worker and the admission sweep thread this engine spawns.
    /// `Some(affinity)` overrides the NUMA round-robin pin
    /// ([`numa::pin_current_thread_to_worker`]) for the workers; `nice`
    /// applies to both. `Default` (every field `None`) is a pure no-op -
    /// today's ungoverned pool, byte-identical.
    pub governance: ThreadGovernance,

    /// Optional embedder-owned memory-accounting hook, charged at job
    /// enqueue (reserve, [`LedgerClass::QueuedJob`]) and at
    /// execute-or-drop (release). Independent of
    /// `wasm_config.memory_ledger`, which charges the wrapped
    /// combustor's own module cache - this axis charges the thrust
    /// queue's own resident bytes. `None` (the default) is a pure
    /// no-op: the per-enqueue sizing pass is skipped entirely when
    /// unset.
    pub memory_ledger: Option<Arc<dyn MemoryLedger>>,
}

impl Default for ThrustEngineConfig {
    fn default() -> Self {
        Self {
            compute_workers: 4,
            io_workers: 0,
            admission_tokens_per_sec: None,
            admission_burst_tokens: 0,
            local_queue_capacity: 256,
            injector_capacity: 4096,
            shutdown_drain_deadline: Duration::from_secs(5),
            wasm_config: WasmConfig::default(),
            governance: ThreadGovernance::default(),
            memory_ledger: None,
        }
    }
}

impl fmt::Debug for ThrustEngineConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `wasm_config` is opaque on purpose: its `host_context` may be a
        // user-supplied trait object we can't format safely. Same for
        // `memory_ledger` - the embedder's `dyn MemoryLedger` isn't Debug.
        f.debug_struct("ThrustEngineConfig")
            .field("compute_workers", &self.compute_workers)
            .field("io_workers", &self.io_workers)
            .field("admission_tokens_per_sec", &self.admission_tokens_per_sec)
            .field("admission_burst_tokens", &self.admission_burst_tokens)
            .field("local_queue_capacity", &self.local_queue_capacity)
            .field("injector_capacity", &self.injector_capacity)
            .field("shutdown_drain_deadline", &self.shutdown_drain_deadline)
            .field("wasm_config", &"<opaque>")
            .field("governance", &self.governance)
            .field("memory_ledger", &self.memory_ledger.is_some())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Bounded queue: lock-free ring (kovan_queue::ArrayQueue)
// ─────────────────────────────────────────────────────────────────────────
//
// Fixed-capacity lock-free MPMC ring with a single CAS per op and no
// per-item allocation - measured 1.4x-2.9x faster than the previous
// depth-counter-over-unbounded-channel construction at every MPMC
// config. The cap is strict (no momentary overshoot): `try_push`
// returns `Err(item)` at capacity so the caller can re-route (to the
// injector) rather than block; `try_pop` is non-blocking. Requires
// kovan-queue >= 0.1.16 (earlier versions livelocked at capacity 1).

struct BoundedQueue<T> {
    q: ArrayQueue<T>,
}

impl<T> BoundedQueue<T> {
    fn new(cap: usize) -> Self {
        Self {
            q: ArrayQueue::new(cap),
        }
    }

    /// Try to push. Returns `Err(item)` if the queue is full, leaving
    /// the item with the caller for re-routing.
    fn try_push(&self, item: T) -> std::result::Result<(), T> {
        self.q.push(item)
    }

    /// Non-blocking pop.
    fn try_pop(&self) -> Option<T> {
        self.q.pop()
    }
}

impl<T> fmt::Debug for BoundedQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedQueue")
            .field("cap", &self.q.capacity())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Stats snapshot
// ─────────────────────────────────────────────────────────────────────────

/// Snapshot of engine counters at call time. Produced by
/// `ThrustEngine::stats()`.
#[derive(Debug, Default, Clone)]
pub struct ThrustEngineStats {
    pub thrusts_queued: u64,
    pub thrusts_completed: u64,
    pub thrusts_rejected: u64,
    pub thrusts_overloaded: u64,
    pub thrusts_via_injector: u64,
    /// Number of tenant buckets currently tracked by the admission
    /// layer. `0` when admission is disabled. A useful pressure-watch
    /// signal; the sweep evicts buckets idle past 5 minutes (P3).
    pub tenant_buckets_tracked: usize,
    /// NUMA nodes detected at engine-startup time (Linux only - all
    /// other platforms report `1`). Workers are round-robined across
    /// nodes and pinned to their node's CPU set via
    /// `sched_setaffinity`.
    pub numa_nodes: usize,
}

// Raw atomic counters kept on the engine - cloned into `ThrustEngineStats`
// by `stats()`. Shared with workers via `Arc`.
#[derive(Debug, Default)]
struct StatsCounters {
    thrusts_queued: AtomicU64,
    thrusts_completed: AtomicU64,
    thrusts_rejected: AtomicU64,
    thrusts_overloaded: AtomicU64,
    thrusts_via_injector: AtomicU64,
    /// Live worker-thread count. Each worker increments at start and
    /// decrements on exit; `Drop` polls this to decide when the drain
    /// has finished naturally.
    workers_alive: AtomicUsize,
}

impl StatsCounters {
    fn snapshot(&self) -> ThrustEngineStats {
        ThrustEngineStats {
            thrusts_queued: self.thrusts_queued.load(Ordering::Relaxed),
            thrusts_completed: self.thrusts_completed.load(Ordering::Relaxed),
            thrusts_rejected: self.thrusts_rejected.load(Ordering::Relaxed),
            thrusts_overloaded: self.thrusts_overloaded.load(Ordering::Relaxed),
            thrusts_via_injector: self.thrusts_via_injector.load(Ordering::Relaxed),
            // Filled in by `ThrustEngine::stats` from the admission
            // layer; the raw counters don't see it.
            tenant_buckets_tracked: 0,
            // Likewise filled in from the NumaTopology.
            numa_nodes: 1,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Thrust handle (one-shot result channel)
// ─────────────────────────────────────────────────────────────────────────

/// Future-like receiver for a thrust result. Hands back exactly one
/// `Result<Value>` from the worker that executed (or would have executed)
/// the job.
pub struct ThrustHandle {
    rx: Receiver<Result<Value>>,
}

impl ThrustHandle {
    /// Block until the worker posts a result, then consume the handle.
    ///
    /// If the sending side is dropped without sending (can happen if the
    /// engine shuts down mid-flight), returns
    /// `Err(AfterburnerError::Engine("thrust channel closed"))`.
    pub fn recv(self) -> Result<Value> {
        self.rx
            .recv()
            .unwrap_or_else(|| Err(AfterburnerError::Engine("thrust channel closed".into())))
    }

    /// Non-blocking poll. `None` means "result not ready yet" - caller
    /// may retry. `Some(Err(Engine("closed")))` means the engine will
    /// never send.
    pub fn try_recv(&self) -> Option<Result<Value>> {
        self.rx.try_recv()
    }

    /// Poll with a wall-clock deadline. `None` = timed out (retryable);
    /// `Some(...)` = result or channel-closed.
    ///
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Result<Value>> {
        let deadline = Instant::now() + timeout;
        let mut sleep = Duration::from_micros(50);
        let cap = Duration::from_millis(2);
        loop {
            if let Some(v) = self.rx.try_recv() {
                return Some(v);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline - now;
            thread::sleep(sleep.min(remaining));
            sleep = (sleep * 2).min(cap);
        }
    }
}

impl fmt::Debug for ThrustHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrustHandle").finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Internal job
// ─────────────────────────────────────────────────────────────────────────

/// One unit of work pushed onto the worker queue.
struct Job {
    id: ScriptId,
    input: Value,
    limits: FuelGauge,
    /// Tenant carried through for stats / future admission; unused in T1.
    #[allow(dead_code)]
    tenant: Option<TenantId>,
    /// One-shot reply channel back to the caller's `ThrustHandle`. `Option`
    /// so `execute` can take it via `&mut self` instead of a partial move
    /// out of `self` - `Job` implements `Drop` (below), and Rust forbids
    /// partially moving a field out of a `Drop` type.
    reply: Option<Sender<Result<Value>>>,
    /// Mirrors `ThrustEngineConfig::memory_ledger`, carried per-job so
    /// `Drop` can release without a back-reference to the engine.
    ledger: Option<Arc<dyn MemoryLedger>>,
    /// Bytes charged to `LedgerClass::QueuedJob` at enqueue (`thrust()`);
    /// `0` when no ledger is configured. Released exactly once, by
    /// `Drop`, covering both terminal paths a queued job can take -
    /// executed (`execute` drops it at the end of the call) and
    /// discarded unexecuted (`Overloaded` rejection, or a force-shutdown
    /// dropping whatever is still queued) - one canonical release path
    /// instead of one per call site.
    charged_bytes: usize,
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job")
            .field("id_hash", &hex8(&self.id.hash))
            .field("tenant", &self.tenant)
            .finish()
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.charged_bytes > 0
            && let Some(ledger) = &self.ledger
        {
            ledger.release(LedgerClass::QueuedJob, self.charged_bytes);
        }
    }
}

/// Coarse byte-size proxy for a queued job's payload, used only for
/// `LedgerClass::QueuedJob` accounting - never computed when no ledger
/// is configured (zero-cost-when-unused). The JSON-serialized size of
/// `input` is the honest, actual byte count that would cross the wasm
/// boundary if this job executes; `FuelGauge` / `ScriptId` are small and
/// fixed-size, not worth charging separately.
fn estimate_job_bytes(input: &Value) -> usize {
    serde_json::to_vec(input).map(|v| v.len()).unwrap_or(0)
}

fn hex8(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &hash[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────
// Worker routing
// ─────────────────────────────────────────────────────────────────────────

/// Affinity routing - same `ScriptId` always lands on the same worker so
/// its compiled state stays warm on that worker's caches (plan §5.1).
///
/// Reads the first 8 bytes of the SHA-256 hash and reduces modulo worker
/// count. This is a byte-level operation - no allocation, no hashing.
#[inline]
fn route_worker(hash: &[u8; 32], n_workers: usize) -> usize {
    debug_assert!(n_workers > 0, "route_worker called with zero workers");
    let bytes = [
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ];
    (u64::from_le_bytes(bytes) as usize) % n_workers
}

fn resolve_worker_count(requested: usize) -> usize {
    if requested > 0 {
        return requested;
    }
    // Logical-CPU probe; SMT-inclusive. Plan §14 flags a preference for
    // physical cores - a future knob can substitute `num_cpus::get_physical`
    // without changing the public surface.
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

// ─────────────────────────────────────────────────────────────────────────
// The engine itself
// ─────────────────────────────────────────────────────────────────────────

/// Multi-worker thrust engine.
///
/// **Production state:** N worker threads, each with its own
/// depth-bounded queue (plan §5.1, cap = `local_queue_capacity`). A
/// shared global injector (cap = `injector_capacity`) holds overflow
/// when a worker's local queue is at the cap. `thrust()` routes by
/// `hash(script_id) % N` for affinity; on local-full it falls through
/// to the injector, and on injector-full it returns
/// `AfterburnerError::Overloaded` immediately. Workers consume in
/// order: own queue → injector → steal from peers → exp-backoff park.
pub struct ThrustEngine {
    config: ThrustEngineConfig,
    combustor: Arc<WasmCombustor>,
    stats: Arc<StatsCounters>,
    /// Per-worker bounded queues. Indexed by worker id. Shared with
    /// workers via `Arc` so each worker can also steal from peers.
    /// `Option`-wrapped so `Drop` can take ownership before joining.
    worker_queues: Option<Arc<Vec<BoundedQueue<Job>>>>,
    /// Global overflow queue. Filled when a worker's local queue is
    /// at cap; drained by workers as a between-pop poll target.
    injector: Option<Arc<BoundedQueue<Job>>>,
    /// Cached worker count - avoids re-reading `worker_queues.len()`
    /// on the hot path.
    n_workers: usize,
    /// NUMA topology - cached so stats() can surface it and the steal
    /// sweep can order peer visits by locality.
    numa: Arc<NumaTopology>,
    /// Token-bucket admission (T4). `None` disables the layer entirely -
    /// `tenant`-bearing thrusts skip straight to the queue.
    admission: Option<TokenBucketAdmission>,
    shutdown: Arc<AtomicU8>,
    /// `Option` so `Drop` can `.take()` the `Vec<JoinHandle>` and join
    /// workers before the engine fully goes away.
    workers: Option<Vec<JoinHandle<()>>>,
}

impl ThrustEngine {
    /// Construct a new engine.
    ///
    /// Returns `Arc<Self>` per the usability-plan §8 commitment: the
    /// facade crate shares one engine across clones of `Afterburner`.
    ///
    /// `config.compute_workers == 0` auto-probes the host parallelism.
    pub fn new(config: ThrustEngineConfig) -> Result<Arc<Self>> {
        let combustor = Arc::new(WasmCombustor::new(config.wasm_config.clone())?);
        let stats = Arc::new(StatsCounters::default());
        let shutdown = Arc::new(AtomicU8::new(STATE_RUN));

        let admission = match config.admission_tokens_per_sec {
            Some(rate) => Some(TokenBucketAdmission::new(
                rate,
                config.admission_burst_tokens,
                config.governance.clone(),
            )?),
            None => None,
        };

        let n_workers = resolve_worker_count(config.compute_workers);
        let local_cap = if config.local_queue_capacity == 0 {
            256
        } else {
            config.local_queue_capacity
        };
        let injector_cap = if config.injector_capacity == 0 {
            local_cap.saturating_mul(16).max(1024)
        } else {
            config.injector_capacity
        };

        let mut queues: Vec<BoundedQueue<Job>> = Vec::with_capacity(n_workers);
        for _ in 0..n_workers {
            queues.push(BoundedQueue::new(local_cap));
        }
        let worker_queues: Arc<Vec<BoundedQueue<Job>>> = Arc::new(queues);
        let injector: Arc<BoundedQueue<Job>> = Arc::new(BoundedQueue::new(injector_cap));
        let numa = Arc::new(NumaTopology::detect(n_workers));

        let mut handles = Vec::with_capacity(n_workers);
        for worker_id in 0..n_workers {
            match spawn_worker(
                worker_id,
                worker_queues.clone(),
                injector.clone(),
                combustor.clone(),
                stats.clone(),
                shutdown.clone(),
                numa.clone(),
                config.governance.clone(),
            ) {
                Ok(handle) => handles.push(handle),
                Err(e) => {
                    // Governance failed "at pool construction" (never
                    // silently mid-pool): signal shutdown, join whatever
                    // already started, let `admission`'s own Drop join
                    // its sweep thread, then propagate. Construction
                    // never returns `Ok` with a partially-governed pool.
                    shutdown.store(STATE_FORCE, Ordering::Release);
                    for h in handles {
                        let _ = h.join();
                    }
                    drop(admission);
                    return Err(e);
                }
            }
        }

        Ok(Arc::new(Self {
            config,
            combustor,
            stats,
            worker_queues: Some(worker_queues),
            injector: Some(injector),
            n_workers,
            numa,
            admission,
            shutdown,
            workers: Some(handles),
        }))
    }

    /// Queue a thrust. Non-blocking - the caller gets a handle back
    /// immediately and the work happens on the worker thread this
    /// script's hash routes to.
    ///
    /// **Admission** (T4): if the engine was built with
    /// `admission_tokens_per_sec = Some(rate)` *and* the caller passed a
    /// `tenant`, the tenant's GCRA bucket is decremented before
    /// queueing. If the bucket is empty, the handle resolves
    /// immediately with `AfterburnerError::RateLimited`. `tenant == None`
    /// (the trusted in-process path) always bypasses the bucket.
    pub fn thrust(
        &self,
        id: &ScriptId,
        input: Value,
        limits: FuelGauge,
        tenant: Option<TenantId>,
    ) -> ThrustHandle {
        let (reply_tx, reply_rx) = unbounded::<Result<Value>>();

        // Engine shut down? Pre-resolve with a typed error so callers
        // don't hang on recv().
        let (queues, injector) = match (self.worker_queues.as_ref(), self.injector.as_ref()) {
            (Some(q), Some(i)) => (q, i),
            _ => {
                self.stats.thrusts_rejected.fetch_add(1, Ordering::Relaxed);
                reply_tx.send(Err(AfterburnerError::Engine(
                    "thrust engine is shut down".into(),
                )));
                return ThrustHandle { rx: reply_rx };
            }
        };

        // Admission check runs before enqueue so rejected thrusts don't
        // occupy queue slots behind workers.
        if let (Some(adm), Some(tid)) = (self.admission.as_ref(), tenant)
            && let Err(retry_ms) = adm.try_acquire(tid)
        {
            self.stats.thrusts_rejected.fetch_add(1, Ordering::Relaxed);
            reply_tx.send(Err(AfterburnerError::RateLimited {
                tenant: Some(tid.get()),
                retry_after_ms: retry_ms,
            }));
            return ThrustHandle { rx: reply_rx };
        }

        let worker_idx = route_worker(&id.hash, self.n_workers);

        // Charge the queued payload BEFORE it exists in a queue slot.
        // Skipped entirely (zero cost) when no ledger is configured. A
        // denial fails the enqueue loudly, before the job is built - the
        // caller never sees a job that looked queued but wasn't charged.
        let charged_bytes = match self.config.memory_ledger.as_ref() {
            Some(ledger) => {
                let bytes = estimate_job_bytes(&input);
                if let Err(denied) = ledger.reserve(LedgerClass::QueuedJob, bytes) {
                    self.stats.thrusts_rejected.fetch_add(1, Ordering::Relaxed);
                    reply_tx.send(Err(AfterburnerError::LedgerDenied(denied.0)));
                    return ThrustHandle { rx: reply_rx };
                }
                bytes
            }
            None => 0,
        };

        let mut job = Job {
            id: *id,
            input,
            limits,
            tenant,
            reply: Some(reply_tx),
            ledger: self.config.memory_ledger.clone(),
            charged_bytes,
        };

        // Try local first (affinity). On overflow, try the global
        // injector. On both full, return Overloaded - production-grade
        // backpressure prevents memory/queue blow-up under burst.
        match queues[worker_idx].try_push(job) {
            Ok(()) => {
                self.stats.thrusts_queued.fetch_add(1, Ordering::Relaxed);
            }
            Err(returned) => {
                job = returned;
                match injector.try_push(job) {
                    Ok(()) => {
                        self.stats.thrusts_queued.fetch_add(1, Ordering::Relaxed);
                        self.stats
                            .thrusts_via_injector
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mut returned) => {
                        // Both queues at cap. Caller must back off.
                        // `returned`'s Drop releases its ledger charge
                        // (if any) when it falls out of scope below - the
                        // one canonical QueuedJob release path.
                        self.stats
                            .thrusts_overloaded
                            .fetch_add(1, Ordering::Relaxed);
                        if let Some(reply) = returned.reply.take() {
                            reply.send(Err(AfterburnerError::Overloaded));
                        }
                        return ThrustHandle { rx: reply_rx };
                    }
                }
            }
        }

        ThrustHandle { rx: reply_rx }
    }

    /// Returns how many worker threads the engine is running. Useful for
    /// tests + tuning; not load-bearing for the API.
    pub fn worker_count(&self) -> usize {
        self.n_workers
    }

    /// Blocking convenience. Equivalent to `self.thrust(...).recv()` but
    /// callable without constructing a handle the caller doesn't need.
    pub fn thrust_sync(
        &self,
        id: &ScriptId,
        input: Value,
        limits: FuelGauge,
        tenant: Option<TenantId>,
    ) -> Result<Value> {
        self.thrust(id, input, limits, tenant).recv()
    }

    /// Compile + cache a source with the underlying combustor.
    /// Subsequent `thrust` calls using the returned `ScriptId` execute
    /// that source.
    pub fn register(&self, source: &str) -> Result<ScriptId> {
        self.combustor.ignite(source)
    }

    /// Columnar UDF entry point. Bypasses the per-job dispatch
    /// pipeline (admission, tenant routing, NUMA-aware steal, etc.)
    /// and calls directly into the inner [`WasmCombustor`]'s
    /// columnar path. This is the right shape because:
    ///
    /// 1. The wasmtime pooling allocator inside `WasmCombustor`
    ///    is itself thread-safe - N concurrent submitters from N
    ///    OS threads all check out a fresh slot per call without
    ///    contention.
    /// 2. The columnar payload is a `&[u8]` blob, not a JSON
    ///    `Value` - it doesn't fit cleanly into the `Job` enum
    ///    that ThrustEngine's worker channels carry, and pretending
    ///    it does would force a copy through the job-encoding step
    ///    that the columnar path explicitly avoids.
    /// 3. The caller's submitter parallelism is what the bench
    ///    measures anyway - adding a worker hop wouldn't increase
    ///    parallelism, just add latency.
    ///
    /// Subscribers that want the admission/tenant/NUMA machinery for
    /// a columnar workload should split N submitters at their own
    /// layer and call this method from each. The
    /// `examples/billion-row-bench` columnar-typed scenario is the
    /// canonical pattern.
    pub fn thrust_columnar_bytes(
        &self,
        id: &ScriptId,
        encoded: &[u8],
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        self.combustor.thrust_columnar_bytes(id, encoded, limits)
    }

    /// Raw-input fast path. Bypasses the per-job dispatch pipeline and
    /// calls directly into the inner [`WasmCombustor`]'s raw path, for
    /// the same three reasons as
    /// [`thrust_columnar_bytes`](Self::thrust_columnar_bytes): the
    /// pooling allocator is thread-safe, the payload is a `&[u8]` that
    /// doesn't fit the `Job` enum without an extra copy, and submitter
    /// parallelism comes from the caller fanning out threads.
    pub fn thrust_raw(&self, id: &ScriptId, input: &[u8], limits: &FuelGauge) -> Result<Value> {
        self.combustor.thrust_raw(id, input, limits)
    }

    /// Output-framing-aware invoke (JSON input): the module's return
    /// type picks the result shape - `Uint8Array` / `ArrayBuffer`
    /// comes back as [`OutputValue::Bytes`], everything else as
    /// [`OutputValue::Json`]. Bypasses the per-job dispatch pipeline
    /// for the same reasons as [`thrust_raw`](Self::thrust_raw).
    pub fn thrust_out(
        &self,
        id: &ScriptId,
        input: &Value,
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        self.combustor.thrust_out(id, input, limits)
    }

    /// Raw input + output-framing-aware result - the full-duplex bulk
    /// path ("bytes in, bytes out"). Bypasses the per-job dispatch
    /// pipeline for the same reasons as
    /// [`thrust_raw`](Self::thrust_raw).
    pub fn thrust_raw_out(
        &self,
        id: &ScriptId,
        input: &[u8],
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        self.combustor.thrust_raw_out(id, input, limits)
    }

    /// Snapshot of operational counters.
    pub fn stats(&self) -> ThrustEngineStats {
        let mut snap = self.stats.snapshot();
        snap.tenant_buckets_tracked = self.admission.as_ref().map_or(0, |a| a.bucket_count());
        snap.numa_nodes = self.numa.node_count;
        snap
    }

    /// Number of NUMA nodes the engine detected at construction time.
    /// `1` on single-socket boxes and on non-Linux platforms where
    /// detection isn't implemented.
    pub fn numa_node_count(&self) -> usize {
        self.numa.node_count
    }

    /// Graceful shutdown - flip to drain mode, let workers finish
    /// pending queued jobs (up to `config.shutdown_drain_deadline`),
    /// then join.
    ///
    /// Shutdown also runs automatically via `Drop` when the last
    /// `Arc<Self>` goes away; this method is the explicit form for
    /// tests and operator-driven teardown.
    pub fn shutdown(self: Arc<Self>) {
        match Arc::try_unwrap(self) {
            Ok(engine) => drop(engine), // triggers full Drop drain+force+join
            Err(arc) => {
                // Other holders still reference us - signal drain so
                // workers begin draining; the last Drop will continue
                // through to force + join.
                arc.shutdown.store(STATE_DRAIN, Ordering::Release);
            }
        }
    }
}

impl Drop for ThrustEngine {
    fn drop(&mut self) {
        // 1. Ask workers to drain remaining queued jobs.
        self.shutdown.store(STATE_DRAIN, Ordering::Release);

        // 2. Wait for them to finish, capped at the configured
        //    deadline. We drop the engine's queue Arcs *after* the
        //    wait so callers retrieving stats during the drain still
        //    see live counters.
        let drain_deadline = Instant::now() + self.config.shutdown_drain_deadline;
        let workers_count = self.workers.as_ref().map_or(0, Vec::len);
        let active_after_drain = self.stats.workers_alive.load(Ordering::Acquire);
        if active_after_drain > 0 {
            let poll = Duration::from_millis(25);
            while Instant::now() < drain_deadline {
                if self.stats.workers_alive.load(Ordering::Acquire) == 0 {
                    break;
                }
                thread::sleep(poll);
            }
        }
        let _ = workers_count; // (kept here in case future tracing wants the original count)

        // 3. Any worker still alive gets the immediate-exit signal.
        //    Workers exit at the top of their next iteration.
        self.shutdown.store(STATE_FORCE, Ordering::Release);

        // Drop our queue Arcs so worker copies can also drop after the
        // workers exit - keeps no hidden roots alive.
        let _ = self.worker_queues.take();
        let _ = self.injector.take();

        if let Some(workers) = self.workers.take() {
            for w in workers {
                let _ = w.join();
            }
        }
    }
}

impl fmt::Debug for ThrustEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrustEngine")
            .field("n_workers", &self.n_workers)
            .field("io_workers", &self.config.io_workers)
            .field(
                "admission_tokens_per_sec",
                &self.config.admission_tokens_per_sec,
            )
            .field("workers_alive", &self.workers.as_ref().map_or(0, Vec::len))
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Worker thread
// ─────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn spawn_worker(
    worker_id: usize,
    queues: Arc<Vec<BoundedQueue<Job>>>,
    injector: Arc<BoundedQueue<Job>>,
    combustor: Arc<WasmCombustor>,
    stats: Arc<StatsCounters>,
    shutdown: Arc<AtomicU8>,
    numa: Arc<NumaTopology>,
    governance: ThreadGovernance,
) -> Result<JoinHandle<()>> {
    // Track liveness so `Drop` can poll for natural drain completion
    // before forcing exit. Increment happens on the *parent* thread so
    // the count is accurate by the time `new()` returns; the spawned
    // thread decrements when it's done (or, if governance fails and the
    // thread never starts the loop, undone below).
    stats.workers_alive.fetch_add(1, Ordering::AcqRel);
    let stats_for_loop = stats.clone();
    let stats_for_decrement = stats.clone();
    let numa_for_pin = numa.clone();
    // An explicit affinity mask overrides the NUMA pin - `apply_governance`
    // (run first, inside `spawn_governed`) already applied it, so the
    // worker must not then re-pin itself to the NUMA node's wider set.
    let affinity_overridden = governance.affinity.is_some();
    let name = governance.thread_name("afterburner-thrust", &format!("-{worker_id}"));
    let result = spawn_governed(name, governance, move || {
        if !affinity_overridden {
            // Pin to our NUMA node's CPU set on Linux multi-socket
            // boxes; no-op elsewhere. Done inside the worker thread so
            // sched_setaffinity applies to the right kernel task.
            pin_current_thread_to_worker(&numa_for_pin, worker_id);
        }
        worker_loop(
            worker_id,
            queues,
            injector,
            combustor,
            stats_for_loop,
            shutdown,
            numa_for_pin,
        );
        stats_for_decrement
            .workers_alive
            .fetch_sub(1, Ordering::AcqRel);
    });
    if result.is_err() {
        // Governance failed before the body ran, so the body's own
        // decrement never happened - undo the increment above so a
        // failed spawn never leaks into the liveness count.
        stats.workers_alive.fetch_sub(1, Ordering::AcqRel);
    }
    result
}

/// Plan §5.2 worker loop (Tokio's poll-injector-every-N pattern at
/// `INJECTOR_POLL_MASK + 1` = 64 local pops):
///
/// 1. **Injector tick** (every 64th iter): `try_pop` the global
///    injector first. Keeps overflow-shed thrusts from starving when
///    locals are persistently busy.
/// 2. **Owner pop** of this worker's local queue - fast path.
/// 3. **Steal** half-search of peers' queues - drains imbalanced
///    routing.
/// 4. **Park** with exponential backoff (50 µs → 2 ms) when all
///    queues are empty. No signals, no futexes - capability-safe.
const INJECTOR_POLL_MASK: u64 = 63; // 64 = 1<<6

fn worker_loop(
    worker_id: usize,
    queues: Arc<Vec<BoundedQueue<Job>>>,
    injector: Arc<BoundedQueue<Job>>,
    combustor: Arc<WasmCombustor>,
    stats: Arc<StatsCounters>,
    shutdown: Arc<AtomicU8>,
    numa: Arc<NumaTopology>,
) {
    let n = queues.len();
    let local = &queues[worker_id];

    // Build the steal-peer list ordered by NUMA locality: same-node
    // peers first, cross-node second. On single-node boxes this
    // degenerates to the old `(worker_id + 1..)` ring order, same
    // work.
    let steal_order: Vec<usize> = build_steal_order(worker_id, n, &numa);

    let initial_park = Duration::from_micros(50);
    let park_cap = Duration::from_millis(2);
    let mut park = initial_park;
    let mut iter: u64 = 0;

    'outer: loop {
        let state = shutdown.load(Ordering::Acquire);
        if state == STATE_FORCE {
            // Force-exit immediately; any remaining queued jobs get
            // their reply senders dropped (handle::recv → Err on
            // closed channel).
            break;
        }

        // Work-finding sequence is identical regardless of state - only
        // the empty-queue case differs (Drain → exit, Run → park).

        // 1. Injector tick.
        if (iter & INJECTOR_POLL_MASK) == 0
            && let Some(job) = injector.try_pop()
        {
            execute(job, &combustor, &stats);
            park = initial_park;
            iter = iter.wrapping_add(1);
            continue 'outer;
        }

        // 2. Owner pop.
        if let Some(job) = local.try_pop() {
            execute(job, &combustor, &stats);
            park = initial_park;
            iter = iter.wrapping_add(1);
            continue 'outer;
        }

        // 3. Steal sweep (NUMA-locality-preferring) + post-sweep
        //    injector poll.
        for &idx in &steal_order {
            if let Some(job) = queues[idx].try_pop() {
                execute(job, &combustor, &stats);
                park = initial_park;
                iter = iter.wrapping_add(1);
                continue 'outer;
            }
        }
        if let Some(job) = injector.try_pop() {
            execute(job, &combustor, &stats);
            park = initial_park;
            iter = iter.wrapping_add(1);
            continue 'outer;
        }

        // 4. All queues empty.
        if state == STATE_DRAIN {
            // Drain complete from this worker's perspective. Any
            // post-Drain thrust() pushes that race past this exit are
            // either picked up by a still-alive peer or surface as a
            // closed-reply-channel Err to the caller.
            break;
        }
        thread::sleep(park);
        park = (park * 2).min(park_cap);
        iter = iter.wrapping_add(1);
    }
}

/// Produce the order in which `worker_id` should visit peers when
/// stealing. Same-NUMA-node peers come first (ordered by distance in
/// the ring), then cross-node peers (same ring ordering). On
/// single-node systems this is identical to the old `(id+1..)` ring.
fn build_steal_order(worker_id: usize, n: usize, numa: &NumaTopology) -> Vec<usize> {
    let my_node = numa.worker_to_node.get(worker_id).copied().unwrap_or(0);
    let mut same_node = Vec::new();
    let mut other_node = Vec::new();
    for offset in 1..n {
        let idx = (worker_id + offset) % n;
        let peer_node = numa.worker_to_node.get(idx).copied().unwrap_or(0);
        if peer_node == my_node {
            same_node.push(idx);
        } else {
            other_node.push(idx);
        }
    }
    same_node.extend(other_node);
    same_node
}

#[inline]
fn execute(mut job: Job, combustor: &WasmCombustor, stats: &StatsCounters) {
    // Field access rather than a destructuring move: `Job` implements
    // `Drop` (it releases its `QueuedJob` ledger charge there), and Rust
    // forbids partially moving fields out of a type that implements
    // `Drop`. `job`'s own `Drop` fires at the end of this function,
    // which is exactly the "queued -> executed" transition the ledger
    // charge's lifetime is defined to cover.
    let result = combustor.thrust(&job.id, &job.input, &job.limits);
    stats.thrusts_completed.fetch_add(1, Ordering::Relaxed);
    // If the caller dropped the handle, send is a no-op - fine.
    if let Some(reply) = job.reply.take() {
        reply.send(result);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::{EngineMode, FuelGauge, ScriptId};
    use serde_json::json;

    fn dummy_script_id() -> ScriptId {
        ScriptId {
            hash: [0u8; 32],
            mode: EngineMode::Wasm,
        }
    }

    #[test]
    fn engine_constructs_with_default_config() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let s = engine.stats();
        assert_eq!(s.thrusts_queued, 0);
        assert_eq!(s.thrusts_completed, 0);
        assert_eq!(s.thrusts_rejected, 0);
    }

    #[test]
    fn register_and_execute_trivial_script() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine.register("module.exports = () => 1 + 2").unwrap();
        let out = engine
            .thrust_sync(&id, json!(null), FuelGauge::unlimited(), None)
            .unwrap();
        assert_eq!(out, json!(3));
    }

    #[test]
    fn thrust_reads_input_through_envelope() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine
            .register("module.exports = (d) => ({ doubled: d.n * 2 })")
            .unwrap();
        let out = engine
            .thrust_sync(&id, json!({ "n": 21 }), FuelGauge::unlimited(), None)
            .unwrap();
        assert_eq!(out, json!({ "doubled": 42 }));
    }

    #[test]
    fn unknown_script_id_surfaces_error() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let out = engine.thrust_sync(
            &dummy_script_id(),
            json!(null),
            FuelGauge::unlimited(),
            None,
        );
        assert!(matches!(out, Err(AfterburnerError::ScriptNotFound)));
    }

    #[test]
    fn stats_count_completed_thrusts() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine.register("module.exports = (d) => d.n + 1").unwrap();
        for i in 0..10 {
            let _ = engine
                .thrust_sync(
                    &id,
                    json!({ "n": i }),
                    FuelGauge::unlimited(),
                    TenantId::new(1),
                )
                .unwrap();
        }
        let s = engine.stats();
        assert_eq!(s.thrusts_queued, 10);
        assert_eq!(s.thrusts_completed, 10);
    }

    #[test]
    fn async_handle_then_recv() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine.register("module.exports = () => 99").unwrap();
        let h = engine.thrust(&id, json!(null), FuelGauge::unlimited(), None);
        // recv blocks until the worker replies.
        assert_eq!(h.recv().unwrap(), json!(99));
    }

    #[test]
    fn handle_recv_timeout_returns_none_on_orphan() {
        // Using a receiver that will NEVER get a send - not tied to the
        // engine at all. We just want to verify the timeout code path
        // correctly reports `None` on timeout and then `Some` on
        // late-arrival.
        let (tx, rx) = unbounded::<Result<Value>>();
        let h = ThrustHandle { rx };
        assert!(h.recv_timeout(Duration::from_millis(10)).is_none());
        tx.send(Ok(json!("hi")));
        let got = h.recv_timeout(Duration::from_secs(1));
        assert_eq!(got.unwrap().unwrap(), json!("hi"));
    }

    #[test]
    fn parallel_thrust_calls_serialize_through_one_worker() {
        // Kick off 20 thrusts from the caller thread (non-blocking
        // enqueue). The single worker drains them in-order. We collect
        // the handles then drain their recv() calls.
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine.register("module.exports = (d) => d.n * 2").unwrap();

        let mut handles = Vec::with_capacity(20);
        for i in 0..20u32 {
            handles.push(engine.thrust(&id, json!({ "n": i }), FuelGauge::unlimited(), None));
        }
        for (i, h) in handles.into_iter().enumerate() {
            assert_eq!(h.recv().unwrap(), json!(i as u32 * 2));
        }
        assert_eq!(engine.stats().thrusts_completed, 20);
    }

    #[test]
    fn shutdown_joins_worker_cleanly() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine.register("module.exports = () => 1").unwrap();
        let _ = engine
            .thrust_sync(&id, json!(null), FuelGauge::unlimited(), None)
            .unwrap();
        // Explicit shutdown: try_unwrap succeeds (we hold the only Arc).
        engine.shutdown();
        // No observable panic / hang means the worker joined.
    }

    #[test]
    fn shutdown_with_outstanding_arc_is_soft_signal() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let engine2 = engine.clone();
        // shutdown with outstanding Arc - falls through the soft-signal
        // branch, drop of engine2 will trigger the real Drop later.
        engine.shutdown();
        drop(engine2);
    }

    #[test]
    fn register_is_idempotent() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id1 = engine.register("module.exports = () => 1").unwrap();
        let id2 = engine.register("module.exports = () => 1").unwrap();
        assert_eq!(id1.hash, id2.hash);
    }

    #[test]
    fn tenant_id_rejects_zero() {
        assert!(TenantId::new(0).is_none());
        assert_eq!(TenantId::new(7).unwrap().get(), 7);
    }

    #[test]
    fn config_is_clone() {
        // usability-plan §8: ThrustEngineConfig must be Clone so the
        // facade builder can snapshot it.
        let cfg = ThrustEngineConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg.compute_workers, cloned.compute_workers);
    }

    #[test]
    fn engine_is_send_sync() {
        // Covers the Arc<ThrustEngine> usage the facade relies on.
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<ThrustEngine>();
    }

    #[test]
    fn thrust_honors_fuel_exhaustion() {
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine
            .register("module.exports = () => { while (true) {} }")
            .unwrap();
        let lim = FuelGauge {
            fuel: Some(100_000),
            ..FuelGauge::unlimited()
        };
        let out = engine.thrust_sync(&id, json!(null), lim, None);
        assert!(matches!(out, Err(AfterburnerError::FuelExhausted)));
    }

    // ── E2 governance config plumbing ──────────────────────────────────

    #[test]
    fn config_default_governance_and_ledger_are_noop() {
        let cfg = ThrustEngineConfig::default();
        assert_eq!(cfg.governance, ThreadGovernance::default());
        assert!(cfg.memory_ledger.is_none());
    }

    #[test]
    fn engine_constructs_with_custom_governance() {
        // Positive (nice=5) never needs CAP_SYS_NICE; must succeed
        // regardless of the box this test runs on.
        let engine = ThrustEngine::new(ThrustEngineConfig {
            governance: ThreadGovernance {
                nice: Some(5),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        let id = engine.register("module.exports = () => 1").unwrap();
        let out = engine
            .thrust_sync(&id, json!(null), FuelGauge::unlimited(), None)
            .unwrap();
        assert_eq!(out, json!(1));
    }

    // ── E3 QueuedJob ledger ─────────────────────────────────────────────

    #[derive(Default)]
    struct MockLedger {
        deny: bool,
        reserved: std::sync::Mutex<Vec<(LedgerClass, usize)>>,
        released: std::sync::Mutex<Vec<(LedgerClass, usize)>>,
    }

    impl MemoryLedger for MockLedger {
        fn reserve(
            &self,
            class: LedgerClass,
            bytes: usize,
        ) -> std::result::Result<(), afterburner_core::ledger::LedgerDenied> {
            if self.deny {
                return Err(afterburner_core::ledger::LedgerDenied(
                    "mock ledger denies everything".to_string(),
                ));
            }
            self.reserved.lock().unwrap().push((class, bytes));
            Ok(())
        }

        fn release(&self, class: LedgerClass, bytes: usize) {
            self.released.lock().unwrap().push((class, bytes));
        }
    }

    /// Direct proof of the canonical release mechanism: `Job::drop`
    /// releases its `QueuedJob` charge exactly once. This covers BOTH
    /// real terminal paths a queued job can take (`execute` letting
    /// `job` fall out of scope at the end of the call; the `Overloaded`
    /// branch letting the returned-but-never-queued `Job` fall out of
    /// scope) without needing to race a live worker thread to force
    /// either condition - both paths defer to this one `Drop` impl.
    #[test]
    fn job_drop_releases_its_queued_job_charge_exactly_once() {
        let ledger = Arc::new(MockLedger::default());
        let (tx, _rx) = unbounded::<Result<Value>>();
        let job = Job {
            id: dummy_script_id(),
            input: json!(null),
            limits: FuelGauge::unlimited(),
            tenant: None,
            reply: Some(tx),
            ledger: Some(ledger.clone() as Arc<dyn MemoryLedger>),
            charged_bytes: 42,
        };
        drop(job);
        assert_eq!(
            ledger.released.lock().unwrap().as_slice(),
            &[(LedgerClass::QueuedJob, 42)]
        );
    }

    #[test]
    fn job_drop_is_a_noop_when_no_ledger_was_charged() {
        // charged_bytes == 0 (no ledger configured at enqueue time):
        // Drop must not call release at all.
        let ledger = Arc::new(MockLedger::default());
        let (tx, _rx) = unbounded::<Result<Value>>();
        let job = Job {
            id: dummy_script_id(),
            input: json!(null),
            limits: FuelGauge::unlimited(),
            tenant: None,
            reply: Some(tx),
            ledger: Some(ledger.clone() as Arc<dyn MemoryLedger>),
            charged_bytes: 0,
        };
        drop(job);
        assert!(ledger.released.lock().unwrap().is_empty());
    }

    /// Bounded poll instead of a fixed sleep: the release happens on a
    /// different (worker) thread than the one observing it, so a tiny
    /// window exists between `thrust_sync` returning (the reply send)
    /// and the worker's `Job` actually dropping.
    fn wait_for<F: Fn() -> bool>(deadline: std::time::Duration, cond: F) -> bool {
        let start = std::time::Instant::now();
        loop {
            if cond() {
                return true;
            }
            if start.elapsed() > deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn thrust_engine_reserves_and_releases_queued_job_ledger_end_to_end() {
        let ledger = Arc::new(MockLedger::default());
        let engine = ThrustEngine::new(ThrustEngineConfig {
            memory_ledger: Some(ledger.clone() as Arc<dyn MemoryLedger>),
            ..Default::default()
        })
        .unwrap();
        let id = engine.register("module.exports = () => 1 + 1").unwrap();
        let out = engine
            .thrust_sync(&id, json!(null), FuelGauge::unlimited(), None)
            .unwrap();
        assert_eq!(out, json!(2));

        assert_eq!(ledger.reserved.lock().unwrap().len(), 1);
        assert_eq!(ledger.reserved.lock().unwrap()[0].0, LedgerClass::QueuedJob);
        let charged = ledger.reserved.lock().unwrap()[0].1;
        assert!(charged > 0);

        assert!(
            wait_for(std::time::Duration::from_secs(2), || {
                ledger.released.lock().unwrap().len() == 1
            }),
            "expected exactly one release within the deadline"
        );
        assert_eq!(
            ledger.released.lock().unwrap()[0],
            (LedgerClass::QueuedJob, charged)
        );
    }

    #[test]
    fn thrust_engine_queued_job_ledger_denial_is_loud_and_never_enqueues() {
        let ledger = Arc::new(MockLedger {
            deny: true,
            ..Default::default()
        });
        let engine = ThrustEngine::new(ThrustEngineConfig {
            memory_ledger: Some(ledger as Arc<dyn MemoryLedger>),
            ..Default::default()
        })
        .unwrap();
        let id = engine.register("module.exports = () => 1").unwrap();
        let err = engine
            .thrust_sync(&id, json!(null), FuelGauge::unlimited(), None)
            .unwrap_err();
        assert!(
            matches!(err, AfterburnerError::LedgerDenied(_)),
            "expected LedgerDenied, got {err}"
        );
        let stats = engine.stats();
        assert_eq!(stats.thrusts_queued, 0, "a denied job must never be queued");
    }

    #[test]
    fn thrust_engine_no_ledger_is_unaffected() {
        // Default config: no memory_ledger. Must behave exactly as
        // before governance/ledger existed.
        let engine = ThrustEngine::new(ThrustEngineConfig::default()).unwrap();
        let id = engine.register("module.exports = () => 5").unwrap();
        let out = engine
            .thrust_sync(&id, json!(null), FuelGauge::unlimited(), None)
            .unwrap();
        assert_eq!(out, json!(5));
    }
}
