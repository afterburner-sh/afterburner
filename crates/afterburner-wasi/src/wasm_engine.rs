// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `WasmCombustor` - untrusted-code path. Instantiates a
//! Wizer-preinitialized Afterburner Javy plugin into a fresh `Store`
//! per thrust and feeds the user source + input as a JSON envelope on
//! stdin. The plugin compiles the source in-process via
//! `javy_plugin_api::compile_src` and runs it; `afterburner:host`
//! imports give capability-gated access to fs/crypto/os/http.
//!
//! No `javy` CLI is involved at runtime. The only JS → bytecode work
//! happens inside the sandbox, driven by the plugin.
//!
//! ### Lifecycle
//!
//! * `WasmCombustor::new` pre-compiles the plugin module once and, unless
//!   [`WasmConfig::spawn_epoch_ticker`] opts out, starts the shared epoch
//!   ticker. An embedder that opts out drives the wall-clock deadline
//!   itself via `engine().increment_epoch()` on its own scheduler.
//! * `ignite(source)` hashes the source and stashes it in-memory - no
//!   compilation. `ScriptId` is content-addressed so identical sources
//!   hash identically across backends (`Adaptive` relies on that).
//! * `thrust(id, input, limits)` looks up the cached source, serializes
//!   `{source, input}` onto stdin, instantiates plugin + runs `_start`,
//!   and reads the JSON result from stdout.

use crate::chamber::{self, TICK_PERIOD_MS, drain_stdout, format_trap_with_stderr};
use crate::host::{HostState, InputFormat};
use crate::host_imports;
use crate::nozzle::parse_output;
use afterburner_core::governance::{ThreadGovernance, spawn_governed};
use afterburner_core::ledger::{LedgerClass, MemoryLedger};
use afterburner_core::log::Level;
use afterburner_core::{
    AfterburnerError, Combustor, EngineMode, FuelGauge, InMemoryStateStore, Manifold, OutputValue,
    Result, RunResult, ScriptId, ScriptInvocation, ScriptOutcome, SharedStateStore, ab_event,
    sha256,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use kovan_map::HopscotchMap;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, InstancePre, Linker, Module, OptLevel,
    PoolingAllocationConfig, Trap,
};
use wasmtime_wasi::I32Exit;
use wasmtime_wasi::p1::add_to_linker_sync;

/// The custom plugin binary (Wizer-preinitialized), committed to the
/// repo and baked into the host crate at compile time.
const PLUGIN_BYTES: &[u8] = include_bytes!("../plugin/afterburner_plugin.wasm");

// Result capture is ceiling-bounded per call via
// `FuelGauge::output_ceiling()` (default 64 MiB) - there is no fixed
// stdout buffer anymore. The old 1 MiB `STDOUT_CAPACITY` gave results
// a hard cliff: the over-budget `fd_write` failed with errno 29 inside
// `__ab_write_stdout` and the call surfaced as an opaque trap.

// ---- pooling allocator defaults -----------------------------------------
//
// Cross-platform high-performance defaults. Wasmtime's `PoolingAllocator`
// is supported on Linux, macOS, and Windows (x86_64 + aarch64) - the same
// values work everywhere. Per-platform sub-features that can fail (e.g.
// memory protection keys on Linux x86_64) are runtime-probed in
// `build_engine` and silently fall back if unsupported.
//
// Memory budget: pre-reserves `MAX_LINEAR_MEMORY_BYTES * POOL_TOTAL_MEMORIES`
// of *virtual* address space (~32 GiB at the defaults). Resident memory
// only grows on first touch via CoW; idle slots reclaim back to
// `LINEAR_MEMORY_KEEP_RESIDENT` of RSS.

/// Per-instance linear-memory ceiling enforced by the pool. Each thrust's
/// `FuelGauge::memory_bytes` (via `ResourceLimiter`) is the per-call
/// dynamic cap below this hard limit.
///
/// 1 GiB by default - comfortably fits the Wizer image (~5 MiB), the
/// plenum polyfill bundle, and a long-running daemon-mode QuickJS Store
/// driving frameworks like Express that keep per-request state alive
/// across the whole listener lifetime.
///
/// Override at startup via `BURN_MAX_LINEAR_MEMORY` (accepts plain
/// bytes or `<N>(K|M|G)` shorthand: `BURN_MAX_LINEAR_MEMORY=4G` →
/// 4 GiB). Capped at 4 GiB because the wasm32 ABI has a hard 4 GiB
/// linear-memory limit per Store; values above that are clamped.
/// Override down (e.g. `=128M`) when running many concurrent
/// instances on small hosts - the pool pre-reserves
/// `MAX_LINEAR_MEMORY_BYTES * POOL_TOTAL_MEMORIES` of virtual address
/// space (4 GiB × 128 = 512 GiB virtual at the defaults; resident only
/// on first touch).
const DEFAULT_MAX_LINEAR_MEMORY_BYTES: usize = 1024 * 1024 * 1024;
const WASM32_MAX_LINEAR_MEMORY_BYTES: usize = 4 * 1024 * 1024 * 1024;

fn max_linear_memory_bytes() -> usize {
    let raw = match std::env::var("BURN_MAX_LINEAR_MEMORY") {
        Ok(v) => v,
        Err(_) => return DEFAULT_MAX_LINEAR_MEMORY_BYTES,
    };
    let s = raw.trim();
    let (num_part, mult) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1024usize),
        Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some('G' | 'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1usize),
    };
    let parsed: usize = match num_part.trim().parse() {
        Ok(n) => n,
        Err(_) => return DEFAULT_MAX_LINEAR_MEMORY_BYTES,
    };
    parsed
        .saturating_mul(mult)
        .min(WASM32_MAX_LINEAR_MEMORY_BYTES)
}

/// Default maximum concurrently-instantiated plugin instances, used when
/// [`WasmConfig::pool_total_instances`] is `None`. Pool reserves
/// virtual-only address space; on a 64-bit host this is "free" until a
/// slot is touched. 128 covers an 8-core box driven at 16x burst, which
/// is a generous default for commodity hardware. An embedder with a
/// known, fixed concurrency ceiling (a bounded worker pool, for
/// instance) should size this to that ceiling via
/// `WasmConfig::pool_total_instances` instead of the generic default.
const POOL_TOTAL_MEMORIES: u32 = 128;

/// Resident bytes kept warm per freed pool slot - CoW reset back to this
/// after a Store drops, so re-instantiation skips the page-zeroing cost
/// for the first 1 MiB. Plan §9.
const LINEAR_MEMORY_KEEP_RESIDENT: usize = 1024 * 1024;

/// Resident bytes kept warm per freed table slot.
const TABLE_KEEP_RESIDENT: usize = 1024 * 1024;

/// Table element ceiling - the Javy plugin uses a single funcref table.
/// 65 536 is the Wasm spec maximum and matches what the plugin requests.
const POOL_TABLE_ELEMENTS: usize = 65_536;

#[derive(Default, Clone)]
pub struct WasmConfig {
    /// Cross-invocation key/value store visible to scripts via
    /// `require('afterburner:state')`. `None` falls back to a fresh
    /// in-memory store created at `WasmCombustor::new`.
    pub state_store: Option<SharedStateStore>,
    /// Optional embedder-provided host context. Scripts that call
    /// `require('afterburner:host').readColumn` / `emitRow` dispatch
    /// through this context; unset means `readColumn` returns `[]` and
    /// `emitRow` is a no-op.
    pub host_context: Option<Arc<dyn afterburner_core::HostContext>>,
    /// called from the JS-side require resolver when loading
    /// `.ts` / `.mts` / `.cts` / `.mjs` files. `None` disables those
    /// extensions (the resolver emits a clean error instead of a JS
    /// parse failure). The CLI wires this to oxc-backed transpile
    /// when built with the `ts` feature.
    pub transpile_hook: Option<crate::host::TranspileFn>,
    /// Optional directory (absolute path) for wasmtime's on-disk
    /// compilation cache. When set, the plugin module's native-code
    /// compilation is persisted there and reused by every subsequent
    /// `WasmCombustor::new` in any process - removing the cold-start
    /// compile cost for short-lived or freshly-forked embedders.
    ///
    /// Entries are keyed by module contents + compiler configuration +
    /// wasmtime version, so engine upgrades and config changes miss
    /// cleanly (old entries are evicted by wasmtime's size-bounded
    /// cleanup worker). Corrupt or stale files are ignored and
    /// recompiled, never fatal. If the cache cannot be initialised
    /// (e.g. unwritable directory), the engine logs a warning and
    /// proceeds without a cache - this knob is purely an optimisation
    /// and never affects correctness.
    pub compile_cache_dir: Option<std::path::PathBuf>,
    /// `None` (default) keeps today's behaviour: Cranelift compiles
    /// functions in parallel across wasmtime's process-global `rayon`
    /// pool (`build_engine`'s `parallel_compilation`). `Some(false)`
    /// forces every compile - the plugin module and every
    /// `register_precompiled` / `register_dyn` call - onto the calling
    /// thread, single-threaded, touching `rayon` never.
    ///
    /// An embedder that already runs its own CPU-bound work on the same
    /// process-global `rayon` pool (a common default in Rust servers)
    /// should set `Some(false)`: `rayon`'s pool is shared and
    /// unpartitioned, so a wasm compile fanning out across it competes
    /// directly with unrelated work, and whichever caller touches
    /// `rayon` first determines the pool's inherited thread priority and
    /// affinity for the rest of the process. Single-threaded compilation
    /// costs cold-start latency (no parallel speedup) in exchange for
    /// zero interaction with any other `rayon` consumer.
    pub parallel_compilation: Option<bool>,
    /// `None` (default) keeps today's behaviour: `WasmCombustor::new`
    /// spawns a dedicated `afterburner-epoch-ticker` thread that sleeps
    /// `crate::chamber::TICK_PERIOD_MS` and calls
    /// `Engine::increment_epoch()` in a loop for the lifetime of the
    /// combustor (joined on [`Drop`]). `Some(false)` suppresses that
    /// spawn entirely - `WasmCombustor::new` then owns zero threads on
    /// this axis.
    ///
    /// An embedder that opts out is responsible for calling
    /// `engine().increment_epoch()` periodically itself (from whatever
    /// scheduler it already runs - a timer task on an existing async
    /// runtime, for instance), or every `Store`'s epoch deadline
    /// (`FuelGauge::timeout_ms`) never fires and only the fuel bound
    /// remains. [`WasmCombustor::engine`] returns a `Clone`-able handle
    /// for exactly this purpose; `Engine::increment_epoch(&self)` takes
    /// a shared reference, so no synchronization is needed to drive it
    /// from another thread.
    pub spawn_epoch_ticker: Option<bool>,
    /// `None` (default) keeps today's hard-coded pool size
    /// (`POOL_TOTAL_MEMORIES`, 128). `Some(n)` sizes the pooling
    /// allocator's instance and linear-memory slot counts to `n`
    /// instead, shrinking (or growing) the pool's virtual address-space
    /// reservation (`n * max_memory_size`) to match an embedder's own
    /// concurrency ceiling rather than a generic commodity-hardware
    /// default.
    pub pool_total_instances: Option<u32>,
    /// `None` (default) keeps today's behaviour: the per-instance linear
    /// memory ceiling comes from the `BURN_MAX_LINEAR_MEMORY`
    /// environment variable (or the 1 GiB default) via
    /// `max_linear_memory_bytes`. `Some(bytes)` sets the ceiling
    /// programmatically instead, taking priority over the environment
    /// variable - the only reliable option for a library embedder, since
    /// mutating process environment variables from a multithreaded
    /// program is `unsafe` as of Rust 2024. Clamped to
    /// `WASM32_MAX_LINEAR_MEMORY_BYTES` exactly like the
    /// environment-variable path.
    pub pool_max_linear_memory_bytes: Option<usize>,
    /// Governance (nice / affinity / name prefix) applied to the
    /// internal `afterburner-epoch-ticker` thread IF this embedder
    /// keeps it (`spawn_epoch_ticker` unset or `Some(true)`) - ignored
    /// entirely when the ticker is suppressed, which is the intended
    /// posture for an embedder driving the epoch itself. `Default`
    /// (every field `None`) is a pure no-op: today's ungoverned ticker,
    /// byte-identical.
    pub ticker_governance: ThreadGovernance,
    /// Optional embedder-owned memory-accounting hook, charged at
    /// `bytecode_cache` / `sealed_cache` / `dyn_cache` insert (reserve,
    /// [`LedgerClass::ModuleCache`]) and evict/extinguish (release).
    /// `None` (the default) is a pure no-op: every charge point is a
    /// single `is_some()` branch on an already-cold path (registration,
    /// never per-call).
    pub memory_ledger: Option<Arc<dyn MemoryLedger>>,
}

/// Cached payload for a registered script. Built once in `ignite` so
/// per-call paths (`thrust`, `thrust_columnar`) become a cheap `Bytes`
/// clone (`Arc` bump) + instantiate.
///
/// `raw` is the bytecode for the regular JSON-shaped UDF wrapper
/// (compiled by the plugin's `compile` mode); `columnar_raw` is the
/// bytecode for the columnar wrapper (compiled by the plugin's
/// `compile-columnar` mode). Both are kept for diagnostics + future
/// non-invoke consumers. The pre-serialised invoke envelopes -
/// `invoke_envelope_bytes` (regular) and `columnar_invoke_envelope_bytes`
/// (columnar) - are the hot-path payload that
/// `Combustor::thrust` / `WasmCombustor::thrust_columnar` clone
/// directly, so per-call work is just an `Arc` bump, never a memcpy of
/// the ~40 KB envelope. Building all four eagerly at register time
/// costs one extra plugin compile (~2 ms per registration) and ~12 KB
/// extra in cache per script; in exchange every per-call path skips
/// both base64 encoding and `serde_json::to_vec` on the envelope.
pub(crate) struct CompiledScript {
    #[allow(dead_code)]
    pub raw: Vec<u8>,
    #[allow(dead_code)]
    pub columnar_raw: Vec<u8>,
    pub invoke_envelope_bytes: Bytes,
    pub columnar_invoke_envelope_bytes: Bytes,
}

/// Total bytes a [`CompiledScript`] entry charges to
/// `LedgerClass::ModuleCache` - the one canonical sizing function used
/// at both `ignite` (charge) and `extinguish` (release) so the two can
/// never drift on what a `bytecode_cache` entry costs.
fn compiled_script_bytes(cs: &CompiledScript) -> usize {
    cs.raw.len()
        + cs.columnar_raw.len()
        + cs.invoke_envelope_bytes.len()
        + cs.columnar_invoke_envelope_bytes.len()
}

/// A pre-compiled, self-contained (SEALED) WASM module registered via
/// [`WasmCombustor::register_precompiled`]. The module imports only
/// `wasi_snapshot_preview1` (no `afterburner:host`); it is instantiated
/// with a WASI-only linker and fed JSON input on stdin, producing JSON
/// output on stdout. No plugin envelope, no bytecode compile step.
pub(crate) struct SealedModule {
    pub instance_pre: InstancePre<HostState>,
}

/// A measured (not proxy) breakdown of a [`WasmCombustor`]'s resident
/// bytes, so an embedder's R1/R2-style accounting can true up against
/// reality instead of a size-at-registration-time estimate. Computed on
/// demand by [`WasmCombustor::resident_estimate`] - never cached, never
/// itself charged to any ledger (this is a read-only verification
/// accessor, not another accounting path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResidentBreakdown {
    /// Serialized size of the compiled plugin module - the one Wizer-
    /// preinitialized module every tier shares.
    pub plugin_module: usize,
    /// Sum of every currently-registered `ignite`d script's bytecode +
    /// envelope bytes.
    pub bytecode_cache: usize,
    /// Sum of every currently-registered sealed-precompiled module's
    /// original byte length.
    pub sealed_modules: usize,
    /// Sum of every currently-registered dynamically-linked module's
    /// original byte length.
    pub dyn_modules: usize,
    /// The pooling allocator's keep-resident floor:
    /// `pool_total_instances * (LINEAR_MEMORY_KEEP_RESIDENT + TABLE_KEEP_RESIDENT)`.
    pub pool_keep_resident: usize,
}

/// A dynamically-linked module registered via
/// [`WasmCombustor::register_precompiled`] with target
/// `"wasm32-wasip1-dyn"`. The module imports `afterburner-plugin-v1`
/// exports (`cabi_realloc`, `invoke`, `memory`) from the shared
/// Afterburner Javy plugin. At thrust time the plugin is instantiated
/// first (wiring WASI + `afterburner:host` including the caller's
/// `Manifold`), then the package module is instantiated against those
/// exports. Capability gating is fully preserved: a crypto call is
/// denied under a sealed Manifold and granted under an open one,
/// identical to the source path.
pub(crate) struct DynModule {
    pub module: Module,
}

/// Import namespace the dynamically-linked package module uses for the
/// Afterburner Javy plugin exports. Produced by `javy build -C dynamic
/// -C plugin=<afterburner_plugin.wasm>`.
const DYN_PLUGIN_NS: &str = "afterburner-plugin-v1";

/// The WASM target string for a dynamically-linked module that requires the
/// Afterburner plugin host.
const DYN_TARGET: &str = "wasm32-wasip1-dyn";

pub struct WasmCombustor {
    engine: Engine,
    /// Source store keyed by SHA-256 of the user-facing source. `ignite`
    /// hashes and stashes so `thrust` can locate the original on a
    /// `ScriptNotFound` retry path. The hot path reads from
    /// `bytecode_cache` directly.
    source_store: HopscotchMap<[u8; 32], String>,
    /// Cached compiled-script payloads keyed by source hash. Populated
    /// by `ignite` (which compiles via the plugin's `compile` mode) and
    /// consumed by `thrust` (which ships the pre-built `invoke`
    /// envelope through the plugin). Skipping per-call source
    /// compilation drops the per-thrust cost from ~2 ms to ~150 µs and
    /// unlocks the plan's 100 K/sec target on commodity 8-core
    /// hardware. The cached payload also pre-bakes the base64-encoded
    /// bytecode + the entire `{"mode":"invoke",...}` JSON envelope, so
    /// per-thrust work is just a slice borrow - no encode, no serde.
    bytecode_cache: HopscotchMap<[u8; 32], Arc<CompiledScript>>,
    /// Pre-compiled self-contained (SEALED) modules registered via
    /// [`register_precompiled`]. Keyed by SHA-256 of the raw wasm bytes.
    /// Thrust path: fresh `Store` + WASI only, JSON on stdin, stdout parsed
    /// by [`nozzle::parse_output`]. No plugin envelope, no `afterburner:host`.
    sealed_cache: HopscotchMap<[u8; 32], Arc<SealedModule>>,
    /// Dynamically-linked modules registered via [`register_precompiled`]
    /// with target `"wasm32-wasip1-dyn"`. Keyed by SHA-256 of the raw wasm
    /// bytes. Thrust path: instantiate plugin (full WASI, `afterburner:host`,
    /// and caller's `Manifold`), then instantiate the package module linking
    /// its `afterburner-plugin-v1` imports to the plugin's exports.
    dyn_cache: HopscotchMap<[u8; 32], Arc<DynModule>>,
    /// Byte length charged per `sealed_cache` entry, keyed the same as
    /// it. A companion map rather than widening `SealedModule` itself,
    /// so every existing `sealed_cache` call site is untouched.
    sealed_bytes: HopscotchMap<[u8; 32], usize>,
    /// Same role as `sealed_bytes`, for `dyn_cache`.
    dyn_bytes: HopscotchMap<[u8; 32], usize>,
    /// Optional embedder-owned memory ledger - charged at cache
    /// insert/evict (`LedgerClass::ModuleCache`). `None` is the
    /// default, zero-cost posture.
    memory_ledger: Option<Arc<dyn MemoryLedger>>,
    /// Running totals mirroring the ledger charges (tracked regardless
    /// of whether a ledger is configured), so `resident_estimate`
    /// reports real numbers without re-walking a cache or
    /// re-serializing every entry.
    bytecode_cache_bytes: AtomicUsize,
    sealed_modules_bytes: AtomicUsize,
    dyn_modules_bytes: AtomicUsize,
    /// Resolved pooling-allocator instance count - mirrors
    /// `build_engine`'s own `pool_total_instances.unwrap_or(POOL_TOTAL_MEMORIES)` -
    /// kept so `resident_estimate` can report the pool's keep-resident
    /// floor without re-deriving it from a discarded `Engine::Config`.
    pool_total_instances: u32,
    /// Counter incremented every time `compile_to_bytecode` actually
    /// invokes the plugin's compile mode. Used by tests to assert the
    /// hot path is genuinely cached (register-once → N thrusts → 1
    /// compile). Lives outside `bytecode_cache` so it survives
    /// extinguish + re-ignite cycles and can distinguish "ignite was
    /// idempotent" from "compile actually ran".
    compile_count: Arc<std::sync::atomic::AtomicU64>,
    /// Pre-resolved plugin instantiation. Built once at `new()` from the
    /// module + linker; per-thrust we just call `instance_pre.instantiate(&mut store)`,
    /// which avoids re-walking imports and re-typechecking on every call.
    instance_pre: Arc<InstancePre<HostState>>,
    /// Cross-invocation state store passed to every thrust.
    state_store: SharedStateStore,
    /// Optional host context - embedder-facing read_column/emit_row hooks.
    host_context: Option<Arc<dyn afterburner_core::HostContext>>,
    /// Transpile hook threaded into every Store's HostState so the JS
    /// require resolver can call `__host_ts_transpile` for TS / ESM.
    transpile_hook: Option<crate::host::TranspileFn>,
    /// Shutdown flag for `ticker`, always allocated even when no ticker
    /// is spawned (`Drop`'s store into it is then a harmless no-op).
    ticker_shutdown: Arc<AtomicBool>,
    /// Long-lived epoch ticker; one per `WasmCombustor`, unless
    /// [`WasmConfig::spawn_epoch_ticker`] is `Some(false)`, in which case
    /// this is `None` and the embedder is driving the epoch itself.
    ticker: Option<JoinHandle<()>>,
}

impl WasmCombustor {
    pub fn new(config: WasmConfig) -> Result<Self> {
        let engine = build_engine(&config)?;
        let plugin_module = build_plugin_module(&engine)?;

        // Build the linker once with every host import resolved, then
        // pre-instantiate so the per-call path is just `Store::new` +
        // `instance_pre.instantiate`. Imports never need re-resolution.
        let mut linker: Linker<HostState> = Linker::new(&engine);
        add_to_linker_sync(&mut linker, |s: &mut HostState| &mut s.wasi)
            .map_err(|e| AfterburnerError::Engine(format!("wasi linker: {e}")))?;
        host_imports::register(&mut linker)?;
        let instance_pre = linker
            .instantiate_pre(&plugin_module)
            .map_err(|e| AfterburnerError::Engine(format!("plugin instantiate_pre: {e}")))?;

        let ticker_shutdown = Arc::new(AtomicBool::new(false));
        let ticker = if config.spawn_epoch_ticker.unwrap_or(true) {
            let engine_for_ticker = engine.clone();
            let shutdown = ticker_shutdown.clone();
            let ticker_name = config
                .ticker_governance
                .thread_name("afterburner-epoch-ticker", "");
            Some(spawn_governed(
                ticker_name,
                config.ticker_governance.clone(),
                move || {
                    while !shutdown.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(TICK_PERIOD_MS));
                        engine_for_ticker.increment_epoch();
                    }
                },
            )?)
        } else {
            None
        };

        let state_store = config
            .state_store
            .unwrap_or_else(InMemoryStateStore::shared);
        let pool_total_instances = config.pool_total_instances.unwrap_or(POOL_TOTAL_MEMORIES);

        Ok(Self {
            engine,
            source_store: HopscotchMap::new(),
            bytecode_cache: HopscotchMap::new(),
            sealed_cache: HopscotchMap::new(),
            dyn_cache: HopscotchMap::new(),
            sealed_bytes: HopscotchMap::new(),
            dyn_bytes: HopscotchMap::new(),
            memory_ledger: config.memory_ledger,
            bytecode_cache_bytes: AtomicUsize::new(0),
            sealed_modules_bytes: AtomicUsize::new(0),
            dyn_modules_bytes: AtomicUsize::new(0),
            pool_total_instances,
            compile_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            instance_pre: Arc::new(instance_pre),
            state_store,
            host_context: config.host_context,
            transpile_hook: config.transpile_hook,
            ticker_shutdown,
            ticker,
        })
    }

    /// Reserve `bytes` against the configured ledger (if any) under
    /// [`LedgerClass::ModuleCache`] and track the running total either
    /// way (so [`Self::resident_estimate`] stays accurate with or
    /// without a ledger). Call BEFORE the cache insert that makes the
    /// bytes resident; on denial the caller must not proceed with the
    /// insert.
    fn charge_module_cache(&self, bytes: usize, total: &AtomicUsize) -> Result<()> {
        if let Some(ledger) = &self.memory_ledger {
            ledger
                .reserve(LedgerClass::ModuleCache, bytes)
                .map_err(|e| AfterburnerError::LedgerDenied(e.0))?;
        }
        total.fetch_add(bytes, Ordering::AcqRel);
        Ok(())
    }

    /// Release `bytes` previously charged via [`Self::charge_module_cache`].
    /// Call AFTER the cache remove.
    fn release_module_cache(&self, bytes: usize, total: &AtomicUsize) {
        if let Some(ledger) = &self.memory_ledger {
            ledger.release(LedgerClass::ModuleCache, bytes);
        }
        total.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// Measure this combustor's resident-byte breakdown right now. Not
    /// free - the plugin module is re-serialized on every call - so
    /// this is for occasional verification / true-up, never a hot path.
    pub fn resident_estimate(&self) -> ResidentBreakdown {
        let plugin_module = self
            .instance_pre
            .module()
            .serialize()
            .map(|b| b.len())
            .unwrap_or(0);
        ResidentBreakdown {
            plugin_module,
            bytecode_cache: self.bytecode_cache_bytes.load(Ordering::Acquire),
            sealed_modules: self.sealed_modules_bytes.load(Ordering::Acquire),
            dyn_modules: self.dyn_modules_bytes.load(Ordering::Acquire),
            pool_keep_resident: self.pool_total_instances as usize
                * (LINEAR_MEMORY_KEEP_RESIDENT + TABLE_KEEP_RESIDENT),
        }
    }

    /// Exposed so the daemon path can thread the same hook into its
    /// long-lived Store's HostState.
    pub fn transpile_hook(&self) -> Option<crate::host::TranspileFn> {
        self.transpile_hook.clone()
    }

    /// Compile `source` for the JSON-shaped UDF path by spinning up a
    /// one-shot plugin Store in `compile` mode. Result is the raw
    /// bytecode for the input-via-`__AB_GET_INPUT__` wrapper.
    fn compile_to_bytecode(&self, source: &str) -> Result<Vec<u8>> {
        self.compile_to_bytecode_with_mode(source, "compile")
    }

    /// Compile `source` for the columnar UDF path. Same shape as
    /// [`Self::compile_to_bytecode`] but uses the plugin's
    /// `compile-columnar` mode, which wraps the source with
    /// `__ab_columnar_dispatch(module.exports)` so the cached
    /// bytecode is wired to read column buffers + write the reply
    /// blob via the host_columnar_reply path.
    fn compile_columnar_to_bytecode(&self, source: &str) -> Result<Vec<u8>> {
        self.compile_to_bytecode_with_mode(source, "compile-columnar")
    }

    fn compile_to_bytecode_with_mode(&self, source: &str, mode: &str) -> Result<Vec<u8>> {
        self.compile_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let envelope = serde_json::json!({
            "mode": mode,
            "source": source,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)?;

        // Compile mode runs the plugin with a sealed manifold and no
        // host context - the only thing it does is invoke
        // `javy_plugin_api::compile_src` and write base64 to stdout.
        let limits = FuelGauge::unlimited();
        let state = HostState::new(
            envelope_bytes,
            None, // no per-call memory cap during compile
            limits.output_ceiling(),
            Manifold::sealed(),
            self.state_store.clone(),
            None,
        );
        let mut store = chamber::prepare_store(&self.engine, state, &limits)?;
        chamber::instantiate_and_start(&mut store, &self.instance_pre)?.map_err(|trap| {
            let stderr = format_trap_with_stderr(&format!("compile: {trap}"), &mut store);
            AfterburnerError::CompileFailed(stderr)
        })?;

        let stdout_bytes = drain_stdout(&mut store);
        // Plugin emits the bytecode as base64-encoded ASCII on stdout.
        // Trim any trailing newline / null padding before decoding.
        let trimmed = trim_trailing_whitespace(&stdout_bytes);
        B64.decode(trimmed)
            .map_err(|e| AfterburnerError::CompileFailed(format!("bytecode b64 decode: {e}")))
    }

    /// Hand-out the active `StateStore` so embedders can inspect /
    /// pre-populate it from outside the script.
    pub fn state_store(&self) -> &SharedStateStore {
        &self.state_store
    }

    /// Register a pre-compiled self-contained (SEALED) WASM module and
    /// return a [`ScriptId`] that `thrust` dispatches through the sealed
    /// path. The module must import only `wasi_snapshot_preview1`; it reads
    /// JSON from stdin and writes JSON to stdout (the Javy self-contained
    /// command pattern).
    ///
    /// `target` is the `[runtime] target` string from the `.afb` manifest.
    /// Accepts `"wasm32-wasip1"` (sealed, self-contained) and
    /// `"wasm32-wasip1-dyn"` (dynamically-linked, two-instance model; routes to
    /// `register_dyn` which carries the caller's `Manifold` through the plugin).
    ///
    /// Registration is content-addressed: calling this twice with identical
    /// `wasm` bytes returns the same `ScriptId` and skips re-compilation of
    /// the module's native code. `wasm` may be a raw `.wasm` binary or a WAT
    /// text module (wasmtime accepts both).
    ///
    /// An embedder that owns an on-disk AOT cache keyed by `wasm`'s
    /// content digest should try [`Self::register_precompiled_deserialize`]
    /// first and fall back to this method (then [`Self::serialize_module`]
    /// to populate the cache) only on a miss.
    pub fn register_precompiled(&self, wasm: &[u8], target: &str) -> Result<ScriptId> {
        if target == DYN_TARGET {
            return self.register_dyn(wasm);
        }

        let hash = sha256(wasm);

        if self.sealed_cache.get(&hash).is_some() {
            ab_event!(Level::Debug, "wasm.sealed.cache_hit", "hash" => hex8(&hash));
            return Ok(ScriptId {
                hash,
                mode: EngineMode::Wasm,
            });
        }

        // Compile the module native code once (cached by wasmtime's on-disk
        // cache when `compile_cache_dir` is set).
        let module = Module::new(&self.engine, wasm)
            .map_err(|e| AfterburnerError::CompileFailed(format!("sealed module compile: {e}")))?;
        let built = self.build_sealed_module(module)?;

        let bytes = wasm.len();
        self.charge_module_cache(bytes, &self.sealed_modules_bytes)?;
        self.sealed_cache.insert(hash, built);
        self.sealed_bytes.insert(hash, bytes);
        ab_event!(
            Level::Info,
            "wasm.sealed.registered",
            "hash" => hex8(&hash),
            "wasm_bytes" => wasm.len(),
        );

        Ok(ScriptId {
            hash,
            mode: EngineMode::Wasm,
        })
    }

    /// Register a precompiled native artifact (a `.cwasm`) previously
    /// produced by [`Self::serialize_module`] (or wasmtime's own
    /// `Module::serialize` / `Engine::precompile_module`), skipping
    /// Cranelift entirely. This is the embedder-owned AOT cache hook:
    /// afterburner installs no on-disk compile cache of its own for
    /// user modules ([`WasmConfig::compile_cache_dir`] is a separate,
    /// wasmtime-managed cache for a different purpose and is not
    /// required for this path) - the embedder reads its own cache
    /// directory, and on a hit calls this instead of
    /// [`Self::register_precompiled`].
    ///
    /// `target` selects sealed (`"wasm32-wasip1"`) vs dynamically-linked
    /// (`"wasm32-wasip1-dyn"`) exactly like [`Self::register_precompiled`].
    /// Registration is content-addressed by the **`cwasm` bytes**, not
    /// an original `.wasm` source - calling this twice with identical
    /// `cwasm` is a cache hit, not a double-deserialize. The resulting
    /// `ScriptId` is therefore independent of whatever `ScriptId` a cold
    /// `register_precompiled(wasm, target)` call for the same logical
    /// module would have produced in another process; callers key their
    /// own persistent identity (a content digest of the original `wasm`,
    /// for instance) separately and only use the returned `ScriptId` as
    /// this process's in-memory dispatch handle.
    ///
    /// # Safety
    ///
    /// `cwasm` must be exactly the unmodified output of a prior
    /// [`Self::serialize_module`] call (or wasmtime's own
    /// `Module::serialize` / `Engine::precompile_module`) against a
    /// compatible `Engine` - see [`Module::deserialize`]'s safety
    /// section for the full contract. Deserializing untrusted or
    /// tampered bytes is a memory-safety violation, not a recoverable
    /// error, which is why this method is `unsafe`. A version, config,
    /// or target-triple mismatch in a *legitimately produced* cache
    /// entry is safe and simply returns `Err` (wasmtime validates a
    /// compatibility header before trusting anything else in the blob);
    /// the danger is exclusively bytes from an untrusted origin. Callers
    /// MUST store cache files under a directory an attacker cannot
    /// write to (mirror this crate's own `private_cache_dir`: created
    /// `0700`, owned by the current user).
    pub unsafe fn register_precompiled_deserialize(
        &self,
        cwasm: &[u8],
        target: &str,
    ) -> Result<ScriptId> {
        if target == DYN_TARGET {
            // Safety: forwarded from this function's own contract.
            return unsafe { self.register_dyn_deserialize(cwasm) };
        }

        let hash = sha256(cwasm);

        if self.sealed_cache.get(&hash).is_some() {
            ab_event!(Level::Debug, "wasm.sealed.cache_hit", "hash" => hex8(&hash));
            return Ok(ScriptId {
                hash,
                mode: EngineMode::Wasm,
            });
        }

        // Safety: forwarded from this function's own contract - `cwasm`
        // must be trusted, unmodified `serialize()` output.
        let module = unsafe { Module::deserialize(&self.engine, cwasm) }.map_err(|e| {
            AfterburnerError::CompileFailed(format!("sealed module deserialize: {e}"))
        })?;
        let built = self.build_sealed_module(module)?;

        let bytes = cwasm.len();
        self.charge_module_cache(bytes, &self.sealed_modules_bytes)?;
        self.sealed_cache.insert(hash, built);
        self.sealed_bytes.insert(hash, bytes);
        ab_event!(
            Level::Info,
            "wasm.sealed.registered_from_cache",
            "hash" => hex8(&hash),
            "cwasm_bytes" => cwasm.len(),
        );

        Ok(ScriptId {
            hash,
            mode: EngineMode::Wasm,
        })
    }

    /// Return the native-compiled artifact for a module previously
    /// registered via [`Self::register_precompiled`] or
    /// [`Self::register_precompiled_deserialize`], so the embedder can
    /// persist it as its own AOT cache entry (atomically - write to a
    /// temp file in the same directory, then rename into place, the
    /// same pattern this crate uses for its own plugin `.cwasm` cache).
    ///
    /// The bytes are wasmtime's `Module::serialize` output: keyed by
    /// the module contents plus the compiling `Engine`'s exact `Config`
    /// plus the wasmtime version, so an engine upgrade or a config
    /// change lands on a fresh cache key and a stale entry is simply
    /// never accepted by [`Self::register_precompiled_deserialize`]
    /// (never silently misread).
    ///
    /// Returns [`AfterburnerError::ScriptNotFound`] if `id` does not
    /// name a currently-registered sealed or dynamically-linked module -
    /// a JS/TS `ScriptId` from [`Combustor::ignite`], for instance, has no
    /// compiled `Module` to serialize.
    pub fn serialize_module(&self, id: &ScriptId) -> Result<Vec<u8>> {
        if let Some(sealed) = self.sealed_cache.get(&id.hash) {
            return sealed
                .instance_pre
                .module()
                .serialize()
                .map_err(|e| AfterburnerError::Engine(format!("sealed module serialize: {e}")));
        }
        if let Some(dyn_module) = self.dyn_cache.get(&id.hash) {
            return dyn_module
                .module
                .serialize()
                .map_err(|e| AfterburnerError::Engine(format!("dyn module serialize: {e}")));
        }
        Err(AfterburnerError::ScriptNotFound)
    }

    /// Wire a compiled or deserialized sealed `Module` into a fresh
    /// WASI-only linker and pre-resolve instantiation. Shared by the
    /// compile path ([`Self::register_precompiled`]) and the AOT-cache
    /// deserialize path ([`Self::register_precompiled_deserialize`]) so
    /// the two can never drift apart.
    fn build_sealed_module(&self, module: Module) -> Result<Arc<SealedModule>> {
        let mut wasi_linker: Linker<HostState> = Linker::new(&self.engine);
        add_to_linker_sync(&mut wasi_linker, |s: &mut HostState| &mut s.wasi)
            .map_err(|e| AfterburnerError::Engine(format!("sealed wasi linker: {e}")))?;
        // Wire outbound HTTP so sealed WASI guests can call
        // `afterburner:host`/`host_http_request`. The caller's Manifold
        // (carried through `FuelGauge` on each thrust) gates every request
        // via `NetAccess::OutboundHttp`; a sealed Manifold yields
        // PermissionDenied before any connection is attempted, preserving
        // the default zero-capability posture when no Manifold is supplied.
        #[cfg(feature = "host-http")]
        host_imports::wrap_http(&mut wasi_linker)?;

        let instance_pre = wasi_linker
            .instantiate_pre(&module)
            .map_err(|e| AfterburnerError::Engine(format!("sealed instantiate_pre: {e}")))?;

        Ok(Arc::new(SealedModule { instance_pre }))
    }

    /// Register a dynamically-linked module (`"wasm32-wasip1-dyn"` target).
    ///
    /// The module imports `afterburner-plugin-v1::{cabi_realloc, invoke,
    /// memory}` from the shared Afterburner Javy plugin. Only the compiled
    /// `Module` is stored here; the per-call linking to a live plugin
    /// instance happens in [`Self::thrust_dyn`] so the caller's `Manifold`
    /// is in scope when `afterburner:host` imports resolve.
    fn register_dyn(&self, wasm: &[u8]) -> Result<ScriptId> {
        let hash = sha256(wasm);

        if self.dyn_cache.get(&hash).is_some() {
            ab_event!(Level::Debug, "wasm.dyn.cache_hit", "hash" => hex8(&hash));
            return Ok(ScriptId {
                hash,
                mode: EngineMode::Wasm,
            });
        }

        // Compile the package module native code once. The module imports
        // only from `afterburner-plugin-v1`; we do not pre-link it because
        // the plugin instance (which provides those exports) is live only
        // inside a per-call Store. Per-call linking costs three Linker::define
        // calls (three export slots) - negligible compared to plugin startup.
        let module = Module::new(&self.engine, wasm)
            .map_err(|e| AfterburnerError::CompileFailed(format!("dyn module compile: {e}")))?;

        let bytes = wasm.len();
        self.charge_module_cache(bytes, &self.dyn_modules_bytes)?;
        self.dyn_cache.insert(hash, Arc::new(DynModule { module }));
        self.dyn_bytes.insert(hash, bytes);
        ab_event!(
            Level::Info,
            "wasm.dyn.registered",
            "hash" => hex8(&hash),
            "wasm_bytes" => wasm.len(),
        );

        Ok(ScriptId {
            hash,
            mode: EngineMode::Wasm,
        })
    }

    /// Deserialize path for [`Self::register_precompiled_deserialize`]
    /// when `target == "wasm32-wasip1-dyn"`. See that method's safety
    /// section - the same contract applies here.
    unsafe fn register_dyn_deserialize(&self, cwasm: &[u8]) -> Result<ScriptId> {
        let hash = sha256(cwasm);

        if self.dyn_cache.get(&hash).is_some() {
            ab_event!(Level::Debug, "wasm.dyn.cache_hit", "hash" => hex8(&hash));
            return Ok(ScriptId {
                hash,
                mode: EngineMode::Wasm,
            });
        }

        // Safety: forwarded from this function's own contract - `cwasm`
        // must be trusted, unmodified `serialize()` output.
        let module = unsafe { Module::deserialize(&self.engine, cwasm) }
            .map_err(|e| AfterburnerError::CompileFailed(format!("dyn module deserialize: {e}")))?;

        let bytes = cwasm.len();
        self.charge_module_cache(bytes, &self.dyn_modules_bytes)?;
        self.dyn_cache.insert(hash, Arc::new(DynModule { module }));
        self.dyn_bytes.insert(hash, bytes);
        ab_event!(
            Level::Info,
            "wasm.dyn.registered_from_cache",
            "hash" => hex8(&hash),
            "cwasm_bytes" => cwasm.len(),
        );

        Ok(ScriptId {
            hash,
            mode: EngineMode::Wasm,
        })
    }

    /// Execute a sealed (pre-compiled self-contained) module. Instantiates
    /// the module in a fresh `Store`, feeds `input` as JSON on stdin, runs
    /// `_start`, and drains stdout through [`parse_output`]. Fuel, epoch
    /// deadline, and the memory limiter are applied identically to the plugin
    /// path. The caller's `Manifold` (from `limits`) gates any
    /// `afterburner:host` imports the module may call. No plugin envelope.
    ///
    /// The module must have been registered via [`register_precompiled`].
    fn thrust_sealed(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<Value> {
        let input_bytes = serde_json::to_vec(input)?;
        let stdout_bytes = self.thrust_sealed_raw_bytes_inner(id, input_bytes, limits)?;
        parse_output(&stdout_bytes)
    }

    /// Raw-bytes-in / raw-bytes-out path for sealed precompiled modules.
    /// Feeds `input_bytes` verbatim to the module's stdin and returns the
    /// raw stdout bytes without parsing. Used by the batch precompiled path
    /// (JSON array wire) and the columnar precompiled path (binary frame).
    ///
    /// The module must have been registered via [`register_precompiled`] with
    /// target `"wasm32-wasip1"`.
    fn thrust_sealed_raw_bytes_inner(
        &self,
        id: &ScriptId,
        input_bytes: Vec<u8>,
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        let sealed = self
            .sealed_cache
            .get(&id.hash)
            .ok_or(AfterburnerError::ScriptNotFound)?;

        // The sealed module reads its input from stdin directly; no plugin
        // envelope. The caller's Manifold gates any `afterburner:host` imports
        // the module may call (e.g. `host_http_request` when the `host-http`
        // feature is on). Callers that pass `FuelGauge::default()` or
        // `FuelGauge::unlimited()` carry `Manifold::sealed()` (the field
        // default), preserving the zero-capability posture for any existing
        // call site that does not explicitly opt in to net access.
        let state = HostState::new(
            input_bytes,
            limits.memory_bytes,
            limits.output_ceiling(),
            limits.manifold.clone(),
            self.state_store.clone(),
            None,
        );

        let mut store = chamber::fire(
            &self.engine,
            &sealed.instance_pre,
            state,
            limits,
            "wasm.sealed_thrust",
        )?;

        Ok(chamber::drain_stdout(&mut store))
    }

    /// Execute a dynamically-linked precompiled module.
    ///
    /// Two-instance model:
    ///
    /// 1. The shared plugin (`self.instance_pre`) is instantiated inside a
    ///    fresh `Store`. Its `afterburner:host` imports resolve through the
    ///    host_imports linker built at `WasmCombustor::new`, carrying the
    ///    caller's `Manifold` in `HostState` - the same gating the source
    ///    path enforces.
    /// 2. A minimal per-call linker exposes the plugin instance's exports
    ///    under the `afterburner-plugin-v1` namespace. The package module is
    ///    then instantiated against those exports via `Linker::instantiate`.
    /// 3. `_start` is called on the package instance; stdin carries the JSON
    ///    input and stdout is drained through [`nozzle::parse_output`].
    ///
    /// No `initialize-runtime` call: the plugin instance comes from the
    /// Wizer-preinitialized `InstancePre` and starts with QuickJS already
    /// warmed up. The per-call cost is two `instantiate` calls + three
    /// `Linker::define` entries (plugin exports), not a re-eval of the
    /// plenum bundle.
    fn thrust_dyn(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<Value> {
        let dyn_mod = self
            .dyn_cache
            .get(&id.hash)
            .ok_or(AfterburnerError::ScriptNotFound)?;

        let input_bytes = serde_json::to_vec(input)?;

        // HostState carries the caller's Manifold so every `afterburner:host`
        // import is gated by it when the plugin resolves a JS host call.
        let state = HostState::new(
            input_bytes,
            limits.memory_bytes,
            limits.output_ceiling(),
            limits.manifold.clone(),
            self.state_store.clone(),
            self.host_context.clone(),
        );

        let mut store = chamber::prepare_store(&self.engine, state, limits)?;

        // Instance 1: the shared plugin. Its `afterburner:host` imports were
        // resolved at `WasmCombustor::new` and are part of `self.instance_pre`.
        let plugin_instance = self
            .instance_pre
            .instantiate(&mut store)
            .map_err(|e| AfterburnerError::Engine(format!("dyn plugin instantiate: {e}")))?;

        // Instance 2: the package module. Build a minimal linker that exposes
        // the plugin instance's exports under `afterburner-plugin-v1`.
        let mut pkg_linker: Linker<HostState> = Linker::new(&self.engine);
        pkg_linker
            .instance(&mut store, DYN_PLUGIN_NS, plugin_instance)
            .map_err(|e| AfterburnerError::Engine(format!("dyn pkg linker: {e}")))?;

        let pkg_instance = pkg_linker
            .instantiate(&mut store, &dyn_mod.module)
            .map_err(|e| AfterburnerError::Engine(format!("dyn pkg instantiate: {e}")))?;

        let start = pkg_instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| AfterburnerError::Engine(format!("dyn _start lookup: {e}")))?;

        let call_result = start.call(&mut store, ());

        // Output-ceiling overflow supersedes the trap diagnosis.
        if store.data().output_overflowed() {
            let limit = store.data().output_ceiling;
            ab_event!(Level::Warn, "wasm.dyn_thrust.output_too_large", "limit" => limit);
            return Err(AfterburnerError::OutputTooLarge { limit });
        }

        if let Err(trap) = call_result {
            if let Some(exit) = trap.downcast_ref::<I32Exit>() {
                if exit.0 == 0 {
                    // Clean WASI proc_exit(0) - fall through to result extraction.
                } else {
                    ab_event!(Level::Warn, "wasm.dyn_thrust.nonzero_exit", "code" => exit.0);
                    let stderr = chamber::format_trap_with_stderr(
                        &format!("dyn module exited with code {}", exit.0),
                        &mut store,
                    );
                    return Err(AfterburnerError::WasmTrap(stderr));
                }
            } else if let Some(t) = trap.downcast_ref::<Trap>() {
                return Err(match t {
                    Trap::Interrupt => {
                        ab_event!(Level::Warn, "wasm.dyn_thrust.timeout");
                        AfterburnerError::Timeout
                    }
                    Trap::OutOfFuel => {
                        ab_event!(Level::Warn, "wasm.dyn_thrust.fuel_exhausted");
                        AfterburnerError::FuelExhausted
                    }
                    other => {
                        let msg = chamber::format_trap_with_stderr(&format!("{other}"), &mut store);
                        ab_event!(Level::Warn, "wasm.dyn_thrust.trap", "kind" => other);
                        AfterburnerError::WasmTrap(msg)
                    }
                });
            } else {
                let chain: Vec<String> = trap.chain().map(|e| format!("{e}")).collect();
                let full = chain.join(" => ");
                if full.contains("memory minimum size") || full.contains("memory size") {
                    ab_event!(Level::Warn, "wasm.dyn_thrust.memory_limit");
                    return Err(AfterburnerError::MemoryLimit);
                }
                let msg = chamber::format_trap_with_stderr(&full, &mut store);
                return Err(AfterburnerError::WasmTrap(msg));
            }
        }

        let stdout_bytes = chamber::drain_stdout(&mut store);
        parse_output(&stdout_bytes)
    }

    /// Compile a daemon-init source to QuickJS bytecode by spinning up
    /// a one-shot plugin Store in `compile-script` mode. The wrap +
    /// compile happens here on the host side; the resulting bytecode
    /// can then be handed to one or more `DaemonRuntime` instances
    /// via [`crate::daemon_runtime::DaemonRuntime::run_init_with_bytecode`], which skips
    /// re-paying the parse + compile cost on each daemon Store.
    ///
    /// `argv` / `env` / `cwd` are baked into the compiled bytecode
    /// via the script-mode envelope wrap; calling
    /// [`crate::daemon_runtime::DaemonRuntime::run_init_with_bytecode`] reuses these
    /// captured values. Embedders that need different values per
    /// invocation should re-compile.
    ///
    /// Returns `Err(AfterburnerError::CompileFailed)` on syntax
    /// errors or transpile failures, with the plugin's stderr
    /// captured in the message - same surface as
    /// `compile_to_bytecode` for the UDF path.
    pub fn compile_daemon_init_bytecode(
        &self,
        source: &str,
        invocation: &ScriptInvocation,
    ) -> Result<Vec<u8>> {
        let envelope = serde_json::json!({
            "mode": "compile-script",
            "source": source,
            "argv": invocation.argv,
            "env": invocation.env,
            "cwd": invocation.cwd,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)?;

        // Same posture as the existing `compile_to_bytecode`: sealed
        // Manifold, no host context, no host coordinators. The only
        // thing the plugin does in this mode is wrap + compile +
        // emit base64 on stdout.
        let limits = FuelGauge::unlimited();
        let state = HostState::new(
            envelope_bytes,
            None,
            limits.output_ceiling(),
            Manifold::sealed(),
            self.state_store.clone(),
            None,
        );
        let mut store = chamber::prepare_store(&self.engine, state, &limits)?;
        chamber::instantiate_and_start(&mut store, &self.instance_pre)?.map_err(|trap| {
            let stderr = format_trap_with_stderr(&format!("compile-script: {trap}"), &mut store);
            AfterburnerError::CompileFailed(stderr)
        })?;

        let stdout_bytes = drain_stdout(&mut store);
        let trimmed = trim_trailing_whitespace(&stdout_bytes);
        B64.decode(trimmed).map_err(|e| {
            AfterburnerError::CompileFailed(format!("compile-script bytecode b64 decode: {e}"))
        })
    }

    /// Shared engine - DaemonRuntime::instantiate uses this when the
    /// CLI constructs the daemon from combustor internals.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Pre-resolved plugin instance - shared between thrust + daemon.
    pub fn instance_pre(&self) -> &Arc<InstancePre<HostState>> {
        &self.instance_pre
    }

    /// Spawn a long-lived daemon runtime with a stub `DaemonHttp`
    /// coordinator - no real TCP binding, just accounting. Used by
    /// tests that exercise the plugin ABI without needing a tokio
    /// runtime or real sockets.
    pub fn spawn_daemon(
        &self,
        source: &str,
        manifold: Manifold,
    ) -> Result<crate::daemon_runtime::DaemonRuntime> {
        self.spawn_daemon_with(source, manifold, crate::daemon_http::DaemonHttp::shared())
    }

    /// Spawn a long-lived daemon runtime against an existing
    /// [`crate::daemon_http::DaemonHttp`] coordinator. The `burn` CLI constructs one via
    /// `DaemonHttp::with_runtime` (under the `daemon` feature) so
    /// `__host_http_listen` lands on a real axum listener. Library
    /// callers pass [`crate::daemon_http::DaemonHttp::shared`] for stub mode.
    pub fn spawn_daemon_with(
        &self,
        source: &str,
        manifold: Manifold,
        daemon_http: Arc<crate::daemon_http::DaemonHttp>,
    ) -> Result<crate::daemon_runtime::DaemonRuntime> {
        crate::daemon_runtime::DaemonRuntime::new(
            &self.engine,
            &self.instance_pre,
            source,
            manifold,
            Some(self.state_store.clone()),
            self.host_context.clone(),
            daemon_http,
        )
    }

    /// Like [`Self::spawn_daemon_with`] but threads a [`ScriptInvocation`]
    /// (argv + env) through. Matches the script-mode CLI surface so
    /// `process.argv` / `process.env` inside the daemon-init script
    /// reflect what the user typed.
    pub fn spawn_daemon_with_invocation(
        &self,
        source: &str,
        invocation: &afterburner_core::ScriptInvocation,
        manifold: Manifold,
        daemon_http: Arc<crate::daemon_http::DaemonHttp>,
    ) -> Result<crate::daemon_runtime::DaemonRuntime> {
        crate::daemon_runtime::DaemonRuntime::new_with_invocation(
            &self.engine,
            &self.instance_pre,
            source,
            invocation,
            manifold,
            Some(self.state_store.clone()),
            self.host_context.clone(),
            daemon_http,
        )
    }

    /// Phase 1 columnar UDF path. Skips the JSON encode/decode the
    /// regular [`Combustor::thrust`] path pays per call: the host
    /// encodes the [`crate::ColumnarBatch`] into one contiguous binary blob
    /// (one `memcpy` per input column), the plugin's columnar-invoke
    /// mode reads the blob through the existing `host_get_input`
    /// channel, and the JS-side polyfill exposes each column as a
    /// TypedArray *view* into wasm linear memory - zero copy on the
    /// guest side. After the user UDF returns, the polyfill writes
    /// the result blob via `host_columnar_reply` and the host decodes
    /// it (one `memcpy` per output column) into [`crate::ColumnarOutput`].
    ///
    /// **Total data movement per call:** one host→guest `memcpy` per
    /// input column + one guest→host `memcpy` per output column. No
    /// JSON, no base64, no varint, no Arrow framing. The unavoidable
    /// boundary copies are the only ones; everything else is in-place.
    ///
    /// **Sandbox model:** identical to [`Combustor::thrust`] - fresh
    /// Store from the pool, fresh linmem, fuel + epoch + memory cap
    /// enforced exactly as today. The columnar path adds *no* new
    /// capability gates; the user UDF executes under the same
    /// `Manifold` it would for a JSON-shaped call.
    ///
    /// **Out of scope for Phase 1:** variable-width (Utf8 / Bytea /
    /// Jsonb) and 16-byte fixed (Decimal128 / Uuid / Interval) dtypes.
    /// `encode_batch` returns [`AfterburnerError::Engine`] if a column
    /// uses one of those tags; Phase 1.5 / Phase 2 add them.
    #[fastrace::trace(name = "WasmCombustor::thrust_columnar")]
    pub fn thrust_columnar(
        &self,
        id: &ScriptId,
        batch: &crate::columnar::ColumnarBatch<'_>,
        limits: &FuelGauge,
    ) -> Result<crate::columnar::ColumnarOutput> {
        let encoded = crate::columnar::encode_batch(batch)?;
        let reply = self.thrust_columnar_bytes_inner(id, encoded.bytes, limits)?;
        crate::columnar::decode_batch(&reply)
    }

    /// Byte-level columnar UDF entry point. Takes the pre-encoded
    /// host blob, returns the guest's reply blob - neither side does
    /// `encode_batch` / `decode_batch`. Used by the `Combustor` trait
    /// override (so the type-erased `Box<dyn Combustor>` shape works)
    /// and as the inner implementation of [`Self::thrust_columnar`].
    fn thrust_columnar_bytes_inner(
        &self,
        id: &ScriptId,
        encoded_input: Vec<u8>,
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        let compiled = self
            .bytecode_cache
            .get(&id.hash)
            .ok_or(AfterburnerError::ScriptNotFound)?;

        // The boundary `memcpy` (host slice → guest linmem) happens
        // inside `HostState::new_with_input` when it stashes the bytes
        // into `pending_input`; the guest copies from there into linmem
        // via `host_get_input`. There is no third copy in this path.
        // The envelope itself is the same bytes every call for this
        // script, so cloning `Bytes` is an `Arc` bump, not a memcpy.
        let envelope_bytes = compiled.columnar_invoke_envelope_bytes.clone();

        let mut state = HostState::new_with_input(
            envelope_bytes,
            encoded_input,
            // The columnar blob is opaque bytes, not JSON text - the
            // dispatcher reads it through `__AB_GET_COLUMNAR_INPUT__`
            // (which ignores the framing flag), but keep the flag
            // truthful for anything else that consults it.
            InputFormat::Raw,
            limits.memory_bytes,
            limits.output_ceiling(),
            limits.manifold.clone(),
            self.state_store.clone(),
            self.host_context.clone(),
        );
        state.transpile_hook = self.transpile_hook.clone();

        // Traps map the same way `thrust` does (shared chamber) so the
        // surface is consistent across the UDF paths.
        let mut store = chamber::fire(
            &self.engine,
            &self.instance_pre,
            state,
            limits,
            "wasm.thrust_columnar",
        )?;

        // Drain the reply set by the `host_columnar_reply` import.
        // Missing reply means the plugin's `_start` returned cleanly
        // without writing back - most commonly because the plugin
        // .wasm doesn't ship a `columnar-invoke` mode handler.
        // Surface as a clean diagnostic instead of an empty Vec, since
        // the caller can't distinguish "0 rows out" from "guest never
        // replied".
        let reply = store
            .data_mut()
            .pending_columnar_reply
            .take()
            .ok_or_else(|| {
                AfterburnerError::Engine(
                    "columnar-invoke: guest returned without calling host_columnar_reply \
                     (the plugin .wasm probably doesn't ship a columnar-invoke handler - \
                     rebuild via crates/afterburner-plugin/build.sh)"
                        .to_string(),
                )
            })?;
        Ok(reply)
    }

    /// Raw-input fast path: execute a compiled script with `input`
    /// delivered to the module as a `Uint8Array` - no JSON
    /// serialization host-side, no guest-side string materialization
    /// or `JSON.parse`. The O(n) byte movement happens in host code
    /// (outside fuel metering); the only guest-side per-byte work is
    /// one copy into a QuickJS-heap `ArrayBuffer`. Same sandbox
    /// properties, bytecode, and output contract as
    /// [`Combustor::thrust`] - the script's return value comes back
    /// as JSON (a bytes-shaped return is the typed
    /// [`AfterburnerError::UnexpectedRawOutput`]; use
    /// [`Self::thrust_raw_out`] to receive it). See `docs/principles`
    /// rule 3: native for O(n) byte work, interpreted only for logic.
    #[fastrace::trace(name = "WasmCombustor::thrust_raw")]
    pub fn thrust_raw(&self, id: &ScriptId, input: &[u8], limits: &FuelGauge) -> Result<Value> {
        self.invoke_with_input(id, input.to_vec(), InputFormat::Raw, limits)?
            .into_json()
    }

    /// Output-framing-aware JSON-input invoke: the module's return
    /// type picks the result shape. A `Uint8Array` / `ArrayBuffer`
    /// return crosses the boundary as raw bytes through the
    /// `host_raw_output` import ([`OutputValue::Bytes`]) - no
    /// `JSON.stringify`, no stdout framing, no base64; everything
    /// else takes the unchanged JSON-over-stdout contract
    /// ([`OutputValue::Json`]). One compiled bytecode serves both
    /// shapes - the invoke wrapper branches on the return type, the
    /// exact output-side mirror of the input framings.
    #[fastrace::trace(name = "WasmCombustor::thrust_out")]
    pub fn thrust_out(
        &self,
        id: &ScriptId,
        input: &Value,
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        let input_bytes = serde_json::to_vec(input)?;
        self.invoke_with_input(id, input_bytes, InputFormat::Json, limits)
    }

    /// Raw input **and** output-framing-aware result - the full-duplex
    /// bulk-payload path ("bytes in, bytes out" with zero JSON /
    /// string / base64 work in either direction). Composition of
    /// [`Self::thrust_raw`]'s input framing and
    /// [`Self::thrust_out`]'s output contract.
    #[fastrace::trace(name = "WasmCombustor::thrust_raw_out")]
    pub fn thrust_raw_out(
        &self,
        id: &ScriptId,
        input: &[u8],
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        self.invoke_with_input(id, input.to_vec(), InputFormat::Raw, limits)
    }

    /// Shared body of every invoke-shaped path ([`Combustor::thrust`],
    /// [`Self::thrust_raw`], [`Self::thrust_out`],
    /// [`Self::thrust_raw_out`]): per-call `Store` setup, plugin
    /// instantiation, `_start` dispatch, trap mapping, result
    /// extraction. The invoke envelope (mode + base64 bytecode) was
    /// built once at `ignite` time and lives in `Arc<CompiledScript>`
    /// as a `Bytes`, so every call for the same script clones the
    /// cached bytes via an `Arc` bump (not a memcpy), saving ~40 µs/call
    /// (base64 encode of ~30 KB bytecode) plus the per-call
    /// `serde_json::to_vec` on the envelope. One
    /// bytecode serves both input framings (`format` rides in
    /// `HostState`, read by the guest through `host_input_format`)
    /// and both output framings (the wrapper branches on the module's
    /// return type: bytes through `host_raw_output`, everything else
    /// JSON over stdout).
    fn invoke_with_input(
        &self,
        id: &ScriptId,
        input: Vec<u8>,
        format: InputFormat,
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        let compiled = self
            .bytecode_cache
            .get(&id.hash)
            .ok_or(AfterburnerError::ScriptNotFound)?;
        let envelope_bytes = compiled.invoke_envelope_bytes.clone();

        let mut state = HostState::new_with_input(
            envelope_bytes,
            input,
            format,
            limits.memory_bytes,
            limits.output_ceiling(),
            limits.manifold.clone(),
            self.state_store.clone(),
            self.host_context.clone(),
        );
        state.transpile_hook = self.transpile_hook.clone();
        let mut store = chamber::fire(
            &self.engine,
            &self.instance_pre,
            state,
            limits,
            "wasm.thrust",
        )?;

        // A bytes-shaped return wins: the wrapper posts `Uint8Array` /
        // `ArrayBuffer` results through `host_raw_output` and writes
        // nothing to stdout. Ceiling overflow on either channel was
        // already mapped to `OutputTooLarge` inside `chamber::fire`.
        if let Some(bytes) = store.data_mut().pending_raw_output.take() {
            return Ok(OutputValue::Bytes(bytes));
        }
        let stdout_bytes = drain_stdout(&mut store);
        parse_output(&stdout_bytes).map(OutputValue::Json)
    }
}

impl Drop for WasmCombustor {
    fn drop(&mut self) {
        self.ticker_shutdown.store(true, Ordering::Release);
        if let Some(t) = self.ticker.take() {
            let _ = t.join();
        }
    }
}

/// Build the wasmtime `Engine` with the highest-performance config the
/// platform supports.
///
/// Cross-platform invariants:
///
/// * `consume_fuel(true)` and `epoch_interruption(true)` - required for
///   per-call fuel + wall-clock bounds. Available on every platform.
///
///   Fuel instrumentation is **unconditional by necessity**, and taxes
///   even calls that run with an unlimited budget (`fuel: None` →
///   `set_fuel(u64::MAX)`). `consume_fuel` is an engine-level codegen
///   flag: the decrement-and-check sequence is baked into the compiled
///   machine code, so there is no per-`Store` off switch - and this one
///   `Engine` (plus its single compiled plugin `Module` / `InstancePre`)
///   is shared by every execution path regardless of budget: bounded
///   UDF calls, unlimited compile-mode stores, and long-lived daemon
///   stores all instantiate from it. Measured overhead on guest-CPU-
///   bound work (release CLI, 3e7-iteration interpreted JS loop):
///   ~5.5 s with fuel vs ~4.5 s without - roughly a 19 % tax. Making it
///   conditional would mean a second `Engine` with `consume_fuel(false)`
///   plus a second module compile and `InstancePre`, routed per call on
///   `limits.fuel.is_some()`: double the cold-start compile (and double
///   the on-disk compile-cache footprint, since cache entries are keyed
///   by compiler configuration), double the pooling allocator's virtual
///   reservation, and a second epoch-ticker target. That trade is not
///   worth ~19 % on the unmetered path today, especially now that the
///   dominant guest-side O(n) hot paths (base64, zlib, crypto, hashing)
///   are host-hoisted and burn no fuel at all. Revisit if profiling
///   shows interpreter-bound unmetered workloads dominating again.
/// * `memory_init_cow(true)` - re-initialize linear memory via copy-on-
///   write page mapping. Cross-platform; on Windows the implementation
///   uses file-backed sections and is functionally equivalent.
/// * `cranelift_opt_level(Speed)` - emit optimized code; safepoint
///   density is high enough that epoch interruption fires inside guest
///   loops including the Javy microtask pump (verified by the
///   `wasm_infinite_microtask_chain_is_bounded` regression test).
/// * `parallel_compilation(..)` - Cranelift uses rayon to compile
///   functions in parallel when [`WasmConfig::parallel_compilation`] is
///   `None` or `Some(true)` (today's default); cuts cold-start when the
///   plugin module first instantiates. `Some(false)` forces every
///   compile onto the calling thread instead, touching the process's
///   `rayon` global pool never - see the field doc for why an embedder
///   would choose that. Available on every platform.
/// * `wasm_threads(false)` - unconditional, not configurable. The
///   `threads` proposal (shared memories, `wait`/`notify`) is refused at
///   compile time for every module this engine ever compiles. Nothing
///   in this crate's execution model uses it: only `wasi_snapshot_preview1`
///   is linked (no `wasi-threads` import), so a guest could not spawn a
///   thread even with `wasm_threads(true)` - this is defense in depth,
///   matching [`crate::embedder_vm::deterministic_engine`]'s posture,
///   with no functional cost to any caller.
/// * `allocation_strategy(Pooling)` - pre-reserved per-instance
///   linear-memory + table slots, sized by
///   [`WasmConfig::pool_total_instances`] /
///   [`WasmConfig::pool_max_linear_memory_bytes`] (defaults:
///   [`POOL_TOTAL_MEMORIES`] instances, [`max_linear_memory_bytes`] each).
///   Slot-affine reuse means re-instantiation skips page zeroing for the
///   first `LINEAR_MEMORY_KEEP_RESIDENT` bytes. Cross-platform.
///
/// Optional sub-features (memory protection keys, etc.) that are
/// platform-specific would be runtime-probed here and silently fall
/// back if unsupported. None are currently enabled - the defaults above
/// already saturate commodity hardware throughput.
///
/// `compile_cache_dir` (see [`WasmConfig::compile_cache_dir`]) enables
/// wasmtime's on-disk compilation cache rooted at the given absolute
/// path. Cache initialisation failure is downgraded to a warning - the
/// cache is an optimisation, never a correctness dependency. An embedder
/// that wants to own its AOT cache directly (no background cache
/// worker at all) leaves this `None` and uses
/// [`WasmCombustor::serialize_module`] /
/// [`WasmCombustor::register_precompiled_deserialize`] instead.
fn build_engine(wasm_config: &WasmConfig) -> Result<Engine> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .memory_init_cow(true)
        .cranelift_opt_level(OptLevel::Speed)
        .parallel_compilation(wasm_config.parallel_compilation.unwrap_or(true))
        .wasm_threads(false);

    if let Some(dir) = wasm_config.compile_cache_dir.as_deref() {
        let mut cache_config = wasmtime::CacheConfig::new();
        cache_config.with_directory(dir);
        match wasmtime::Cache::new(cache_config) {
            Ok(cache) => {
                config.cache(Some(cache));
            }
            Err(e) => ab_event!(
                Level::Warn,
                "wasm.engine.compile_cache_disabled",
                "dir" => dir.display().to_string(),
                "error" => e.to_string(),
            ),
        }
    }

    let total_instances = wasm_config
        .pool_total_instances
        .unwrap_or(POOL_TOTAL_MEMORIES);
    let max_memory_size = wasm_config
        .pool_max_linear_memory_bytes
        .map(|bytes| bytes.min(WASM32_MAX_LINEAR_MEMORY_BYTES))
        .unwrap_or_else(max_linear_memory_bytes);

    let mut pool = PoolingAllocationConfig::default();
    pool.total_core_instances(total_instances);
    pool.total_memories(total_instances);
    pool.max_memory_size(max_memory_size);
    pool.linear_memory_keep_resident(LINEAR_MEMORY_KEEP_RESIDENT);
    pool.table_keep_resident(TABLE_KEEP_RESIDENT);
    pool.table_elements(POOL_TABLE_ELEMENTS);

    config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));

    Engine::new(&config).map_err(|e| AfterburnerError::Engine(format!("engine init: {e}")))
}

/// Cranelift-compiling the 8.5 MiB plugin module from scratch costs
/// multiple seconds. The CLI's parent shard pays it once at startup,
/// but every `cluster.fork()` / `new Worker()` spawns a *fresh* `burn`
/// process whose [`WasmCombustor::new`] would re-pay the full compile.
/// Under `cluster` with N workers that is N concurrent multi-second
/// cranelift runs fighting for the same handful of CPUs - on a
/// constrained CI runner the contention stretches a single worker's
/// compile past the cluster test's 60 s safety timeout, so the worker
/// never reaches `app.listen()` / posts its `online` frame and the
/// primary hangs.
///
/// Fix: cache the *native-compiled* plugin on disk, content-addressed
/// by the plugin bytes + the engine's own compatibility key, and have
/// every process after the first `Module::deserialize` it (which skips
/// cranelift entirely - microseconds, not seconds). The producer writes
/// to a unique temp file and atomically `rename`s it into place, so a
/// concurrent reader never observes a partial file; the content-address
/// in the name means an engine / plugin upgrade lands on a new path and
/// stale files are simply ignored, never reused.
///
/// We deserialize from an in-memory copy of the bytes (not a live mmap
/// of the file) so an already-loaded module is immune to any later
/// change to the on-disk file. `Module::deserialize` validates the
/// blob and returns a clean `Err` for any version / config mismatch or
/// corruption, so a bad cache entry falls back to a cold compile rather
/// than misbehaving.
fn build_plugin_module(engine: &Engine) -> Result<Module> {
    let cache_path = plugin_cwasm_cache_path(engine);

    // Fast path: a previously-written cache entry. Read the whole file
    // into owned memory, then deserialize the copy - never mmap the
    // live file (its pages must not change under a loaded module).
    if let Some(path) = &cache_path
        && let Ok(bytes) = std::fs::read(path)
    {
        // Safety: the bytes were produced by `Module::serialize` from a
        // wasmtime build of this same `burn` binary. `deserialize`
        // additionally validates the embedded compatibility header and
        // returns `Err` (never UB) for any mismatch or corruption, so a
        // stale or partial file degrades to the cold-compile path below.
        match unsafe { Module::deserialize(engine, &bytes) } {
            Ok(module) => return Ok(module),
            Err(e) => ab_event!(
                Level::Debug,
                "wasm.plugin.cwasm_cache_miss",
                "path" => path.display().to_string(),
                "error" => e.to_string(),
            ),
        }
    }

    // Cold path: cranelift-compile the plugin, then best-effort publish
    // the native artifact for sibling / future processes (typically the
    // cluster workers this parent is about to fork).
    let module = Module::new(engine, PLUGIN_BYTES)
        .map_err(|e| AfterburnerError::Engine(format!("plugin module: {e}")))?;
    if let Some(path) = &cache_path
        && let Ok(serialized) = module.serialize()
    {
        publish_cwasm_cache(path, &serialized);
    }
    Ok(module)
}

/// Content-addressed path for the cached native plugin module, or
/// `None` if no usable private cache directory exists (then we always
/// cold-compile).
///
/// `Module::deserialize` trusts the bytes for native code execution, so
/// the cache must not be plantable by another user. We therefore root it
/// in a **per-uid** directory created `0700` and owned by us (see
/// [`private_cache_dir`]); a different user can neither write a poisoned
/// entry into it nor read ours. Same-uid processes - crucially the
/// cluster / worker children this parent forks, which run as the same
/// user - share it freely.
///
/// The file name folds in the plugin bytes (so a plugin rebuild relocates
/// the cache) and `Engine::precompile_compatibility_hash` (so any change
/// to the engine `Config` or wasmtime version relocates it too), making
/// every entry self-validating by name; an incompatible entry is never
/// even read.
fn plugin_cwasm_cache_path(engine: &Engine) -> Option<std::path::PathBuf> {
    let dir = private_cache_dir()?;
    let plugin_hash = sha256(PLUGIN_BYTES);
    let compat = engine.precompile_compatibility_hash();
    // 16 hex chars of plugin hash + the engine compat token keep the
    // name short while staying collision-free in practice.
    let name = format!(
        "plugin-{}-{:016x}.cwasm",
        hex8(&plugin_hash),
        fold_compat_hash(compat),
    );
    Some(dir.join(name))
}

/// A per-user cache directory under the system temp root, created with
/// owner-only (`0700`) permissions so no other user can plant a file the
/// `Module::deserialize` fast path would execute. Returns `None` if it
/// cannot be created or (on Unix) is not a directory we own with the
/// expected mode - in which case the caller cold-compiles instead of
/// trusting a directory it cannot vouch for.
///
/// `pub(crate)` so the one secure-cache-dir policy is shared: both the
/// plugin `.cwasm` cache here and the deterministic embedder's on-disk
/// wasmtime compile cache (see [`crate::embedder_vm::deterministic_engine`])
/// root in the *same* owner-only directory rather than each rolling its own.
pub(crate) fn private_cache_dir() -> Option<std::path::PathBuf> {
    let base = std::env::temp_dir();
    if base.as_os_str().is_empty() {
        return None;
    }
    #[cfg(unix)]
    let uid = {
        // Safe: `getuid` is a pure syscall with no preconditions.
        unsafe { libc::getuid() }
    };
    #[cfg(not(unix))]
    let uid = 0u32;
    let dir = base.join(format!("burn-cache-{uid}"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // create_dir with mode 0700; ignore AlreadyExists, then verify.
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700);
        match b.create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return None,
        }
        // Verify the existing dir is really a directory we own with no
        // group / other access - defends against a pre-planted symlink
        // or a loosened-permission dir from another user.
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&dir).ok()?;
        if !meta.is_dir() || meta.uid() != uid || (meta.mode() & 0o077) != 0 {
            return None;
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir).ok()?;
    }
    Some(dir)
}

/// Reduce wasmtime's compatibility hash (a `Hash`-able opaque token) to
/// a `u64` we can stamp into the cache file name.
fn fold_compat_hash(compat: impl core::hash::Hash) -> u64 {
    use core::hash::Hasher;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    compat.hash(&mut h);
    h.finish()
}

/// Atomically install `bytes` at `path`: write to a unique sibling temp
/// file, then `rename` (atomic on the same filesystem) into place. A
/// reader therefore only ever sees a complete file. All failures are
/// swallowed - the cache is an optimisation, and a missing entry just
/// means the next process cold-compiles.
fn publish_cwasm_cache(path: &std::path::Path, bytes: &[u8]) {
    let Some(parent) = path.parent() else { return };
    // Unique temp name (pid + a monotonic counter) so concurrent
    // producers never collide on the staging file.
    use std::sync::atomic::AtomicU64;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("plugin"),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    if write_private(&tmp, bytes).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    // rename onto the final path. If a sibling won the race the content
    // is byte-identical, so last-writer-wins is harmless.
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Write `bytes` to `path`, owner-read/write only on Unix (`0600`).
/// Belt-and-braces alongside the `0700` cache dir: the file itself is
/// never group / world readable even if the dir mode were ever relaxed.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.flush()
}

impl Combustor for WasmCombustor {
    #[fastrace::trace(name = "WasmCombustor::ignite")]
    fn ignite(&self, source: &str) -> Result<ScriptId> {
        let hash = sha256(source.as_bytes());
        if self.bytecode_cache.get(&hash).is_some() {
            ab_event!(Level::Debug, "wasm.ignite.cache_hit", "hash" => hex8(&hash));
            return Ok(ScriptId {
                hash,
                mode: EngineMode::Wasm,
            });
        }

        // Cache miss: compile through the plugin, then stash both the
        // source (for diagnostics + future retry) and the bytecode
        // alongside a pre-built `invoke` envelope. Pre-building here
        // hoists the per-thrust base64 encode and per-thrust envelope
        // serde out of the hot path - every subsequent `thrust` for
        // this script borrows the cached bytes directly.
        let bytecode = self.compile_to_bytecode(source)?;
        let bytecode_b64 = B64.encode(&bytecode);
        let invoke_envelope = serde_json::json!({
            "mode": "invoke",
            "bytecode_b64": bytecode_b64,
        });
        let invoke_envelope_bytes = Bytes::from(serde_json::to_vec(&invoke_envelope)?);

        // Columnar wrapper compile - produces a separate bytecode
        // that wires `module.exports` to `__ab_columnar_dispatch`.
        // Same source, different wrapper, different bytecode hash.
        // Eager build because the per-call path needs both envelopes
        // pre-built; lazy compilation would put a 2 ms latency spike
        // on the first columnar call after register, which is the
        // worst time for one.
        let columnar_bytecode = self.compile_columnar_to_bytecode(source)?;
        let columnar_bytecode_b64 = B64.encode(&columnar_bytecode);
        let columnar_envelope = serde_json::json!({
            "mode": "columnar-invoke",
            "bytecode_b64": columnar_bytecode_b64,
        });
        let columnar_invoke_envelope_bytes = Bytes::from(serde_json::to_vec(&columnar_envelope)?);
        let compiled = CompiledScript {
            raw: bytecode,
            columnar_raw: columnar_bytecode,
            invoke_envelope_bytes,
            columnar_invoke_envelope_bytes,
        };
        self.charge_module_cache(compiled_script_bytes(&compiled), &self.bytecode_cache_bytes)?;
        self.source_store.insert(hash, source.to_string());
        self.bytecode_cache.insert(hash, Arc::new(compiled));
        ab_event!(
            Level::Info,
            "wasm.ignite.compiled",
            "hash" => hex8(&hash),
            "source_bytes" => source.len(),
        );

        Ok(ScriptId {
            hash,
            mode: EngineMode::Wasm,
        })
    }

    #[fastrace::trace(name = "WasmCombustor::thrust")]
    fn thrust(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<Value> {
        // Sealed path: id was registered via `register_precompiled`. No plugin
        // envelope, no `afterburner:host` wiring.
        if self.sealed_cache.get(&id.hash).is_some() {
            return self.thrust_sealed(id, input, limits);
        }
        // Dyn path: id was registered via `register_precompiled` with target
        // `"wasm32-wasip1-dyn"`. Two-instance model with full manifold gating.
        if self.dyn_cache.get(&id.hash).is_some() {
            return self.thrust_dyn(id, input, limits);
        }
        // Input serializes per-call because it changes per-call; it
        // goes via `HostState::pending_input` (read by the
        // `host_get_input` linker import) - not via the envelope.
        let input_bytes = serde_json::to_vec(input)?;
        self.invoke_with_input(id, input_bytes, InputFormat::Json, limits)?
            .into_json()
    }

    /// Combustor-trait override that delegates to the inherent
    /// [`Self::thrust_raw`] - same delegation shape as
    /// `thrust_columnar_bytes` below.
    fn thrust_raw(&self, id: &ScriptId, input: &[u8], limits: &FuelGauge) -> Result<Value> {
        WasmCombustor::thrust_raw(self, id, input, limits)
    }

    /// Combustor-trait override delegating to the inherent
    /// [`Self::thrust_out`].
    fn thrust_out(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<OutputValue> {
        WasmCombustor::thrust_out(self, id, input, limits)
    }

    /// Combustor-trait override delegating to the inherent
    /// [`Self::thrust_raw_out`].
    fn thrust_raw_out(
        &self,
        id: &ScriptId,
        input: &[u8],
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        WasmCombustor::thrust_raw_out(self, id, input, limits)
    }

    /// Combustor-trait override: raw-bytes-in / raw-bytes-out for sealed
    /// precompiled modules. Delegates to the inherent
    /// `thrust_sealed_raw_bytes_inner`.
    fn thrust_sealed_raw_bytes(
        &self,
        id: &ScriptId,
        input: Vec<u8>,
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        self.thrust_sealed_raw_bytes_inner(id, input, limits)
    }

    fn extinguish(&self, id: &ScriptId) {
        self.source_store.remove(&id.hash);
        if let Some(compiled) = self.bytecode_cache.remove(&id.hash) {
            self.release_module_cache(compiled_script_bytes(&compiled), &self.bytecode_cache_bytes);
        }
        // Also remove from sealed_cache and dyn_cache in case this id was
        // registered via register_precompiled - extinguish is content-addressed
        // and must cover all paths.
        self.sealed_cache.remove(&id.hash);
        if let Some(bytes) = self.sealed_bytes.remove(&id.hash) {
            self.release_module_cache(bytes, &self.sealed_modules_bytes);
        }
        self.dyn_cache.remove(&id.hash);
        if let Some(bytes) = self.dyn_bytes.remove(&id.hash) {
            self.release_module_cache(bytes, &self.dyn_modules_bytes);
        }
        ab_event!(Level::Info, "wasm.extinguish", "hash" => hex8(&id.hash));
    }

    /// Combustor-trait override: delegates to the inherent
    /// [`Self::register_precompiled`], wiring the sealed-module path
    /// through `Box<dyn Combustor>` so `BurnCache` and the `Afterburner`
    /// facade can call it without knowing the concrete combustor type.
    fn register_precompiled(&self, wasm: &[u8], target: &str) -> Result<ScriptId> {
        WasmCombustor::register_precompiled(self, wasm, target)
    }

    /// Combustor-trait override that delegates to the inherent
    /// byte-level path. The `BurnCache` (and therefore the public
    /// `Afterburner` facade) calls this via `Box<dyn Combustor>` -
    /// the typed
    /// [`Self::thrust_columnar`] convenience is for direct callers.
    fn thrust_columnar_bytes(
        &self,
        id: &ScriptId,
        encoded: &[u8],
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        // The inner takes ownership of the encoded blob (the wasm-side
        // path stashes it into HostState's pending_input). We clone
        // here because the trait method gives us a borrow; cloning is
        // the unavoidable boundary alloc + memcpy that gets the bytes
        // into a Vec for the host-state stash.
        self.thrust_columnar_bytes_inner(id, encoded.to_vec(), limits)
    }

    #[fastrace::trace(name = "WasmCombustor::run_script")]
    fn run_script(
        &self,
        source: &str,
        invocation: &ScriptInvocation,
        limits: &FuelGauge,
    ) -> Result<ScriptOutcome> {
        // Script mode envelope: source + process.argv + process.env
        // carried through. The plugin unpacks argv/env into JS globals
        // before evaluating the user source (see modes/script.rs).
        let envelope = serde_json::json!({
            "mode": "script",
            "source": source,
            "argv": invocation.argv,
            "env": invocation.env,
            "cwd": invocation.cwd,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)?;

        let mut state = HostState::new(
            envelope_bytes,
            limits.memory_bytes,
            limits.output_ceiling(),
            limits.manifold.clone(),
            self.state_store.clone(),
            self.host_context.clone(),
        );
        state.transpile_hook = self.transpile_hook.clone();
        let mut store = chamber::prepare_store(&self.engine, state, limits)?;
        // Script mode keeps its own trap contract (proc_exit(N) is an
        // exit code, not an error), so it maps the raw `_start` result
        // itself instead of going through `chamber::fire`.
        let call_result = chamber::instantiate_and_start(&mut store, &self.instance_pre)?;

        // Ceiling overflow is an infrastructural failure, not a script
        // outcome: the stdout capture is truncated, so neither the
        // exit code nor the captured bytes are trustworthy. Mirrors
        // the UDF paths' mapping inside `chamber::fire`.
        if store.data().output_overflowed() {
            let limit = store.data().output_ceiling;
            ab_event!(Level::Warn, "wasm.script.output_too_large", "limit" => limit);
            return Err(AfterburnerError::OutputTooLarge { limit });
        }

        let stdout_bytes = drain_stdout(&mut store);
        let stderr_bytes = store.data().stderr.contents().to_vec();

        // The script-mode trap contract is shared with `run_with_result`; keep
        // it in one place so the two never diverge (proc_exit vs timeout vs
        // uncaught exception).
        let (stdout, stderr, exit_code) =
            finish_script_run(call_result, stdout_bytes, stderr_bytes)?;
        Ok(ScriptOutcome {
            stdout,
            stderr,
            exit_code,
        })
    }

    /// Script mode with a typed result and a host seam (R2/R3): run `source`
    /// exactly as [`run_script`](Self::run_script), threading the borrowed
    /// `host` through every `afterburner:host` effect import (the record /
    /// replay seam), and surface the module's typed return alongside the
    /// captured streams.
    ///
    /// The typed [`OutputValue`] comes from the native binary channel: a run
    /// that posted bytes through `host_raw_output` yields
    /// [`OutputValue::Bytes`]; otherwise the result is
    /// [`OutputValue::Json`]`(Null)` - "no value surfaced". JS script mode has
    /// no JSON-return envelope (its top-level completion value is `null`; see
    /// the plugin's `modes/script.rs`), so stdout is deliberately **not**
    /// reparsed as the return value: stdout is console output, and coercing it
    /// into `output` would fabricate a return the script never made (and error
    /// on any non-JSON log). JS is the one substrate with a first-class binary
    /// return today; the JSON-return path lights up here the moment a
    /// script-mode value convention lands plugin-side.
    #[fastrace::trace(name = "WasmCombustor::run_with_result")]
    fn run_with_result(
        &self,
        source: &[u8],
        invocation: &ScriptInvocation,
        limits: &FuelGauge,
        host: &dyn afterburner_core::HostContext,
    ) -> Result<RunResult> {
        let source_str = std::str::from_utf8(source).map_err(|e| {
            AfterburnerError::Engine(format!("run_with_result: source is not utf-8: {e}"))
        })?;
        // Bridge the borrowed host into the 'static Store for the run's
        // duration. Sound: the Store (sole long-lived owner) and every seam
        // clone are dropped before this call returns - before `host`'s borrow
        // ends - even on an unwinding trap. See `effect_seam::borrow_host`.
        let bridged: Arc<dyn afterburner_core::HostContext> =
            unsafe { crate::effect_seam::borrow_host(host) };

        let envelope = serde_json::json!({
            "mode": "script",
            "source": source_str,
            "argv": invocation.argv,
            "env": invocation.env,
            "cwd": invocation.cwd,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)?;

        let mut state = HostState::new(
            envelope_bytes,
            limits.memory_bytes,
            limits.output_ceiling(),
            limits.manifold.clone(),
            self.state_store.clone(),
            Some(bridged),
        );
        state.transpile_hook = self.transpile_hook.clone();
        let mut store = chamber::prepare_store(&self.engine, state, limits)?;
        let call_result = chamber::instantiate_and_start(&mut store, &self.instance_pre)?;

        if store.data().output_overflowed() {
            let limit = store.data().output_ceiling;
            ab_event!(Level::Warn, "wasm.run_with_result.output_too_large", "limit" => limit);
            return Err(AfterburnerError::OutputTooLarge { limit });
        }

        // Typed return: the native binary channel wins; otherwise no value was
        // surfaced (see the doc comment for why stdout is not reparsed).
        let output = match store.data_mut().pending_raw_output.take() {
            Some(bytes) => OutputValue::Bytes(bytes),
            None => OutputValue::Json(Value::Null),
        };

        let stdout_bytes = drain_stdout(&mut store);
        let stderr_bytes = store.data().stderr.contents().to_vec();
        // Drop the Store (and with it the bridged host Arc) before returning,
        // so the borrowed host outlives every clone of the bridge.
        drop(store);

        let (stdout, stderr, exit_code) =
            finish_script_run(call_result, stdout_bytes, stderr_bytes)?;
        Ok(RunResult {
            stdout,
            stderr,
            exit_code,
            output,
        })
    }
}

/// Map a generic WASM trap in script mode to either `CompileFailed`
/// (when the plugin wrote its "compile_src (script): …" preface to
/// stderr) or an `Ok(ScriptOutcome { exit_code: 1 })` for an uncaught
/// JS exception. The Err path here is the only non-infrastructural
/// error script mode surfaces; everything else is Ok with captured
/// output so the CLI can still print what the script managed to emit
/// before it failed.
fn map_script_trap(stdout: Vec<u8>, stderr: Vec<u8>) -> Result<ScriptOutcome> {
    let stderr_str = String::from_utf8_lossy(&stderr);
    if stderr_str.contains("compile_src (script):") {
        return Err(AfterburnerError::CompileFailed(stderr_str.into_owned()));
    }
    Ok(ScriptOutcome {
        stdout,
        stderr,
        exit_code: 1,
    })
}

/// Apply the script-mode trap contract to a finished `_start` call, shared by
/// [`WasmCombustor::run_script`] and [`WasmCombustor::run_with_result`] so the
/// two never diverge on how a `proc_exit`, a timeout / fuel / memory trap, or
/// an uncaught JS exception maps to `(stdout, stderr, exit_code)` or an `Err`.
///
/// `proc_exit(N)` -> exit code `N`; interrupt -> [`AfterburnerError::Timeout`];
/// out-of-fuel -> [`AfterburnerError::FuelExhausted`]; a memory-size trap ->
/// [`AfterburnerError::MemoryLimit`]; a compile preface -> the
/// [`AfterburnerError::CompileFailed`] from [`map_script_trap`]; any other trap
/// -> exit code 1 with the captured output (an uncaught user exception).
fn finish_script_run(
    call_result: std::result::Result<(), wasmtime::Error>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, i32)> {
    let Err(trap) = call_result else {
        return Ok((stdout, stderr, 0));
    };
    if let Some(exit) = trap.downcast_ref::<I32Exit>() {
        // `process.exit(N)` path: preserve N. I32Exit(0) is a clean WASI exit.
        ab_event!(Level::Info, "wasm.script.proc_exit", "code" => exit.0);
        return Ok((stdout, stderr, exit.0));
    }
    if let Some(t) = trap.downcast_ref::<Trap>() {
        match t {
            Trap::Interrupt => {
                ab_event!(Level::Warn, "wasm.script.timeout");
                return Err(AfterburnerError::Timeout);
            }
            Trap::OutOfFuel => {
                ab_event!(Level::Warn, "wasm.script.fuel_exhausted");
                return Err(AfterburnerError::FuelExhausted);
            }
            _ => {}
        }
    } else {
        let chain: Vec<String> = trap.chain().map(|e| format!("{e}")).collect();
        let full = chain.join(" => ");
        if full.contains("memory minimum size") || full.contains("memory size") {
            ab_event!(Level::Warn, "wasm.script.memory_limit");
            return Err(AfterburnerError::MemoryLimit);
        }
    }
    // Uncaught JS exception (or a compile preface) -> the script's captured
    // output with exit code 1, or `CompileFailed` when the plugin flagged it.
    let outcome = map_script_trap(stdout, stderr)?;
    Ok((outcome.stdout, outcome.stderr, outcome.exit_code))
}

/// Trim trailing whitespace + null bytes from a stdout capture before
/// base64-decoding the bytecode emitted by the plugin's `compile` mode.
fn trim_trailing_whitespace(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 {
        let b = bytes[end - 1];
        if b == 0 || b.is_ascii_whitespace() {
            end -= 1;
        } else {
            break;
        }
    }
    &bytes[..end]
}

fn hex8(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &hash[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::BurnCache;
    use serde_json::json;

    fn make_combustor() -> WasmCombustor {
        WasmCombustor::new(WasmConfig::default()).unwrap()
    }

    #[test]
    fn eval_arithmetic_module_exports() {
        let c = make_combustor();
        let id = c.ignite("module.exports = () => 1 + 2").unwrap();
        let out = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!(3));
    }

    #[test]
    fn eval_reads_input_through_envelope() {
        let c = make_combustor();
        let id = c
            .ignite("module.exports = (d) => ({ doubled: d.n * 2 })")
            .unwrap();
        let out = c
            .thrust(&id, &json!({ "n": 21 }), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!({"doubled": 42}));
    }

    #[test]
    fn eval_array_map() {
        let c = make_combustor();
        let id = c
            .ignite("module.exports = (d) => d.xs.map(x => x * 2)")
            .unwrap();
        let out = c
            .thrust(&id, &json!({ "xs": [1, 2, 3] }), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!([2, 4, 6]));
    }

    #[test]
    fn wasm_require_path_join_works() {
        let c = make_combustor();
        let id = c
            .ignite("module.exports = () => require('path').join('/a', 'b', 'c.js')")
            .unwrap();
        let out = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!("/a/b/c.js"));
    }

    #[test]
    fn wasm_require_buffer_base64_roundtrip() {
        let c = make_combustor();
        let id = c
            .ignite(
                r#"
                module.exports = () => {
                    const { Buffer } = require('buffer');
                    return Buffer.from('hello world').toString('base64');
                };
                "#,
            )
            .unwrap();
        let out = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!("aGVsbG8gd29ybGQ="));
    }

    #[test]
    fn wasm_require_events_emitter_roundtrip() {
        let c = make_combustor();
        let id = c
            .ignite(
                r#"
                module.exports = () => {
                    const EE = require('events');
                    const e = new EE();
                    let hits = 0;
                    e.on('tick', (n) => { hits += n; });
                    e.emit('tick', 3);
                    e.emit('tick', 4);
                    return hits;
                };
                "#,
            )
            .unwrap();
        let out = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!(7));
    }

    #[test]
    fn wasm_require_unknown_module_throws() {
        let c = make_combustor();
        let id = c
            .ignite(
                r#"
                module.exports = () => {
                    try { require('no-such-module'); return 'unexpected'; }
                    catch (e) { return e.message; }
                };
                "#,
            )
            .unwrap();
        let out = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        // The message may carry a "(resolved against '<dir>')" suffix
        // naming the node_modules base the walk started from - assert
        // on the Node-shaped prefix.
        let msg = out.as_str().expect("error message string");
        assert!(
            msg.starts_with("Cannot find module 'no-such-module'"),
            "unexpected require error message: {msg}"
        );
    }

    #[test]
    fn hash_is_content_addressed_wasm() {
        let c = make_combustor();
        let id1 = c.ignite("const x = 1;").unwrap();
        let id2 = c.ignite("const x = 1;").unwrap();
        assert_eq!(id1.hash, id2.hash);
    }

    #[test]
    fn script_not_found_after_extinguish_wasm() {
        let c = make_combustor();
        let id = c.ignite("const x = 1;").unwrap();
        c.extinguish(&id);
        let err = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap_err();
        assert!(matches!(err, AfterburnerError::ScriptNotFound));
    }

    #[test]
    fn bytecode_cache_compiles_once_per_source() {
        // Phase 0.1 + Phase 1.4 regression: register a script once,
        // thrust it many times, and confirm the plugin's `compile`
        // modes run exactly twice per registration (regular invoke +
        // columnar). Catches a bytecode-cache miss the day it
        // happens (would silently 100× slow down every thrust).
        let c = make_combustor();
        assert_eq!(
            c.compile_count.load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        let id = c
            .ignite("module.exports = (d) => ({ doubled: d.n * 2 })")
            .unwrap();
        // Two compiles per ignite: one for the regular UDF wrapper,
        // one for the columnar wrapper (Phase 1.4).
        assert_eq!(
            c.compile_count.load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        for n in 0..32 {
            let out = c
                .thrust(&id, &json!({ "n": n }), &FuelGauge::unlimited())
                .unwrap();
            assert_eq!(out, json!({ "doubled": n * 2 }));
        }
        // After 32 thrusts the cache has done its job: still two compiles.
        assert_eq!(
            c.compile_count.load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        // Re-igniting the same source must also hit the cache (no
        // recompile) - content-addressed by hash.
        let id2 = c
            .ignite("module.exports = (d) => ({ doubled: d.n * 2 })")
            .unwrap();
        assert_eq!(id2.hash, id.hash);
        assert_eq!(
            c.compile_count.load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        // A different source compiles exactly twice more (regular + columnar).
        let _id3 = c.ignite("module.exports = () => 42").unwrap();
        assert_eq!(
            c.compile_count.load(std::sync::atomic::Ordering::Relaxed),
            4
        );
    }

    #[test]
    fn invoke_envelope_is_prebuilt_at_ignite() {
        // Phase 0.1 + Phase 1.4: the cached `CompiledScript` must
        // carry both the raw bytecodes AND both pre-encoded invoke
        // envelopes (regular + columnar). Catches a future refactor
        // that accidentally re-introduces per-thrust base64 + serde,
        // or one that conflates the two compile paths.
        let c = make_combustor();
        let id = c.ignite("module.exports = () => 'ok'").unwrap();
        let compiled = c.bytecode_cache.get(&id.hash).expect("cached");
        assert!(!compiled.raw.is_empty(), "raw bytecode must be cached");
        assert!(
            !compiled.columnar_raw.is_empty(),
            "columnar bytecode must be cached",
        );
        // The two bytecodes are different - different wrappers around
        // the same user source produce different compiled bodies.
        assert_ne!(
            compiled.raw, compiled.columnar_raw,
            "regular + columnar bytecodes must differ",
        );

        // Regular invoke envelope round-trip.
        assert!(
            !compiled.invoke_envelope_bytes.is_empty(),
            "invoke envelope must be pre-built at ignite",
        );
        let env: serde_json::Value =
            serde_json::from_slice(&compiled.invoke_envelope_bytes).unwrap();
        assert_eq!(env["mode"], json!("invoke"));
        let b64 = env["bytecode_b64"].as_str().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), compiled.raw);

        // Columnar invoke envelope round-trip.
        assert!(
            !compiled.columnar_invoke_envelope_bytes.is_empty(),
            "columnar invoke envelope must be pre-built at ignite",
        );
        let cenv: serde_json::Value =
            serde_json::from_slice(&compiled.columnar_invoke_envelope_bytes).unwrap();
        assert_eq!(cenv["mode"], json!("columnar-invoke"));
        let cb64 = cenv["bytecode_b64"].as_str().unwrap();
        assert_eq!(B64.decode(cb64).unwrap(), compiled.columnar_raw);
    }

    #[test]
    fn thrust_columnar_int32_sum_two_columns_e2e() {
        // Phase 1.4 end-to-end smoke test for the columnar UDF path.
        // Two Int32 input columns, the UDF sums them per-row and emits
        // an Int32 result column. Exercises every link in the chain:
        // host encode → linmem write → guest typed-array view → user
        // UDF compute → guest reply blob → linmem read → host decode.
        use crate::columnar::{ColumnDtype, ColumnRef, ColumnarBatch};
        let c = make_combustor();
        let id = c
            .ignite(
                r#"module.exports = (batch) => {
                    const c0 = batch.columns.c0;
                    const c1 = batch.columns.c1;
                    const out = new Int32Array(batch.row_count);
                    for (let i = 0; i < batch.row_count; i++) out[i] = c0[i] + c1[i];
                    return { row_count: batch.row_count, columns: { sum: out } };
                };"#,
            )
            .unwrap();

        let c0_data: Vec<u8> = [1i32, 2, 3, 4, 5]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let c1_data: Vec<u8> = [10i32, 20, 30, 40, 50]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let mut batch = ColumnarBatch::new(5);
        batch.push(ColumnRef {
            name: "c0",
            dtype: ColumnDtype::Int32,
            data: &c0_data,
            heap: None,
            validity: None,
        });
        batch.push(ColumnRef {
            name: "c1",
            dtype: ColumnDtype::Int32,
            data: &c1_data,
            heap: None,
            validity: None,
        });

        let out = c
            .thrust_columnar(&id, &batch, &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out.row_count, 5);
        assert_eq!(out.columns.len(), 1);
        assert_eq!(out.columns[0].name, "sum");
        assert_eq!(out.columns[0].dtype, ColumnDtype::Int32);
        let sums: Vec<i32> = out.columns[0]
            .data
            .chunks_exact(4)
            .map(|c| i32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(sums, vec![11, 22, 33, 44, 55]);
    }

    #[test]
    fn thrust_columnar_float64_sum_of_columns_e2e() {
        // Phase 1.4: 32 Float64 columns × 64 rows, the canonical
        // analytics workload shape. UDF computes sum of all columns
        // per row. The bench's Float64 sum-of-columns scenario is
        // exactly this shape (just with more rows + parallel
        // submitters).
        use crate::columnar::{ColumnDtype, ColumnRef, ColumnarBatch};
        const COLS: usize = 32;
        const ROWS: usize = 64;
        let c = make_combustor();
        let id = c
            .ignite(
                r#"module.exports = (batch) => {
                    const n = batch.row_count;
                    const out = new Float64Array(n);
                    for (let i = 0; i < n; i++) {
                        let s = 0;
                        for (let j = 0; j < 32; j++) s += batch.columns['c' + j][i];
                        out[i] = s;
                    }
                    return { row_count: n, columns: { sum: out } };
                };"#,
            )
            .unwrap();

        let mut col_bufs: Vec<Vec<u8>> = Vec::with_capacity(COLS);
        for j in 0..COLS {
            let buf: Vec<u8> = (0..ROWS)
                .flat_map(|i| (((i + 1) * (j + 1)) as f64).to_le_bytes())
                .collect();
            col_bufs.push(buf);
        }
        let mut batch = ColumnarBatch::new(ROWS as u32);
        let names: Vec<String> = (0..COLS).map(|j| format!("c{j}")).collect();
        for (j, buf) in col_bufs.iter().enumerate() {
            batch.push(ColumnRef {
                name: names[j].as_str(),
                dtype: ColumnDtype::Float64,
                data: buf,
                heap: None,
                validity: None,
            });
        }

        let out = c
            .thrust_columnar(&id, &batch, &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out.row_count, ROWS as u32);
        assert_eq!(out.columns.len(), 1);
        assert_eq!(out.columns[0].dtype, ColumnDtype::Float64);
        let sums: Vec<f64> = out.columns[0]
            .data
            .chunks_exact(8)
            .map(|c| f64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        // Row i's sum is sum_{j=1..=32} (i+1)*j  = (i+1) * (32*33/2) = 528*(i+1).
        for (i, s) in sums.iter().enumerate() {
            let expected = 528.0 * (i + 1) as f64;
            assert!(
                (s - expected).abs() < 1e-9,
                "row {i} got {s}, expected {expected}",
            );
        }
    }

    #[test]
    fn thrust_columnar_unknown_script_id() {
        // Calling with a fresh-but-unregistered ScriptId should error
        // cleanly (matches `thrust`'s behaviour for the same case).
        use crate::columnar::{ColumnDtype, ColumnRef, ColumnarBatch};
        let c = make_combustor();
        let bogus = ScriptId {
            hash: [0u8; 32],
            mode: EngineMode::Wasm,
        };
        let data = vec![0u8; 4];
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "c0",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: None,
            validity: None,
        });
        let err = c
            .thrust_columnar(&bogus, &batch, &FuelGauge::unlimited())
            .unwrap_err();
        assert!(matches!(err, AfterburnerError::ScriptNotFound));
    }

    #[test]
    fn thrust_columnar_phase1_unsupported_dtype_clean_error() {
        // Decimal128 is reserved for a later phase; the current
        // runtime rejects it at the boundary. Passing it must surface
        // a clean Engine error from `encode_batch`, not a guest-side
        // trap. Catches a regression where the unsupported-dtype
        // guard is bypassed.
        use crate::columnar::{ColumnDtype, ColumnRef, ColumnarBatch};
        let c = make_combustor();
        let id = c
            .ignite("module.exports = (b) => ({ row_count: 0, columns: {} })")
            .unwrap();
        let data = vec![0u8; 16];
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "amount",
            dtype: ColumnDtype::Decimal128,
            data: &data,
            heap: None,
            validity: None,
        });
        let err = c
            .thrust_columnar(&id, &batch, &FuelGauge::unlimited())
            .unwrap_err();
        match err {
            AfterburnerError::Engine(msg) => {
                assert!(msg.contains("Decimal128"), "got {msg}")
            }
            _ => panic!("expected Engine error, got {err:?}"),
        }
    }

    #[test]
    fn execute_batch_end_to_end() {
        let c = make_combustor();
        let source = "module.exports = (rows) => rows.map(r => ({ doubled: r.n * 2 }))";
        let cache = BurnCache::new(Box::new(c));
        let id = cache.register(source).unwrap();
        let input = json!([{"n": 1}, {"n": 2}, {"n": 3}]);
        let out = cache
            .execute_batch(&id, &input, &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!([{"doubled": 2}, {"doubled": 4}, {"doubled": 6}]));
    }

    #[test]
    fn run_with_result_captures_stdout_and_no_typed_output() {
        let c = make_combustor();
        let r = c
            .run_with_result(
                b"console.log('hi from run_with_result')",
                &ScriptInvocation::default(),
                &FuelGauge::unlimited(),
                &afterburner_core::NullHost,
            )
            .unwrap();
        assert_eq!(
            r.exit_code,
            0,
            "stderr: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert!(String::from_utf8_lossy(&r.stdout).contains("hi from run_with_result"));
        // JS script mode has no JSON-return envelope: no value surfaced.
        assert_eq!(r.output, OutputValue::Json(Value::Null));
    }

    #[test]
    fn run_with_result_records_fs_read_effect_through_the_seam() {
        use afterburner_core::effect::{EffectKind, FileOp, HostEffectRecord};
        use afterburner_core::{FsAccess, HostContext, Manifold};
        use std::sync::Mutex;

        // A recording host: journals every effect, replays none.
        #[derive(Default)]
        struct RecordingHost {
            log: Mutex<Vec<HostEffectRecord>>,
        }
        impl HostContext for RecordingHost {
            fn record_host_effect(&self, r: HostEffectRecord) {
                self.log.lock().unwrap().push(r);
            }
            fn get_effect_log(&self) -> Vec<HostEffectRecord> {
                self.log.lock().unwrap().clone()
            }
        }

        // A file the guest will read through the seamed fs import.
        let dir = std::env::temp_dir().join(format!("afb-rwr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("payload.txt");
        std::fs::write(&file, b"recorded-content").unwrap();
        let file_str = file.to_str().unwrap().to_owned();

        let mut limits = FuelGauge::unlimited();
        limits.manifold = Manifold {
            fs: FsAccess::ReadOnly(vec![dir.clone()]),
            ..Manifold::sealed()
        };

        let c = make_combustor();
        let host = RecordingHost::default();
        let src = format!(
            "const fs = require('fs'); process.stdout.write(fs.readFileSync({file_str:?}, 'utf8'));"
        );
        let r = c
            .run_with_result(src.as_bytes(), &ScriptInvocation::default(), &limits, &host)
            .unwrap();
        assert_eq!(
            r.exit_code,
            0,
            "stderr: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        // Runtime frames captured stdout with a trailing newline; the
        // byte-exact fidelity check is the recorded effect output below.
        assert_eq!(
            String::from_utf8_lossy(&r.stdout).trim_end(),
            "recorded-content"
        );

        // The seam journaled the read with the raw file content as its output.
        let log = host.get_effect_log();
        assert!(
            log.iter()
                .any(|e| matches!(e.effect.kind, EffectKind::Fs(FileOp::Read))
                    && e.output == b"recorded-content"),
            "expected a recorded Fs(Read) effect carrying the file content; log kinds: {:?}",
            log.iter().map(|e| e.effect.kind).collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A minimal, real WASI command module: writes the ASCII bytes `"42"`
    /// to stdout via `fd_write` and exits cleanly. Same hand-rolled-WAT
    /// technique as `tests/sealed_precompiled.rs`'s HTTP probe (real
    /// `fd_write` plumbing, no external tool needed to build a fixture).
    /// Zero imports beyond WASI, so it compiles under any target and
    /// needs nothing from the `afterburner:host` linker.
    const SERIALIZE_ROUNDTRIP_WAT: &str = r#"(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "42")
  (func (export "_start")
    (i32.store (i32.const 100) (i32.const 0))
    (i32.store (i32.const 104) (i32.const 2))
    (drop (call $fd_write (i32.const 1) (i32.const 100) (i32.const 1) (i32.const 200)))
    (call $proc_exit (i32.const 0))
  )
)"#;

    /// A-cache proof: `serialize_module` -> `register_precompiled_deserialize`
    /// round-trips a compiled module. Covers both directions:
    ///   1. functional: the module deserialized into a *second, independent*
    ///      combustor (mimicking a fresh process reading its own on-disk AOT
    ///      cache) executes and produces the exact same output as the
    ///      freshly-compiled original;
    ///   2. byte-exact: re-serializing the deserialized module reproduces the
    ///      identical bytes wasmtime emitted the first time
    ///      (serialize -> deserialize -> serialize is the identity).
    #[test]
    fn serialize_module_and_register_precompiled_deserialize_round_trip() {
        let c1 = make_combustor();
        let id1 = c1
            .register_precompiled(SERIALIZE_ROUNDTRIP_WAT.as_bytes(), "wasm32-wasip1")
            .unwrap();
        let out1 = c1
            .thrust(&id1, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out1, json!(42));

        // The AOT-cache hook an embedder persists to disk.
        let cwasm = c1.serialize_module(&id1).unwrap();
        assert!(!cwasm.is_empty(), "serialized module must not be empty");

        // A second, independent engine (mimics a fresh process deserializing
        // its own on-disk cache entry instead of recompiling).
        let c2 = make_combustor();
        // Safety: `cwasm` is exactly `c1.serialize_module`'s output,
        // unmodified, and `c2`'s engine uses the same `WasmConfig::default()`
        // (so a compatible compile-config header), satisfying the method's
        // safety contract.
        let id2 = unsafe { c2.register_precompiled_deserialize(&cwasm, "wasm32-wasip1") }.unwrap();
        let out2 = c2
            .thrust(&id2, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(
            out2,
            json!(42),
            "module deserialized from the AOT cache must produce identical output"
        );

        let cwasm_again = c2.serialize_module(&id2).unwrap();
        assert_eq!(
            cwasm, cwasm_again,
            "serialize(deserialize(serialize(module))) must be byte-identical"
        );
    }

    /// `serialize_module` on an id the engine has never seen (nor a JS/TS
    /// `ScriptId` from `ignite`, which has no compiled `Module` at all)
    /// fails loud with `ScriptNotFound` rather than panicking or silently
    /// returning empty bytes.
    #[test]
    fn serialize_module_unknown_id_returns_script_not_found() {
        let c = make_combustor();
        let bogus = ScriptId {
            hash: [0u8; 32],
            mode: EngineMode::Wasm,
        };
        let err = c.serialize_module(&bogus).unwrap_err();
        assert!(matches!(err, AfterburnerError::ScriptNotFound));

        // A real, live JS ScriptId (from `ignite`, not `register_precompiled`)
        // has bytecode, not a compiled `Module` - also ScriptNotFound.
        let js_id = c.ignite("module.exports = () => 1").unwrap();
        let err = c.serialize_module(&js_id).unwrap_err();
        assert!(matches!(err, AfterburnerError::ScriptNotFound));
    }

    // ── E2/E3 governance + ledger ──────────────────────────────────────

    #[test]
    fn default_config_ticker_still_spawns_and_engine_still_works() {
        // Byte-identical-defaults proof: WasmConfig::default() carries
        // ThreadGovernance::default() (a no-op) for ticker_governance and
        // None for memory_ledger - the epoch ticker still spawns
        // ungoverned exactly as before, and ordinary thrust is unaffected.
        let c = make_combustor();
        assert!(c.ticker.is_some(), "default config keeps the epoch ticker");
        let id = c.ignite("module.exports = () => 1 + 1").unwrap();
        let out = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!(2));
    }

    #[test]
    fn ticker_governance_is_ignored_when_ticker_suppressed() {
        // spawn_epoch_ticker(false) must still suppress the ticker even
        // when a non-default ticker_governance is configured - governance
        // never resurrects a thread the embedder explicitly opted out of.
        let cfg = WasmConfig {
            spawn_epoch_ticker: Some(false),
            ticker_governance: ThreadGovernance {
                name_prefix: Some("myapp-ticker".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let c = WasmCombustor::new(cfg).unwrap();
        assert!(c.ticker.is_none());
    }

    #[test]
    fn resident_estimate_reports_zero_caches_on_a_fresh_combustor() {
        let c = make_combustor();
        let r = c.resident_estimate();
        assert!(r.plugin_module > 0, "plugin module must have a real size");
        assert_eq!(r.bytecode_cache, 0);
        assert_eq!(r.sealed_modules, 0);
        assert_eq!(r.dyn_modules, 0);
        assert!(r.pool_keep_resident > 0);
    }

    #[test]
    fn resident_estimate_tracks_ignite_and_extinguish() {
        let c = make_combustor();
        let before = c.resident_estimate().bytecode_cache;
        let id = c.ignite("module.exports = () => 1").unwrap();
        let after_ignite = c.resident_estimate().bytecode_cache;
        assert!(
            after_ignite > before,
            "ignite must grow the tracked bytecode_cache total"
        );
        c.extinguish(&id);
        let after_extinguish = c.resident_estimate().bytecode_cache;
        assert_eq!(
            after_extinguish, before,
            "extinguish must release exactly what ignite charged"
        );
    }

    #[test]
    fn resident_estimate_tracks_sealed_register_and_extinguish() {
        let c = make_combustor();
        let before = c.resident_estimate().sealed_modules;
        let id = c
            .register_precompiled(SERIALIZE_ROUNDTRIP_WAT.as_bytes(), "wasm32-wasip1")
            .unwrap();
        let after_register = c.resident_estimate().sealed_modules;
        assert!(after_register > before);
        c.extinguish(&id);
        assert_eq!(c.resident_estimate().sealed_modules, before);
    }

    /// Records every `reserve`/`release` call so tests can assert both
    /// the class and the byte count charged, and optionally denies every
    /// reservation to exercise the loud-failure path.
    #[derive(Default)]
    struct MockLedger {
        deny: bool,
        reserved: std::sync::Mutex<Vec<(afterburner_core::ledger::LedgerClass, usize)>>,
        released: std::sync::Mutex<Vec<(afterburner_core::ledger::LedgerClass, usize)>>,
    }

    impl afterburner_core::ledger::MemoryLedger for MockLedger {
        fn reserve(
            &self,
            class: afterburner_core::ledger::LedgerClass,
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

        fn release(&self, class: afterburner_core::ledger::LedgerClass, bytes: usize) {
            self.released.lock().unwrap().push((class, bytes));
        }
    }

    #[test]
    fn memory_ledger_reserve_and_release_round_trip_on_ignite_extinguish() {
        let ledger = Arc::new(MockLedger::default());
        let cfg = WasmConfig {
            memory_ledger: Some(ledger.clone() as Arc<dyn MemoryLedger>),
            ..Default::default()
        };
        let c = WasmCombustor::new(cfg).unwrap();

        let id = c.ignite("module.exports = () => 1").unwrap();
        {
            let reserved = ledger.reserved.lock().unwrap();
            assert_eq!(reserved.len(), 1);
            assert_eq!(reserved[0].0, LedgerClass::ModuleCache);
            assert!(reserved[0].1 > 0);
        }
        assert!(ledger.released.lock().unwrap().is_empty());

        c.extinguish(&id);
        let reserved_bytes = ledger.reserved.lock().unwrap()[0].1;
        let released = ledger.released.lock().unwrap();
        assert_eq!(released.len(), 1);
        assert_eq!(released[0], (LedgerClass::ModuleCache, reserved_bytes));
    }

    #[test]
    fn memory_ledger_denial_is_loud_and_never_registers() {
        let ledger = Arc::new(MockLedger {
            deny: true,
            ..Default::default()
        });
        let cfg = WasmConfig {
            memory_ledger: Some(ledger as Arc<dyn MemoryLedger>),
            ..Default::default()
        };
        let c = WasmCombustor::new(cfg).unwrap();

        let err = c.ignite("module.exports = () => 1").unwrap_err();
        assert!(
            matches!(err, AfterburnerError::LedgerDenied(_)),
            "expected LedgerDenied, got {err}"
        );
        // A denied registration must not be resolvable.
        assert_eq!(c.resident_estimate().bytecode_cache, 0);
    }

    #[test]
    fn memory_ledger_none_is_free_and_unchanged() {
        // No ledger configured: registration succeeds exactly as before,
        // and resident_estimate still tracks totals (that bookkeeping is
        // independent of ledger presence).
        let c = make_combustor();
        let id = c.ignite("module.exports = () => 1").unwrap();
        let out = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!(1));
        assert!(c.resident_estimate().bytecode_cache > 0);
    }

    // ── limiter_tripped ─────────────────────────────────────────────────

    #[test]
    fn limiter_tripped_flag_is_set_on_memory_cap_denial() {
        // Covers the embedder case this flag exists for: a guest
        // allocation well past FuelGauge::memory_bytes must trip the
        // flag regardless of whether the resulting failure surfaces as
        // a typed MemoryLimit or a generic wasm trap (the guest
        // runtime's own allocator can catch the denial and abort
        // differently depending on what it was doing).
        let c = make_combustor();
        let id = c
            .ignite(
                r#"module.exports = () => {
                    const huge = new Float64Array(8 * 1024 * 1024); // 64MB
                    huge[0] = 1;
                    return huge[0];
                };"#,
            )
            .unwrap();
        let tripped = Arc::new(AtomicBool::new(false));
        let limits = FuelGauge {
            memory_bytes: Some(24 * 1024 * 1024),
            limiter_tripped: Some(tripped.clone()),
            ..FuelGauge::unlimited()
        };
        let result = c.thrust(&id, &json!(null), &limits);
        assert!(result.is_err(), "an over-budget allocation must fail");
        assert!(
            tripped.load(Ordering::Acquire),
            "the ResourceLimiter denial must set the tripped flag regardless of \
             how the guest's own runtime surfaced the failure: {result:?}"
        );
    }

    #[test]
    fn limiter_tripped_flag_stays_false_when_never_denied() {
        let c = make_combustor();
        let id = c.ignite("module.exports = () => 1 + 1").unwrap();
        let tripped = Arc::new(AtomicBool::new(false));
        let limits = FuelGauge {
            limiter_tripped: Some(tripped.clone()),
            ..FuelGauge::unlimited()
        };
        let out = c.thrust(&id, &json!(null), &limits).unwrap();
        assert_eq!(out, json!(2));
        assert!(!tripped.load(Ordering::Acquire));
    }

    #[test]
    fn limiter_tripped_defaults_to_none_and_costs_nothing() {
        // No sink supplied: HostState::limiter_tripped() reads false and
        // nothing panics, even under a denial.
        let c = make_combustor();
        let id = c
            .ignite(
                r#"module.exports = () => {
                    const huge = new Float64Array(8 * 1024 * 1024);
                    return huge.length;
                };"#,
            )
            .unwrap();
        let limits = FuelGauge {
            memory_bytes: Some(24 * 1024 * 1024),
            ..FuelGauge::unlimited()
        };
        // Must not panic; the caller simply has no sink to consult.
        let _ = c.thrust(&id, &json!(null), &limits);
    }
}
