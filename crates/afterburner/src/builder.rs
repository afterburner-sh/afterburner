// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `Afterburner` and its builder — the one-stop entry point.
//!
//! Internally wraps either a single-threaded [`BurnCache`] around one of
//! the backend combustors, or an [`afterburner_thrust::ThrustEngine`]
//! for the multi-threaded path. The caller sees one shape; dispatch is
//! compiled away when only one backend feature is enabled.

use afterburner_core::{
    AfterburnerError, BurnCache, BurnCacheBackend, Combustor, FuelGauge, HostContext,
    InMemoryStateStore, Manifold, Result, ScriptId, ScriptInvocation, ScriptOutcome,
    SharedStateStore,
};
use serde_json::Value;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Which backend `AfterburnerBuilder::build` should construct.
///
/// `Default` picks the best available per feature set (adaptive > wasm >
/// native). The impl is manual because the default variant is
/// feature-conditional — `#[derive(Default)]` can't express that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// rquickjs FFI — trusted code, sub-microsecond startup.
    Native,
    /// Wasmtime + QuickJS plugin — untrusted code, sandbox + capability gates.
    #[cfg(feature = "wasm")]
    Wasm,
    /// First call native, background-compile to WASM, subsequent calls WASM.
    #[cfg(feature = "adaptive")]
    Adaptive,
}

// Manual Default — can't derive with feature-gated variants.
#[allow(clippy::derivable_impls)]
impl Default for Mode {
    fn default() -> Self {
        #[cfg(feature = "adaptive")]
        {
            Mode::Adaptive
        }
        #[cfg(all(feature = "wasm", not(feature = "adaptive")))]
        {
            Mode::Wasm
        }
        #[cfg(all(not(feature = "wasm"), not(feature = "adaptive"), feature = "native"))]
        {
            Mode::Native
        }
        #[cfg(all(
            not(feature = "wasm"),
            not(feature = "adaptive"),
            not(feature = "native")
        ))]
        compile_error!("afterburner requires at least one of the features: wasm, native, adaptive");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Engine holder — internal dispatch
// ─────────────────────────────────────────────────────────────────────────

enum EngineHolder {
    /// Single-threaded BurnCache around a trait-object combustor.
    Cache(BurnCache),
    #[cfg(feature = "thrust")]
    Thrust(Arc<afterburner_thrust::ThrustEngine>),
}

impl fmt::Debug for EngineHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineHolder::Cache(_) => f.debug_tuple("Cache").finish(),
            #[cfg(feature = "thrust")]
            EngineHolder::Thrust(_) => f.debug_tuple("Thrust").finish(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Afterburner — the public entry point
// ─────────────────────────────────────────────────────────────────────────

/// One-stop entry point. Construct via [`Afterburner::new`] or
/// [`Afterburner::builder`].
pub struct Afterburner {
    engine: EngineHolder,
    defaults: FuelGauge,
    /// Kept for debug/introspection; backend already holds its own clone.
    _state_store: SharedStateStore,
    /// Working directory for the registered scripts. When `Some`,
    /// `register()` prepends a small JS prelude that pins
    /// `globalThis.__host_cwd` and refreshes the entry-`require`
    /// resolver so `require('foo')` walks `<cwd>/node_modules/foo` —
    /// matching how `cwd` flows through Node's CommonJS resolver. The
    /// prelude also rebinds the local `require` parameter (the UDF
    /// envelope passes `globalThis.require` by value at call time, so
    /// updating `globalThis.require` is invisible to the function-
    /// scoped `require` without an explicit re-fetch).
    cwd: Option<PathBuf>,
    /// `Some` only in flow mode; gives `register_bundle` a path to the
    /// flow-engine's multi-file loader.
    #[cfg(feature = "flow")]
    flow: Option<afterburner_flow::FlowEngine>,
}

impl fmt::Debug for Afterburner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Afterburner")
            .field("engine", &self.engine)
            .field("defaults", &self.defaults)
            .finish_non_exhaustive()
    }
}

impl Afterburner {
    /// Construct with defaults: adaptive engine (when enabled), sealed
    /// manifold, in-memory state store, no host context, no fuel/memory/
    /// timeout caps.
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    /// Start a builder for fine-grained configuration.
    pub fn builder() -> AfterburnerBuilder {
        AfterburnerBuilder::default()
    }

    /// Compile + cache a source. Idempotent by content hash — registering
    /// the same source twice returns the same `ScriptId` and skips
    /// recompilation.
    ///
    /// When the builder was configured with `.cwd(path)`, this method
    /// prepends a JS prelude that pins `globalThis.__host_cwd` and
    /// refreshes the require resolver so `require('foo')` walks from
    /// `<cwd>/node_modules/foo`. The prelude also rebinds the local
    /// `require` parameter — the UDF envelope passes
    /// `globalThis.require` *by value* at the function-call site, so
    /// updating the global is invisible without an explicit re-fetch.
    /// Without the rebind, `require('express')` walks from `/` and
    /// fails to resolve.
    pub fn register(&self, source: &str) -> Result<ScriptId> {
        let wrapped: String;
        let effective: &str = match self.cwd_prelude() {
            Some(prelude) => {
                wrapped = format!("{prelude}{source}");
                wrapped.as_str()
            }
            None => source,
        };
        match &self.engine {
            EngineHolder::Cache(c) => c.register(effective),
            #[cfg(feature = "thrust")]
            EngineHolder::Thrust(t) => t.register(effective),
        }
    }

    /// Render the cwd-pin prelude when a cwd is configured, else `None`.
    /// Centralised so both `register()` and any future per-call cwd
    /// path emit identical JS.
    fn cwd_prelude(&self) -> Option<String> {
        let cwd = self.cwd.as_ref()?;
        let cwd_str = cwd.to_str()?;
        // JSON-encode for safe interpolation into a JS string literal.
        let cwd_json = serde_json::to_string(cwd_str).ok()?;
        Some(format!(
            "globalThis.__host_cwd = {cwd_json};\n\
             if (typeof globalThis.__plenum_refresh_entry_require === 'function') {{\n\
                 globalThis.__plenum_refresh_entry_require();\n\
                 require = globalThis.require;\n\
             }}\n"
        ))
    }

    /// Compile + cache a multi-file ES-module bundle. Flow mode only;
    /// other modes return a typed error.
    ///
    /// `entry` is the module path the top-level import resolves to;
    /// `modules` is the (path, source) pairs the entry may import.
    #[cfg(feature = "flow")]
    pub fn register_bundle(&self, entry: &str, modules: &[(String, String)]) -> Result<ScriptId> {
        match self.flow.as_ref() {
            Some(f) => f.load_bundle(entry, modules),
            None => Err(AfterburnerError::Engine(
                "register_bundle requires flow mode; call .flow() on the builder".into(),
            )),
        }
    }

    /// Run a registered script with the builder-captured defaults.
    pub fn run(&self, id: &ScriptId, input: &Value) -> Result<Value> {
        self.run_with(id, input, &self.defaults)
    }

    /// Run a registered script with explicit per-call limits.
    pub fn run_with(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<Value> {
        match &self.engine {
            EngineHolder::Cache(c) => c.execute(id, input, limits),
            #[cfg(feature = "thrust")]
            EngineHolder::Thrust(t) => t.thrust_sync(id, input.clone(), limits.clone(), None),
        }
    }

    /// Run a registered script against a typed [`ColumnarBatch`] and
    /// receive the result columns directly — no JSON parse / stringify
    /// on either side. Phase 1 of the UDF perf push: the data path
    /// is `host slice → wasm linmem → JS-side TypedArray view → user
    /// UDF → JS-side TypedArray result → wasm linmem → host slice`,
    /// with exactly two `memcpy`s (the unavoidable host↔guest
    /// boundary copies) and no other data movement.
    ///
    /// **Sandbox properties** are identical to [`run`](Self::run): a
    /// fresh Wasmtime Store per call, fuel + epoch + memory caps
    /// enforced, capability gates honoured. The columnar payload is
    /// just bytes flowing through host imports — no new attack
    /// surface beyond the existing `host_get_input` channel.
    ///
    /// **Phase 1.5 dtype scope:** `Bool` / `Int8`–`Int64` /
    /// `UInt8`–`UInt64` / `Float32` / `Float64` / `Date32` /
    /// `Timestamp` / `Utf8` / `Bytea` / `Jsonb`. 16-byte fixed dtypes
    /// (`Decimal128` / `Uuid` / `Interval`) have stable wire tags but
    /// surface [`AfterburnerError::Engine`] from `encode_batch` —
    /// Phase 2 adds them.
    ///
    /// **Engine-mode behaviour:**
    ///
    /// * `Mode::Wasm` — direct call into [`WasmCombustor`].
    /// * `Mode::Adaptive` — routes to the wasm tier; if the
    ///   background wasm compile is still in flight on the first
    ///   columnar call, blocks up to 5 s waiting for it (subsequent
    ///   calls hit the READY tier with no wait).
    /// * `Mode::Native` — surfaces a clean
    ///   [`AfterburnerError::Engine`] (the native `rquickjs` backend
    ///   has no TypedArray-over-linmem mechanism; users on
    ///   native-only builds get the JSON-shaped [`run`](Self::run)
    ///   instead).
    /// * Threaded engine (`.threaded(N)`) — bypasses the worker
    ///   pipeline and dispatches directly into the inner
    ///   `WasmCombustor` (the wasmtime pool is itself thread-safe;
    ///   submitter parallelism comes from the caller fanning out N
    ///   threads, not from the worker pool).
    ///
    /// Available only when the `wasm` feature is enabled.
    #[cfg(feature = "wasm")]
    pub fn run_columnar(
        &self,
        id: &ScriptId,
        batch: &afterburner_wasi::ColumnarBatch<'_>,
    ) -> Result<afterburner_wasi::ColumnarOutput> {
        self.run_columnar_with(id, batch, &self.defaults)
    }

    /// Like [`run_columnar`](Self::run_columnar) but with explicit
    /// per-call limits.
    #[cfg(feature = "wasm")]
    pub fn run_columnar_with(
        &self,
        id: &ScriptId,
        batch: &afterburner_wasi::ColumnarBatch<'_>,
        limits: &FuelGauge,
    ) -> Result<afterburner_wasi::ColumnarOutput> {
        let encoded = afterburner_wasi::encode_batch(batch)?;
        let reply = match &self.engine {
            EngineHolder::Cache(c) => c.execute_columnar_bytes(id, &encoded.bytes, limits)?,
            #[cfg(feature = "thrust")]
            EngineHolder::Thrust(t) => t.thrust_columnar_bytes(id, &encoded.bytes, limits)?,
        };
        afterburner_wasi::decode_batch(&reply)
    }

    /// Apply the same script across a JSON array of records, returning
    /// an array of outputs. Equivalent to `run` over each element.
    pub fn run_batch(&self, id: &ScriptId, input: &Value) -> Result<Value> {
        match &self.engine {
            EngineHolder::Cache(c) => c.execute_batch(id, input, &self.defaults),
            #[cfg(feature = "thrust")]
            EngineHolder::Thrust(_) => {
                // ThrustEngine doesn't expose a batched API yet; loop
                // through and submit N thrusts, collect.
                let arr = input.as_array().ok_or_else(|| {
                    AfterburnerError::Host("run_batch: input must be array".into())
                })?;
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(self.run_with(id, item, &self.defaults)?);
                }
                Ok(Value::Array(out))
            }
        }
    }

    /// Run `source` as a **top-level script** (no UDF envelope). This
    /// is the `burn run foo.js` path: the script's `console.log`
    /// output is captured into [`ScriptOutcome::stdout`], exceptions
    /// thrown from user code yield a non-zero exit code rather than an
    /// `Err`.
    ///
    /// Intended for CLI consumers. Library callers typically want
    /// [`run`](Self::run) (UDF shape) instead — script mode's one-shot
    /// semantics and captured-output model don't compose well with
    /// long-running embedders.
    ///
    /// Currently requires a single-threaded engine. The multi-threaded
    /// `ThrustEngine` variant returns an error — script mode is not
    /// pool-scheduled (each call is an independent compile + run).
    pub fn run_script(&self, source: &str) -> Result<ScriptOutcome> {
        self.run_script_with(source, &ScriptInvocation::default(), &self.defaults)
    }

    /// Like [`run_script`](Self::run_script) but with explicit
    /// `process.argv` / `process.env` values and per-call limits
    /// overriding the builder defaults.
    pub fn run_script_with(
        &self,
        source: &str,
        invocation: &ScriptInvocation,
        limits: &FuelGauge,
    ) -> Result<ScriptOutcome> {
        match &self.engine {
            EngineHolder::Cache(c) => c.run_script(source, invocation, limits),
            #[cfg(feature = "thrust")]
            EngineHolder::Thrust(_) => Err(AfterburnerError::Engine(
                "run_script requires a single-threaded engine; \
                 construct `Afterburner::builder()` without .threaded()"
                    .into(),
            )),
        }
    }

    /// Drop cached compilation artifacts for `id`. Next `run` re-compiles
    /// from source if available.
    pub fn unload(&self, id: &ScriptId) {
        match &self.engine {
            EngineHolder::Cache(c) => c.forget(id),
            #[cfg(feature = "thrust")]
            EngineHolder::Thrust(_) => {
                // ThrustEngine owns its WasmCombustor internally; no
                // direct extinguish path exposed yet. Scripts get GC'd
                // when the engine drops.
            }
        }
    }

    /// Immutable view of the default FuelGauge this engine was built with.
    pub fn default_limits(&self) -> &FuelGauge {
        &self.defaults
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────────────────────────────

/// Configuration builder for [`Afterburner`].
#[derive(Default)]
pub struct AfterburnerBuilder {
    mode: Option<Mode>,
    fuel: Option<u64>,
    memory_bytes: Option<usize>,
    timeout_ms: Option<u64>,
    manifold: Option<Manifold>,
    host_context: Option<Arc<dyn HostContext>>,
    state_store: Option<SharedStateStore>,
    cache_backend: Option<Arc<dyn BurnCacheBackend>>,
    cwd: Option<PathBuf>,
    /// Optional shard count for daemon-mode (multi-shard pool).
    /// `None` → `available_parallelism()` at daemon spawn time.
    /// Library affordance only — the CLI does NOT expose a flag /
    /// env-var; deployment caps CPU at the container layer.
    shards: Option<usize>,
    #[cfg(feature = "flow")]
    use_flow: bool,
}

/// Resolution order shared by the daemon (`burn server.js`) and
/// the library `threaded_auto()` builder method:
///
/// 1. `BURN_SHARDS` env var if set + parses + non-zero. Same env
///    var that pins the daemon's shard count, reused here so
///    operators have one knob across the whole system.
/// 2. `std::thread::available_parallelism()` — container-aware
///    on Linux (cgroup CPU quotas honoured via
///    `sched_getaffinity`).
/// 3. `1` if `available_parallelism()` errors (rare — usually
///    only on the strangest /proc-less containers).
#[cfg(feature = "thrust")]
fn auto_worker_count() -> usize {
    if let Ok(s) = std::env::var("BURN_SHARDS")
        && let Ok(n) = s.trim().parse::<usize>()
        && (1..=128).contains(&n)
    {
        return n;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

impl fmt::Debug for AfterburnerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AfterburnerBuilder")
            .field("mode", &self.mode)
            .field("fuel", &self.fuel)
            .field("memory_bytes", &self.memory_bytes)
            .field("timeout_ms", &self.timeout_ms)
            .field("manifold", &self.manifold)
            .field("host_context", &self.host_context.is_some())
            .field("state_store", &self.state_store.is_some())
            .field("cache_backend", &self.cache_backend.is_some())
            .finish_non_exhaustive()
    }
}

impl AfterburnerBuilder {
    /// Explicit mode override. Default picks the best available per
    /// enabled features (adaptive > wasm > native).
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// `FuelGauge::fuel` — backend-specific instruction budget.
    pub fn fuel(mut self, fuel: u64) -> Self {
        self.fuel = Some(fuel);
        self
    }

    /// `FuelGauge::memory_bytes` — linear memory cap.
    pub fn memory_bytes(mut self, bytes: usize) -> Self {
        self.memory_bytes = Some(bytes);
        self
    }

    /// `FuelGauge::timeout_ms` — wall-clock cap per thrust.
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Capability profile (fs/net/crypto/env/http_timeout_ms).
    pub fn manifold(mut self, m: Manifold) -> Self {
        self.manifold = Some(m);
        self
    }

    /// Host hooks for `readColumn` / `emitRow` / `getEnv` / `log` / `http_request`.
    pub fn host_context(mut self, ctx: Arc<dyn HostContext>) -> Self {
        self.host_context = Some(ctx);
        self
    }

    /// Override the state store. Default is a fresh [`InMemoryStateStore`].
    pub fn state_store(mut self, store: SharedStateStore) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Attach a shared (cluster-wide) bytecode/source cache backend.
    pub fn cache_backend(mut self, backend: Arc<dyn BurnCacheBackend>) -> Self {
        self.cache_backend = Some(backend);
        self
    }

    /// Set the working directory for registered scripts. When set, the
    /// require resolver walks `node_modules` from this directory rather
    /// than the host process's cwd. Required for embedders that ship
    /// JS with `require('foo')` against vendored or `npm install`-ed
    /// dependencies (e.g. an Express app whose `node_modules` lives
    /// alongside the example, not next to the host binary).
    ///
    /// The path must be valid UTF-8; non-UTF-8 paths are silently
    /// ignored at registration time (the prelude is omitted). Pass an
    /// absolute path to avoid surprises — relative paths resolve
    /// against the host process's working directory at register time,
    /// not at run time.
    pub fn cwd(mut self, path: impl Into<PathBuf>) -> Self {
        self.cwd = Some(path.into());
        self
    }

    /// Number of parallel JS shards for daemon mode. Each shard is
    /// its own Wasmtime Store + QuickJS isolate served from a
    /// dedicated OS thread.
    ///
    /// Default: `std::thread::available_parallelism()` — container-
    /// aware on Linux (cgroup CPU quotas honoured via
    /// `sched_getaffinity`). Override only for specific reasons —
    /// oversubscribing cores incurs context-switch tax with zero
    /// throughput benefit; under-subscribing leaves performance on
    /// the table that the operator already paid for at the cgroup
    /// layer.
    ///
    /// In-process JS state (counters, in-memory caches, Express
    /// router state) is per-shard, not global. Use
    /// `require('afterburner:state')` for shared state across
    /// shards. Sandbox boundary preserved per-shard: capability
    /// gates apply per-Store; Wasmtime guarantees per-Store memory
    /// isolation.
    ///
    /// Library-only affordance — the `burn` CLI does not expose
    /// a flag or env-var. Deployment caps shard count at the
    /// container CPU limit, which `available_parallelism()` reads
    /// transparently.
    pub fn shards(mut self, n: usize) -> Self {
        // Hardcoded limits — the wasi crate's MAX_SHARDS constant
        // is gated behind the `daemon` feature; we duplicate the
        // value here so library consumers building without daemon
        // can still call this method (e.g., for test setup that
        // happens to not trigger the daemon path). The cap of 128
        // matches Wasmtime's pooling allocator slot count
        // (`POOL_TOTAL_MEMORIES`); requesting more would exhaust
        // the pool at instantiate time.
        const MIN: usize = 1;
        const MAX: usize = 128;
        assert!(n >= MIN, "shards must be ≥ {MIN}");
        assert!(n <= MAX, "shards must be ≤ {MAX}");
        self.shards = Some(n);
        self
    }

    /// Switch into multi-worker scheduler mode. Returns a specialized
    /// builder for thrust-only knobs.
    #[cfg(feature = "thrust")]
    pub fn threaded(self, workers: usize) -> ThreadedBuilder {
        ThreadedBuilder {
            parent: self,
            workers,
            io_workers: 0,
            tokens_per_sec: None,
            burst_tokens: 0,
            local_queue_capacity: 0,
            injector_capacity: 0,
            shutdown_drain_deadline: Duration::from_secs(5),
        }
    }

    /// Switch into multi-worker scheduler mode with the worker count
    /// auto-detected from the OS — the same `available_parallelism()`
    /// call the daemon uses, so a `docker run --cpus=4` cap produces
    /// 4 workers, k8s `cpu: "4"` produces 4 workers, and so on.
    /// Honors `BURN_SHARDS` if set (so operators can pin a count
    /// without changing application code).
    ///
    /// Library equivalent of the daemon's auto-detect for batch
    /// workloads — UDFs over billions of rows want one worker per
    /// CPU by default and a way to override at deploy time.
    #[cfg(feature = "thrust")]
    pub fn threaded_auto(self) -> ThreadedBuilder {
        let workers = auto_worker_count();
        self.threaded(workers)
    }

    /// Configure flow-engine defaults for multi-module bundle scripts.
    /// Default fuel = 1e9, memory = 64 MiB, timeout = 30 s.
    #[cfg(feature = "flow")]
    pub fn flow(mut self) -> Self {
        self.use_flow = true;
        // Inherit flow defaults unless caller already set explicit values.
        let flow_defaults = afterburner_flow::default_fuel_gauge();
        if self.fuel.is_none() {
            self.fuel = flow_defaults.fuel;
        }
        if self.memory_bytes.is_none() {
            self.memory_bytes = flow_defaults.memory_bytes;
        }
        if self.timeout_ms.is_none() {
            self.timeout_ms = flow_defaults.timeout_ms;
        }
        self
    }

    /// Materialize into a concrete [`Afterburner`].
    pub fn build(self) -> Result<Afterburner> {
        let state_store = self.state_store.unwrap_or_else(InMemoryStateStore::shared);
        let manifold = self.manifold.unwrap_or_else(Manifold::sealed);
        let defaults = FuelGauge {
            fuel: self.fuel,
            memory_bytes: self.memory_bytes,
            timeout_ms: self.timeout_ms,
            manifold: manifold.clone(),
        };

        let mode = self.mode.unwrap_or_default();

        #[cfg(feature = "flow")]
        let flow = if self.use_flow {
            let eng = afterburner_flow::FlowEngine::with_fuel(defaults.clone())?;
            Some(eng)
        } else {
            None
        };

        // Build the concrete combustor for the chosen mode. `host_context`
        // and `state_store` thread through per-backend constructors.
        let combustor: Box<dyn Combustor> =
            build_combustor(mode, state_store.clone(), self.host_context.clone())?;

        let mut cache = BurnCache::new(combustor);
        if let Some(b) = self.cache_backend.clone() {
            cache = cache.with_backend(b);
        }

        Ok(Afterburner {
            engine: EngineHolder::Cache(cache),
            defaults,
            _state_store: state_store,
            cwd: self.cwd,
            #[cfg(feature = "flow")]
            flow,
        })
    }
}

// Dispatches feature-gated combustor construction. Returns an error if
// the requested mode isn't enabled in the compile-time feature set.
#[allow(unused_variables)]
fn build_combustor(
    mode: Mode,
    state_store: SharedStateStore,
    host_context: Option<Arc<dyn HostContext>>,
) -> Result<Box<dyn Combustor>> {
    match mode {
        Mode::Native => build_native(state_store, host_context),
        #[cfg(feature = "wasm")]
        Mode::Wasm => build_wasm(state_store, host_context),
        #[cfg(feature = "adaptive")]
        Mode::Adaptive => build_adaptive(state_store, host_context),
    }
}

#[cfg(feature = "native")]
fn build_native(
    state_store: SharedStateStore,
    host_context: Option<Arc<dyn HostContext>>,
) -> Result<Box<dyn Combustor>> {
    let mut c = afterburner_ignite::NativeCombustor::with_state_store(state_store)?;
    if let Some(ctx) = host_context {
        c = c.with_host_context(ctx);
    }
    Ok(Box::new(c))
}

#[cfg(not(feature = "native"))]
fn build_native(
    _state_store: SharedStateStore,
    _host_context: Option<Arc<dyn HostContext>>,
) -> Result<Box<dyn Combustor>> {
    Err(AfterburnerError::Engine(
        "native mode requested but the `native` feature is not enabled".into(),
    ))
}

#[cfg(feature = "wasm")]
fn build_wasm(
    state_store: SharedStateStore,
    host_context: Option<Arc<dyn HostContext>>,
) -> Result<Box<dyn Combustor>> {
    let cfg = afterburner_wasi::WasmConfig {
        state_store: Some(state_store),
        host_context,
        transpile_hook: None,
    };
    Ok(Box::new(afterburner_wasi::WasmCombustor::new(cfg)?))
}

#[cfg(feature = "adaptive")]
fn build_adaptive(
    state_store: SharedStateStore,
    host_context: Option<Arc<dyn HostContext>>,
) -> Result<Box<dyn Combustor>> {
    let cfg = afterburner_wasi::WasmConfig {
        state_store: Some(state_store),
        host_context,
        transpile_hook: None,
    };
    Ok(Box::new(
        afterburner_adaptive::AdaptiveCombustor::with_wasm_config(cfg)?,
    ))
}

// ─────────────────────────────────────────────────────────────────────────
// ThreadedBuilder
// ─────────────────────────────────────────────────────────────────────────

/// Builder for the multi-threaded [`Afterburner`] variant. Obtained via
/// [`AfterburnerBuilder::threaded`].
#[cfg(feature = "thrust")]
pub struct ThreadedBuilder {
    parent: AfterburnerBuilder,
    workers: usize,
    io_workers: usize,
    tokens_per_sec: Option<u64>,
    burst_tokens: u64,
    local_queue_capacity: usize,
    injector_capacity: usize,
    shutdown_drain_deadline: Duration,
}

#[cfg(feature = "thrust")]
impl fmt::Debug for ThreadedBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadedBuilder")
            .field("workers", &self.workers)
            .field("io_workers", &self.io_workers)
            .field("tokens_per_sec", &self.tokens_per_sec)
            .field("burst_tokens", &self.burst_tokens)
            .field("local_queue_capacity", &self.local_queue_capacity)
            .field("injector_capacity", &self.injector_capacity)
            .field("shutdown_drain_deadline", &self.shutdown_drain_deadline)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "thrust")]
impl ThreadedBuilder {
    pub fn io_workers(mut self, n: usize) -> Self {
        self.io_workers = n;
        self
    }

    pub fn admission_tokens_per_sec(mut self, rate: u64) -> Self {
        self.tokens_per_sec = Some(rate);
        self
    }

    pub fn admission_burst(mut self, tokens: u64) -> Self {
        self.burst_tokens = tokens;
        self
    }

    pub fn local_queue_capacity(mut self, cap: usize) -> Self {
        self.local_queue_capacity = cap;
        self
    }

    pub fn injector_capacity(mut self, cap: usize) -> Self {
        self.injector_capacity = cap;
        self
    }

    pub fn shutdown_drain_deadline(mut self, d: Duration) -> Self {
        self.shutdown_drain_deadline = d;
        self
    }

    pub fn build(self) -> Result<Afterburner> {
        let state_store = self
            .parent
            .state_store
            .clone()
            .unwrap_or_else(InMemoryStateStore::shared);
        let manifold = self
            .parent
            .manifold
            .clone()
            .unwrap_or_else(Manifold::sealed);
        let defaults = FuelGauge {
            fuel: self.parent.fuel,
            memory_bytes: self.parent.memory_bytes,
            timeout_ms: self.parent.timeout_ms,
            manifold: manifold.clone(),
        };

        let wasm_config = afterburner_wasi::WasmConfig {
            state_store: Some(state_store.clone()),
            host_context: self.parent.host_context.clone(),
            transpile_hook: None,
        };

        let cfg = afterburner_thrust::ThrustEngineConfig {
            compute_workers: self.workers,
            io_workers: self.io_workers,
            admission_tokens_per_sec: self.tokens_per_sec,
            admission_burst_tokens: self.burst_tokens,
            local_queue_capacity: self.local_queue_capacity,
            injector_capacity: self.injector_capacity,
            shutdown_drain_deadline: self.shutdown_drain_deadline,
            wasm_config,
        };

        let engine = afterburner_thrust::ThrustEngine::new(cfg)?;

        Ok(Afterburner {
            engine: EngineHolder::Thrust(engine),
            defaults,
            _state_store: state_store,
            cwd: self.parent.cwd,
            #[cfg(feature = "flow")]
            flow: None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_runs_trivial_script() {
        let ab = Afterburner::new().expect("new");
        let id = ab
            .register("module.exports = (d) => d.n + 1")
            .expect("register");
        let out = ab.run(&id, &json!({ "n": 41 })).expect("run");
        assert_eq!(out, json!(42));
    }

    #[test]
    fn register_is_idempotent() {
        let ab = Afterburner::new().unwrap();
        let id1 = ab.register("module.exports = (d) => d").unwrap();
        let id2 = ab.register("module.exports = (d) => d").unwrap();
        assert_eq!(id1.hash, id2.hash);
    }

    #[cfg(feature = "native")]
    #[test]
    fn native_mode_works() {
        let ab = Afterburner::builder().mode(Mode::Native).build().unwrap();
        let id = ab.register("module.exports = (d) => d * 3").unwrap();
        let out = ab.run(&id, &json!(7)).unwrap();
        assert_eq!(out, json!(21));
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn wasm_mode_works() {
        let ab = Afterburner::builder().mode(Mode::Wasm).build().unwrap();
        let id = ab.register("module.exports = (d) => d * 2").unwrap();
        let out = ab.run(&id, &json!(21)).unwrap();
        assert_eq!(out, json!(42));
    }

    #[cfg(feature = "adaptive")]
    #[test]
    fn adaptive_mode_works() {
        let ab = Afterburner::builder().mode(Mode::Adaptive).build().unwrap();
        let id = ab.register("module.exports = (d) => d + 1").unwrap();
        let out = ab.run(&id, &json!(99)).unwrap();
        assert_eq!(out, json!(100));
    }

    #[test]
    fn builder_applies_fuel_limit() {
        // Very low fuel → infinite loop → FuelExhausted.
        let ab = Afterburner::builder()
            .mode(Mode::Native)
            .fuel(10_000)
            .build()
            .unwrap();
        let id = ab
            .register("module.exports = () => { while (true) {} }")
            .unwrap();
        let out = ab.run(&id, &json!(null));
        assert!(matches!(out, Err(AfterburnerError::FuelExhausted)));
    }

    #[cfg(feature = "thrust")]
    #[test]
    fn threaded_mode_runs_trivially() {
        let ab = Afterburner::builder()
            .threaded(2)
            .build()
            .expect("threaded build");
        let id = ab.register("module.exports = (d) => d.n + 1").unwrap();
        let out = ab.run(&id, &json!({ "n": 5 })).unwrap();
        assert_eq!(out, json!(6));
    }

    #[cfg(feature = "thrust")]
    #[test]
    fn threaded_run_batch_returns_array() {
        let ab = Afterburner::builder().threaded(2).build().unwrap();
        let id = ab.register("module.exports = (d) => d.x * 2").unwrap();
        let input = json!([{ "x": 1 }, { "x": 2 }, { "x": 3 }]);
        let out = ab.run_batch(&id, &input).unwrap();
        assert_eq!(out, json!([2, 4, 6]));
    }

    #[cfg(feature = "flow")]
    #[test]
    fn flow_mode_exposes_register_bundle() {
        let ab = Afterburner::builder().flow().build().unwrap();
        let entry = "main";
        let modules = vec![
            (
                "main".to_string(),
                "import { two } from './helper'; module.exports = (d) => d + two;".to_string(),
            ),
            ("helper".to_string(), "export const two = 2;".to_string()),
        ];
        // load_bundle only: we don't execute here since the adaptive /
        // wasm-compatible bundler depends on FlowEngine internals; the
        // test just verifies the facade's register_bundle plumbing.
        let _ = ab.register_bundle(entry, &modules);
    }

    #[cfg(not(feature = "flow"))]
    #[test]
    fn register_bundle_requires_flow_mode_feature() {
        // Without `flow`, `register_bundle` isn't in the public API at
        // all — compile-gated. Nothing to assert at runtime; this test
        // documents the feature gate.
    }

    #[test]
    fn run_with_overrides_per_call_limits() {
        let ab = Afterburner::builder()
            .mode(Mode::Native)
            .fuel(u64::MAX)
            .build()
            .unwrap();
        let id = ab
            .register("module.exports = () => { while (true) {} }")
            .unwrap();
        let strict = FuelGauge {
            fuel: Some(10_000),
            ..FuelGauge::unlimited()
        };
        let out = ab.run_with(&id, &json!(null), &strict);
        assert!(matches!(out, Err(AfterburnerError::FuelExhausted)));
    }
}
