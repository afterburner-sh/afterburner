// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `BurnCache` — content-addressed script cache sitting in front of any
//! `Combustor`. Compiles each unique source exactly once; `execute`
//! delegates to the engine's `thrust` with per-call limits.

use crate::ab_event;
use crate::engine::Combustor;
use crate::error::{AfterburnerError, Result};
use crate::log::Level;
use crate::types::{FuelGauge, ScriptId, sha256};
use kovan_map::HopscotchMap;
use serde_json::Value;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

/// Pluggable storage for script source text, keyed by SHA-256 of the
/// source. Enables distributed deployments where a single script is
/// registered once on any node and replicated via an external
/// coordinator (Redis, S3, NATS, etc.). Each node still compiles
/// locally — the backend stores source text, not compiled modules,
/// since the compiled form is engine-specific (wasmtime vs rquickjs)
/// and not portably serializable today.
///
/// Trait objects must be `Send + Sync` because `BurnCache` is shared
/// across threads.
pub trait BurnCacheBackend: Send + Sync {
    /// Look up the source for `hash`. `Ok(None)` means "not in this
    /// backend" — BurnCache then expects the caller to supply the
    /// source via `register(source)`. `Err(_)` is treated the same as
    /// `Ok(None)` in the hot path — backend errors must never block
    /// registration of a locally-available source.
    fn fetch(&self, hash: &[u8; 32]) -> Result<Option<String>>;

    /// Store `source` under `hash`. Called after a successful local
    /// compile so peer nodes can look it up on their own registration.
    /// Must be idempotent — a concurrent publisher racing this call
    /// with the same hash is explicitly allowed.
    fn publish(&self, hash: &[u8; 32], source: &str) -> Result<()>;
}

/// In-process default backend — no network involvement, state lives in
/// a single lock-free map. Equivalent to the pre-Phase-G behavior.
#[derive(Default)]
pub struct InProcessCacheBackend {
    store: HopscotchMap<[u8; 32], String>,
}

impl InProcessCacheBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl BurnCacheBackend for InProcessCacheBackend {
    fn fetch(&self, hash: &[u8; 32]) -> Result<Option<String>> {
        Ok(self.store.get(hash))
    }

    fn publish(&self, hash: &[u8; 32], source: &str) -> Result<()> {
        self.store.insert(*hash, source.to_string());
        Ok(())
    }
}

/// Statistics the cache exposes for observability. Load-atomically; no
/// snapshot guarantees across fields.
#[derive(Default)]
pub struct RegistryStats {
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

impl RegistryStats {
    pub fn hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }
    pub fn misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }
}

/// One-shot, wait-free cell for a single compile attempt. First writer
/// fills the `OnceLock`; later waiters spin briefly on `Option::is_some()`
/// (wait-free read) until the writer publishes.
///
/// Stored as `Arc<CompileCell>` inside `compiled` so every concurrent
/// caller for a given hash shares the same cell.
struct CompileCell {
    /// Outcome of the compile. `Ok(id)` on success, `Err(msg)` on failure.
    /// We keep the error as `String` because `AfterburnerError` is not
    /// `Clone`; waiters that lose the race reconstruct a
    /// `CompileFailed(msg)` with the same text.
    result: OnceLock<std::result::Result<ScriptId, String>>,
}

impl CompileCell {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            result: OnceLock::new(),
        })
    }
}

/// Thread-safe compile-or-cache wrapper over a `Combustor`. Identical
/// sources produce **exactly one** compile across concurrent callers;
/// losers of the insert race wait on the same `OnceLock` rather than
/// issuing a duplicate `ignite`. Hit path is wait-free.
pub struct BurnCache {
    engine: Box<dyn Combustor>,
    compiled: HopscotchMap<[u8; 32], Arc<CompileCell>>,
    source_store: HopscotchMap<[u8; 32], String>,
    /// Optional cross-process / cross-node backend. Local-only builds
    /// set this to `None` (equivalent to `InProcessCacheBackend`
    /// behavior) so there's no hot-path branch unless the caller opted
    /// into distributed caching.
    backend: Option<Arc<dyn BurnCacheBackend>>,
    stats: RegistryStats,
}

impl BurnCache {
    pub fn new(engine: Box<dyn Combustor>) -> Self {
        Self {
            engine,
            compiled: HopscotchMap::new(),
            source_store: HopscotchMap::new(),
            backend: None,
            stats: RegistryStats::default(),
        }
    }

    /// Attach a distributed cache backend. See [`BurnCacheBackend`].
    /// When set, `register_by_hash` and `register` consult the backend
    /// for a cache miss before treating it as a genuinely-new script.
    pub fn with_backend(mut self, backend: Arc<dyn BurnCacheBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Register a script when only its hash is known — the source is
    /// fetched from the [`BurnCacheBackend`]. Returns
    /// [`AfterburnerError::ScriptNotFound`] if no backend is attached
    /// or the backend has no entry for `hash`.
    ///
    /// Useful for "worker nodes" in a distributed deployment that
    /// receive only a script-id reference and must pull the source
    /// from a shared store before running it.
    pub fn register_by_hash(&self, hash: &[u8; 32]) -> Result<ScriptId> {
        // Fast path: source already cached locally.
        if let Some(src) = self.source_store.get(hash) {
            return self.register(&src);
        }
        let backend = self
            .backend
            .as_ref()
            .ok_or(AfterburnerError::ScriptNotFound)?;
        match backend.fetch(hash)? {
            Some(src) => self.register(&src),
            None => Err(AfterburnerError::ScriptNotFound),
        }
    }

    /// Compile-or-cache. Idempotent. Thread-safe. **At most one** `ignite`
    /// per unique source across concurrent callers: the winner of the
    /// insert race compiles, losers wait on the shared `OnceLock` and
    /// observe the same outcome.
    ///
    /// The hit path (cell present, result already filled) is wait-free.
    #[fastrace::trace(name = "BurnCache::register")]
    pub fn register(&self, source: &str) -> Result<ScriptId> {
        let hash = sha256(source.as_bytes());

        // Fast hit: cell exists and the result is already published.
        if let Some(cell) = self.compiled.get(&hash)
            && let Some(outcome) = cell.result.get()
        {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            ab_event!(Level::Debug, "burn_cache.hit", "hash" => hex32(&hash));
            return outcome_to_result(outcome);
        }

        // Slow path: try to install a fresh cell. Whoever wins performs
        // the compile; everyone else waits on the shared cell.
        //
        // kovan_map's `insert_if_absent` is *not* a strong CAS: the
        // CAS-then-hop-bit window can let multiple racing inserts of
        // the same key all return `None` (each thinking it just
        // installed). The map then exposes the canonical (lowest-
        // offset) entry via `get`. We follow the same pattern its own
        // `get_or_insert` uses — install, then re-get to find the
        // canonical entry — and decide winner via Arc pointer
        // identity. Without this re-get, two threads could both run
        // `engine.ignite` for the same source under contention.
        let fresh = CompileCell::new();
        self.compiled.insert_if_absent(hash, fresh.clone());
        let cell = self.compiled.get(&hash).unwrap_or_else(|| fresh.clone());
        let is_winner = Arc::ptr_eq(&cell, &fresh);

        if is_winner {
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            ab_event!(
                Level::Info,
                "burn_cache.miss",
                "hash" => hex32(&hash),
                "source_bytes" => source.len(),
            );
            self.source_store.insert(hash, source.to_string());
            // Publish to the distributed backend (if attached) so peer
            // nodes can fetch the source by hash. Publish failures are
            // logged but don't abort registration — local compilation
            // succeeded and we want the caller to keep working.
            if let Some(b) = self.backend.as_ref()
                && let Err(e) = b.publish(&hash, source)
            {
                ab_event!(Level::Warn, "burn_cache.publish_failed", "error" => e.to_string());
            }
            let stored = match self.engine.ignite(source) {
                Ok(id) => Ok(id),
                Err(e) => {
                    ab_event!(Level::Warn, "burn_cache.compile_failed", "error" => e);
                    Err(e.to_string())
                }
            };
            // `set` can only fail if someone else already set — impossible
            // because we're the sole writer via is_winner=true.
            let _ = cell.result.set(stored.clone());
            return match stored {
                Ok(id) => Ok(id),
                Err(msg) => Err(AfterburnerError::CompileFailed(msg)),
            };
        }

        // Waiter path: spin (wait-free read) until the winner publishes.
        self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
        ab_event!(
            Level::Debug,
            "burn_cache.wait_on_peer",
            "hash" => hex32(&hash),
        );
        loop {
            if let Some(outcome) = cell.result.get() {
                return outcome_to_result(outcome);
            }
            thread::yield_now();
        }
    }

    /// Execute a compiled script. Creates an isolated invocation per
    /// call — per-call `Store` in the WASM path, fresh interrupt handler
    /// in the native path.
    #[fastrace::trace(name = "BurnCache::execute")]
    pub fn execute(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<Value> {
        self.engine.thrust(id, input, limits)
    }

    /// Run `source` as a top-level script (no UDF envelope). See
    /// [`Combustor::run_script`] for semantics. Script-mode calls are
    /// **not** cached — every invocation is a fresh compile + run.
    /// Caching a script-mode script is almost never what the user
    /// wants: Node-style scripts usually have side effects at top
    /// level, and the host has no way to know whether a particular
    /// re-run should re-execute those effects.
    #[fastrace::trace(name = "BurnCache::run_script")]
    pub fn run_script(
        &self,
        source: &str,
        invocation: &crate::ScriptInvocation,
        limits: &FuelGauge,
    ) -> Result<crate::ScriptOutcome> {
        self.engine.run_script(source, invocation, limits)
    }

    /// Array-in / array-out batch helper.
    ///
    /// Contract: `rows` must be a JSON array. The script receives the whole
    /// array and must return an array — typically via
    /// `module.exports = (rows) => rows.map(r => ({...}))`. The helper
    /// enforces the shape and returns a typed error if either side
    /// violates it.
    #[fastrace::trace(name = "BurnCache::execute_batch")]
    pub fn execute_batch(&self, id: &ScriptId, rows: &Value, limits: &FuelGauge) -> Result<Value> {
        if !rows.is_array() {
            return Err(AfterburnerError::Host(
                "execute_batch: input must be a JSON array".into(),
            ));
        }
        let out = self.engine.thrust(id, rows, limits)?;
        if !out.is_array() {
            return Err(AfterburnerError::Host(format!(
                "execute_batch: script must return an array; got {}",
                type_name(&out)
            )));
        }
        Ok(out)
    }

    /// Columnar UDF entry point. Forwards the pre-encoded blob to the
    /// underlying combustor via the trait method, which knows how to
    /// dispatch into the wasm path. Decoding the reply blob back into
    /// host-side `ColumnarOutput` is the caller's responsibility — the
    /// `Afterburner::run_columnar` facade wraps this with the
    /// `encode_batch` / `decode_batch` pair from `afterburner-wasi`.
    #[fastrace::trace(name = "BurnCache::execute_columnar_bytes")]
    pub fn execute_columnar_bytes(
        &self,
        id: &ScriptId,
        encoded: &[u8],
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        self.engine.thrust_columnar_bytes(id, encoded, limits)
    }

    /// Remove a compiled script from the cache. The engine's `extinguish`
    /// is also called so backend-owned resources (wasmtime modules,
    /// rquickjs source buffers) are released.
    pub fn forget(&self, id: &ScriptId) {
        self.compiled.remove(&id.hash);
        self.source_store.remove(&id.hash);
        self.engine.extinguish(id);
        ab_event!(Level::Info, "burn_cache.forget", "hash" => hex32(&id.hash));
    }

    /// Retrieve the original source for a `ScriptId`, if still cached.
    pub fn source(&self, id: &ScriptId) -> Option<String> {
        self.source_store.get(&id.hash)
    }

    pub fn stats(&self) -> &RegistryStats {
        &self.stats
    }
}

/// Translate a published `CompileCell` outcome back into a `Result`.
/// Waiters that lose the insert race see a cloned `ScriptId` on success,
/// or a fresh `CompileFailed(msg)` carrying the winner's error text.
fn outcome_to_result(o: &std::result::Result<ScriptId, String>) -> Result<ScriptId> {
    match o {
        Ok(id) => Ok(*id),
        Err(msg) => Err(AfterburnerError::CompileFailed(msg.clone())),
    }
}

/// Render a 32-byte hash as a 16-char hex prefix — short enough for log
/// output, long enough to disambiguate scripts in practice.
///
/// This is a *display* helper, not a content address: it encodes only the
/// first 8 bytes. Full-width content-addressing hex lives in `afterburner-afb`
/// (`digest::hex`); do not use this for cache keys or registry paths.
pub fn hex32(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &hash[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Combustor;
    use crate::types::EngineMode;
    use serde_json::json;

    /// Minimal fake Combustor that records every `ignite` and `thrust`
    /// call so tests can assert idempotence / delegation.
    ///
    /// "Last thrust input" is stored in a lock-free `HopscotchMap`
    /// keyed by a unit sentinel (u8=0) — no Mutex in test code either.
    #[derive(Default)]
    struct MockCombustor {
        ignite_count: AtomicU64,
        thrust_count: AtomicU64,
        last_thrust: HopscotchMap<u8, Value>,
    }

    impl Combustor for MockCombustor {
        fn ignite(&self, source: &str) -> Result<ScriptId> {
            self.ignite_count.fetch_add(1, Ordering::Relaxed);
            Ok(ScriptId {
                hash: sha256(source.as_bytes()),
                mode: EngineMode::Native,
            })
        }
        fn thrust(&self, _id: &ScriptId, input: &Value, _lim: &FuelGauge) -> Result<Value> {
            self.thrust_count.fetch_add(1, Ordering::Relaxed);
            self.last_thrust.insert(0u8, input.clone());
            Ok(json!({"echo": input}))
        }
        fn extinguish(&self, _id: &ScriptId) {}
    }

    fn cache_with_mock() -> (BurnCache, std::sync::Arc<MockCombustor>) {
        let mock = std::sync::Arc::new(MockCombustor::default());
        // BurnCache takes a Box<dyn Combustor>, but we also want to peek
        // at counters. Use an Arc-wrapped shim.
        struct Shim(std::sync::Arc<MockCombustor>);
        impl Combustor for Shim {
            fn ignite(&self, s: &str) -> Result<ScriptId> {
                self.0.ignite(s)
            }
            fn thrust(&self, id: &ScriptId, i: &Value, l: &FuelGauge) -> Result<Value> {
                self.0.thrust(id, i, l)
            }
            fn extinguish(&self, id: &ScriptId) {
                self.0.extinguish(id)
            }
        }
        (BurnCache::new(Box::new(Shim(mock.clone()))), mock)
    }

    #[test]
    fn register_is_idempotent() {
        let (cache, mock) = cache_with_mock();
        let id1 = cache.register("module.exports = () => 1").unwrap();
        let id2 = cache.register("module.exports = () => 1").unwrap();
        assert_eq!(id1.hash, id2.hash);
        assert_eq!(mock.ignite_count.load(Ordering::Relaxed), 1);
        assert_eq!(cache.stats().hits(), 1);
        assert_eq!(cache.stats().misses(), 1);
    }

    #[test]
    fn different_sources_compile_separately() {
        let (cache, mock) = cache_with_mock();
        cache.register("module.exports = () => 1").unwrap();
        cache.register("module.exports = () => 2").unwrap();
        assert_eq!(mock.ignite_count.load(Ordering::Relaxed), 2);
        assert_eq!(cache.stats().misses(), 2);
    }

    #[test]
    fn execute_delegates_to_engine() {
        let (cache, mock) = cache_with_mock();
        let id = cache.register("module.exports = () => 1").unwrap();
        let out = cache
            .execute(&id, &json!({"x": 7}), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!({"echo": {"x": 7}}));
        assert_eq!(mock.thrust_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn forget_removes_from_cache() {
        let (cache, _mock) = cache_with_mock();
        let id = cache.register("module.exports = () => 1").unwrap();
        assert!(cache.source(&id).is_some());
        cache.forget(&id);
        assert!(cache.source(&id).is_none());
    }

    /// Build two BurnCache instances around independent MockCombustors
    /// but sharing a single BurnCacheBackend. Simulates a two-node
    /// cluster with a distributed source store.
    fn shared_backend_pair() -> (
        BurnCache,
        BurnCache,
        std::sync::Arc<MockCombustor>,
        std::sync::Arc<MockCombustor>,
        std::sync::Arc<InProcessCacheBackend>,
    ) {
        let mock_a = std::sync::Arc::new(MockCombustor::default());
        let mock_b = std::sync::Arc::new(MockCombustor::default());
        struct Shim(std::sync::Arc<MockCombustor>);
        impl Combustor for Shim {
            fn ignite(&self, s: &str) -> Result<ScriptId> {
                self.0.ignite(s)
            }
            fn thrust(&self, id: &ScriptId, i: &Value, l: &FuelGauge) -> Result<Value> {
                self.0.thrust(id, i, l)
            }
            fn extinguish(&self, id: &ScriptId) {
                self.0.extinguish(id)
            }
        }
        let backend = InProcessCacheBackend::shared();
        let cache_a = BurnCache::new(Box::new(Shim(mock_a.clone())))
            .with_backend(backend.clone() as std::sync::Arc<dyn BurnCacheBackend>);
        let cache_b = BurnCache::new(Box::new(Shim(mock_b.clone())))
            .with_backend(backend.clone() as std::sync::Arc<dyn BurnCacheBackend>);
        (cache_a, cache_b, mock_a, mock_b, backend)
    }

    #[test]
    fn register_publishes_to_backend() {
        let (cache_a, _cache_b, _mock_a, _mock_b, backend) = shared_backend_pair();
        let id = cache_a.register("module.exports = () => 99").unwrap();
        // Backend got the source at the same hash.
        let fetched = backend.fetch(&id.hash).unwrap();
        assert_eq!(fetched.as_deref(), Some("module.exports = () => 99"));
    }

    #[test]
    fn register_by_hash_resolves_via_shared_backend() {
        // Node A registers a source. Node B knows only the hash and
        // asks BurnCache to materialize it. The shared backend
        // supplies the source; Node B still compiles locally (each
        // engine keeps its own compile state — source distribution is
        // what the backend gives us, not compiled modules).
        let (cache_a, cache_b, _mock_a, mock_b, _backend) = shared_backend_pair();
        let id_a = cache_a.register("module.exports = (d) => d + 1").unwrap();
        // Node B: only knows the hash.
        let id_b = cache_b.register_by_hash(&id_a.hash).unwrap();
        assert_eq!(id_a.hash, id_b.hash);
        // Node B compiled exactly once — its own mock shows one ignite.
        assert_eq!(mock_b.ignite_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn register_by_hash_without_backend_is_not_found() {
        let (cache, _mock) = cache_with_mock();
        // No backend attached; hash is bogus, source isn't locally
        // known — should surface ScriptNotFound, not a panic.
        let err = cache.register_by_hash(&[0xab; 32]).unwrap_err();
        assert!(
            matches!(err, AfterburnerError::ScriptNotFound),
            "got: {err:?}"
        );
    }

    #[test]
    fn register_by_hash_prefers_local_source_over_backend() {
        // If the source is already cached locally, register_by_hash
        // must not phone home. We enforce this via a test backend
        // whose fetch panics.
        struct LoudBackend;
        impl BurnCacheBackend for LoudBackend {
            fn fetch(&self, _: &[u8; 32]) -> Result<Option<String>> {
                panic!("backend.fetch should not be called on a local hit");
            }
            fn publish(&self, _: &[u8; 32], _: &str) -> Result<()> {
                Ok(())
            }
        }
        let mock = std::sync::Arc::new(MockCombustor::default());
        struct Shim(std::sync::Arc<MockCombustor>);
        impl Combustor for Shim {
            fn ignite(&self, s: &str) -> Result<ScriptId> {
                self.0.ignite(s)
            }
            fn thrust(&self, id: &ScriptId, i: &Value, l: &FuelGauge) -> Result<Value> {
                self.0.thrust(id, i, l)
            }
            fn extinguish(&self, id: &ScriptId) {
                self.0.extinguish(id)
            }
        }
        let cache = BurnCache::new(Box::new(Shim(mock.clone())))
            .with_backend(std::sync::Arc::new(LoudBackend));
        let id = cache.register("module.exports = () => 7").unwrap();
        // This call must short-circuit on source_store, not hit the backend.
        let id2 = cache.register_by_hash(&id.hash).unwrap();
        assert_eq!(id.hash, id2.hash);
    }

    #[test]
    fn execute_batch_rejects_non_array_input() {
        let (cache, _) = cache_with_mock();
        let id = cache.register("module.exports = (r) => r").unwrap();
        let err = cache
            .execute_batch(&id, &json!({"x": 1}), &FuelGauge::unlimited())
            .unwrap_err();
        match err {
            crate::AfterburnerError::Host(m) => {
                assert!(m.contains("must be a JSON array"), "got: {m}");
            }
            other => panic!("expected Host error; got {other:?}"),
        }
    }

    #[test]
    fn execute_batch_rejects_non_array_output() {
        // MockCombustor echoes input inside an object. Feeding an
        // array therefore yields {"echo": [...]} — not an array, so
        // execute_batch must reject.
        let (cache, _) = cache_with_mock();
        let id = cache.register("module.exports = (r) => r").unwrap();
        let err = cache
            .execute_batch(&id, &json!([{"n": 1}]), &FuelGauge::unlimited())
            .unwrap_err();
        match err {
            crate::AfterburnerError::Host(m) => {
                assert!(m.contains("must return an array"), "got: {m}");
            }
            other => panic!("expected Host error; got {other:?}"),
        }
    }

    #[test]
    fn concurrent_register_compiles_exactly_once_per_source() {
        // With the `OnceLock`-gated `CompileCell`, concurrent registrations
        // of the same source fan into a single `ignite`; losers of the
        // insert race wait on the shared cell and observe the same id.
        use std::thread;
        let (cache, mock) = cache_with_mock();
        let cache = std::sync::Arc::new(cache);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                c.register("module.exports = () => 42").unwrap()
            }));
        }
        let ids: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(ids.windows(2).all(|w| w[0].hash == w[1].hash));
        assert_eq!(
            mock.ignite_count.load(Ordering::Relaxed),
            1,
            "OnceLock dedup must collapse N concurrent registers into 1 ignite"
        );
    }
}
