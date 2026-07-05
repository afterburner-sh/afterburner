// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Cross-invocation key/value persistence - the `StateStore` trait.
//!
//! Scripts running in Afterburner are otherwise stateless: every thrust
//! gets a fresh JS context. `StateStore` plugs in a small KV the script
//! can read/write across calls (counters, deduplication caches, last-seen
//! cursors, …). The default backend is in-memory and lives for the
//! lifetime of the engine; embedders can drop in a Redis/SQLite/etc.
//! implementation by depending on the trait.
//!
//! Capability gating: `Manifold` does not gate `StateStore` - the store
//! is supplied by the host explicitly, so its presence and scope are
//! deliberate. If you want to deny state access, install a no-op store.

use kovan_map::HopscotchMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Pluggable cross-invocation key/value storage.
///
/// All operations are synchronous because the JS API
/// (`require('afterburner:state').get(key)`) is sync. Implementations
/// must be `Send + Sync` to support concurrent thrusts.
///
/// `increment_i64` is a required primitive, not a convenience helper -
/// the JS-side `state.increment` counter would race without a single
/// host call. Implementations MUST apply the delta atomically
/// relative to other concurrent callers.
pub trait StateStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn set(&self, key: &str, value: Vec<u8>);
    fn delete(&self, key: &str);
    /// Atomically add `delta` to the signed integer stored under `key`
    /// (or 0 if absent) and return the new value. Implementations must
    /// ensure no reader sees a partial update under concurrent access.
    fn increment_i64(&self, key: &str, delta: i64) -> i64;
    /// Best-effort prefix listing. The default in-memory backend
    /// returns an empty vec - embedders that need iteration should
    /// plug in a backend whose storage supports it.
    fn list_keys(&self, _prefix: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Convenience shared handle. The store is reference-counted and
/// `Arc<dyn StateStore>` is what gets stashed in `WasmCombustor` /
/// thread-local activator.
pub type SharedStateStore = Arc<dyn StateStore>;

/// Default in-process backend backed by a lock-free `HopscotchMap`.
/// Suitable for single-process deployments; not durable across restarts.
///
/// Integer counters get their own `HopscotchMap<String, Arc<AtomicI64>>`
/// so `increment_i64` can CAS atomically without RMW-racing through the
/// byte-keyed bucket. Readers of the byte store see the counter value
/// as decimal ASCII on `get(key)` after an increment - this mirrors the
/// JS polyfill's `setJSON`/`getJSON` contract.
#[derive(Default)]
pub struct InMemoryStateStore {
    bytes: HopscotchMap<String, Vec<u8>>,
    counters: HopscotchMap<String, Arc<AtomicI64>>,
    /// Set once, the first time a counter is created. Gates all
    /// `counters` map access in `get`/`set`/`delete` so pure-KV
    /// workloads (no `increment_i64` ever called) never touch it.
    counters_live: AtomicBool,
}

impl InMemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn shared() -> SharedStateStore {
        Arc::new(Self::new())
    }
}

impl StateStore for InMemoryStateStore {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        // Prefer the counter value so `increment` is observable. Gated
        // on counters_live: skip the counters map entirely until a
        // counter has ever existed.
        if self.counters_live.load(Ordering::Relaxed)
            && let Some(counter) = self.counters.get(key)
        {
            return Some(counter.load(Ordering::Acquire).to_string().into_bytes());
        }
        self.bytes.get(key)
    }
    fn set(&self, key: &str, value: Vec<u8>) {
        // Writing a fresh value clears any counter at the same key so
        // `set` then `get` returns what was written. Gated: nothing to
        // clear if no counter has ever existed.
        if self.counters_live.load(Ordering::Relaxed) {
            self.counters.remove(key);
        }
        self.bytes.insert(key.to_string(), value);
    }
    fn delete(&self, key: &str) {
        self.bytes.remove(key);
        if self.counters_live.load(Ordering::Relaxed) {
            self.counters.remove(key);
        }
    }
    fn increment_i64(&self, key: &str, delta: i64) -> i64 {
        // Fast path: counter already exists.
        if let Some(counter) = self.counters.get(key) {
            return counter.fetch_add(delta, Ordering::AcqRel) + delta;
        }
        // Slow path: seed from any existing bytes value (parsed as
        // decimal) then install the counter. Concurrent initializers
        // race on `insert_if_absent` - the winner's counter survives.
        let seed = self
            .bytes
            .get(key)
            .and_then(|v| {
                std::str::from_utf8(&v)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
            })
            .unwrap_or(0);
        let fresh = Arc::new(AtomicI64::new(seed));
        // A counter is about to exist; unblock the gated counter-map reads
        // in get/set/delete before publishing it.
        self.counters_live.store(true, Ordering::Relaxed);
        let counter = match self
            .counters
            .insert_if_absent(key.to_string(), fresh.clone())
        {
            None => fresh,
            Some(existing) => existing,
        };
        counter.fetch_add(delta, Ordering::AcqRel) + delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_get_set_delete() {
        let s = InMemoryStateStore::new();
        assert!(s.get("k").is_none());
        s.set("k", b"v1".to_vec());
        assert_eq!(s.get("k"), Some(b"v1".to_vec()));
        s.set("k", b"v2".to_vec());
        assert_eq!(s.get("k"), Some(b"v2".to_vec()));
        s.delete("k");
        assert!(s.get("k").is_none());
    }

    #[test]
    fn increment_is_atomic_under_concurrency() {
        use std::thread;
        let store = InMemoryStateStore::shared();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = store.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    s.increment_i64("hits", 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let final_val: i64 = std::str::from_utf8(&store.get("hits").unwrap())
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(final_val, 16_000);
    }

    #[test]
    fn increment_seeds_from_set_value() {
        let s = InMemoryStateStore::new();
        s.set("k", b"5".to_vec());
        assert_eq!(s.increment_i64("k", 3), 8);
        assert_eq!(s.get("k"), Some(b"8".to_vec()));
    }

    #[test]
    fn set_after_increment_clears_counter() {
        let s = InMemoryStateStore::new();
        s.increment_i64("k", 10);
        s.set("k", b"fresh".to_vec());
        assert_eq!(s.get("k"), Some(b"fresh".to_vec()));
    }
}
