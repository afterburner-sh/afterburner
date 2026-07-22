// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Pluggable, coarse-grained memory-accounting hook. An embedder that
//! wants every tier's resident bytes routed through its own accounting
//! (a database's global memory pool, for instance) implements
//! [`MemoryLedger`] and wires it in via `WasmConfig::memory_ledger`,
//! `ThrustEngineConfig::memory_ledger`, and
//! `NativeCombustor::with_ledger`. `None` (the default in every one of
//! those) is a pure no-op: the charge points are a single branch on
//! each cold path (module-cache insert/evict, native-runtime creation,
//! queued-job enqueue/dequeue - never per-row, never per-allocation),
//! preserving the zero-cost-when-unused property.
//!
//! Per-call guest memory (`FuelGauge::memory_bytes`) needs no hook:
//! every tier already enforces that natively (wasmtime's
//! `ResourceLimiter` / QuickJS's `set_memory_limit`) and an embedder
//! reserves the worst case up front from its own per-invocation caps.

/// The coarse byte classes a [`MemoryLedger`] accounts. Charge points
/// are registration/cache/queue granularity, matching what an embedder
/// can actually reserve ahead of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerClass {
    /// `bytecode_cache` / `sealed_cache` / `dyn_cache` insert+evict
    /// (wasm tier), and the per-thread compiled-entry cache insert+evict
    /// (native tier).
    ModuleCache,
    /// Per-thread `rquickjs` `Runtime` creation (native tier), charged
    /// once per thread-local runtime, not per call.
    NativeRuntime,
    /// Queued `Job` payload bytes: charged at enqueue, released at
    /// execute-or-drop (thrust tier).
    QueuedJob,
}

/// A reservation denied by the ledger. Carries the human-readable reason
/// the embedder's accounting refused the bytes (e.g. "exceeds the
/// configured module-cache budget"); the caller wraps this into
/// `AfterburnerError::LedgerDenied` so the denial surfaces loud and
/// typed, never silently.
#[derive(Debug, Clone)]
pub struct LedgerDenied(pub String);

impl std::fmt::Display for LedgerDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LedgerDenied {}

/// Pluggable memory-accounting hook. An embedder implements this once
/// and shares one `Arc<dyn MemoryLedger>` across every tier it builds,
/// so every byte class any tier can allocate is reserved through the
/// SAME external accounting the embedder already trusts - never a
/// second, divergent tracker.
pub trait MemoryLedger: Send + Sync {
    /// Called BEFORE the bytes exist (before the cache insert, before
    /// the runtime is created, before the job is queued). `Err` fails
    /// the triggering operation loudly with
    /// `AfterburnerError::LedgerDenied(reason)` - the caller never
    /// proceeds as if the reservation had succeeded.
    fn reserve(&self, class: LedgerClass, bytes: usize) -> Result<(), LedgerDenied>;

    /// Called when the bytes are freed (cache evict, runtime drop, job
    /// dequeue/drop). Every successful `reserve` is matched by exactly
    /// one `release` for the same `(class, bytes)`.
    fn release(&self, class: LedgerClass, bytes: usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicIsize, Ordering};

    /// Minimal in-memory ledger for tests: tracks a running total per
    /// class and denies once a configured cap is exceeded.
    struct CappedLedger {
        cap: usize,
        outstanding: AtomicIsize,
    }

    impl MemoryLedger for CappedLedger {
        fn reserve(&self, _class: LedgerClass, bytes: usize) -> Result<(), LedgerDenied> {
            let after =
                self.outstanding.fetch_add(bytes as isize, Ordering::AcqRel) + bytes as isize;
            if after as usize > self.cap {
                self.outstanding.fetch_sub(bytes as isize, Ordering::AcqRel);
                return Err(LedgerDenied(format!(
                    "reserve({bytes}) would exceed cap {}",
                    self.cap
                )));
            }
            Ok(())
        }

        fn release(&self, _class: LedgerClass, bytes: usize) {
            self.outstanding.fetch_sub(bytes as isize, Ordering::AcqRel);
        }
    }

    #[test]
    fn reserve_then_release_round_trips_to_zero() {
        let ledger = CappedLedger {
            cap: 1024,
            outstanding: AtomicIsize::new(0),
        };
        ledger.reserve(LedgerClass::ModuleCache, 512).unwrap();
        assert_eq!(ledger.outstanding.load(Ordering::Acquire), 512);
        ledger.release(LedgerClass::ModuleCache, 512);
        assert_eq!(ledger.outstanding.load(Ordering::Acquire), 0);
    }

    #[test]
    fn reserve_denies_loud_over_cap() {
        let ledger = CappedLedger {
            cap: 100,
            outstanding: AtomicIsize::new(0),
        };
        ledger.reserve(LedgerClass::NativeRuntime, 60).unwrap();
        let err = ledger.reserve(LedgerClass::NativeRuntime, 60).unwrap_err();
        assert!(err.0.contains("exceed cap"));
        // The denied reservation must not have been partially applied.
        assert_eq!(ledger.outstanding.load(Ordering::Acquire), 60);
    }

    #[test]
    fn ledger_denied_displays_its_reason() {
        let e = LedgerDenied("out of budget".to_string());
        assert_eq!(e.to_string(), "out of budget");
    }

    #[test]
    fn arc_dyn_memory_ledger_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<dyn MemoryLedger>>();
    }

    #[test]
    fn ledger_class_is_hashable_for_embedder_counters() {
        use std::collections::HashMap;
        let mut counters: HashMap<LedgerClass, usize> = HashMap::new();
        counters.insert(LedgerClass::ModuleCache, 1);
        counters.insert(LedgerClass::NativeRuntime, 2);
        counters.insert(LedgerClass::QueuedJob, 3);
        assert_eq!(counters[&LedgerClass::ModuleCache], 1);
        assert_eq!(counters[&LedgerClass::NativeRuntime], 2);
        assert_eq!(counters[&LedgerClass::QueuedJob], 3);
    }
}
