// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `AdaptiveCombustor` - native-first, with a single background worker that
//! compiles the same source through the WASM backend and switches future
//! `thrust` calls onto it once ready.
//!
//! ### Determinism guarantees
//!
//! Every `extinguish` cancels any in-flight WASM compile for that script
//! deterministically, with no observable race against subsequent `ignite`
//! calls. Concretely:
//!
//! * The compile worker is **single-threaded**, so messages for the same
//!   hash are always processed in arrival order.
//! * Each script gets a `Slot { state: AtomicU8 }` that the worker
//!   transitions via `compare_exchange` from `COMPILING` to `READY` /
//!   `FAILED`. `extinguish` swaps the same atomic to `CANCELLED`.
//! * The worker treats a failed CAS as cancellation: it cleans up any WASM
//!   cache entry it just produced and discards the result.
//! * Because the slot is an `Arc<Slot>`, the worker holds its own handle
//!   and isn't affected by `state.remove`. A re-ignite after `extinguish`
//!   creates a *new* slot, gets a *new* compile message, and is processed
//!   strictly after any pending cancellation cleanup completes.
//!
//! Sticky failure: a `FAILED` slot stays installed in the state map. The
//! next thrust on that hash routes to native; the next ignite reuses the
//! `FAILED` slot (idempotent, no compile re-attempt).

use afterburner_core::log::Level;
use afterburner_core::{
    AfterburnerError, Combustor, EngineMode, FuelGauge, OutputValue, Result, ScriptId,
    ScriptInvocation, ScriptOutcome, ab_event,
};
use afterburner_ignite::NativeCombustor;
use afterburner_wasi::{WasmCombustor, WasmConfig};
use kovan_channel::flavors::unbounded::{Receiver, Sender};
use kovan_channel::unbounded;
use kovan_map::HopscotchMap;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const COMPILING: u8 = 0;
const READY: u8 = 1;
const FAILED: u8 = 2;
const CANCELLED: u8 = 3;

/// Outcome of waiting on a background WASM compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileOutcome {
    /// WASM compile succeeded; future `thrust` calls route to the WASM tier.
    Ready,
    /// WASM compile failed; future `thrust` calls stay on the native tier.
    Failed,
    /// The script was extinguished or replaced before the compile finished.
    Cancelled,
    /// The wait deadline elapsed; the compile is still in progress.
    Pending,
}

struct Slot {
    state: AtomicU8,
}

enum WorkerMsg {
    Compile {
        hash: [u8; 32],
        source: String,
        slot: Arc<Slot>,
    },
    Shutdown,
}

pub struct AdaptiveCombustor {
    native: Arc<NativeCombustor>,
    wasm: Arc<WasmCombustor>,
    state: Arc<HopscotchMap<[u8; 32], Arc<Slot>>>,
    tx: Sender<WorkerMsg>,
    worker: Option<JoinHandle<()>>,
}

impl AdaptiveCombustor {
    pub fn new() -> Result<Self> {
        Self::with_wasm_config(WasmConfig::default())
    }

    /// Build an adaptive combustor with a custom Wasm-backend config -
    /// useful for tests that want to point at a specific Javy CLI.
    pub fn with_wasm_config(cfg: WasmConfig) -> Result<Self> {
        let native = Arc::new(NativeCombustor::new()?);
        let wasm = Arc::new(WasmCombustor::new(cfg)?);
        let state: Arc<HopscotchMap<[u8; 32], Arc<Slot>>> = Arc::new(HopscotchMap::new());
        let (tx, rx) = unbounded::<WorkerMsg>();
        let worker = {
            let wasm = wasm.clone();
            thread::spawn(move || worker_loop(rx, wasm))
        };
        Ok(Self {
            native,
            wasm,
            state,
            tx,
            worker: Some(worker),
        })
    }

    /// Wait until the WASM compile for `id` settles or `max_wait_ms` elapses.
    pub fn wait_for_compile(&self, id: &ScriptId, max_wait_ms: u64) -> CompileOutcome {
        let step = Duration::from_millis(10);
        let deadline = Instant::now() + Duration::from_millis(max_wait_ms);
        loop {
            match self
                .state
                .get(&id.hash)
                .map(|s| s.state.load(Ordering::Acquire))
            {
                Some(READY) => return CompileOutcome::Ready,
                Some(FAILED) => return CompileOutcome::Failed,
                Some(CANCELLED) | None => return CompileOutcome::Cancelled,
                _ => {}
            }
            if Instant::now() >= deadline {
                return CompileOutcome::Pending;
            }
            thread::sleep(step);
        }
    }

    /// Gate for wasm-only execution paths (columnar, raw input): the
    /// native (rquickjs) tier has no TypedArray-over-linmem mechanism,
    /// so these calls must route to the wasm tier. If the background
    /// wasm compile is still in flight, block-wait for it; the worker
    /// normally finishes within a few ms. FAILED / CANCELLED slots
    /// surface as a clean error rather than silently routing to
    /// native. Returns the wasm-mode `ScriptId` to dispatch with;
    /// `what` names the calling path in diagnostics.
    fn require_wasm_tier(&self, id: &ScriptId, what: &str) -> Result<ScriptId> {
        let slot_state = self
            .state
            .get(&id.hash)
            .map(|s| s.state.load(Ordering::Acquire));
        match slot_state {
            Some(READY) => {}
            Some(COMPILING) | None => {
                // Block up to 5 s for the worker to finish. 5 s is
                // ~10× the worst-case observed compile (~2-4 ms each
                // for the regular + columnar wrappers); anything
                // beyond that points at a deeper failure (worker
                // wedged, missing plugin .wasm, etc.).
                match self.wait_for_compile(id, 5_000) {
                    CompileOutcome::Ready => {}
                    CompileOutcome::Pending => {
                        return Err(AfterburnerError::Engine(format!(
                            "{what}: wasm compile still in flight after 5s - \
                             check that the plugin worker is healthy and that the \
                             script ignited cleanly"
                        )));
                    }
                    CompileOutcome::Failed => {
                        return Err(AfterburnerError::Engine(format!(
                            "{what}: wasm compile failed for this script - \
                             see prior `wasm.ignite.compile_failed` event for details"
                        )));
                    }
                    CompileOutcome::Cancelled => {
                        return Err(AfterburnerError::ScriptNotFound);
                    }
                }
            }
            Some(FAILED) => {
                return Err(AfterburnerError::Engine(format!(
                    "{what}: wasm compile failed for this script (sticky)"
                )));
            }
            Some(CANCELLED) => return Err(AfterburnerError::ScriptNotFound),
            Some(_) => {}
        }
        Ok(ScriptId {
            hash: id.hash,
            mode: EngineMode::Wasm,
        })
    }

    /// Test/diagnostic accessor - which tier would service the next thrust?
    #[cfg(test)]
    pub fn current_tier(&self, id: &ScriptId) -> &'static str {
        match self
            .state
            .get(&id.hash)
            .map(|s| s.state.load(Ordering::Acquire))
        {
            Some(READY) => "wasm",
            Some(FAILED) => "native-sticky",
            Some(CANCELLED) => "native-cancelled",
            Some(COMPILING) => "native-during-compile",
            _ => "native-uncompiled",
        }
    }

    fn enqueue_compile(&self, hash: [u8; 32], source: &str) {
        let new_slot = Arc::new(Slot {
            state: AtomicU8::new(COMPILING),
        });
        // Common path: no slot present → install ours and enqueue.
        if self
            .state
            .insert_if_absent(hash, new_slot.clone())
            .is_none()
        {
            self.tx.send(WorkerMsg::Compile {
                hash,
                source: source.to_string(),
                slot: new_slot,
            });
            return;
        }
        // A slot already exists. If it's in a terminal-non-success state
        // (CANCELLED or FAILED) we replace it so the next thrust gets
        // another chance at WASM. If it's COMPILING or READY there's
        // nothing to do.
        if let Some(existing) = self.state.get(&hash) {
            let s = existing.state.load(Ordering::Acquire);
            if s == CANCELLED {
                // Replace cancelled slot. Concurrent re-ignites may both
                // reach this branch - the worker tolerates duplicate
                // compile messages because each carries its own slot.
                self.state.insert(hash, new_slot.clone());
                self.tx.send(WorkerMsg::Compile {
                    hash,
                    source: source.to_string(),
                    slot: new_slot,
                });
            }
            // FAILED is sticky on purpose; READY/COMPILING already in flight.
        }
    }
}

fn worker_loop(rx: Receiver<WorkerMsg>, wasm: Arc<WasmCombustor>) {
    while let Some(msg) = rx.recv() {
        match msg {
            WorkerMsg::Compile { hash, source, slot } => {
                if slot.state.load(Ordering::Acquire) != COMPILING {
                    ab_event!(Level::Debug, "adaptive.worker.skip_cancelled");
                    continue;
                }
                let result = wasm.ignite(&source);
                let target = if result.is_ok() { READY } else { FAILED };
                let cas = slot.state.compare_exchange(
                    COMPILING,
                    target,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                match cas {
                    Ok(_) if target == READY => {
                        ab_event!(Level::Info, "adaptive.tier_switched", "tier" => "wasm");
                    }
                    Ok(_) => {
                        ab_event!(Level::Warn, "adaptive.compile_failed");
                    }
                    Err(_) => {
                        // Cancelled mid-compile. Single-worker design
                        // guarantees no newer compile for this hash has
                        // populated the cache yet, so this remove is safe.
                        if result.is_ok() {
                            wasm.extinguish(&ScriptId {
                                hash,
                                mode: EngineMode::Wasm,
                            });
                        }
                        ab_event!(Level::Info, "adaptive.compile_cancelled");
                    }
                }
            }
            WorkerMsg::Shutdown => return,
        }
    }
}

impl Combustor for AdaptiveCombustor {
    #[fastrace::trace(name = "AdaptiveCombustor::ignite")]
    fn ignite(&self, source: &str) -> Result<ScriptId> {
        let native_id = self.native.ignite(source)?;
        self.enqueue_compile(native_id.hash, source);
        Ok(native_id)
    }

    #[fastrace::trace(name = "AdaptiveCombustor::thrust")]
    fn thrust(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<Value> {
        match self
            .state
            .get(&id.hash)
            .map(|s| s.state.load(Ordering::Acquire))
        {
            Some(READY) => {
                let wasm_id = ScriptId {
                    hash: id.hash,
                    mode: EngineMode::Wasm,
                };
                self.wasm.thrust(&wasm_id, input, limits)
            }
            _ => {
                let native_id = ScriptId {
                    hash: id.hash,
                    mode: EngineMode::Native,
                };
                self.native.thrust(&native_id, input, limits)
            }
        }
    }

    fn thrust_columnar_bytes(
        &self,
        id: &ScriptId,
        encoded: &[u8],
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        let wasm_id = self.require_wasm_tier(id, "columnar UDF")?;
        self.wasm.thrust_columnar_bytes(&wasm_id, encoded, limits)
    }

    fn thrust_raw(&self, id: &ScriptId, input: &[u8], limits: &FuelGauge) -> Result<Value> {
        let wasm_id = self.require_wasm_tier(id, "raw input")?;
        self.wasm.thrust_raw(&wasm_id, input, limits)
    }

    /// Output-framing-aware paths route to the wasm tier like the
    /// other wasm-only calls (columnar, raw input): only the wasm
    /// backend has the `host_raw_output` bridge, and letting the
    /// native tier serve a bytes-returning module would mangle the
    /// result into rquickjs's JSON view of a `Uint8Array`.
    fn thrust_out(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<OutputValue> {
        let wasm_id = self.require_wasm_tier(id, "raw output")?;
        self.wasm.thrust_out(&wasm_id, input, limits)
    }

    fn thrust_raw_out(
        &self,
        id: &ScriptId,
        input: &[u8],
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        let wasm_id = self.require_wasm_tier(id, "raw output")?;
        self.wasm.thrust_raw_out(&wasm_id, input, limits)
    }

    fn extinguish(&self, id: &ScriptId) {
        // Cancel atomically. Any worker mid-compile observes the CANCELLED
        // state via its CAS and rolls back the WASM cache entry it built.
        // If the slot was already READY, the WASM cache definitely holds
        // the module - we clean it here.
        if let Some(slot) = self.state.get(&id.hash) {
            let prev = slot.state.swap(CANCELLED, Ordering::AcqRel);
            if prev == READY {
                self.wasm.extinguish(&ScriptId {
                    hash: id.hash,
                    mode: EngineMode::Wasm,
                });
            }
        }
        self.state.remove(&id.hash);
        self.native.extinguish(&ScriptId {
            hash: id.hash,
            mode: EngineMode::Native,
        });
    }

    /// Script mode runs exclusively through the WASM backend - the
    /// whole point of adaptive is to *cache* compiled scripts across
    /// many calls, but script mode is one-shot. Native would also work
    /// but the sandboxed path matches the Q1-D expectation that
    /// `burn foo.js` behaves like a sandboxable Node replacement.
    fn run_script(
        &self,
        source: &str,
        invocation: &ScriptInvocation,
        limits: &FuelGauge,
    ) -> Result<ScriptOutcome> {
        self.wasm.run_script(source, invocation, limits)
    }
}

impl Drop for AdaptiveCombustor {
    fn drop(&mut self) {
        self.tx.send(WorkerMsg::Shutdown);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

/// Adaptive variant of `BurnCache` convenience constructor.
pub fn make_adaptive_cache() -> Result<afterburner_core::BurnCache> {
    let engine = AdaptiveCombustor::new()?;
    Ok(afterburner_core::BurnCache::new(Box::new(engine)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn first_call_uses_native() {
        let c = AdaptiveCombustor::new().unwrap();
        let id = c.ignite("module.exports = (d) => d.x * 2").unwrap();
        let out = c
            .thrust(&id, &json!({"x": 21}), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!(42));
    }

    #[test]
    fn second_call_uses_wasm_after_compile() {
        let c = AdaptiveCombustor::new().unwrap();
        let id = c.ignite("module.exports = (d) => d.x * 2").unwrap();
        assert_eq!(c.wait_for_compile(&id, 60_000), CompileOutcome::Ready);
        assert_eq!(c.current_tier(&id), "wasm");
        let out = c
            .thrust(&id, &json!({"x": 21}), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out, json!(42));
    }

    #[test]
    fn repeated_ignite_of_same_source_is_idempotent() {
        let c = AdaptiveCombustor::new().unwrap();
        let id1 = c.ignite("module.exports = () => 1").unwrap();
        let id2 = c.ignite("module.exports = () => 1").unwrap();
        assert_eq!(id1.hash, id2.hash);
    }

    #[test]
    fn extinguish_clears_adaptive_state() {
        let c = AdaptiveCombustor::new().unwrap();
        let id = c.ignite("module.exports = () => 1").unwrap();
        c.extinguish(&id);
        assert_eq!(c.current_tier(&id), "native-uncompiled");
    }

    #[test]
    fn extinguish_then_reignite_thrusts_correctly() {
        // Regression: previously the in-flight compile from the first
        // ignite could write Ready into the state map *after* extinguish
        // had cleared the wasm cache, leaving subsequent thrusts pointed
        // at an empty cache → ScriptNotFound.
        let c = AdaptiveCombustor::new().unwrap();
        let src = "module.exports = (d) => d.n + 100";
        let id = c.ignite(src).unwrap();
        // Extinguish during the (likely-still-running) wasm compile.
        c.extinguish(&id);
        // Re-ignite immediately. The previous in-flight compile must not
        // poison the new slot.
        let id2 = c.ignite(src).unwrap();
        assert_eq!(id.hash, id2.hash);
        // Drive both tiers: native works immediately; once wasm settles,
        // it must also work without ScriptNotFound.
        let native_out = c
            .thrust(&id2, &json!({"n": 1}), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(native_out, json!(101));

        let outcome = c.wait_for_compile(&id2, 60_000);
        assert_eq!(outcome, CompileOutcome::Ready, "compile should land Ready");
        let wasm_out = c
            .thrust(&id2, &json!({"n": 2}), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(wasm_out, json!(102));
    }

    #[test]
    fn wait_for_compile_reports_cancelled_after_extinguish() {
        let c = AdaptiveCombustor::new().unwrap();
        let id = c.ignite("module.exports = () => 1").unwrap();
        c.extinguish(&id);
        assert_eq!(
            c.wait_for_compile(&id, 100),
            CompileOutcome::Cancelled,
            "extinguished script should report Cancelled, not Pending"
        );
    }
}
