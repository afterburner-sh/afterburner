// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Per-call execution chamber - the machinery every one-shot plugin
//! invocation shares: `Store` setup (limiter, fuel, epoch deadline),
//! instantiation through the pre-resolved [`InstancePre`], `_start`
//! dispatch, and the UDF-path trap → typed-error mapping.
//!
//! Three entry shapes, by how much of the pipeline the caller wants:
//!
//! * [`fire`] - full pipeline for the UDF-shaped paths (`thrust`,
//!   `thrust_raw`, columnar): returns the post-run `Store` on success
//!   so the caller extracts its result channel (stdout for the JSON
//!   paths, `pending_columnar_reply` for columnar). Traps map to
//!   typed errors uniformly; `scope` prefixes the diagnostic events
//!   (`wasm.thrust`, `wasm.thrust_columnar`).
//! * [`prepare_store`] + [`instantiate_and_start`] - the setup and
//!   dispatch halves, for paths with their own trap contract
//!   (script mode maps `proc_exit(N)` to an exit code instead of an
//!   error; compile mode maps every trap to `CompileFailed`).
//! * [`drain_stdout`] / [`format_trap_with_stderr`] - post-run
//!   extraction + diagnosis helpers shared by all of the above.

use afterburner_core::log::Level;
use afterburner_core::{AfterburnerError, FuelGauge, Result, ab_event};
use afterburner_wasi_host::I32Exit;
use std::thread;
use std::time::{Duration, Instant};
use wasmtime::{Engine, InstancePre, Store, Trap};

use crate::host::HostState;

/// Epoch ticker period. Minimum timeout granularity = one tick.
pub(crate) const TICK_PERIOD_MS: u64 = 10;

/// Paces an epoch ticker by elapsed monotonic time rather than by
/// wake-ups. A `Store`'s epoch deadline is a tick count, so a ticker
/// that adds one per wake counts wake-ups: under load or timer
/// coalescing each `TICK_PERIOD_MS` sleep can end late, and a
/// declared `timeout_ms` stretches by the tick count times that
/// lateness. The pacer owes one increment per whole period elapsed
/// since `start`, so a late wake catches up and the deadline fires at
/// most one late wake after the timeout.
pub(crate) struct EpochPacer {
    start: Instant,
    issued: u64,
}

impl EpochPacer {
    pub(crate) fn new(start: Instant) -> Self {
        Self { start, issued: 0 }
    }

    /// Increments owed at `now`: whole periods elapsed since `start`
    /// that have not been issued yet. Never negative, so a clock read
    /// that does not advance owes nothing.
    pub(crate) fn due(&mut self, now: Instant) -> u64 {
        let elapsed =
            now.saturating_duration_since(self.start).as_millis() / u128::from(TICK_PERIOD_MS);
        let target = u64::try_from(elapsed).unwrap_or(u64::MAX);
        let owed = target.saturating_sub(self.issued);
        self.issued = self.issued.max(target);
        owed
    }
}

/// Drives `engine`'s epoch for as long as `running` answers `true`:
/// sleep one period, then catch up to elapsed time ([`EpochPacer`]).
pub(crate) fn run_epoch_ticker(engine: &Engine, running: impl Fn() -> bool) {
    let mut pacer = EpochPacer::new(Instant::now());
    while running() {
        thread::sleep(Duration::from_millis(TICK_PERIOD_MS));
        for _ in 0..pacer.due(Instant::now()) {
            engine.increment_epoch();
        }
    }
}

/// Stderr capture limit for trap-diagnosis messages.
const STDERR_DIAGNOSIS_CAP: usize = 4 * 1024;

/// Build the per-call `Store`: wire the memory limiter, charge the
/// fuel budget (`u64::MAX` when unlimited), and arm the epoch
/// deadline from `timeout_ms` (effectively-infinite when absent).
pub(crate) fn prepare_store(
    engine: &Engine,
    state: HostState,
    limits: &FuelGauge,
) -> Result<Store<HostState>> {
    let mut store = Store::new(engine, state);
    // Mirror the caller's tripped-flag sink (if any) before the limiter
    // is wired in - this is the one canonical Store-construction choke
    // point every thrust/columnar/compile path funnels through, so a
    // single line here covers every one of them.
    store.data_mut().limiter_tripped = limits.limiter_tripped.clone();
    store.limiter(|s| s.limiter());

    let fuel = limits.fuel.unwrap_or(u64::MAX);
    store
        .set_fuel(fuel)
        .map_err(|e| AfterburnerError::Engine(format!("set_fuel: {e}")))?;

    if let Some(ms) = limits.timeout_ms {
        let ticks = ms.div_ceil(TICK_PERIOD_MS).max(1);
        store.set_epoch_deadline(ticks);
    } else {
        store.set_epoch_deadline(u64::MAX / 2);
    }
    Ok(store)
}

/// Instantiate the plugin from the pre-resolved imports and call
/// `_start`. Pre-resolution makes this just a slot checkout from the
/// pooling allocator + a memory-image clone via CoW - no linker
/// re-walk, no import re-typecheck. The outer `Result` carries
/// infrastructure failures (instantiation, export lookup); the inner
/// one is `_start`'s own outcome, returned raw so each caller maps
/// traps per its contract.
pub(crate) fn instantiate_and_start(
    store: &mut Store<HostState>,
    instance_pre: &InstancePre<HostState>,
) -> Result<std::result::Result<(), wasmtime::Error>> {
    let instance = instance_pre
        .instantiate(&mut *store)
        .map_err(|e| AfterburnerError::Engine(format!("plugin instantiate: {e}")))?;
    let start = instance
        .get_typed_func::<(), ()>(&mut *store, "_start")
        .map_err(|e| AfterburnerError::Engine(format!("_start lookup: {e}")))?;
    Ok(start.call(store, ()))
}

/// Full UDF-path pipeline: [`prepare_store`] →
/// [`instantiate_and_start`] → uniform trap mapping. On success
/// (including a clean `proc_exit(0)`) the post-run `Store` comes back
/// for result extraction. `scope` names the calling path in the
/// diagnostic events (e.g. `wasm.thrust` → `wasm.thrust.timeout`).
pub(crate) fn fire(
    engine: &Engine,
    instance_pre: &InstancePre<HostState>,
    state: HostState,
    limits: &FuelGauge,
    scope: &str,
) -> Result<Store<HostState>> {
    let mut store = prepare_store(engine, state, limits)?;
    let call_result = instantiate_and_start(&mut store, instance_pre)?;
    // Output-ceiling overflow wins over whatever the trap looks like:
    // the guest-visible failure is an opaque errno-29 write error (or
    // a clean exit if the script swallowed it), but the root cause is
    // the result exceeding `FuelGauge::output_bytes` - surface the
    // structured error uniformly, never the bare trap.
    if store.data().output_overflowed() {
        let limit = store.data().output_ceiling;
        ab_event!(Level::Warn, format!("{scope}.output_too_large"), "limit" => limit);
        return Err(AfterburnerError::OutputTooLarge { limit });
    }
    if let Err(trap) = call_result {
        if let Some(exit) = trap.downcast_ref::<I32Exit>() {
            if exit.0 == 0 {
                // proc_exit(0): clean exit through WASI - fall through
                // to result extraction.
                return Ok(store);
            }
            ab_event!(Level::Warn, format!("{scope}.nonzero_exit"), "code" => exit.0);
            let msg = format_trap_with_stderr(
                &format!("script exited with non-zero code {}", exit.0),
                &mut store,
            );
            return Err(AfterburnerError::WasmTrap(msg));
        }
        if let Some(t) = trap.downcast_ref::<Trap>() {
            return Err(match t {
                Trap::Interrupt => {
                    ab_event!(Level::Warn, format!("{scope}.timeout"));
                    AfterburnerError::Timeout
                }
                Trap::OutOfFuel => {
                    ab_event!(Level::Warn, format!("{scope}.fuel_exhausted"));
                    AfterburnerError::FuelExhausted
                }
                other => {
                    let msg = format_trap_with_stderr(&format!("{other}"), &mut store);
                    ab_event!(Level::Warn, format!("{scope}.trap"), "kind" => other);
                    AfterburnerError::WasmTrap(msg)
                }
            });
        }
        let chain: Vec<String> = trap.chain().map(|e| format!("{e}")).collect();
        let full = chain.join(" => ");
        if full.contains("memory minimum size") || full.contains("memory size") {
            ab_event!(Level::Warn, format!("{scope}.memory_limit"));
            return Err(AfterburnerError::MemoryLimit);
        }
        let msg = format_trap_with_stderr(&full, &mut store);
        return Err(AfterburnerError::WasmTrap(msg));
    }
    Ok(store)
}

/// Snapshot the bounded stdout capture.
pub(crate) fn drain_stdout(store: &mut Store<HostState>) -> Vec<u8> {
    store.data().stdout.contents().to_vec()
}

/// Append the (capped) stderr capture to a trap message so script
/// errors surface with their JS-side diagnostics attached.
pub(crate) fn format_trap_with_stderr(base: &str, store: &mut Store<HostState>) -> String {
    let stderr = store.data().stderr.contents();
    if stderr.is_empty() {
        return base.to_string();
    }
    let visible = &stderr[..stderr.len().min(STDERR_DIAGNOSIS_CAP)];
    let text = String::from_utf8_lossy(visible);
    let truncated = if stderr.len() > STDERR_DIAGNOSIS_CAP {
        " (truncated)"
    } else {
        ""
    };
    format!("{base}\nstderr{truncated}: {text}")
}

#[cfg(test)]
mod tests {
    use super::{EpochPacer, TICK_PERIOD_MS};
    use std::time::{Duration, Instant};

    fn at(start: Instant, ms: u64) -> Instant {
        start + Duration::from_millis(ms)
    }

    #[test]
    fn punctual_wakes_owe_one_tick_each() {
        let start = Instant::now();
        let mut pacer = EpochPacer::new(start);
        for n in 1..=50 {
            assert_eq!(pacer.due(at(start, n * TICK_PERIOD_MS)), 1);
        }
    }

    #[test]
    fn a_late_wake_catches_up_to_elapsed_time() {
        let start = Instant::now();
        let mut pacer = EpochPacer::new(start);
        assert_eq!(pacer.due(at(start, 4 * TICK_PERIOD_MS)), 4);
        assert_eq!(pacer.due(at(start, 5 * TICK_PERIOD_MS)), 1);
    }

    #[test]
    fn uniformly_late_wakes_keep_the_epoch_on_elapsed_time() {
        // Every 10 ms sleep ends at 38 ms: a wake-counted ticker would
        // reach 500 ticks (a 5 s timeout) only after 19 s.
        let start = Instant::now();
        let mut pacer = EpochPacer::new(start);
        let mut epoch = 0;
        let mut now_ms = 0;
        while epoch < 500 {
            now_ms += 38;
            epoch += pacer.due(at(start, now_ms));
        }
        assert!(now_ms < 5_000 + 38, "500 ticks took {now_ms} ms");
        assert_eq!(epoch, now_ms / TICK_PERIOD_MS);
    }

    #[test]
    fn an_early_or_repeated_wake_owes_nothing() {
        let start = Instant::now();
        let mut pacer = EpochPacer::new(start);
        assert_eq!(pacer.due(at(start, TICK_PERIOD_MS - 1)), 0);
        assert_eq!(pacer.due(at(start, TICK_PERIOD_MS)), 1);
        assert_eq!(pacer.due(at(start, TICK_PERIOD_MS)), 0);
        assert_eq!(pacer.due(at(start, 2 * TICK_PERIOD_MS - 1)), 0);
    }

    #[test]
    fn a_clock_read_before_start_owes_nothing() {
        let start = Instant::now() + Duration::from_secs(1);
        let mut pacer = EpochPacer::new(start);
        assert_eq!(pacer.due(Instant::now()), 0);
    }

    #[test]
    fn issued_ticks_never_exceed_elapsed_periods() {
        let start = Instant::now();
        let mut pacer = EpochPacer::new(start);
        let mut issued = 0;
        for ms in [3, 17, 17, 95, 96, 400, 401, 1_234] {
            issued += pacer.due(at(start, ms));
            assert_eq!(issued, ms / TICK_PERIOD_MS);
        }
    }
}
