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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    clock: Arc<EpochClock>,
    issued: u64,
}

/// What a ticker publishes about its epoch so that a thread arming a
/// deadline can see how far behind the ticker is: its start instant
/// and the periods it has fully issued. The ticker is the only writer.
pub(crate) struct EpochClock {
    start: Instant,
    issued: AtomicU64,
}

impl EpochClock {
    pub(crate) fn new(start: Instant) -> Self {
        Self {
            start,
            issued: AtomicU64::new(0),
        }
    }

    /// Whole periods elapsed since `start` at `now` (zero if `now` is
    /// before `start`).
    fn periods_at(&self, now: Instant) -> u64 {
        let periods =
            now.saturating_duration_since(self.start).as_millis() / u128::from(TICK_PERIOD_MS);
        u64::try_from(periods).unwrap_or(u64::MAX)
    }

    /// Periods that passed before `now` and that the ticker has not
    /// issued yet: what its next wake will add to the epoch for time
    /// that elapsed before any store created now existed.
    fn backlog(&self, now: Instant) -> u64 {
        self.periods_at(now)
            .saturating_sub(self.issued.load(Ordering::Acquire))
    }
}

impl EpochPacer {
    pub(crate) fn new(clock: Arc<EpochClock>) -> Self {
        Self { clock, issued: 0 }
    }

    /// Increments owed at `now`: whole periods elapsed since `start`
    /// that have not been issued yet. Never negative, so a clock read
    /// that does not advance owes nothing.
    pub(crate) fn due(&mut self, now: Instant) -> u64 {
        let target = self.clock.periods_at(now);
        let owed = target.saturating_sub(self.issued);
        self.issued = self.issued.max(target);
        owed
    }

    /// Issue what is owed at `now` through `increment`, then publish the
    /// issued count. Publishing AFTER the increments is what keeps a
    /// reader's backlog from being too small: a reader that sees the new
    /// count also sees an epoch that already moved.
    pub(crate) fn tick(&mut self, now: Instant, mut increment: impl FnMut()) {
        for _ in 0..self.due(now) {
            increment();
        }
        self.clock.issued.store(self.issued, Ordering::Release);
    }
}

/// Drives `engine`'s epoch for as long as `running` answers `true`:
/// sleep one period, then catch up to elapsed time ([`EpochPacer`]).
/// `clock` is what stores armed on this engine read their backlog from.
pub(crate) fn run_epoch_ticker(
    engine: &Engine,
    clock: Arc<EpochClock>,
    running: impl Fn() -> bool,
) {
    run_epoch_ticker_with(engine, clock, running, || {
        thread::sleep(Duration::from_millis(TICK_PERIOD_MS));
    });
}

/// [`run_epoch_ticker`] with the sleep between wakes supplied by the
/// caller, so a test can make a wake late on purpose.
pub(crate) fn run_epoch_ticker_with(
    engine: &Engine,
    clock: Arc<EpochClock>,
    running: impl Fn() -> bool,
    mut nap: impl FnMut(),
) {
    let mut pacer = EpochPacer::new(clock);
    while running() {
        nap();
        pacer.tick(Instant::now(), || engine.increment_epoch());
    }
}

/// The ONLY place a timeout becomes an epoch tick count: the timeout in
/// whole periods (at least one) plus the ticker's backlog at `now`, so a
/// store created while its ticker is overdue counts only time that
/// passes after it exists. `clock` is `None` when the embedder drives the
/// epoch itself (no ticker of ours, no backlog).
///
/// Bound: the timeout fires no earlier than one period before its time
/// (the phase of the first tick) and no later than one late wake after
/// it. Race: the ticker may issue between the load of its issued count
/// here and the caller's `set_epoch_deadline`; the backlog is then too
/// large by what was just issued, so the deadline is late by at most
/// that, never early (the ticker publishes after it increments).
pub(crate) fn deadline_ticks(clock: Option<&EpochClock>, timeout: Duration, now: Instant) -> u64 {
    let ms = timeout.as_millis().max(1);
    let own = u64::try_from(ms.div_ceil(u128::from(TICK_PERIOD_MS)))
        .unwrap_or(u64::MAX)
        .max(1);
    own.saturating_add(clock.map_or(0, |c| c.backlog(now)))
}

/// Stderr capture limit for trap-diagnosis messages.
const STDERR_DIAGNOSIS_CAP: usize = 4 * 1024;

/// Build the per-call `Store`: wire the memory limiter, charge the
/// fuel budget (`u64::MAX` when unlimited), and arm the epoch
/// deadline from `timeout_ms` (effectively-infinite when absent).
pub(crate) fn prepare_store(
    engine: &Engine,
    clock: Option<&EpochClock>,
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
        let ticks = deadline_ticks(clock, Duration::from_millis(ms), Instant::now());
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
    clock: Option<&EpochClock>,
    instance_pre: &InstancePre<HostState>,
    state: HostState,
    limits: &FuelGauge,
    scope: &str,
) -> Result<Store<HostState>> {
    let mut store = prepare_store(engine, clock, state, limits)?;
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
    use super::{EpochClock, EpochPacer, TICK_PERIOD_MS, deadline_ticks, run_epoch_ticker_with};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    /// `(module (func (export "spin") (loop (br 0))))`: runs until trapped.
    const SPIN_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
        0x03, 0x02, 0x01, 0x00, // one function of that type
        0x07, 0x08, 0x01, 0x04, b's', b'p', b'i', b'n', 0x00, 0x00, // export "spin"
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b, // loop, br 0
    ];

    fn ticking_clock(start: Instant) -> (Arc<EpochClock>, EpochPacer) {
        let clock = Arc::new(EpochClock::new(start));
        let pacer = EpochPacer::new(Arc::clone(&clock));
        (clock, pacer)
    }

    fn pacer_at(start: Instant) -> EpochPacer {
        ticking_clock(start).1
    }

    #[test]
    fn a_punctual_ticker_has_no_backlog() {
        let start = Instant::now();
        let (clock, mut pacer) = ticking_clock(start);
        for n in 1..=50 {
            let now = at(start, n * TICK_PERIOD_MS);
            pacer.tick(now, || {});
            assert_eq!(
                deadline_ticks(Some(&clock), Duration::from_millis(500), now),
                50
            );
        }
    }

    #[test]
    fn an_overdue_ticker_adds_its_backlog_until_it_catches_up() {
        let start = Instant::now();
        let (clock, mut pacer) = ticking_clock(start);
        let now = at(start, 4 * TICK_PERIOD_MS);
        assert_eq!(
            deadline_ticks(Some(&clock), Duration::from_millis(500), now),
            54
        );
        pacer.tick(now, || {});
        assert_eq!(
            deadline_ticks(Some(&clock), Duration::from_millis(500), now),
            50
        );
    }

    #[test]
    fn a_reader_between_two_issues_is_never_early() {
        // The epoch the ticker has reached plus the deadline a reader arms
        // is the absolute epoch the store traps at: it must never fall
        // below the periods elapsed at `now` plus the timeout's own ticks.
        let start = Instant::now();
        let (clock, _) = ticking_clock(start);
        let now = at(start, 6 * TICK_PERIOD_MS);
        for issued in 0..=6u64 {
            clock.issued.store(issued, Ordering::Release);
            let ticks = deadline_ticks(Some(&clock), Duration::from_millis(100), now);
            assert!(issued + ticks >= 6 + 10, "issued {issued}: {ticks} ticks");
        }
    }

    #[test]
    fn without_a_ticker_of_ours_the_deadline_is_the_timeout_alone() {
        let now = Instant::now();
        assert_eq!(deadline_ticks(None, Duration::from_millis(25), now), 3);
        assert_eq!(deadline_ticks(None, Duration::from_millis(10), now), 1);
        assert_eq!(deadline_ticks(None, Duration::ZERO, now), 1);
    }

    /// A ticker whose first wake is 600 ms late, a store created at 450 ms
    /// (overdue by 45 periods) with a 300 ms timeout, and a guest that never
    /// returns. Without the backlog the 60 periods issued at the first wake
    /// stop the guest 150 ms after its creation: the lower-bound assertion
    /// below is the one that catches that gap. With it the guest is stopped
    /// when the epoch reaches 75, about 300 ms after creation.
    #[test]
    fn a_store_created_while_the_ticker_is_overdue_is_not_stopped_early() {
        const FIRST_WAKE_MS: u64 = 600;
        const CREATE_AT_MS: u64 = 450;
        const TIMEOUT_MS: u64 = 300;
        // A busy runner may delay the stop; five seconds is far past any
        // honest delay and still fails a guest that is never stopped.
        const GENEROUS_MS: u64 = 5_000;

        let mut cfg = wasmtime::Config::new();
        cfg.epoch_interruption(true);
        let engine = wasmtime::Engine::new(&cfg).expect("engine");
        let module = wasmtime::Module::new(&engine, SPIN_WASM).expect("module");

        let t0 = Instant::now();
        let clock = Arc::new(EpochClock::new(t0));
        let running = Arc::new(AtomicBool::new(true));
        let ticker = {
            let (engine, clock, running) =
                (engine.clone(), Arc::clone(&clock), Arc::clone(&running));
            thread::spawn(move || {
                let mut first = true;
                run_epoch_ticker_with(
                    &engine,
                    clock,
                    || running.load(Ordering::Acquire),
                    || {
                        let ms = if first { FIRST_WAKE_MS } else { TICK_PERIOD_MS };
                        first = false;
                        thread::sleep(Duration::from_millis(ms));
                    },
                );
            })
        };

        thread::sleep(Duration::from_millis(CREATE_AT_MS).saturating_sub(t0.elapsed()));
        let created = Instant::now();
        let mut store = wasmtime::Store::new(&engine, ());
        store.set_epoch_deadline(deadline_ticks(
            Some(&clock),
            Duration::from_millis(TIMEOUT_MS),
            created,
        ));
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).expect("instance");
        let spin = instance
            .get_typed_func::<(), ()>(&mut store, "spin")
            .expect("spin");
        let result = spin.call(&mut store, ());
        let elapsed = created.elapsed();
        running.store(false, Ordering::Release);
        ticker.join().expect("ticker thread");

        assert!(result.is_err(), "the guest was never stopped");
        assert!(
            elapsed >= Duration::from_millis(TIMEOUT_MS - TICK_PERIOD_MS),
            "stopped after {elapsed:?}, before timeout minus one period"
        );
        assert!(
            elapsed
                < Duration::from_millis(TIMEOUT_MS + (FIRST_WAKE_MS - CREATE_AT_MS) + GENEROUS_MS),
            "stopped after {elapsed:?}, long after the timeout"
        );
    }

    fn at(start: Instant, ms: u64) -> Instant {
        start + Duration::from_millis(ms)
    }

    #[test]
    fn punctual_wakes_owe_one_tick_each() {
        let start = Instant::now();
        let mut pacer = pacer_at(start);
        for n in 1..=50 {
            assert_eq!(pacer.due(at(start, n * TICK_PERIOD_MS)), 1);
        }
    }

    #[test]
    fn a_late_wake_catches_up_to_elapsed_time() {
        let start = Instant::now();
        let mut pacer = pacer_at(start);
        assert_eq!(pacer.due(at(start, 4 * TICK_PERIOD_MS)), 4);
        assert_eq!(pacer.due(at(start, 5 * TICK_PERIOD_MS)), 1);
    }

    #[test]
    fn uniformly_late_wakes_keep_the_epoch_on_elapsed_time() {
        // Every 10 ms sleep ends at 38 ms: a wake-counted ticker would
        // reach 500 ticks (a 5 s timeout) only after 19 s.
        let start = Instant::now();
        let mut pacer = pacer_at(start);
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
        let mut pacer = pacer_at(start);
        assert_eq!(pacer.due(at(start, TICK_PERIOD_MS - 1)), 0);
        assert_eq!(pacer.due(at(start, TICK_PERIOD_MS)), 1);
        assert_eq!(pacer.due(at(start, TICK_PERIOD_MS)), 0);
        assert_eq!(pacer.due(at(start, 2 * TICK_PERIOD_MS - 1)), 0);
    }

    #[test]
    fn a_clock_read_before_start_owes_nothing() {
        let start = Instant::now() + Duration::from_secs(1);
        let mut pacer = pacer_at(start);
        assert_eq!(pacer.due(Instant::now()), 0);
    }

    #[test]
    fn issued_ticks_never_exceed_elapsed_periods() {
        let start = Instant::now();
        let mut pacer = pacer_at(start);
        let mut issued = 0;
        for ms in [3, 17, 17, 95, 96, 400, 401, 1_234] {
            issued += pacer.due(at(start, ms));
            assert_eq!(issued, ms / TICK_PERIOD_MS);
        }
    }
}
