// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

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
use wasmtime::{Engine, InstancePre, Store, Trap};
use wasmtime_wasi::I32Exit;

use crate::host::HostState;

/// Epoch ticker period. Minimum timeout granularity = one tick.
pub(crate) const TICK_PERIOD_MS: u64 = 10;

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
    store.limiter(|s| &mut s.limits);

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
