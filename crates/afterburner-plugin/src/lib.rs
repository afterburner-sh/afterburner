// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Afterburner custom Javy plugin.
//!
//! Targets `wasm32-wasip1`. Committed as a Wizer-preinitialized binary
//! (`quickjs-provider/afterburner_plugin.wasm`) so the host never needs
//! the `javy` CLI at runtime.
//!
//! ### Runtime protocol
//!
//! The host instantiates this plugin into a fresh `Store` per thrust
//! and calls the exported `_start` function. `_start`:
//!
//! 1. Reads a JSON envelope from stdin.
//! 2. Dispatches by envelope `mode` field via the `modes` module.
//!
//! ### Module layout
//!
//! - `host_api` — `afterburner:host` extern declarations.
//! - `stdio` — WASI preview1 `fd_read` / `fd_write` helpers.
//! - `envelope` — JS source wrappers (input-inlined + input-via-global).
//! - `globals` — `modify_runtime`-time JS global installers.
//! - `modes` — per-mode dispatchers (`compile`, `invoke`, `legacy`).
//!
//! ### Error reporting
//!
//! Variable-length host responses use a buffer protocol — the callee
//! writes bytes into a caller-provided region and returns either the
//! length or a negative error code. A detailed message is stashed in
//! the host's `last_error` slot and readable via the `host_last_error`
//! import.

#![no_std]
#![cfg(target_arch = "wasm32")]

extern crate alloc;

mod envelope;
mod globals;
mod host_api;
mod modes;
mod stdio;

use javy_plugin_api::javy::Runtime;
use javy_plugin_api::{Config, import_namespace};

import_namespace!("afterburner-plugin-v1");

/// Called by Wizer-preinit so every instantiation starts with the
/// global bridges + plenum polyfill bundle already in the runtime
/// snapshot.
fn modify_runtime(runtime: Runtime) -> Runtime {
    runtime.context().with(globals::install);
    runtime
}

fn config() -> Config {
    let mut c = Config::default();
    // `event_loop(true)` makes Javy automatically drain pending microtasks
    // after every `invoke` call — required for `fetch().then(...)`,
    // `await`, `setTimeout(fn, 0)`, and any Promise chain. Without it,
    // scheduling a microtask traps with "Pending jobs in the event
    // queue. Scheduling events is not supported when the event-loop
    // runtime config is not enabled."
    //
    // `event_loop` lives on the outer `javy_plugin_api::Config`;
    // `text_encoding` / `javy_stream_io` are on the inner `javy::Config`
    // reached through `DerefMut`. Two passes because the chain returns
    // the inner config, not the outer one.
    c.event_loop(true);
    c.text_encoding(true).javy_stream_io(true);
    c
}

#[unsafe(export_name = "initialize-runtime")]
pub extern "C" fn initialize_runtime() {
    if javy_plugin_api::initialize_runtime(config, modify_runtime).is_err() {
        core::arch::wasm32::unreachable()
    }
}

/// `_start` — one-shot path. Reads the JSON envelope from stdin and
/// delegates to the mode dispatcher in [`modes`]. Used by every
/// combustor that tears down the Store after a single call (UDF
/// `invoke`, `script`, `compile`, `legacy`).
#[unsafe(export_name = "_start")]
pub extern "C" fn start() {
    let envelope = match stdio::read_stdin() {
        Ok(bytes) => bytes,
        Err(_) => core::arch::wasm32::unreachable(),
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&envelope) {
        Ok(v) => v,
        Err(_) => core::arch::wasm32::unreachable(),
    };

    modes::dispatch(&parsed);
}

/// `daemon_step` — long-lived-Store path. Reads the envelope bytes
/// from `HostState::pending_envelope` via the `host_get_envelope`
/// import, parses, and dispatches.
///
/// The host keeps the same Wasmtime Store alive across many
/// `daemon_step` invocations so JS-side state (plenum caches,
/// handler tables from `http.createServer().listen(...)`) persists.
/// That's what makes daemon mode different from every other
/// combustor path in this plugin — nothing here reads stdin or
/// tears down the runtime.
#[unsafe(export_name = "daemon_step")]
pub extern "C" fn daemon_step() {
    let env_bytes = read_daemon_envelope();
    let parsed: serde_json::Value = match serde_json::from_slice(&env_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    modes::dispatch(&parsed);
}

/// Read `HostState::pending_envelope` via the `host_get_envelope`
/// import directly from Rust (no JS hop). Mirrors
/// `call_read` in `globals/mod.rs` but is available at the top
/// level of the plugin so `daemon_step` can dispatch in Rust.
fn read_daemon_envelope() -> alloc::vec::Vec<u8> {
    use alloc::vec;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { host_api::host_get_envelope(buf.as_mut_ptr(), buf.len() as u32) };
        if n >= 0 {
            buf.truncate(n as usize);
            return buf;
        }
        if n == -4 {
            let new_cap = buf.len().saturating_mul(2);
            if new_cap > 16 * 1024 * 1024 {
                return alloc::vec::Vec::new();
            }
            buf.resize(new_cap, 0);
            continue;
        }
        return alloc::vec::Vec::new();
    }
}
