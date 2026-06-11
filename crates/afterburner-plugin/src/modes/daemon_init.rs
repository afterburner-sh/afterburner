// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Daemon-init mode: long-lived-Store path.
//!
//! Two envelope shapes accepted:
//!
//! * `{mode: "daemon-init", source, argv?, env?, cwd?}` - wrap the
//!   user source in script-mode shape, compile to bytecode, invoke.
//!   The original single-Store flow.
//!
//! * `{mode: "daemon-init", bytecode_b64}` - invoke pre-compiled
//!   bytecode produced by the `compile-script` mode. The wrap +
//!   compile already happened on the host side; we just decode the
//!   bytes and invoke. This is the fast path for multi-Store
//!   sharding (the host compiles once and ships the same bytecode
//!   into every shard) and for any caller that wants to surface
//!   compile errors out-of-band without aborting the daemon Store.
//!
//! Either way: evaluates the user code in script-mode shape (top-
//! level, AsyncFunction-wrapped for top-level await) once per daemon
//! lifetime. User code that calls
//! `http.createServer(cb).listen(port)` registers `cb` into a JS-side
//! map keyed by `server_id` returned from `__host_http_listen`;
//! subsequent `daemon-event` envelopes dispatch against that map.
//!
//! Unlike script mode, we do NOT return the result here - the JS
//! state persists in the Store across calls so handlers stay live.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use base64::Engine;

use crate::envelope::wrap_script_source;
use crate::stdio::write_stderr;

pub fn run(envelope: &serde_json::Value) {
    // Preferred path: pre-compiled bytecode in the envelope. Skips
    // the per-launch source parse + wrap + compile.
    if let Some(b64) = envelope.get("bytecode_b64").and_then(|v| v.as_str()) {
        let bytecode: Vec<u8> = match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("daemon-init: bytecode_b64 decode: {e}\n");
                write_stderr(msg.as_bytes());
                core::arch::wasm32::unreachable()
            }
        };
        if let Err(e) = javy_plugin_api::invoke(&bytecode, None) {
            let msg = format!("invoke (daemon-init bytecode): {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
        return;
    }

    // Fallback: source path. daemon-init argv/env mirror script-mode
    // conventions so `process.argv` / `process.env` inside the daemon
    // code see the same thing a one-shot `burn foo.js` would.
    let source = envelope
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let argv_json = envelope
        .get("argv")
        .filter(|v| v.is_array())
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| "[]".into());
    let env_json = envelope
        .get("env")
        .filter(|v| v.is_object())
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| "{}".into());
    let cwd_json = envelope
        .get("cwd")
        .filter(|v| v.is_string())
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| "\"/\"".into());
    let wrapped = wrap_script_source(source, &argv_json, &env_json, &cwd_json);

    let bytecode = match javy_plugin_api::compile_src(wrapped.as_bytes()) {
        Ok(bc) => bc,
        Err(e) => {
            let msg = format!("compile_src (daemon-init): {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };

    if let Err(e) = javy_plugin_api::invoke(&bytecode, None) {
        let msg = format!("invoke (daemon-init): {e}\n");
        write_stderr(msg.as_bytes());
        core::arch::wasm32::unreachable()
    }
}
