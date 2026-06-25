// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Script mode: top-level code execution, no UDF envelope.
//!
//! Envelope: `{ mode: "script", source: string }`. The plugin wraps
//! the user source with a Node-style module wrapper (providing
//! `module`, `exports`, `require`) and runs it to completion. Unlike
//! UDF mode, there is no `module.exports(data)` invocation - whatever
//! the source does at top level is the output. `console.log` goes to
//! stdout; the final JSON return value of the thrust is JS `null`.
//!
//! `process.argv` / `process.env` are populated from host imports
//! (`host_get_input` carries a JSON-encoded `{ argv: [...], env: {...} }`
//! so we don't need to extend the envelope protocol).
//!
//! Top-level `await` in user code resolves through Javy's event-loop
//! drain: the outer wrapper is compiled as an ES module, so a
//! rejecting Promise surfaces as a module-evaluation error that
//! `invoke` returns as `Err`.

use alloc::format;
use alloc::string::ToString;

use crate::envelope::wrap_script_source;
use crate::stdio::write_stderr;

pub fn run(envelope: &serde_json::Value) {
    let source = envelope
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // `to_string()` on a `serde_json::Value` serializes it back to
    // valid JSON text, which is also valid JS when used as an array
    // / object literal. `null` / missing → empty array / object so
    // `process.argv` / `process.env` always have the right *shape*
    // even when the host passed nothing through.
    let argv_json = envelope
        .get("argv")
        .filter(|v| v.is_array())
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| "[]".to_string());
    let env_json = envelope
        .get("env")
        .filter(|v| v.is_object())
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| "{}".to_string());
    // `cwd` becomes the baseline for B6's require() path resolver when
    // the entry point has no meaningful `__dirname` (eval mode) and is
    // surfaced to user code as `process.cwd()`.
    let cwd_json = envelope
        .get("cwd")
        .filter(|v| v.is_string())
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| "\"/\"".to_string());
    let wrapped = wrap_script_source(source, &argv_json, &env_json, &cwd_json);

    let bytecode = match javy_plugin_api::compile_src(wrapped.as_bytes()) {
        Ok(bc) => bc,
        Err(e) => {
            let msg = format!("compile_src (script): {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };

    if let Err(e) = javy_plugin_api::invoke(&bytecode, None) {
        let msg = format!("invoke (script): {e}\n");
        write_stderr(msg.as_bytes());
        core::arch::wasm32::unreachable()
    }
}
