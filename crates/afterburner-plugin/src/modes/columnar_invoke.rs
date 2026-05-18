// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Columnar-invoke mode: decode cached columnar bytecode and execute.
//!
//! Envelope: `{ mode: "columnar-invoke", bytecode_b64: string }`.
//!
//! The cached bytecode was produced by [`super::compile_columnar`]
//! and runs `__ab_columnar_dispatch(module.exports)` after evaluating
//! the user source. The dispatcher reads the input blob via
//! `__AB_GET_COLUMNAR_INPUT__`, builds typed views, dispatches the
//! UDF, and ships the reply via `__AB_COLUMNAR_REPLY__` — so this
//! mode is just `javy_plugin_api::invoke(&bytecode, None)`, identical
//! shape to [`super::invoke`] but with a different cached bytecode
//! body.

use alloc::format;
use base64::Engine;

use crate::stdio::write_stderr;

pub fn run(envelope: &serde_json::Value) {
    let b64 = envelope
        .get("bytecode_b64")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let bytecode = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("columnar-invoke: bytecode_b64 decode: {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };

    if let Err(e) = javy_plugin_api::invoke(&bytecode, None) {
        let msg = format!("columnar-invoke: cached bytecode: {e}\n");
        write_stderr(msg.as_bytes());
        core::arch::wasm32::unreachable()
    }
}
