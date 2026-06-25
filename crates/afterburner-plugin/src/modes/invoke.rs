// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Invoke mode: decode cached bytecode and execute.
//!
//! Envelope: `{ mode: "invoke", bytecode_b64: string }`. Input is
//! delivered via the `host_get_input` import (called from JS via
//! `__AB_GET_INPUT_VALUE__()`) - not via the envelope. That keeps this
//! path a single `invoke` with no per-call preamble compile. The same
//! bytecode serves JSON and raw input framing; `host_input_format`
//! tells the getter which shape to materialize.

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
            let msg = format!("invoke: bytecode_b64 decode: {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };

    if let Err(e) = javy_plugin_api::invoke(&bytecode, None) {
        let msg = format!("invoke: cached bytecode: {e}\n");
        write_stderr(msg.as_bytes());
        core::arch::wasm32::unreachable()
    }
}
