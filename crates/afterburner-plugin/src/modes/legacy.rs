// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Legacy mode: compile + run source with inlined input.
//!
//! Envelope shape: `{ source: string, input: any }`. The plugin wraps
//! the source with the input literal inlined into the JS text, compiles
//! once, and invokes. Retained for back-compat with callers that
//! haven't migrated to the cached bytecode envelope.

use alloc::format;
use alloc::string::ToString;

use crate::envelope::wrap_user_source;
use crate::stdio::write_stderr;

pub fn run(envelope: &serde_json::Value) {
    let source = envelope
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let input = envelope
        .get("input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let input_json = input.to_string();

    let wrapped = wrap_user_source(source, &input_json);

    let bytecode = match javy_plugin_api::compile_src(wrapped.as_bytes()) {
        Ok(bc) => bc,
        Err(e) => {
            let msg = format!("compile_src: {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };

    if let Err(e) = javy_plugin_api::invoke(&bytecode, None) {
        let msg = format!("invoke: {e}\n");
        write_stderr(msg.as_bytes());
        core::arch::wasm32::unreachable()
    }
}
