// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Compile mode: wrap user source with the input-via-global template,
//! compile to QuickJS bytecode, emit base64 on stdout.
//!
//! Envelope: `{ mode: "compile", source: string }`. The host caches the
//! returned bytecode by `ScriptId.hash`, so repeated thrusts of the
//! same script never re-pay the compile cost.

use alloc::format;
use base64::Engine;

use crate::envelope::wrap_user_source_with_input_global;
use crate::stdio::{write_stderr, write_stdout};

pub fn run(envelope: &serde_json::Value) {
    let source = envelope
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let wrapped = wrap_user_source_with_input_global(source);
    let bytecode = match javy_plugin_api::compile_src(wrapped.as_bytes()) {
        Ok(bc) => bc,
        Err(e) => {
            let msg = format!("compile_src: {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytecode);
    write_stdout(b64.as_bytes());
}
