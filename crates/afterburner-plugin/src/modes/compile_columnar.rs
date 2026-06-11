// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Compile-columnar mode: wrap user source with the columnar
//! dispatcher and emit base64 bytecode on stdout.
//!
//! Envelope: `{ mode: "compile-columnar", source: string }`.
//!
//! Same shape as [`super::compile`] except for the wrap function:
//! the resulting bytecode invokes `__ab_columnar_dispatch` instead
//! of writing JSON to stdout, so it can only be run via the
//! `columnar-invoke` plugin mode.
//!
//! Output bytecode is base64 on stdout - the host stashes it
//! alongside the regular invoke bytecode in
//! `WasmCombustor::CompiledScript` so `thrust_columnar` can ship it
//! through the `columnar-invoke` envelope.

use alloc::format;
use base64::Engine;

use crate::envelope::wrap_user_source_columnar;
use crate::stdio::{write_stderr, write_stdout};

pub fn run(envelope: &serde_json::Value) {
    let source = envelope
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let wrapped = wrap_user_source_columnar(source);
    let bytecode = match javy_plugin_api::compile_src(wrapped.as_bytes()) {
        Ok(bc) => bc,
        Err(e) => {
            let msg = format!("compile_src (columnar): {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytecode);
    write_stdout(b64.as_bytes());
}
