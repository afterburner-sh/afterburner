// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Compile-script mode: wrap user source in the daemon-init / script
//! envelope (`wrap_script_source`), compile to QuickJS bytecode,
//! emit the base64-encoded bytes on stdout. Pairs with the
//! `daemon-init` mode: when daemon-init's envelope carries a
//! `bytecode_b64` field, the host can skip the per-launch
//! source-parse + wrap + compile and invoke the cached bytecode
//! directly.
//!
//! This is the foundation for B1 multi-shard sharing - N daemon
//! Store instances all invoke the same Vec<u8> instead of each
//! re-paying the source-compile cost. Even at workers=1 it lets the
//! host inspect compile errors out-of-band (compile failure surfaces
//! through this mode's stderr; daemon-init failures with the same
//! source previously had to wait for daemon-init to abort mid-run).
//!
//! Envelope: `{ mode: "compile-script", source, argv?, env?, cwd? }`.
//! Output: base64-encoded QuickJS bytecode on stdout. Failure: trap
//! after writing the error message to stderr.

use alloc::format;
use alloc::string::ToString;
use base64::Engine;

use crate::envelope::wrap_script_source;
use crate::stdio::{write_stderr, write_stdout};

pub fn run(envelope: &serde_json::Value) {
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
            let msg = format!("compile_src (compile-script): {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };

    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytecode);
    write_stdout(b64.as_bytes());
}
