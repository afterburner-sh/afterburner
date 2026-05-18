// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Plugin mode dispatcher.
//!
//! The plugin's `_start` reads a JSON envelope from stdin and delegates
//! to one of the per-mode handlers below, keyed on `envelope.mode`:
//!
//! | mode               | envelope                                                       | output                       |
//! |--------------------|----------------------------------------------------------------|------------------------------|
//! | `"compile"`        | `{ mode, source }`                                             | base64(bytecode) on stdout   |
//! | `"compile-script"` | `{ mode, source, argv?, env?, cwd? }`                          | base64(bytecode) on stdout (script/daemon-init wrap) |
//! | `"invoke"`         | `{ mode, bytecode_b64 }`                                       | wrapped script's JSON output |
//! | `"script"`         | `{ mode, source, argv?, env? }`                                | whatever top-level JS writes |
//! | `"daemon-init"`    | `{ mode, source, argv?, env? }` OR `{ mode, bytecode_b64 }`    | side-effect only (Store kept alive by host) |
//! | `"daemon-event"`   | `{ mode, event: {kind, ...} }`                                 | side-effect only (reply via `__host_http_reply`) |
//! | (omitted)          | `{ source, input }`                                            | wrapped script's JSON output |

pub mod columnar_invoke;
pub mod compile;
pub mod compile_columnar;
pub mod compile_script;
pub mod daemon_event;
pub mod daemon_init;
pub mod invoke;
pub mod legacy;
pub mod script;

/// Dispatch on `envelope.mode`. `_start` in the crate root calls this
/// exactly once per plugin instantiation.
pub fn dispatch(envelope: &serde_json::Value) {
    let mode = envelope.get("mode").and_then(|v| v.as_str());
    match mode {
        Some("compile") => compile::run(envelope),
        Some("compile-script") => compile_script::run(envelope),
        Some("compile-columnar") => compile_columnar::run(envelope),
        Some("invoke") => invoke::run(envelope),
        Some("columnar-invoke") => columnar_invoke::run(envelope),
        Some("script") => script::run(envelope),
        Some("daemon-init") => daemon_init::run(envelope),
        Some("daemon-event") => daemon_event::run(envelope),
        _ => legacy::run(envelope),
    }
}
