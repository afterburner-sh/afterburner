// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Integration tests for the raw-input fast path
//! (`Afterburner::run_raw` / `run_raw_with`).
//!
//! Exercises the full chain: host `&[u8]` → `HostState::pending_input`
//! (+ `InputFormat::Raw`) → `host_get_input` / `host_input_format`
//! imports → `__AB_GET_INPUT_VALUE__` → module receives a `Uint8Array`
//! → JSON output via the unchanged stdout contract.
//!
//! Sandbox / capability-gate / fresh-per-call invariants are verified
//! by the existing `b_*` integration suite running alongside; these
//! tests focus on the raw-input contract.

use afterburner::{Afterburner, AfterburnerError, FuelGauge};
use serde_json::json;

fn ab() -> Afterburner {
    Afterburner::new().expect("build Afterburner")
}

#[test]
fn raw_input_arrives_as_uint8array() {
    let burn = ab();
    let id = burn
        .register(
            "module.exports = (b) => ({\n\
                 is_u8: b instanceof Uint8Array,\n\
                 len: b.length,\n\
                 first: b[0],\n\
                 last: b[b.length - 1],\n\
             })",
        )
        .expect("register");
    let payload = vec![7u8, 1, 2, 3, 4, 5, 6, 9];
    let out = burn.run_raw(&id, &payload).expect("run_raw");
    assert_eq!(
        out,
        json!({ "is_u8": true, "len": 8, "first": 7, "last": 9 })
    );
}

#[test]
fn raw_input_preserves_arbitrary_binary_bytes() {
    // Every byte value 0..=255, repeated — including invalid-UTF-8
    // sequences and NULs that a string-framed crossing would mangle.
    let burn = ab();
    let id = burn
        .register(
            "module.exports = (b) => {\n\
                 let sum = 0;\n\
                 let mismatch = -1;\n\
                 for (let i = 0; i < b.length; i++) {\n\
                     sum += b[i];\n\
                     if (b[i] !== (i % 256) && mismatch < 0) mismatch = i;\n\
                 }\n\
                 return { len: b.length, sum: sum, mismatch: mismatch };\n\
             }",
        )
        .expect("register");
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
    let expected_sum: u64 = payload.iter().map(|&b| u64::from(b)).sum();
    let out = burn.run_raw(&id, &payload).expect("run_raw");
    assert_eq!(
        out,
        json!({ "len": 4096, "sum": expected_sum, "mismatch": -1 })
    );
}

#[test]
fn raw_input_buffer_supports_typed_views() {
    // The backing ArrayBuffer is allocated in the runtime heap
    // (≥8-byte aligned), so constructing wider typed views over
    // `.buffer` must work — same contract as the codec + columnar
    // bridges.
    let burn = ab();
    let id = burn
        .register(
            "module.exports = (b) => {\n\
                 const f = new Float64Array(b.buffer, 0, 2);\n\
                 return [f[0], f[1]];\n\
             }",
        )
        .expect("register");
    let mut payload = Vec::new();
    payload.extend_from_slice(&1.5f64.to_le_bytes());
    payload.extend_from_slice(&(-2.25f64).to_le_bytes());
    let out = burn.run_raw(&id, &payload).expect("run_raw");
    assert_eq!(out, json!([1.5, -2.25]));
}

#[test]
fn raw_input_empty_payload() {
    let burn = ab();
    let id = burn
        .register("module.exports = (b) => ({ is_u8: b instanceof Uint8Array, len: b.length })")
        .expect("register");
    let out = burn.run_raw(&id, &[]).expect("run_raw");
    assert_eq!(out, json!({ "is_u8": true, "len": 0 }));
}

#[test]
fn same_script_serves_json_and_raw_framing() {
    // One registered script (one compiled bytecode) handles both
    // crossings — the wrapper branches on what the input getter
    // returns.
    let burn = ab();
    let id = burn
        .register(
            "module.exports = (d) =>\n\
                 (d instanceof Uint8Array) ? { kind: 'raw', n: d.length }\n\
                                           : { kind: 'json', n: d.n }",
        )
        .expect("register");
    let raw = burn.run_raw(&id, &[1, 2, 3]).expect("run_raw");
    assert_eq!(raw, json!({ "kind": "raw", "n": 3 }));
    let parsed = burn.run(&id, &json!({ "n": 41 })).expect("run");
    assert_eq!(parsed, json!({ "kind": "json", "n": 41 }));
}

#[test]
fn raw_input_respects_fuel_limit() {
    let burn = ab();
    let id = burn
        .register(
            "module.exports = (b) => {\n\
                 let x = 0;\n\
                 for (let i = 0; i < 100_000_000; i++) x += i;\n\
                 return x;\n\
             }",
        )
        .expect("register");
    let tight = FuelGauge {
        fuel: Some(10_000),
        ..FuelGauge::unlimited()
    };
    let err = burn
        .run_raw_with(&id, &[1, 2, 3], &tight)
        .expect_err("tight fuel + busy loop should exhaust");
    assert!(
        matches!(err, AfterburnerError::FuelExhausted) || matches!(err, AfterburnerError::Timeout),
        "expected FuelExhausted or Timeout, got: {err:?}"
    );
}

#[test]
fn raw_input_unknown_script_id_errors() {
    let burn = ab();
    let id = burn
        .register("module.exports = (b) => b.length")
        .expect("register");
    burn.unload(&id);
    let err = burn
        .run_raw(&id, &[1, 2, 3])
        .expect_err("unloaded script must not run");
    assert!(
        matches!(err, AfterburnerError::ScriptNotFound),
        "expected ScriptNotFound, got: {err:?}"
    );
}

#[cfg(feature = "native")]
#[test]
fn raw_input_native_mode_errors_cleanly() {
    use afterburner::Mode;
    let burn = Afterburner::builder()
        .mode(Mode::Native)
        .build()
        .expect("build native");
    let id = burn
        .register("module.exports = (b) => b.length")
        .expect("register");
    let err = burn
        .run_raw(&id, &[1, 2, 3])
        .expect_err("native backend has no raw-input bridge");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("raw input"),
        "expected a raw-input diagnostic, got: {msg}"
    );
}

#[cfg(feature = "thrust")]
#[test]
fn raw_input_works_on_threaded_engine() {
    let burn = Afterburner::builder()
        .threaded(2)
        .build()
        .expect("build threaded");
    let id = burn
        .register("module.exports = (b) => b.length + 1")
        .expect("register");
    let out = burn.run_raw(&id, &[9, 9, 9]).expect("run_raw threaded");
    assert_eq!(out, json!(4));
}
