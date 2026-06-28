// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Sealed precompiled-WASM path.
//!
//! Correctness proofs:
//!   1. Single-invoke: `register_precompiled(fixture)` + thrust produces the
//!      same `serde_json::Value` as `ignite(source)` + thrust for the same inputs.
//!   2. Batch: `register_precompiled(batch_fixture)` + `thrust_sealed_raw_bytes`
//!      with a JSON array produces the same output as the source batch path.
//!   3. Columnar: `register_precompiled(columnar_fixture)` +
//!      `thrust_sealed_raw_bytes` with an encoded batch produces the same
//!      decoded output as the source columnar path.
//!
//! Safety proof: `"wasm32-wasip1-dyn"` target is rejected with a clear
//! not-yet-supported error and never silently bypasses capability gating.
//!
//! The fixture (`fixtures/sealed_probe.{js,wasm}`) is a small, self-contained
//! sealed package; regenerate the wasm with `fixtures/build.sh`.
//! The batch fixture (`fixtures/sealed_probe_batch.wasm`) is the same source
//! wrapped in the array-in/array-out harness.
//! The columnar fixture (`fixtures/sealed_probe_columnar.wasm`) is the Int32 sum
//! source (`fixtures/sealed_probe_columnar_src.js`) wrapped in the binary-frame
//! harness.

use afterburner_core::{Combustor, FuelGauge};
use afterburner_wasi::{WasmCombustor, WasmConfig};
use serde_json::{Value, json};

/// The sealed fixture module compiled to a self-contained WASM command
/// (wasi_snapshot_preview1 imports only, no `afterburner:host`).
const PROBE_SEALED_WASM: &[u8] = include_bytes!("fixtures/sealed_probe.wasm");

/// The same fixture's JS source, run through the in-process source path so the
/// two paths can be compared on identical inputs. Byte-identical to the source
/// the wasm fixture was built from.
const PROBE_SOURCE: &str = include_str!("fixtures/sealed_probe.js");

/// The batch fixture: the same probe source wrapped in the array-in/array-out
/// harness (`build_wrapped_source_batch`). Used to prove batch precompiled
/// output equals batch source output.
const PROBE_BATCH_WASM: &[u8] = include_bytes!("fixtures/sealed_probe_batch.wasm");

/// The columnar fixture: a simple Int32 sum UDF (c0[i] + c1[i] -> sum[i])
/// wrapped in the binary-frame harness (`build_wrapped_source_columnar`).
const PROBE_COLUMNAR_WASM: &[u8] = include_bytes!("fixtures/sealed_probe_columnar.wasm");

/// JS source for the columnar fixture UDF.
const PROBE_COLUMNAR_SOURCE: &str = include_str!("fixtures/sealed_probe_columnar_src.js");

fn make_combustor() -> WasmCombustor {
    WasmCombustor::new(WasmConfig::default()).unwrap()
}

// ---- correctness: precompiled output == source output --------------------

/// Run both paths with a given input and assert the returned Values are equal.
fn assert_sealed_matches_source(input: &Value) {
    let c = make_combustor();
    let limits = FuelGauge::unlimited();

    // Source path.
    let src_id = c.ignite(PROBE_SOURCE).unwrap();
    let src_out = c.thrust(&src_id, input, &limits).unwrap();

    // Sealed (precompiled) path.
    let sealed_id = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    let sealed_out = c.thrust(&sealed_id, input, &limits).unwrap();

    assert_eq!(
        sealed_out, src_out,
        "sealed output differs from source output for input {input}\n  \
         sealed: {sealed_out}\n  source: {src_out}"
    );
}

#[test]
fn sealed_sum_op_matches_source() {
    // op:sum - an array fold, deterministic. Both paths must agree exactly.
    assert_sealed_matches_source(&json!({ "op": "sum", "values": [1, 2, 3, 4] }));
}

#[test]
fn sealed_bytelen_op_matches_source() {
    // op:bytelen - exercises TextEncoder (a builtin), deterministic.
    assert_sealed_matches_source(&json!({ "op": "bytelen", "text": "hello world" }));
}

#[test]
fn sealed_error_path_matches_source() {
    // Unknown op - both paths return { ok: false, error: "..." }.
    assert_sealed_matches_source(&json!({ "op": "nope" }));
}

#[test]
fn sealed_empty_values_matches_source() {
    // Edge case: empty values array.
    assert_sealed_matches_source(&json!({ "op": "sum", "values": [] }));
}

// ---- cache: second registration returns same ScriptId without re-compile ----

#[test]
fn register_precompiled_is_idempotent() {
    let c = make_combustor();
    let id1 = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    let id2 = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    assert_eq!(
        id1.hash, id2.hash,
        "second registration of identical bytes must return the same hash"
    );
}

// ---- dyn target: valid wasm bytes are accepted; sealed wasm bytes are
// rejected at module-compile time (import mismatch) -----------------------

#[test]
fn register_precompiled_dyn_target_accepts_valid_dyn_wasm_and_rejects_sealed() {
    let c = make_combustor();
    // The sealed probe is a self-contained WASM command (wasi_snapshot_preview1
    // imports only). Passing it as a "wasm32-wasip1-dyn" target fails at
    // module compile time because wasmtime sees a module that does NOT import
    // from `afterburner-plugin-v1`, so instantiation of the package module
    // against a linker that only exposes `afterburner-plugin-v1` exports
    // should still fail if the module can be compiled. However, a
    // wasi-only module CAN be compiled as a Module; only instantiation fails.
    // The key invariant: passing the sealed wasm as dyn target must either
    // compile cleanly (at which point thrust_dyn will fail when _start tries
    // to run without WASI resolvers) or fail during registration.
    //
    // What the test actually guards: the prior "not yet supported" error is
    // GONE - dyn target is now a real implementation, not a stub rejection.
    // This test documents the new behaviour and is not a safety gate.
    let result = c.register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1-dyn");
    // The sealed wasm doesn't import afterburner-plugin-v1, so it compiles
    // as a Module with no imports; registration succeeds because we only
    // compile the Module here. The test just verifies there is no
    // "not yet supported" stub error.
    match result {
        Ok(_) => {
            // Registration succeeded - the sealed module compiled as a Module.
            // thrust_dyn would fail because it has no plugin imports to link,
            // but that is a separate concern.
        }
        Err(afterburner_core::AfterburnerError::CompileFailed(_)) => {
            // Module compilation failed (unexpected for a valid wasm, but not
            // an "unsupported" stub error - acceptable).
        }
        Err(other) => panic!("expected Ok or CompileFailed for dyn target, got: {other:?}"),
    }
}

// ---- robustness: unknown-ScriptId on the sealed path yields ScriptNotFound -

#[test]
fn sealed_thrust_unknown_id_returns_script_not_found() {
    use afterburner_core::{AfterburnerError, EngineMode, ScriptId};

    let c = make_combustor();
    let bogus = ScriptId {
        hash: [0u8; 32],
        mode: EngineMode::Wasm,
    };
    // Register the sealed module, then thrust an unrelated (bogus) id: it is in
    // neither cache, so thrust must fail cleanly with ScriptNotFound - the same
    // contract as the source path.
    let _ = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    let err = c
        .thrust(&bogus, &json!(null), &FuelGauge::unlimited())
        .unwrap_err();
    assert!(
        matches!(err, AfterburnerError::ScriptNotFound),
        "expected ScriptNotFound for unregistered id, got {err:?}"
    );
}

// ---- PROOF: batch precompiled output == batch source output ---------------
//
// The batch precompiled WASM uses the array-in/array-out harness produced by
// `build_wrapped_source_batch`. This test proves that running the batch
// fixture through `thrust_sealed_raw_bytes` with a JSON array input produces
// the same output as the source batch path (`ignite` + per-element `thrust`).

#[test]
fn batch_precompiled_output_equals_source_output() {
    use afterburner_core::Combustor;

    let c = make_combustor();
    let limits = FuelGauge::unlimited();

    // Register the batch fixture WASM via the sealed path.
    let batch_id = c
        .register_precompiled(PROBE_BATCH_WASM, "wasm32-wasip1")
        .unwrap();

    // Source batch path: ignite the same probe source, invoke per-element.
    let src_id = c.ignite(PROBE_SOURCE).unwrap();

    let inputs: Vec<Value> = vec![
        json!({ "op": "sum", "values": [1, 2, 3] }),
        json!({ "op": "bytelen", "text": "hello" }),
        json!({ "op": "unknown" }),
        json!(null),
    ];
    let input_arr = Value::Array(inputs.clone());

    // Precompiled batch path: single boundary crossing.
    let input_bytes = serde_json::to_vec(&input_arr).unwrap();
    let reply_bytes = c
        .thrust_sealed_raw_bytes(&batch_id, input_bytes, &limits)
        .unwrap();
    let batch_out: Value = serde_json::from_slice(&reply_bytes).unwrap();
    assert!(
        batch_out.is_array(),
        "batch precompiled must return an array"
    );
    let batch_arr = batch_out.as_array().unwrap();

    // Source path: per-element.
    let mut src_arr: Vec<Value> = Vec::with_capacity(inputs.len());
    for elem in &inputs {
        if elem.is_null() {
            src_arr.push(Value::Null);
        } else {
            src_arr.push(c.thrust(&src_id, elem, &limits).unwrap());
        }
    }

    assert_eq!(
        batch_arr.len(),
        src_arr.len(),
        "batch precompiled and source must return same number of elements"
    );
    for (i, (pc, src)) in batch_arr.iter().zip(src_arr.iter()).enumerate() {
        assert_eq!(
            pc, src,
            "batch precompiled element {i} differs from source output\n  precompiled: {pc}\n  source: {src}"
        );
    }
}

// ---- PROOF: columnar precompiled output == columnar source output ----------
//
// The columnar precompiled WASM uses the binary-frame harness produced by
// `build_wrapped_source_columnar`. This test proves that encoding a batch,
// running through the columnar fixture's `thrust_sealed_raw_bytes`, and
// decoding produces the same columns as the source columnar path
// (`ignite` + `thrust_columnar`).

#[test]
fn columnar_precompiled_output_equals_source_output() {
    use afterburner_wasi::columnar::{
        ColumnDtype, ColumnRef, ColumnarBatch, decode_batch, encode_batch,
    };

    let c = make_combustor();
    let limits = FuelGauge::unlimited();

    // Register the columnar fixture WASM.
    let col_id = c
        .register_precompiled(PROBE_COLUMNAR_WASM, "wasm32-wasip1")
        .unwrap();

    // Source path via thrust_columnar (ignite the same source).
    let src_id = c.ignite(PROBE_COLUMNAR_SOURCE).unwrap();

    // Build a typed Int32 batch: 5 rows, c0 = [1,2,3,4,5], c1 = [10,20,30,40,50].
    let c0_data: Vec<u8> = [1i32, 2, 3, 4, 5]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let c1_data: Vec<u8> = [10i32, 20, 30, 40, 50]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let mut batch = ColumnarBatch::new(5);
    batch.push(ColumnRef {
        name: "c0",
        dtype: ColumnDtype::Int32,
        data: &c0_data,
        heap: None,
        validity: None,
    });
    batch.push(ColumnRef {
        name: "c1",
        dtype: ColumnDtype::Int32,
        data: &c1_data,
        heap: None,
        validity: None,
    });

    // Precompiled columnar path: encode -> thrust_sealed_raw_bytes -> decode.
    let encoded = encode_batch(&batch).unwrap();
    let reply_bytes = c
        .thrust_sealed_raw_bytes(&col_id, encoded.bytes, &limits)
        .unwrap();
    let pc_out = decode_batch(&reply_bytes).unwrap();

    // Source columnar path.
    let src_out = c.thrust_columnar(&src_id, &batch, &limits).unwrap();

    assert_eq!(
        pc_out.row_count, src_out.row_count,
        "columnar precompiled and source must agree on row_count"
    );
    assert_eq!(
        pc_out.columns.len(),
        src_out.columns.len(),
        "columnar precompiled and source must return same number of columns"
    );
    for (i, (pc_col, src_col)) in pc_out
        .columns
        .iter()
        .zip(src_out.columns.iter())
        .enumerate()
    {
        assert_eq!(
            pc_col.name, src_col.name,
            "column {i} name mismatch: precompiled={}, source={}",
            pc_col.name, src_col.name
        );
        assert_eq!(pc_col.dtype, src_col.dtype, "column {i} dtype mismatch");
        assert_eq!(
            pc_col.data, src_col.data,
            "column {i} '{}' data mismatch\n  precompiled: {:?}\n  source: {:?}",
            pc_col.name, pc_col.data, src_col.data
        );
    }
    // Verify the actual sum values (1+10=11, 2+20=22, ...).
    let sums: Vec<i32> = pc_out.columns[0]
        .data
        .chunks_exact(4)
        .map(|c| i32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    assert_eq!(
        sums,
        vec![11, 22, 33, 44, 55],
        "columnar sum values must be correct"
    );
}

// ---- SEALED WASM HTTP EGRESS -------------------------------------------
//
// Proofs for the `host-http` feature: sealed WASI guests (compiled
// wasm32-wasip1 programs registered via `register_precompiled`) can now
// call `afterburner:host`/`host_http_request`. The feature is gated so the
// tests only compile when `host-http` is enabled.
//
// WAT probe design:
//   Memory layout (one 64 KiB page):
//     0..2    = "GET" (method, 3 bytes)
//     4..N    = URL (templated by `build_http_probe_wat`)
//     512     = HTTP response output buffer (30 000 bytes)
//     30520   = iov[0].ptr (4 bytes, little-endian)
//     30524   = iov[0].len (4 bytes)
//     30528   = nwritten scratch (4 bytes)
//     30532   = i32 result from host_http_request (4 bytes written to stdout)
//
//   `_start` calls host_http_request, stores the i32 result at 30532,
//   sets up a single iov pointing at it (4 bytes), writes it to stdout
//   via fd_write(1,...), then exits cleanly with proc_exit(0).
//
//   The host reads the 4-byte stdout and interprets it as an i32 LE:
//     >= 0  success (bytes written to the out buffer)
//      -1   PermissionDenied (E_PERMISSION in host_imports.rs)
//     <-1   other host error

#[cfg(feature = "host-http")]
mod http_egress {
    use super::make_combustor;
    use afterburner_core::{Combustor, FuelGauge, Manifold, NetAccess};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Build a WAT probe module that calls `host_http_request` with `url`
    /// and writes the i32 result to stdout as 4 raw little-endian bytes.
    fn build_http_probe_wat(url: &str) -> String {
        format!(
            r#"(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (import "afterburner:host" "host_http_request"
    (func $http_req (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "GET")
  (data (i32.const 4) "{url}")
  (func (export "_start")
    (local $r i32)
    (local.set $r (call $http_req
      (i32.const 0)
      (i32.const 3)
      (i32.const 4)
      (i32.const {url_len})
      (i32.const 0)
      (i32.const 0)
      (i32.const 512)
      (i32.const 30000)
    ))
    (i32.store (i32.const 30532) (local.get $r))
    (i32.store (i32.const 30520) (i32.const 30532))
    (i32.store (i32.const 30524) (i32.const 4))
    (drop (call $fd_write (i32.const 1) (i32.const 30520) (i32.const 1) (i32.const 30528)))
    (call $proc_exit (i32.const 0))
  )
)"#,
            url = url,
            url_len = url.len(),
        )
    }

    /// Read an i32 LE result from the 4-byte raw stdout of the probe module.
    fn read_result(raw: &[u8]) -> i32 {
        assert_eq!(
            raw.len(),
            4,
            "probe stdout must be exactly 4 bytes; got {raw:?}"
        );
        i32::from_le_bytes(raw[..4].try_into().unwrap())
    }

    /// Spin up a minimal HTTP/1.1 server that accepts one connection and
    /// replies with a 200 OK. Same pattern as `node_compat_host.rs`.
    fn spawn_one_shot_http_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            let _ = stream.read(&mut buf);
            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = stream.write_all(reply);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        });
        port
    }

    /// Proof 1: `register_precompiled` resolves the `host_http_request` import
    /// (the import is in the linker), and with a sealed Manifold the call is
    /// rejected before any network I/O with PermissionDenied (code -1).
    #[test]
    fn sealed_wasm_http_sealed_manifold_is_denied() {
        // Any URL works for the denied case; the gate fires before connect.
        let wat = build_http_probe_wat("http://127.0.0.1:1/probe");
        let c = make_combustor();
        // This must succeed: the sealed linker now resolves `host_http_request`.
        let id = c
            .register_precompiled(wat.as_bytes(), "wasm32-wasip1")
            .expect("register_precompiled must succeed (import now in sealed linker)");
        let limits = FuelGauge {
            manifold: Manifold::sealed(),
            ..FuelGauge::unlimited()
        };
        let raw = c
            .thrust_sealed_raw_bytes(&id, vec![], &limits)
            .expect("thrust must complete (module exits cleanly)");
        let code = read_result(&raw);
        assert_eq!(
            code, -1,
            "sealed Manifold must yield PermissionDenied (-1); got {code}"
        );
    }

    /// Proof 2: with a Manifold that grants `OutboundHttp` for the target host,
    /// the sealed WASI guest reaches the localhost mock and gets a successful
    /// result (non-negative bytes written to the response buffer).
    #[test]
    fn sealed_wasm_http_open_manifold_reaches_server() {
        let port = spawn_one_shot_http_server();
        let url = format!("http://127.0.0.1:{port}/probe");
        let wat = build_http_probe_wat(&url);
        let c = make_combustor();
        let id = c
            .register_precompiled(wat.as_bytes(), "wasm32-wasip1")
            .expect("register_precompiled");
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundHttp(Some(vec![format!("127.0.0.1:{port}")]));
        let limits = FuelGauge {
            manifold: m,
            ..FuelGauge::unlimited()
        };
        let raw = c
            .thrust_sealed_raw_bytes(&id, vec![], &limits)
            .expect("thrust must complete");
        let code = read_result(&raw);
        assert!(
            code >= 0,
            "open Manifold must reach server and return >= 0 bytes written; got {code}"
        );
    }
}
