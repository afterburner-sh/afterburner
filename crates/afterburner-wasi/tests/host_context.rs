// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Integration tests for the `HostContext` wiring. Scripts call
//! `require('afterburner:host').{readColumn, emitRow, getEnv}`; the
//! embedder-provided context answers via the trait methods. Covers
//! both native and WASM paths against the same test context type.

use afterburner_core::{Combustor, FuelGauge, HostContext, Manifold};
use afterburner_ignite::NativeCombustor;
use afterburner_wasi::{WasmCombustor, WasmConfig};
use kovan_map::HopscotchMap;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Test harness context. `read_column` returns a fixed per-name vec
/// so the script can assert correctness; `emit_row` accumulates into
/// a lock-free HopscotchMap keyed by call index so the test can
/// inspect what the script produced.
#[derive(Default)]
struct TestContext {
    next_idx: AtomicU64,
    emitted: HopscotchMap<u64, Value>,
}

impl TestContext {
    fn emitted_rows(&self) -> Vec<Value> {
        let n = self.next_idx.load(Ordering::Relaxed);
        (0..n).filter_map(|i| self.emitted.get(&i)).collect()
    }
}

impl HostContext for TestContext {
    fn read_column(&self, name: &str) -> Vec<Value> {
        match name {
            "ids" => vec![json!(1), json!(2), json!(3)],
            "labels" => vec![json!("a"), json!("b"), json!("c")],
            _ => Vec::new(),
        }
    }

    fn emit_row(&self, row: Value) {
        let idx = self.next_idx.fetch_add(1, Ordering::Relaxed);
        self.emitted.insert(idx, row);
    }

    fn get_env(&self, key: &str) -> Option<String> {
        match key {
            "TEST_ENV_KEY" => Some("test-env-value".into()),
            _ => None,
        }
    }
}

const SCRIPT: &str = r#"
    module.exports = () => {
        const host = require('afterburner:host');
        const ids = host.readColumn('ids');
        const labels = host.readColumn('labels');
        const missing = host.readColumn('missing');

        // Zip the two columns and emit one row per entry.
        for (let i = 0; i < ids.length; i++) {
            host.emitRow({ id: ids[i], label: labels[i] });
        }

        return {
            idsLen: ids.length,
            labelsLen: labels.length,
            missingIsEmpty: Array.isArray(missing) && missing.length === 0,
            env: host.getEnv('TEST_ENV_KEY'),
            envMissing: host.getEnv('NOT_SET') === undefined,
        };
    };
"#;

fn run_on<C: Combustor>(c: &C) -> Value {
    let id = c.ignite(SCRIPT).unwrap();
    let limits = FuelGauge {
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    c.thrust(&id, &json!(null), &limits).unwrap()
}

#[test]
fn native_host_context_round_trip() {
    let ctx = Arc::new(TestContext::default());
    let c = NativeCombustor::new()
        .unwrap()
        .with_host_context(ctx.clone() as Arc<dyn HostContext>);
    let out = run_on(&c);
    assert_eq!(
        out,
        json!({
            "idsLen": 3,
            "labelsLen": 3,
            "missingIsEmpty": true,
            "env": "test-env-value",
            "envMissing": true,
        }),
        "native: {out}"
    );
    assert_eq!(
        ctx.emitted_rows(),
        vec![
            json!({ "id": 1, "label": "a" }),
            json!({ "id": 2, "label": "b" }),
            json!({ "id": 3, "label": "c" }),
        ]
    );
}

#[test]
fn wasm_host_context_round_trip() {
    let ctx = Arc::new(TestContext::default());
    let cfg = WasmConfig {
        state_store: None,
        host_context: Some(ctx.clone() as Arc<dyn HostContext>),
        ..WasmConfig::default()
    };
    let c = WasmCombustor::new(cfg).unwrap();
    let out = run_on(&c);
    assert_eq!(
        out,
        json!({
            "idsLen": 3,
            "labelsLen": 3,
            "missingIsEmpty": true,
            "env": "test-env-value",
            "envMissing": true,
        }),
        "wasm: {out}"
    );
    assert_eq!(
        ctx.emitted_rows(),
        vec![
            json!({ "id": 1, "label": "a" }),
            json!({ "id": 2, "label": "b" }),
            json!({ "id": 3, "label": "c" }),
        ]
    );
}

#[test]
fn wasm_without_host_context_defaults_are_harmless() {
    // No context wired - readColumn returns [], emitRow is a no-op,
    // getEnv returns undefined. Must not crash.
    let cfg = WasmConfig::default();
    let c = WasmCombustor::new(cfg).unwrap();
    let id = c
        .ignite(
            r#"
            module.exports = () => {
                const host = require('afterburner:host');
                host.emitRow({ x: 1 });  // silently dropped
                return {
                    rows: host.readColumn('ids'),
                    envIsUndefined: host.getEnv('ANY') === undefined,
                };
            };
        "#,
        )
        .unwrap();
    let limits = FuelGauge {
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    let out = c.thrust(&id, &json!(null), &limits).unwrap();
    // `undefined` round-trips out of JSON as a missing key; `envIsUndefined`
    // lets us prove the polyfill returned the right sentinel rather than
    // something like `null` or an empty string.
    assert_eq!(out, json!({ "rows": [], "envIsUndefined": true }));
}
