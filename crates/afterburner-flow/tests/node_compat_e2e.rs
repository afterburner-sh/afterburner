// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! End-to-end integration of node-compat through `FlowEngine`.
//! Proves the WASM path + Manifold wiring reach through the public API.

use afterburner_core::{FsAccess, FuelGauge, Manifold};
use afterburner_flow::FlowEngine;
use serde_json::json;
use std::path::PathBuf;

fn temp_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "afterburner-flow-node-compat-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn flow_with_manifold(m: Manifold) -> FlowEngine {
    let fuel = FuelGauge {
        fuel: Some(1_000_000_000),
        memory_bytes: Some(64 * 1024 * 1024),
        timeout_ms: Some(30_000),
        manifold: m,
        ..FuelGauge::unlimited()
    };
    FlowEngine::with_fuel(fuel).unwrap()
}

#[test]
fn flow_pure_js_modules_work_with_sealed_manifold() {
    let engine = flow_with_manifold(Manifold::sealed());
    let src = r#"
        module.exports = (input) => {
            const path = require('path');
            const { Buffer } = require('buffer');
            return {
                joined: path.join('/data', input.file),
                b64: Buffer.from(input.file).toString('base64'),
            };
        };
    "#;
    let id = engine.load(src).unwrap();
    let out = engine.execute(&id, &json!({ "file": "x.json" })).unwrap();
    assert_eq!(out, json!({ "joined": "/data/x.json", "b64": "eC5qc29u" }));
}

#[test]
fn flow_fs_round_trip_with_scoped_manifold() {
    let root = temp_root();
    let file = root.join("flow-demo.txt");
    let path = file.to_string_lossy().into_owned();

    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let engine = flow_with_manifold(m);

    let src = format!(
        r#"
        module.exports = (input) => {{
            const fs = require('fs');
            fs.writeFileSync({p:?}, input.body);
            return fs.readFileSync({p:?}, 'utf8');
        }};
        "#,
        p = path
    );
    let id = engine.load(&src).unwrap();
    let out = engine
        .execute(&id, &json!({ "body": "flow end-to-end" }))
        .unwrap();
    assert_eq!(out, json!("flow end-to-end"));
}

#[test]
fn flow_crypto_works_with_crypto_manifold() {
    let mut m = Manifold::sealed();
    m.crypto = true;
    let engine = flow_with_manifold(m);

    let src = r#"
        module.exports = (input) =>
            require('crypto').createHash('sha256').update(input.body).digest('hex');
    "#;
    let id = engine.load(src).unwrap();
    let out = engine.execute(&id, &json!({ "body": "abc" })).unwrap();
    assert_eq!(
        out,
        json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn flow_load_bundle_resolves_relative_require() {
    let engine = flow_with_manifold(Manifold::sealed());
    let entry = r#"
        const util = require('./util');
        const greet = require('./greet');
        module.exports = (input) => greet(util.uppercase(input.name));
    "#;
    let modules = vec![
        (
            "./util".to_string(),
            r#"
                module.exports = {
                    uppercase: (s) => String(s).toUpperCase(),
                };
            "#
            .to_string(),
        ),
        (
            "./greet".to_string(),
            r#"
                module.exports = (who) => 'Hello, ' + who + '!';
            "#
            .to_string(),
        ),
    ];
    let id = engine.load_bundle(entry, &modules).unwrap();
    let out = engine
        .execute(&id, &json!({ "name": "afterburner" }))
        .unwrap();
    assert_eq!(out, json!("Hello, AFTERBURNER!"));
}

#[test]
fn flow_load_bundle_modules_can_require_each_other() {
    let engine = flow_with_manifold(Manifold::sealed());
    let entry = r#"
        const lib = require('./lib');
        module.exports = (input) => lib.process(input.value);
    "#;
    let modules = vec![
        (
            "./lib".to_string(),
            r#"
                const helpers = require('./helpers');
                module.exports = {
                    process: (v) => helpers.tag('processed', v),
                };
            "#
            .to_string(),
        ),
        (
            "./helpers".to_string(),
            r#"
                module.exports = {
                    tag: (label, v) => ({ label, v }),
                };
            "#
            .to_string(),
        ),
    ];
    let id = engine.load_bundle(entry, &modules).unwrap();
    let out = engine.execute(&id, &json!({ "value": 42 })).unwrap();
    assert_eq!(out, json!({ "label": "processed", "v": 42 }));
}

#[test]
fn flow_sealed_denies_fs() {
    let engine = flow_with_manifold(Manifold::sealed());
    let src = r#"
        module.exports = () => {
            try { require('fs').readFileSync('/etc/hostname'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let id = engine.load(src).unwrap();
    let out = engine.execute(&id, &json!(null)).unwrap();
    let msg = out.as_str().unwrap().to_lowercase();
    assert!(
        msg.contains("permission denied"),
        "expected fs denial; got {msg}"
    );
}
