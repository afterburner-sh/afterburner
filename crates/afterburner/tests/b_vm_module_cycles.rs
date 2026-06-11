// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! C2 — `vm.SourceTextModule` cyclic graph reference table.
//!
//! Validates:
//! 1. Two modules A ↔ B that import each other link without errors.
//! 2. After evaluate, both namespaces are populated with their own
//!    exports.
//! 3. Cross-references through the live-binding proxy resolve to the
//!    other module's exports after both bodies finish.
//! 4. A self-cycle (A imports A) terminates linking without infinite
//!    recursion.

use serial_test::serial;
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn write_temp(dir: &TempDir, name: &str, source: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(source.as_bytes()).expect("write");
    path
}

#[test]
#[serial]
fn cycle_AB_links_and_evaluates() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "cycle.js",
        r#"
            const vm = require('vm');
            // Cycle A -> B -> A. Burn's CJS-shaped lowering captures
            // imports as snapshot bindings (not live), so the
            // "first-evaluated wins" direction sees populated values
            // and the other sees undefined for back-edge references.
            // The contract validated here is the structural one:
            // linking and evaluating the cycle complete without
            // errors and each module's own exports are populated.
            const sourceA = `
                import { fromB } from 'B';
                export const fromA = 'A_VALUE';
                export function readB() { return fromB; }
            `;
            const sourceB = `
                import { fromA } from 'A';
                export const fromB = 'B_VALUE';
                export function readA() { return fromA; }
            `;
            const A = new vm.SourceTextModule(sourceA, { identifier: 'A' });
            const B = new vm.SourceTextModule(sourceB, { identifier: 'B' });
            const linker = (spec, _ref) => {
                if (spec === 'A') return A;
                if (spec === 'B') return B;
                throw new Error('unknown ' + spec);
            };
            A.link(linker)
                .then(() => A.evaluate())
                .then(() => {
                    if (B.status !== 'evaluated') {
                        console.error('B not evaluated after A; status=' + B.status);
                        process.exit(2);
                    }
                    if (A.namespace.fromA !== 'A_VALUE') {
                        console.error('A.fromA=', A.namespace.fromA);
                        process.exit(3);
                    }
                    if (B.namespace.fromB !== 'B_VALUE') {
                        console.error('B.fromB=', B.namespace.fromB);
                        process.exit(4);
                    }
                    // Live-binding semantics: every reference to an
                    // imported name gets rewritten by the transpiler
                    // into a property access on the dep's namespace.
                    // Both directions of the cycle resolve correctly
                    // post-evaluate, regardless of which body ran
                    // first.
                    var rb = A.namespace.readB();
                    var ra = B.namespace.readA();
                    if (rb !== 'B_VALUE' || ra !== 'A_VALUE') {
                        console.error('cross-ref: A.readB()=' + rb + ' B.readA()=' + ra);
                        process.exit(5);
                    }
                    console.log('CYCLE_OK');
                    process.exit(0);
                })
                .catch((e) => {
                    console.error('cycle err:', (e && e.stack) || e);
                    process.exit(6);
                });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("CYCLE_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn self_cycle_links_without_infinite_recursion() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "self.js",
        r#"
            const vm = require('vm');
            const src = `
                import { y as imported } from 'self';
                export const y = 'self-y';
                export function read() { return imported; }
            `;
            const M = new vm.SourceTextModule(src, { identifier: 'self' });
            const linker = (spec, _ref) => {
                if (spec === 'self') return M;
                throw new Error('unknown ' + spec);
            };
            M.link(linker)
                .then(() => M.evaluate())
                .then(() => {
                    if (M.namespace.y !== 'self-y') {
                        console.error('M.y=' + M.namespace.y);
                        process.exit(2);
                    }
                    console.log('SELF_CYCLE_OK');
                    process.exit(0);
                })
                .catch((e) => {
                    console.error('self cycle err:', (e && e.stack) || e);
                    process.exit(3);
                });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("SELF_CYCLE_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn three_node_cycle_ABC() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "abc.js",
        r#"
            const vm = require('vm');
            const A = new vm.SourceTextModule(
                "import { b } from 'B'; export const a = 1; export function bv(){return b;}",
                { identifier: 'A' });
            const B = new vm.SourceTextModule(
                "import { c } from 'C'; export const b = 2; export function cv(){return c;}",
                { identifier: 'B' });
            const C = new vm.SourceTextModule(
                "import { a } from 'A'; export const c = 3; export function av(){return a;}",
                { identifier: 'C' });
            const map = { A, B, C };
            const linker = (spec) => map[spec];
            A.link(linker)
                .then(() => A.evaluate())
                .then(() => {
                    if (A.namespace.a !== 1 || B.namespace.b !== 2 || C.namespace.c !== 3) {
                        console.error('values:', A.namespace.a, B.namespace.b, C.namespace.c);
                        process.exit(2);
                    }
                    // Depth-first eval order is A -> B -> C -> (back-edge to A is short-circuited).
                    // C runs first, B second, A last. So A.bv() reads B
                    // post-evaluate (works), B.cv() reads C post-evaluate
                    // (works). C.av() is the back-edge — it captured A
                    // pre-evaluate when its body ran, so it's undefined
                    // under snapshot semantics.
                    // Live-binding semantics applies to every back-edge
                    // in the cycle: each cross-ref reads the dep's
                    // current namespace property at call time.
                    if (A.namespace.bv() !== 2 || B.namespace.cv() !== 3
                        || C.namespace.av() !== 1) {
                        console.error('cross-refs:', A.namespace.bv(),
                            B.namespace.cv(), C.namespace.av());
                        process.exit(3);
                    }
                    console.log('THREE_CYCLE_OK');
                    process.exit(0);
                })
                .catch((e) => {
                    console.error('three-cycle err:', (e && e.stack) || e);
                    process.exit(4);
                });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("THREE_CYCLE_OK"), "STDOUT:\n{stdout}");
}

#[test]
#[serial]
fn linear_dependency_still_works() {
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "linear.js",
        r#"
            const vm = require('vm');
            const A = new vm.SourceTextModule(
                "export const value = 'A';",
                { identifier: 'A' });
            const B = new vm.SourceTextModule(
                "import { value as a } from 'A'; export const value = 'B+' + a;",
                { identifier: 'B' });
            B.link((spec) => spec === 'A' ? A : null)
                .then(() => B.evaluate())
                .then(() => {
                    if (B.namespace.value === 'B+A') {
                        console.log('LINEAR_OK');
                        process.exit(0);
                    } else {
                        console.error('B.value=' + B.namespace.value);
                        process.exit(2);
                    }
                })
                .catch((e) => {
                    console.error('linear err:', (e && e.stack) || e);
                    process.exit(3);
                });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "STDOUT:\n{stdout}\nSTDERR:\n{stderr}");
    assert!(stdout.contains("LINEAR_OK"), "STDOUT:\n{stdout}");
}
