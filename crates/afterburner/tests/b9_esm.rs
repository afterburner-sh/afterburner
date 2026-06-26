// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! B9 phase gate: ESM → CJS transform.
//!
//! oxc 0.127 ships TypeScript strip-types but no ESM→CJS transform
//! (upstream #4050). We cover the gap with an AST-guided source
//! rewrite: parse with oxc, collect byte spans of every top-level
//! import/export, splice CommonJS equivalents in their place, then
//! run the result through the existing CJS runtime.
//!
//! Tests drive the transform via `burn <file>` so the full pipeline
//! (ts strip → esm lower → require resolver → script mode) is
//! exercised end-to-end.

#![cfg(all(feature = "bin", feature = "ts"))]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn scratch(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_b9_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_burn_file(script: &PathBuf) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} FAILED\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- imports ------------------------------------------------------------

#[test]
fn esm_named_import_with_cjs_dependency() {
    // Entry uses ESM named imports; dependency is plain CJS. Tests
    // that our ESM→CJS lowering plays nicely with the CJS side of
    // the module graph (the common TS-source consuming CJS-lib case).
    let dir = scratch("named_import");
    fs::write(
        dir.join("util.js"),
        "module.exports = { greet: (n) => 'hi ' + n, shout: (n) => n.toUpperCase() };",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import { greet, shout } from './util';\n\
         console.log(greet('world'));\n\
         console.log(shout(greet('team')));",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "named imports");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hi world"), "stdout: {stdout}");
    assert!(stdout.contains("HI TEAM"), "stdout: {stdout}");
}

#[test]
fn esm_default_import_with_interop() {
    let dir = scratch("default_import");
    // Dependency marks `__esModule` so interop pulls `.default`.
    fs::write(
        dir.join("dep.js"),
        "Object.defineProperty(exports, '__esModule', { value: true });\n\
         exports.default = function(x) { return x * 3; };",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import triple from './dep';\nconsole.log(triple(14));",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "default import via __esModule interop");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "42");
}

#[test]
fn esm_default_import_falls_back_to_whole_module() {
    let dir = scratch("default_plain_cjs");
    // Dependency is plain CJS with `module.exports = fn`. No
    // `__esModule` flag → default binding should be the whole module.
    fs::write(
        dir.join("dep.js"),
        "module.exports = function(x) { return x + 10; };",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(&entry, "import f from './dep';\nconsole.log(f(32));").unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "default import from plain CJS");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "42");
}

#[test]
fn esm_namespace_import() {
    let dir = scratch("namespace");
    fs::write(
        dir.join("math.js"),
        "exports.add = (a, b) => a + b;\n\
         exports.mul = (a, b) => a * b;",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import * as math from './math';\n\
         console.log(math.add(2, 3));\n\
         console.log(math.mul(math.add(1, 4), 3));",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "namespace import");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("5"), "stdout: {stdout}");
    assert!(stdout.contains("15"), "stdout: {stdout}");
}

#[test]
fn esm_side_effect_only_import() {
    let dir = scratch("side_effect");
    fs::write(
        dir.join("effect.js"),
        "console.log('effect ran');\nexports.v = 1;",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(&entry, "import './effect';\nconsole.log('main done');").unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "side-effect import");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("effect ran"), "stdout: {stdout}");
    assert!(stdout.contains("main done"), "stdout: {stdout}");
}

#[test]
fn esm_default_and_named_combined() {
    let dir = scratch("combined");
    fs::write(
        dir.join("lib.js"),
        "Object.defineProperty(exports, '__esModule', { value: true });\n\
         exports.default = { tag: 'default-export' };\n\
         exports.a = 1;\n\
         exports.b = 2;",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import def, { a, b } from './lib';\n\
         console.log(def.tag);\n\
         console.log(a + b);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "combined default + named");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("default-export"), "stdout: {stdout}");
    assert!(stdout.contains("3"), "stdout: {stdout}");
}

#[test]
fn esm_named_alias() {
    let dir = scratch("alias");
    fs::write(
        dir.join("lib.js"),
        "exports.originalName = 'hello-from-lib';",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import { originalName as renamed } from './lib';\n\
         console.log(renamed);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "named import with `as` alias");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello-from-lib"
    );
}

// ---- exports ------------------------------------------------------------

#[test]
fn esm_default_export_value() {
    let dir = scratch("default_value");
    fs::write(
        dir.join("lib.mjs"),
        "export default { status: 'ok', count: 7 };",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import lib from './lib';\n\
         console.log(lib.status);\n\
         console.log(lib.count);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "default export of object literal");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok"), "stdout: {stdout}");
    assert!(stdout.contains("7"), "stdout: {stdout}");
}

#[test]
fn esm_default_export_function_preserves_name_binding() {
    let dir = scratch("default_fn");
    fs::write(
        dir.join("lib.mjs"),
        "export default function greeter(n) { return 'hi ' + n; }",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(&entry, "import g from './lib';\nconsole.log(g('world'));").unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "default export named function");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi world");
}

#[test]
fn esm_named_export_const_let_var() {
    let dir = scratch("named_export");
    fs::write(
        dir.join("lib.mjs"),
        "export const A = 1;\n\
         export let B = 2;\n\
         export var C = 3;",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import { A, B, C } from './lib';\nconsole.log(A + B + C);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "named const/let/var export");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "6");
}

#[test]
fn esm_named_export_function_and_class() {
    let dir = scratch("named_fn_cls");
    fs::write(
        dir.join("lib.mjs"),
        "export function mul(a, b) { return a * b; }\n\
         export class Point {\n\
             constructor(x, y) { this.x = x; this.y = y; }\n\
             sum() { return this.x + this.y; }\n\
         }",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import { mul, Point } from './lib';\n\
         console.log(mul(7, 6));\n\
         const p = new Point(3, 4);\n\
         console.log(p.sum());",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "named function/class export");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("42"), "stdout: {stdout}");
    assert!(stdout.contains("7"), "stdout: {stdout}");
}

#[test]
fn esm_named_export_list() {
    let dir = scratch("export_list");
    fs::write(
        dir.join("lib.mjs"),
        "const x = 10; const y = 20; const z = 30;\n\
         export { x, y as yy, z };",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import { x, yy, z } from './lib';\nconsole.log(x + yy + z);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "export list with alias");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "60");
}

#[test]
fn esm_esmodule_flag_set_on_exports() {
    let dir = scratch("es_flag");
    fs::write(dir.join("lib.mjs"), "export const marker = 'yes';").unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "const lib = require('./lib');\n\
         console.log(lib.__esModule);\n\
         console.log(lib.marker);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "__esModule flag");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("true"), "stdout: {stdout}");
    assert!(stdout.contains("yes"), "stdout: {stdout}");
}

// ---- re-exports --------------------------------------------------------

#[test]
fn esm_export_star_copies_non_default() {
    let dir = scratch("export_star");
    fs::write(
        dir.join("src.js"),
        "exports.a = 1;\nexports.b = 2;\nexports.default = 99;",
    )
    .unwrap();
    fs::write(dir.join("index.mjs"), "export * from './src';").unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "const lib = require('./index');\n\
         console.log(lib.a + lib.b);\n\
         console.log(lib.default);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "export * from");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("3"), "a+b wrong: {stdout}");
    // `default` is intentionally NOT re-exported - matches Node's
    // documented semantics for `export *`.
    assert!(
        stdout.contains("undefined"),
        "default should not leak through export *: {stdout}"
    );
}

#[test]
fn esm_export_named_from_source() {
    let dir = scratch("export_from");
    fs::write(dir.join("src.js"), "exports.origName = 'source-val';").unwrap();
    fs::write(
        dir.join("reexport.mjs"),
        "export { origName as renamed } from './src';",
    )
    .unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import { renamed } from './reexport';\nconsole.log(renamed);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "export { name } from 'src'");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "source-val");
}

#[test]
fn esm_export_star_as_namespace() {
    let dir = scratch("export_star_as");
    fs::write(
        dir.join("src.js"),
        "exports.tag = 'nested';\nexports.n = 5;",
    )
    .unwrap();
    fs::write(dir.join("index.mjs"), "export * as Src from './src';").unwrap();
    let entry = dir.join("main.mjs");
    fs::write(
        &entry,
        "import { Src } from './index';\n\
         console.log(Src.tag);\n\
         console.log(Src.n);",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "export * as Ns from");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nested"), "stdout: {stdout}");
    assert!(stdout.contains("5"), "stdout: {stdout}");
}

// ---- TypeScript + ESM together -----------------------------------------

#[test]
fn ts_with_esm_imports_and_type_annotations() {
    let dir = scratch("ts_plus_esm");
    fs::write(
        dir.join("util.ts"),
        "export const increment = (n: number): number => n + 1;\n\
         export interface Counter { value: number }",
    )
    .unwrap();
    let entry = dir.join("main.ts");
    fs::write(
        &entry,
        "import { increment } from './util';\n\
         import type { Counter } from './util';\n\
         const c: Counter = { value: 5 };\n\
         console.log(increment(c.value));",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "TS + ESM integration");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "6");
}

// ---- CJS passthrough (no ESM declarations) -----------------------------

#[test]
fn plain_cjs_js_file_runs_unchanged() {
    // `.js` file with no import/export - the ESM lowering should
    // pass it through untouched (the transform is a no-op when no
    // ESM declarations are present).
    let dir = scratch("plain_cjs");
    let entry = dir.join("main.js");
    fs::write(
        &entry,
        "const { format } = require('util');\n\
         module.exports = null;\n\
         console.log(format('%s-%d', 'n', 42));",
    )
    .unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "plain CJS unchanged");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "n-42");
}
