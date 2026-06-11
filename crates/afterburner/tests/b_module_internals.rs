// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `module._resolveFilename` / `_nodeModulePaths` / `Module.prototype.load` /
//! `Module.wrap` — the webpack/corepack-internal surface. Pinned so a
//! polyfill regression doesn't silently break corepack-managed pnpm/yarn
//! flows that read these internals at module-init.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

#[test]
fn module_node_module_paths_walks_up_to_root() {
    let out = run_inline(
        r#"
        const Module = require('module');
        const paths = Module._nodeModulePaths('/a/b/c');
        if (paths.length >= 4 &&
            paths[0] === '/a/b/c/node_modules' &&
            paths[paths.length - 1] === '/node_modules') {
            console.log('NODE-MODULE-PATHS-OK');
        } else {
            console.log('FAIL', JSON.stringify(paths));
        }
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("NODE-MODULE-PATHS-OK"),
        "node_module_paths bad: {stdout}"
    );
}

#[test]
fn module_resolve_filename_handles_absolute_path() {
    let out = run_inline(
        r#"
        const Module = require('module');
        const r = Module._resolveFilename('/foo/bar.js', null, true);
        if (r === '/foo/bar.js') console.log('RESOLVE-OK');
        else console.log('FAIL', r);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RESOLVE-OK"), "resolve bad: {stdout}");
}

#[test]
fn module_wrap_emits_canonical_function_wrapper() {
    let out = run_inline(
        r#"
        const Module = require('module');
        const wrapped = Module.wrap('console.log("hi")');
        if (wrapped.indexOf('(function (exports, require, module, __filename, __dirname)') === 0 &&
            wrapped.endsWith('\n});')) {
            console.log('WRAP-OK');
        } else {
            console.log('FAIL', wrapped);
        }
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("WRAP-OK"), "wrap bad: {stdout}");
}

#[test]
fn module_instance_load_runs_target_and_assigns_exports() {
    use std::fs;
    let dir = std::env::temp_dir().join(format!(
        "burn_module_load_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let target = dir.join("payload.js");
    fs::write(&target, b"module.exports = { tag: 'loaded-via-Module' };\n").unwrap();
    let script = format!(
        r#"
        const Module = require('module');
        const m = new Module('{p}', null);
        m.load('{p}');
        if (m.loaded === true && m.exports && m.exports.tag === 'loaded-via-Module') {{
            console.log('LOAD-OK');
        }} else {{
            console.log('FAIL', m.loaded, JSON.stringify(m.exports));
        }}
        "#,
        p = target.to_str().unwrap()
    );
    let out = run_inline(&script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LOAD-OK"), "Module.load bad: {stdout}");
}

#[test]
fn module_wrapper_array_first_and_last_match_wrap() {
    let out = run_inline(
        r#"
        const Module = require('module');
        if (Array.isArray(Module.wrapper) && Module.wrapper.length === 2 &&
            typeof Module.wrapper[0] === 'string' && typeof Module.wrapper[1] === 'string' &&
            Module.wrap('X') === Module.wrapper[0] + 'X' + Module.wrapper[1]) {
            console.log('WRAPPER-OK');
        } else {
            console.log('FAIL');
        }
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("WRAPPER-OK"), "wrapper bad: {stdout}");
}
