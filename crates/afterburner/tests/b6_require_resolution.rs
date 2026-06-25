// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! B6 phase gate: CommonJS `require(pkg)` + `node_modules` walk.
//!
//! The plan's gate is `require('express')` loading from an installed
//! `node_modules/express/`. These tests cover the resolver mechanics
//! directly - without requiring real npm packages in CI - by
//! materializing `node_modules/<pkg>/…` trees in a scratch dir and
//! driving `burn` against them:
//!
//! * **Relative / absolute paths.** `require('./x')`, `require('../y')`,
//!   `require('/abs/path/z')`.
//! * **`package.json "main"`** - the loader reads `main` when a
//!   directory is targeted.
//! * **`index.js` / `index.json` fallback** when `main` is absent.
//! * **`node_modules` walk** - the loader walks up from the requiring
//!   module's dir until it finds `node_modules/<pkg>`.
//! * **Per-module `require`** - `./sibling` inside a loaded module
//!   resolves relative to that module's dir, not the entry script's.
//! * **`.json` auto-parsing** - `require('./cfg.json')` returns an
//!   object, no `JSON.parse` needed.
//! * **Module caching** - two requires return the same object
//!   identity, and cyclic requires see a partial exports object
//!   rather than infinite-looping.
//! * **`require.resolve(name)`** returns the absolute path without
//!   loading.
//! * **`require.cache`** maps absolute paths to loaded exports.
//! * **Missing module** → `MODULE_NOT_FOUND`.
//! * **Stdlib precedence** - `require('path')` still returns the
//!   plenum polyfill even when `node_modules/path/` exists; the
//!   node_modules walk is a fallback, not an override.

#![cfg(feature = "bin")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn scratch(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_b6_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_burn_in(cwd: &PathBuf, src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(cwd)
        .arg("-e")
        .arg(src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
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

// ---- relative path resolution ------------------------------------------

#[test]
fn require_relative_js_file() {
    let dir = scratch("rel_js");
    fs::write(
        dir.join("lib.js"),
        "module.exports = { greet: () => 'hello from lib' };",
    )
    .unwrap();
    let out = run_burn_in(
        &dir,
        "const lib = require('./lib'); console.log(lib.greet());",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('./lib')");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello from lib"
    );
}

#[test]
fn require_relative_explicit_extension() {
    let dir = scratch("rel_ext");
    fs::write(dir.join("mod.js"), "module.exports = 42;").unwrap();
    let out = run_burn_in(&dir, "console.log(require('./mod.js'));");
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('./mod.js') explicit extension");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "42");
}

#[test]
fn require_parent_directory() {
    let dir = scratch("parent");
    let sub = dir.join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::write(dir.join("root.js"), "module.exports = 'from root';").unwrap();
    let entry = sub.join("entry.js");
    fs::write(&entry, "const r = require('../root'); console.log(r);").unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('../root')");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "from root");
}

#[test]
fn require_absolute_path() {
    let dir = scratch("absolute");
    let abs = dir.join("abs.js");
    fs::write(&abs, "module.exports = 'abs-loaded';").unwrap();
    let src = format!(
        "const r = require({abs_lit}); console.log(r);",
        abs_lit = serde_json::to_string(&abs.to_string_lossy().into_owned()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require(<absolute>)");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "abs-loaded");
}

// ---- package.json "main" + index.js/index.json -------------------------

#[test]
fn require_directory_uses_package_json_main() {
    let dir = scratch("pkg_main");
    let pkg_dir = dir.join("mypkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"mypkg","main":"lib/entry.js"}"#,
    )
    .unwrap();
    fs::create_dir_all(pkg_dir.join("lib")).unwrap();
    fs::write(
        pkg_dir.join("lib/entry.js"),
        "module.exports = 'hit package main';",
    )
    .unwrap();
    let out = run_burn_in(&dir, "console.log(require('./mypkg'));");
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('./mypkg') via package.json main");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hit package main"
    );
}

#[test]
fn require_directory_falls_back_to_index_js() {
    let dir = scratch("index_js");
    let pkg_dir = dir.join("pkg_noindex");
    fs::create_dir_all(&pkg_dir).unwrap();
    // No package.json - directory must fall through to index.js.
    fs::write(pkg_dir.join("index.js"), "module.exports = 'idx';").unwrap();
    let out = run_burn_in(&dir, "console.log(require('./pkg_noindex'));");
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('./dir') via index.js");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "idx");
}

#[test]
fn require_directory_falls_back_to_index_json() {
    let dir = scratch("index_json");
    let pkg_dir = dir.join("jsonpkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join("index.json"), r#"{"ok":true,"v":5}"#).unwrap();
    let out = run_burn_in(&dir, "console.log(JSON.stringify(require('./jsonpkg')));");
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('./dir') via index.json");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        r#"{"ok":true,"v":5}"#
    );
}

// ---- node_modules walk --------------------------------------------------

#[test]
fn require_finds_package_in_node_modules() {
    let dir = scratch("nm_basic");
    let pkg_dir = dir.join("node_modules/widget");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"widget","main":"index.js"}"#,
    )
    .unwrap();
    fs::write(
        pkg_dir.join("index.js"),
        "module.exports = function(x) { return x * 2; };",
    )
    .unwrap();
    let out = run_burn_in(&dir, "const w = require('widget'); console.log(w(21));");
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('widget') from node_modules");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "42");
}

#[test]
fn require_walks_up_to_find_node_modules() {
    // Entry script lives deep in a subdir; node_modules is at the
    // scratch root. The resolver must walk up through sub/sub2.
    let dir = scratch("nm_walk");
    let sub2 = dir.join("sub/sub2");
    fs::create_dir_all(&sub2).unwrap();
    let pkg_dir = dir.join("node_modules/uphill");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join("index.js"), "module.exports = 'walked';").unwrap();
    let entry = sub2.join("entry.js");
    fs::write(&entry, "console.log(require('uphill'));").unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "node_modules walk");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "walked");
}

#[test]
fn require_closest_node_modules_wins() {
    // Both `/root/node_modules/p` and `/root/sub/node_modules/p`
    // exist; a file under `/root/sub/` must see the nearer one.
    let dir = scratch("nm_nearest");
    let outer = dir.join("node_modules/pkg");
    fs::create_dir_all(&outer).unwrap();
    fs::write(outer.join("index.js"), "module.exports = 'outer';").unwrap();
    let inner = dir.join("sub/node_modules/pkg");
    fs::create_dir_all(&inner).unwrap();
    fs::write(inner.join("index.js"), "module.exports = 'inner';").unwrap();
    let entry = dir.join("sub/entry.js");
    fs::write(&entry, "console.log(require('pkg'));").unwrap();
    let out = run_burn_file(&entry);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "closest node_modules wins");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "inner");
}

// ---- per-module require scoping ----------------------------------------

#[test]
fn required_module_sees_its_own_dirname() {
    let dir = scratch("per_mod");
    let sub = dir.join("sub");
    fs::create_dir_all(&sub).unwrap();
    // The caller is `entry.js` in <dir>; it requires `./sub/loader`.
    // Inside `loader.js`, the require is scoped to <dir>/sub, so
    // `./sibling` must resolve to <dir>/sub/sibling.js - NOT
    // <dir>/sibling.js.
    fs::write(
        sub.join("loader.js"),
        "module.exports = require('./sibling');",
    )
    .unwrap();
    fs::write(sub.join("sibling.js"), "module.exports = 'sibling in sub';").unwrap();
    // Put a decoy at <dir>/sibling.js to prove the inner require
    // doesn't fall back to the entry script's dir.
    fs::write(dir.join("sibling.js"), "module.exports = 'decoy at root';").unwrap();
    let out = run_burn_in(&dir, "console.log(require('./sub/loader'));");
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "per-module __dirname");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "sibling in sub"
    );
}

#[test]
fn loaded_module_receives_filename_and_dirname() {
    let dir = scratch("filename");
    let sub = dir.join("s");
    fs::create_dir_all(&sub).unwrap();
    fs::write(
        sub.join("probe.js"),
        "module.exports = { file: __filename, dir: __dirname };",
    )
    .unwrap();
    let out = run_burn_in(
        &dir,
        "const p = require('./s/probe'); console.log(p.file); console.log(p.dir);",
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "__filename / __dirname");
    assert!(
        stdout.contains("/s/probe.js"),
        "__filename missing / wrong: {stdout}"
    );
    assert!(
        stdout.contains("/s\n"),
        "__dirname missing / wrong: {stdout}"
    );
}

// ---- JSON auto-parse ---------------------------------------------------

#[test]
fn require_json_returns_parsed_object() {
    let dir = scratch("json");
    fs::write(dir.join("cfg.json"), r#"{"port":3000,"host":"localhost"}"#).unwrap();
    let out = run_burn_in(
        &dir,
        "const c = require('./cfg.json'); console.log(c.port); console.log(c.host);",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require('./cfg.json')");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("3000"), "stdout: {stdout}");
    assert!(stdout.contains("localhost"), "stdout: {stdout}");
}

// ---- caching + identity ------------------------------------------------

#[test]
fn two_requires_return_same_object_identity() {
    let dir = scratch("cache");
    fs::write(
        dir.join("shared.js"),
        "module.exports = { tag: Symbol('once') };",
    )
    .unwrap();
    let out = run_burn_in(
        &dir,
        "const a = require('./shared'); const b = require('./shared'); console.log(a === b);",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "cache identity");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");
}

#[test]
fn circular_require_yields_partial_exports() {
    // a → requires b → requires a. When b first runs, a's exports is
    // the partial in-progress object. This matches Node's documented
    // CJS semantics.
    let dir = scratch("circular");
    fs::write(
        dir.join("a.js"),
        "exports.start = 'a-start';\n\
         const b = require('./b');\n\
         exports.got_b = b.label;\n\
         exports.done = 'a-done';",
    )
    .unwrap();
    fs::write(
        dir.join("b.js"),
        "const a = require('./a');\n\
         exports.label = 'b-saw-' + (a.start || 'nothing') + ',done=' + (a.done || 'no');",
    )
    .unwrap();
    let out = run_burn_in(
        &dir,
        "const a = require('./a'); console.log(a.got_b); console.log(a.done);",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "circular require");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // b sees a.start (set before the require('./b')) but not a.done
    // (set after) - proving the partial-exports semantics.
    assert!(
        stdout.contains("b-saw-a-start,done=no"),
        "circular semantics: {stdout}"
    );
    assert!(stdout.contains("a-done"), "a completes: {stdout}");
}

// ---- require.resolve + require.cache -----------------------------------

#[test]
fn require_resolve_returns_absolute_path() {
    let dir = scratch("resolve");
    fs::write(dir.join("target.js"), "module.exports = 1;").unwrap();
    let out = run_burn_in(
        &dir,
        "const p = require.resolve('./target'); console.log(p.endsWith('/target.js'));",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require.resolve");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");
}

#[test]
fn require_cache_is_keyed_by_absolute_path() {
    let dir = scratch("cache_key");
    fs::write(dir.join("m.js"), "module.exports = { id: 'abc' };").unwrap();
    let out = run_burn_in(
        &dir,
        "require('./m');\n\
         const keys = Object.keys(require.cache);\n\
         console.log(keys.some(k => k.endsWith('/m.js')));",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require.cache keying");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");
}

#[test]
fn require_cache_eviction_forces_reload() {
    // Node's canonical pattern for hot-reloadable modules is
    // `delete require.cache[require.resolve(name)]`. Burn must
    // honor that - re-requiring after eviction must execute the
    // module body a second time, not return the stale cached value.
    let dir = scratch("cache_evict");
    // The module captures Math.random() at load time; if we
    // observe two distinct values for two requires (with eviction
    // between them) the cache evict path is wired correctly.
    fs::write(
        dir.join("rand.js"),
        "module.exports = { v: Math.random() + ':' + Date.now() };",
    )
    .unwrap();
    let out = run_burn_in(
        &dir,
        "const a = require('./rand');\n\
         const abs = require.resolve('./rand');\n\
         delete require.cache[abs];\n\
         const b = require('./rand');\n\
         console.log('SAME=' + (a === b));\n\
         console.log('VAL_EQ=' + (a.v === b.v));",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require.cache eviction");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SAME=false"), "stdout: {stdout}");
    assert!(stdout.contains("VAL_EQ=false"), "stdout: {stdout}");
}

#[test]
fn require_main_points_at_entry() {
    // Node's `require.main` is the descriptor for the script that
    // booted the process. In `-e` mode it's the synthetic [eval]
    // entry; in `burn run foo.js` it's foo.js's absolute path.
    let dir = scratch("require_main");
    let out = run_burn_in(
        &dir,
        "console.log('TYPE=' + typeof require.main);\n\
         console.log('FN=' + (require.main && require.main.filename));\n\
         console.log('PATHS=' + Array.isArray(require.main && require.main.paths));",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require.main");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TYPE=object"), "stdout: {stdout}");
    assert!(stdout.contains("FN=[eval]"), "stdout: {stdout}");
    assert!(stdout.contains("PATHS=true"), "stdout: {stdout}");
}

#[test]
fn require_main_for_file_invocation() {
    // Same require.main check, but boot via `burn run foo.js` so the
    // entry filename must be the script's absolute path.
    let dir = scratch("require_main_file");
    let script = dir.join("entry.js");
    fs::write(
        &script,
        "console.log('FN=' + require.main.filename);\n\
         console.log('IS_MAIN_FORMAT=' + (typeof require.main.id === 'string'));",
    )
    .unwrap();
    let out = run_burn_file(&script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "require.main file invocation");
    let abs = std::fs::canonicalize(&script)
        .unwrap_or(script.clone())
        .display()
        .to_string();
    assert!(
        stdout.contains(&format!("FN={}", abs))
            || stdout.contains(&format!("FN={}", script.display())),
        "stdout: {stdout}\nexpected filename: {abs}"
    );
    assert!(stdout.contains("IS_MAIN_FORMAT=true"));
}

// ---- error shapes ------------------------------------------------------

#[test]
fn missing_relative_module_throws_module_not_found() {
    let dir = scratch("missing");
    let out = run_burn_in(
        &dir,
        "try { require('./nope'); console.log('BAD'); }\n\
         catch (e) { console.log(e.code); console.log(/Cannot find module/.test(e.message)); }",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "missing module error shape");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("MODULE_NOT_FOUND"), "stdout: {stdout}");
    assert!(stdout.contains("true"), "stdout: {stdout}");
}

#[test]
fn missing_bare_package_throws_module_not_found() {
    let dir = scratch("missing_bare");
    let out = run_burn_in(
        &dir,
        "try { require('no-such-npm-package-xyzzy'); console.log('BAD'); }\n\
         catch (e) { console.log(e.code); }",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "missing bare package error shape");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "MODULE_NOT_FOUND"
    );
}

// ---- stdlib precedence -------------------------------------------------

#[test]
fn stdlib_wins_over_node_modules_shadow() {
    // If a user has `./node_modules/path/index.js`, `require('path')`
    // must still return the plenum polyfill - stdlib names are not
    // shadowable via node_modules, matching how Node treats built-ins
    // until ESM's import-maps land.
    let dir = scratch("stdlib_vs_nm");
    let shadow = dir.join("node_modules/path");
    fs::create_dir_all(&shadow).unwrap();
    fs::write(shadow.join("index.js"), "module.exports = 'shadowed';").unwrap();
    let out = run_burn_in(
        &dir,
        "const path = require('path'); console.log(typeof path.join);",
    );
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "stdlib precedence");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "function");
}

// ---- process.cwd() --------------------------------------------------------

#[test]
fn process_cwd_matches_invocation_dir() {
    let dir = scratch("cwd");
    let out = run_burn_in(&dir, "console.log(process.cwd());");
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let _ = fs::remove_dir_all(&dir);
    assert_ok(&out, "process.cwd()");
    // `dir` was canonicalized from temp_dir → may or may not include a
    // `/private/` prefix on macOS; check the tail component.
    let expected_tail = format!("burn_b6_cwd_{}", std::process::id());
    assert!(
        stdout.contains(&expected_tail),
        "cwd mismatch; got {stdout}, expected to contain {expected_tail}"
    );
}
