// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Phase 0 / Gap C regression: `Afterburner::builder().cwd(path)`
//! prepends a JS prelude to registered sources that pins
//! `globalThis.__host_cwd`, refreshes the entry require resolver, and
//! rebinds the local `require` parameter — so a `require('foo')` call
//! in user code walks `<cwd>/node_modules/foo` instead of `/`.
//!
//! Why this matters: real npm packages live next to the embedding
//! example, not next to the host binary. Without `.cwd(path)`, an
//! Express example that does `const express = require('express')`
//! after `cd examples/express-app && npm install` walks from the host
//! process's cwd (often the repo root or wherever the user invoked
//! `cargo run` from) and fails to resolve.
//!
//! The local-`require` rebind is the non-obvious part. The UDF
//! envelope (`crates/afterburner-plugin/src/envelope.rs`) wraps user
//! source in `new Function('module', 'exports', 'require', source)`
//! and calls it with `(__ab_module, __ab_module.exports,
//! globalThis.require)`. The `require` parameter captures
//! `globalThis.require` *by value at call time*. Updating
//! `globalThis.require` from inside the user code (which is what
//! `__plenum_refresh_entry_require()` does) is invisible to the
//! function-scoped `require` parameter unless we explicitly do
//! `require = globalThis.require`. The prelude does both.
//!
//! Coverage:
//!   * `.cwd(tmpdir).register("require('foo')")` resolves `foo` from
//!     `<tmpdir>/node_modules/foo`.
//!   * Without `.cwd()`, the same registration fails with
//!     `MODULE_NOT_FOUND` (regression check — the change is opt-in).
//!   * Path-relative requires (`./util`, `../shared`) inside the cwd
//!     resolve correctly.
//!   * `__host_cwd` global reflects the configured path.
//!   * Prelude is idempotent — the user's source still sees the
//!     `module`, `exports`, `require` bindings the envelope passed.

use afterburner::{Afterburner, FsAccess, Manifold};
use serde_json::json;
use std::fs;
use tempfile::TempDir;

/// Read-only manifold scoped to a temp dir — what an embedder would
/// configure when it wants `require('foo')` to resolve out of its
/// vendored `node_modules` and nothing else. Net, env, crypto,
/// child_process, exit all stay denied.
fn manifold_readable(path: &std::path::Path) -> Manifold {
    Manifold {
        fs: FsAccess::ReadOnly(vec![path.to_path_buf()]),
        ..Manifold::sealed()
    }
}

fn write_file(dir: &std::path::Path, name: &str, contents: &str) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dirs");
    }
    fs::write(path, contents).expect("write fixture");
}

/// Build a temp dir with `node_modules/foo/index.js` returning a
/// sentinel marker. The sentinel changes per test so cache hits
/// across tests are detectable.
fn fixture_with_foo(sentinel: &str) -> TempDir {
    let tmp = TempDir::new().expect("tempdir");
    write_file(
        tmp.path(),
        "node_modules/foo/package.json",
        r#"{"name":"foo","version":"0.0.0","main":"index.js"}"#,
    );
    write_file(
        tmp.path(),
        "node_modules/foo/index.js",
        &format!("module.exports = {{ marker: '{sentinel}' }};\n"),
    );
    tmp
}

#[test]
fn register_with_cwd_resolves_node_modules() {
    let fixture = fixture_with_foo("FOUND_FOO");
    let ab = Afterburner::builder()
        .manifold(manifold_readable(fixture.path()))
        .cwd(fixture.path())
        .build()
        .expect("build");

    let id = ab
        .register("module.exports = function() { return require('foo').marker; };")
        .expect("register");
    let out = ab.run(&id, &json!(null)).expect("run");
    assert_eq!(out, json!("FOUND_FOO"), "actual = {out:?}");
}

#[test]
fn register_without_cwd_cannot_resolve_local_node_modules() {
    // Regression: the cwd-prelude is opt-in. Without `.cwd()`, the
    // require resolver walks from `/` (or whatever `__host_cwd` was
    // before the registration; default falls back to the host
    // process's cwd, which won't have a `foo` package). The same
    // registration that succeeded above must throw MODULE_NOT_FOUND.
    let _fixture = fixture_with_foo("UNREACHED");
    let ab = Afterburner::builder().build().expect("build");

    let id = ab
        .register(
            "module.exports = function() {\n\
                 try { return require('foo').marker; }\n\
                 catch (e) { return 'CAUGHT:' + (e.code || e.message || e); }\n\
             };",
        )
        .expect("register");
    let out = ab.run(&id, &json!(null)).expect("run");
    let s = out.as_str().unwrap_or("");
    assert!(
        s.starts_with("CAUGHT:"),
        "expected MODULE_NOT_FOUND but got {out:?}"
    );
    assert!(
        s.contains("MODULE_NOT_FOUND") || s.contains("Cannot find module"),
        "unexpected error message: {s}"
    );
}

#[test]
fn cwd_is_visible_as_host_cwd_global() {
    let fixture = fixture_with_foo("X");
    let want = fixture.path().to_string_lossy().into_owned();
    let ab = Afterburner::builder()
        .manifold(manifold_readable(fixture.path()))
        .cwd(fixture.path())
        .build()
        .expect("build");

    let id = ab
        .register("module.exports = function() { return globalThis.__host_cwd; };")
        .expect("register");
    let out = ab.run(&id, &json!(null)).expect("run");
    assert_eq!(out, json!(want), "actual = {out:?}");
}

#[test]
fn relative_require_inside_cwd_works() {
    // `./helper.js` inside the cwd-rooted node_modules tree resolves
    // relative to the loading file. This is the common pattern in
    // multi-file npm packages (express -> ./lib/router etc.).
    let fixture = fixture_with_foo("UNUSED");
    write_file(
        fixture.path(),
        "node_modules/foo/helper.js",
        "module.exports = { from_helper: 99 };\n",
    );
    write_file(
        fixture.path(),
        "node_modules/foo/index.js",
        "var h = require('./helper'); module.exports = { passthrough: h.from_helper };\n",
    );
    let ab = Afterburner::builder()
        .manifold(manifold_readable(fixture.path()))
        .cwd(fixture.path())
        .build()
        .expect("build");

    let id = ab
        .register("module.exports = function() { return require('foo').passthrough; };")
        .expect("register");
    let out = ab.run(&id, &json!(null)).expect("run");
    assert_eq!(out, json!(99), "actual = {out:?}");
}

#[test]
fn cwd_prelude_does_not_break_user_module_exports_pattern() {
    // Sanity: the prelude must not shadow the `module` / `exports` /
    // `require` bindings the wrapper passes. Test the canonical
    // `module.exports = ...` UDF shape and confirm the input flows
    // through.
    let fixture = fixture_with_foo("X");
    let ab = Afterburner::builder()
        .manifold(manifold_readable(fixture.path()))
        .cwd(fixture.path())
        .build()
        .expect("build");

    let id = ab
        .register("module.exports = function(input) { return { doubled: input.n * 2 }; };")
        .expect("register");
    let out = ab.run(&id, &json!({"n": 21})).expect("run");
    assert_eq!(out, json!({"doubled": 42}), "actual = {out:?}");
}
