// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Node-compat prerequisites that `burn npm install` exercises and that
//! had silently-broken implementations. Each of these blocked the npm
//! pipeline at a different stage; they're isolated here as fast,
//! network-free regression tests (the live-registry integration lives
//! in `b_npm_install_e2e`, which is `#[ignore]`'d).
//!
//! * `util.formatWithOptions` — npm formats ALL of its output/logs
//!   through this; when it was missing, `npm.load()` threw and npm
//!   silently produced no output and did nothing.
//! * package.json `exports` **subpath** resolution — npm deps like
//!   `@sigstore/protobuf-specs/rekor/v2` resolve only through the
//!   `exports` map; the legacy `main`/index resolver couldn't reach
//!   them (`MODULE_NOT_FOUND`).
//! * `exports` **condition** priority — for a CJS `require()`, the
//!   `require`/`node` conditions must win over `import`; dual-build
//!   packages (glob: import→esm, require→commonjs) otherwise loaded
//!   their ESM build and failed to parse.

#![cfg(feature = "bin")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn fresh(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_prereq_{label}_{pid}_{n}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_in(dir: &PathBuf, code: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .current_dir(dir)
        .args(["-A", "-e", code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "burn failed. stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains(marker), "missing `{marker}`. stdout={stdout}\nstderr={stderr}");
}

#[test]
fn util_format_with_options_formats_like_format() {
    let dir = fresh("fwo");
    let out = run_in(
        &dir,
        r#"
        const util = require('util');
        if (typeof util.formatWithOptions !== 'function') { console.log('FAIL: missing'); }
        else {
          const r = util.formatWithOptions({ colors: false }, 'a %s b %d c %j', 'X', 5, { k: 1 });
          console.log(r === 'a X b 5 c {"k":1}' ? 'FWO-OK' : ('FAIL:' + r));
        }
        "#,
    );
    assert_marker(&out, "FWO-OK");
}

#[test]
fn exports_subpath_resolves_through_exports_map() {
    let dir = fresh("exp");
    let pkg = dir.join("node_modules/@scope/pkg");
    fs::create_dir_all(pkg.join("dist")).unwrap();
    fs::write(
        pkg.join("package.json"),
        r#"{"name":"@scope/pkg","exports":{".":"./dist/index.js","./sub/deep":"./dist/deep.js"}}"#,
    )
    .unwrap();
    fs::write(pkg.join("dist/index.js"), "module.exports = 'MAIN';").unwrap();
    fs::write(pkg.join("dist/deep.js"), "module.exports = 'DEEP';").unwrap();
    let out = run_in(
        &dir,
        r#"
        const main = require('@scope/pkg');
        const deep = require('@scope/pkg/sub/deep');
        console.log((main === 'MAIN' && deep === 'DEEP') ? 'EXP-OK' : ('FAIL:' + main + '/' + deep));
        "#,
    );
    assert_marker(&out, "EXP-OK");
}

#[test]
fn exports_conditions_prefer_require_over_import() {
    // Dual-build package: `import` points at an ESM file, `require` at
    // the CommonJS file. A `require()` must resolve to the CJS build
    // regardless of key order in the package.json (glob lists `import`
    // first).
    let dir = fresh("cond");
    let pkg = dir.join("node_modules/dual");
    fs::create_dir_all(pkg.join("dist")).unwrap();
    fs::write(
        pkg.join("package.json"),
        r#"{"name":"dual","exports":{".":{"import":"./dist/esm.js","require":"./dist/cjs.js"}}}"#,
    )
    .unwrap();
    fs::write(pkg.join("dist/esm.js"), "export default 'ESM';").unwrap();
    fs::write(pkg.join("dist/cjs.js"), "module.exports = 'CJS';").unwrap();
    let out = run_in(
        &dir,
        r#"
        const m = require('dual');
        console.log(m === 'CJS' ? 'COND-OK' : ('FAIL:' + JSON.stringify(m)));
        "#,
    );
    assert_marker(&out, "COND-OK");
}

#[test]
fn exports_pattern_subpath_resolves() {
    // Wildcard subpath export: "./features/*" -> "./dist/features/*.js"
    let dir = fresh("pat");
    let pkg = dir.join("node_modules/patpkg");
    fs::create_dir_all(pkg.join("dist/features")).unwrap();
    fs::write(
        pkg.join("package.json"),
        r#"{"name":"patpkg","exports":{"./features/*":"./dist/features/*.js"}}"#,
    )
    .unwrap();
    fs::write(pkg.join("dist/features/alpha.js"), "module.exports = 'ALPHA';").unwrap();
    let out = run_in(
        &dir,
        r#"
        const a = require('patpkg/features/alpha');
        console.log(a === 'ALPHA' ? 'PAT-OK' : ('FAIL:' + a));
        "#,
    );
    assert_marker(&out, "PAT-OK");
}

#[test]
fn require_parse_error_names_the_module() {
    // A SyntaxError in a required module must name the offending file.
    // Without it, a broken dependency surfaces as a bare "Unexpected
    // token …" with no hint which file is at fault — the diagnostic
    // that made the Buffer.subarray/tar bug findable in the first place.
    let dir = fresh("parseerr");
    let pkg = dir.join("node_modules/brokenpkg");
    fs::create_dir_all(&pkg).unwrap();
    fs::write(pkg.join("package.json"), r#"{"name":"brokenpkg","main":"index.js"}"#).unwrap();
    // `const = 5;` is a hard parse error (missing binding identifier).
    fs::write(pkg.join("index.js"), "const = 5;\n").unwrap();
    let out = run_in(
        &dir,
        r#"
        try {
          require('brokenpkg');
          console.log('NO-THROW');
        } catch (e) {
          var m = String((e && e.message) || e);
          console.log(/brokenpkg[\/\\]index\.js/.test(m) ? 'NAMED-OK' : ('FAIL:' + m));
        }
        "#,
    );
    assert_marker(&out, "NAMED-OK");
}
