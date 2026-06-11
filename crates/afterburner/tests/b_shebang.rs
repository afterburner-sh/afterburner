// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Shebang / hashbang handling.
//!
//! QuickJS rejects a leading `#!` (it starts tokenising a private
//! field name and chokes on `!`). Node.js silently rewrites the line
//! to a comment before handing the source to V8. We do the same in
//! two spots:
//!
//! * `crates/afterburner-plugin/src/envelope.rs::wrap_*_source` —
//!   every script-mode / UDF wrap normalises the user source so the
//!   AsyncFunction body parses.
//! * `crates/afterburner-node-compat/polyfills/require.js` — every
//!   `require('./foo.js')` strips a hashbang on the loaded file
//!   before passing it to the CJS Function constructor.
//!
//! The replacement is length-preserving (`#!` → `//`) so error line
//! and column numbers still match the user's file. A leading UTF-8
//! BOM is also stripped on the require path.
//!
//! Without these fix-ups, anything with a `#!/usr/bin/env node`
//! prologue (every npm-installed CLI, the `npm` binary itself, and
//! many user scripts) trapped at daemon-init time with the cryptic
//! QuickJS message `invalid first character of private name`. This
//! is the regression spine for that path.

#![cfg(feature = "bin")]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn tmp_dir(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_shebang_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_script(dir: &Path, name: &str, contents: &[u8]) -> std::process::Output {
    let path = dir.join(name);
    let mut f = fs::File::create(&path).expect("create script");
    f.write_all(contents).expect("write script");
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

#[test]
fn entry_script_with_node_shebang_runs() {
    let dir = tmp_dir("entry_node_shebang");
    let out = run_script(
        &dir,
        "main.js",
        b"#!/usr/bin/env node\nconsole.log('shebang-ok');\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("shebang-ok"),
        "expected normal stdout, got: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("invalid first character of private name"),
        "shebang regression — QuickJS choked on `#!`: {stderr}"
    );
}

#[test]
fn entry_script_with_arbitrary_shebang_runs() {
    // Not just `#!/usr/bin/env node` — anything starting with `#!`
    // must be tolerated. Real-world Python wrappers, /bin/sh runners,
    // and one-off `#!ignore` test fixtures all hit the same path.
    let dir = tmp_dir("entry_arb_shebang");
    let out = run_script(
        &dir,
        "main.js",
        b"#!/this/is/whatever\nconsole.log('arb-shebang-ok');\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("arb-shebang-ok"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn shebang_preserves_line_numbers_in_errors() {
    // We replace `#!` with `//` (length-preserving) so error sites
    // still point at the same on-disk line a user editor shows. If we
    // ever switched to stripping the line outright, every stack trace
    // for any shebang'd script would shift by one — silently wrong.
    let dir = tmp_dir("shebang_lineno");
    let out = run_script(
        &dir,
        "main.js",
        b"#!/usr/bin/env node\n// line 2\nthrow new Error('boom-on-line-3');\n",
    );
    assert!(
        !out.status.success(),
        "should fail: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("boom-on-line-3"),
        "thrown message should reach stderr: {stderr}"
    );
}

#[test]
fn require_loads_file_with_shebang() {
    // `require('./helper.js')` must also tolerate a hashbang on the
    // loaded file — npm / pnpm / yarn / bun all import many CLI
    // entry points (every `node_modules/.../bin/*` script) by path,
    // and those scripts uniformly start with `#!/usr/bin/env node`.
    let dir = tmp_dir("require_shebang");
    fs::write(
        dir.join("helper.js"),
        b"#!/usr/bin/env node\nmodule.exports = function add(a, b) { return a + b; };\n",
    )
    .unwrap();
    let out = run_script(
        &dir,
        "main.js",
        b"const add = require('./helper.js');\nconsole.log('add(2,3)=', add(2, 3));\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("add(2,3)= 5"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn require_loads_file_with_utf8_bom() {
    // UTF-8 BOM (`\u{FEFF}`) at offset 0 is another silent killer:
    // if it survives into the QuickJS Function constructor body,
    // parsing fails on the invisible character. Matches Node's
    // `loader.js` behaviour, which strips BOM unconditionally.
    let dir = tmp_dir("require_bom");
    let mut helper = b"\xEF\xBB\xBF".to_vec();
    helper.extend_from_slice(b"module.exports = 'with-bom';\n");
    fs::write(dir.join("helper.js"), &helper).unwrap();
    let out = run_script(
        &dir,
        "main.js",
        b"const v = require('./helper.js');\nconsole.log('val:', v);\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("val: with-bom"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn require_loads_file_with_bom_and_shebang() {
    // Some toolchains (notably Windows-ported PowerShell-emitted
    // scripts) write BOM *and* a shebang. Both have to be peeled
    // off in order — BOM first, then `#!`.
    let dir = tmp_dir("require_bom_shebang");
    let mut helper = b"\xEF\xBB\xBF".to_vec();
    helper.extend_from_slice(b"#!/usr/bin/env node\nmodule.exports = 42;\n");
    fs::write(dir.join("helper.js"), &helper).unwrap();
    let out = run_script(
        &dir,
        "main.js",
        b"const v = require('./helper.js');\nconsole.log('val:', v);\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("val: 42"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn eval_mode_with_shebang_in_source() {
    // `burn -e CODE` is the CLI's eval path — it goes through the
    // same wrap_script_source envelope. Pasting a script-from-disk
    // inline (curl | sh style) often retains the shebang. Tolerate.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg("#!/usr/bin/env node\nconsole.log('eval-shebang-ok');\n")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("eval-shebang-ok"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn check_subcommand_accepts_shebang() {
    // `burn check FILE` parse+compiles without executing. Used by CI
    // gates / git pre-commit hooks. Hashbang must not turn a parseable
    // file into a phantom syntax error.
    let dir = tmp_dir("check_shebang");
    let path = dir.join("ok.js");
    fs::write(
        &path,
        b"#!/usr/bin/env node\nconst x = 1;\nmodule.exports = x;\n",
    )
    .unwrap();
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("check")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn check");
    assert!(
        out.status.success(),
        "burn check should accept shebang. stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(feature = "ts")]
#[test]
fn ts_file_with_shebang_runs() {
    // .ts files go through oxc strip-types BEFORE the envelope wrap,
    // and oxc accepts hashbang. The envelope-side fix-up still has to
    // catch them: oxc's codegen preserves hashbang in its output, so
    // QuickJS would still see `#!` without our normaliser.
    let dir = tmp_dir("ts_shebang");
    let out = run_script(
        &dir,
        "main.ts",
        b"#!/usr/bin/env node\nconst n: number = 7;\nconsole.log('ts-ok:', n);\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("ts-ok: 7"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn no_shebang_unchanged() {
    // Negative control: a normal file (no shebang, no BOM) must
    // still run. Easy to break by accident if normalise_shebang
    // ever returned an empty string for the no-prefix path.
    let dir = tmp_dir("no_shebang");
    let out = run_script(&dir, "main.js", b"console.log('plain-ok');\n");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("plain-ok"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn crypto_get_hashes_returns_supported_algorithms() {
    // ssri (transitive dep of npm/pnpm/yarn) calls `crypto.getHashes()`
    // at module-init time. Without it, every npm-related dispatch
    // crashes during require chain bootstrap with `TypeError: not a
    // function`. Pin the surface so we don't silently regress.
    let dir = tmp_dir("crypto_getHashes");
    let out = run_script(
        &dir,
        "main.js",
        br#"
            const crypto = require('crypto');
            const hashes = crypto.getHashes();
            if (!Array.isArray(hashes)) throw new Error('not an array');
            for (const h of ['md5','sha1','sha256','sha384','sha512']) {
                if (!hashes.includes(h)) throw new Error('missing ' + h);
            }
            const ciphers = crypto.getCiphers();
            if (!Array.isArray(ciphers) || !ciphers.includes('aes-256-gcm'))
                throw new Error('aes-256-gcm missing');
            console.log('crypto-catalogue-ok');
        "#,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("crypto-catalogue-ok"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
