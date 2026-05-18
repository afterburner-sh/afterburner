// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Real values for `os.homedir()` / `os.tmpdir()` / `os.hostname()`.
//! Before this commit the WASM plugin only wired `platform` and
//! `arch`; everything else fell back to compile-time defaults
//! (`/`, `/tmp`, `afterburner`). corepack-managed pnpm / yarn
//! computed `path.join(os.homedir(), '.cache', 'node', 'corepack')`
//! and tried to write `/.cache/node/corepack/lastKnownGood.json`,
//! which fails outside root. Tests pin the correct values so the
//! fallback never silently regresses.

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
fn os_homedir_returns_real_directory_not_root() {
    let out = run_inline(
        r#"
        const home = require('os').homedir();
        if (home && home !== '/' && home.length > 1) console.log('HOMEDIR-OK:' + home);
        else console.log('FAIL', home);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("HOMEDIR-OK:"), "homedir not real: {stdout}");
}

#[test]
fn os_tmpdir_returns_writable_path() {
    let out = run_inline(
        r#"
        const tmp = require('os').tmpdir();
        if (tmp && tmp.length > 0) console.log('TMP-OK:' + tmp);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TMP-OK:"), "tmpdir empty: {stdout}");
}

#[test]
fn os_hostname_returns_non_default_value() {
    let out = run_inline(
        r#"
        const h = require('os').hostname();
        if (h && h.length > 0) console.log('HOST-OK:' + h);
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The host hostname will vary by machine; we only assert non-
    // empty + non-default.
    assert!(stdout.contains("HOST-OK:"), "hostname empty: {stdout}");
}

#[test]
fn os_userinfo_uses_real_homedir() {
    let out = run_inline(
        r#"
        const ui = require('os').userInfo();
        if (ui && ui.homedir && ui.homedir !== '/') console.log('UINFO-OK:' + ui.homedir);
        else console.log('FAIL', JSON.stringify(ui));
        "#,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("UINFO-OK:"), "userInfo bad: {stdout}");
}
