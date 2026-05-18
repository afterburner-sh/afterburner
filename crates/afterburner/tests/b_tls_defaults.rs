// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `tls.DEFAULT_ECDH_CURVE` / `DEFAULT_CIPHERS` (Node 8+) and
//! `tls.CLIENT_RENEG_LIMIT` / `CLIENT_RENEG_WINDOW`.

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

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed. stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

#[test]
fn tls_default_ecdh_curve_is_auto() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        if (tls.DEFAULT_ECDH_CURVE === 'auto') console.log('ECDH-OK');
        else console.log('FAIL', tls.DEFAULT_ECDH_CURVE);
        "#,
    );
    assert_marker(&out, "ECDH-OK");
}

#[test]
fn tls_default_ciphers_lists_tls13_suites() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        const c = tls.DEFAULT_CIPHERS;
        if (typeof c === 'string' &&
            c.includes('TLS_AES_256_GCM_SHA384') &&
            c.includes('!aNULL'))
            console.log('CIPH-OK');
        else console.log('FAIL', c);
        "#,
    );
    assert_marker(&out, "CIPH-OK");
}

#[test]
fn tls_client_reneg_constants_present() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        if (tls.CLIENT_RENEG_LIMIT === 3 && tls.CLIENT_RENEG_WINDOW === 600)
            console.log('RENEG-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "RENEG-OK");
}
