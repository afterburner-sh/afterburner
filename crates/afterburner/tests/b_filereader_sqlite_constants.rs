// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `globalThis.FileReader` (Web API, Node 23+ global) and
//! `node:sqlite` SQLITE_CHANGESET_* constants (Node 22+).

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
fn file_reader_global_is_function() {
    let out = run_inline(
        r#"
        if (typeof FileReader === 'function' && FileReader.EMPTY === 0 &&
            FileReader.LOADING === 1 && FileReader.DONE === 2)
            console.log('FR-FN-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "FR-FN-OK");
}

#[test]
fn file_reader_read_as_text_fires_load() {
    let out = run_inline(
        r#"
        const blob = new Blob(['hello world'], { type: 'text/plain' });
        const fr = new FileReader();
        fr.onload = () => {
            if (fr.result === 'hello world' && fr.readyState === 2)
                console.log('FR-TEXT-OK');
            else console.log('FAIL', JSON.stringify(fr.result));
        };
        fr.readAsText(blob);
        "#,
    );
    assert_marker(&out, "FR-TEXT-OK");
}

#[test]
fn file_reader_read_as_data_url_emits_b64() {
    let out = run_inline(
        r#"
        const blob = new Blob(['hi'], { type: 'text/plain' });
        const fr = new FileReader();
        fr.onloadend = () => {
            if (fr.result.indexOf('data:text/plain;base64,') === 0 &&
                fr.result.indexOf('aGk=') !== -1)
                console.log('FR-DURL-OK');
            else console.log('FAIL', fr.result);
        };
        fr.readAsDataURL(blob);
        "#,
    );
    assert_marker(&out, "FR-DURL-OK");
}

#[test]
fn file_reader_read_as_array_buffer() {
    let out = run_inline(
        r#"
        const blob = new Blob(['abc'], { type: 'text/plain' });
        const fr = new FileReader();
        fr.onload = () => {
            if (fr.result instanceof ArrayBuffer && fr.result.byteLength === 3)
                console.log('FR-AB-OK');
            else console.log('FAIL', fr.result);
        };
        fr.readAsArrayBuffer(blob);
        "#,
    );
    assert_marker(&out, "FR-AB-OK");
}

#[test]
fn sqlite_changeset_constants_present() {
    let out = run_inline(
        r#"
        const sqlite = require('node:sqlite');
        if (sqlite.SQLITE_CHANGESET_OMIT === 0 &&
            sqlite.SQLITE_CHANGESET_REPLACE === 1 &&
            sqlite.SQLITE_CHANGESET_ABORT === 2 &&
            sqlite.SQLITE_CHANGESET_NOTFOUND === 2 &&
            sqlite.SQLITE_CHANGESET_CONFLICT === 3)
            console.log('SQLITE-CONST-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SQLITE-CONST-OK");
}
