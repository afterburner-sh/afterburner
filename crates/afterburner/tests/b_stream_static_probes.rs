// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `stream.isDisturbed` / `isErrored` / `isReadable` (Node 16+) and
//! `stream.{get,set}DefaultHighWaterMark` (Node 19.9+).

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
fn stream_is_readable_on_fresh_pass_through() {
    let out = run_inline(
        r#"
        const { PassThrough, isReadable } = require('stream');
        const p = new PassThrough();
        if (isReadable(p) === true && isReadable(null) === false &&
            isReadable({}) === false)
            console.log('IS-READABLE-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "IS-READABLE-OK");
}

#[test]
fn stream_is_errored_after_destroy_with_error() {
    let out = run_inline(
        r#"
        const { Readable, isErrored } = require('stream');
        const r = new Readable({ read() {} });
        if (isErrored(r) === false) {
            r.destroy(new Error('boom'));
            // destroy is async; emit happens on nextTick
            setTimeout(() => {
                if (isErrored(r) === true) console.log('ERRORED-OK');
                else console.log('FAIL after-destroy', !!r.errored);
            }, 10);
        } else console.log('FAIL pre-destroy');
        "#,
    );
    assert_marker(&out, "ERRORED-OK");
}

#[test]
fn stream_get_default_high_water_mark_byte_and_object() {
    let out = run_inline(
        r#"
        const s = require('stream');
        const byte = s.getDefaultHighWaterMark(false);
        const obj = s.getDefaultHighWaterMark(true);
        if (byte === 16384 && obj === 16) console.log('HWM-DEFAULT-OK');
        else console.log('FAIL', byte, obj);
        "#,
    );
    assert_marker(&out, "HWM-DEFAULT-OK");
}

#[test]
fn stream_set_default_high_water_mark_round_trips() {
    let out = run_inline(
        r#"
        const s = require('stream');
        s.setDefaultHighWaterMark(false, 8192);
        s.setDefaultHighWaterMark(true, 32);
        if (s.getDefaultHighWaterMark(false) === 8192 &&
            s.getDefaultHighWaterMark(true) === 32)
            console.log('HWM-SET-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "HWM-SET-OK");
}

#[test]
fn stream_set_default_high_water_mark_rejects_zero() {
    let out = run_inline(
        r#"
        const s = require('stream');
        try { s.setDefaultHighWaterMark(false, 0); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_OUT_OF_RANGE') console.log('REJECT-OK'); else console.log('FAIL wrong-code', e.code); }
        "#,
    );
    assert_marker(&out, "REJECT-OK");
}
