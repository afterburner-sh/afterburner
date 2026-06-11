// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `fs.Stats` / `fs.StatFs` / `fs.ReadStream` / `fs.WriteStream`
//! constructor surface — real apps probe these classes at module
//! init for `instanceof` checks.

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
fn fs_stats_class_is_constructable_with_default_predicates() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        const s = new fs.Stats();
        if (s.isFile() === false && s.isDirectory() === false &&
            s.isSymbolicLink() === false && s.isCharacterDevice() === false) {
            console.log('STATS-OK');
        } else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "STATS-OK");
}

#[test]
fn fs_statfs_class_is_constructable() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        const sf = new fs.StatFs();
        if (typeof sf.bsize === 'number' && typeof sf.blocks === 'number') console.log('STATFS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "STATFS-OK");
}

#[test]
fn fs_read_stream_class_extends_readable() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        const stream = require('stream');
        if (typeof fs.ReadStream === 'function' &&
            (fs.ReadStream.prototype instanceof stream.Readable ||
             Object.getPrototypeOf(fs.ReadStream.prototype) === stream.Readable.prototype)) {
            console.log('READSTREAM-OK');
        } else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "READSTREAM-OK");
}

#[test]
fn fs_write_stream_class_extends_writable() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        const stream = require('stream');
        if (typeof fs.WriteStream === 'function' &&
            (fs.WriteStream.prototype instanceof stream.Writable ||
             Object.getPrototypeOf(fs.WriteStream.prototype) === stream.Writable.prototype)) {
            console.log('WRITESTREAM-OK');
        } else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "WRITESTREAM-OK");
}

#[test]
fn fs_file_aliases_match_canonical_classes() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        if (fs.FileReadStream === fs.ReadStream && fs.FileWriteStream === fs.WriteStream)
            console.log('ALIAS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "ALIAS-OK");
}
