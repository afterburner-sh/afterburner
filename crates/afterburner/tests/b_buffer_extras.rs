// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `Buffer.copyBytesFrom` (Node 19+) / `Buffer.allocUnsafeSlow` /
//! `Buffer.poolSize`.

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
fn buffer_compare_returns_signed_byte_order() {
    let out = run_inline(
        r#"
        const a = Buffer.from('abc');
        const b = Buffer.from('abd');
        if (Buffer.compare(a, b) < 0 && Buffer.compare(b, a) > 0 && Buffer.compare(a, a) === 0)
            console.log('CMP-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CMP-OK");
}

#[test]
fn buffer_subarray_returns_decodable_buffer() {
    // `Buffer.subarray()` MUST return a Buffer (not a bare Uint8Array)
    // so the returned view still decodes via `.toString(encoding)`.
    // The `tar` package — and many npm deps — read header fields with
    // `buf.subarray(off, end).toString('utf8')`; a bare Uint8Array
    // there yields comma-joined byte values ("68,69,70") instead of
    // "DEF", which made every tar checksum parse as garbage and broke
    // `npm install` tarball extraction.
    let out = run_inline(
        r#"
        const b = Buffer.from('ABCDEFGHIJ');
        const s = b.subarray(3, 6);
        const ok = s.toString('utf8') === 'DEF'
            && Buffer.isBuffer(s)
            && s.toString('hex') === '444546'
            && b.subarray(3).toString('utf8') === 'DEFGHIJ'
            && b.subarray(3, 6).toString('ascii') === 'DEF';
        console.log(ok ? 'SUBARRAY-OK' : ('FAIL:' + JSON.stringify(s.toString('utf8'))));
        "#,
    );
    assert_marker(&out, "SUBARRAY-OK");
}

#[test]
fn buffer_is_encoding_recognises_canonical_set() {
    let out = run_inline(
        r#"
        if (Buffer.isEncoding('utf8') && Buffer.isEncoding('UTF-8') &&
            Buffer.isEncoding('hex') && Buffer.isEncoding('base64') &&
            Buffer.isEncoding('latin1') && !Buffer.isEncoding('xyz') &&
            !Buffer.isEncoding(123)) console.log('ENC-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "ENC-OK");
}

#[test]
fn buffer_swap16_reverses_byte_pairs() {
    let out = run_inline(
        r#"
        const b = Buffer.from([1, 2, 3, 4, 5, 6]);
        b.swap16();
        if (Array.from(b).join(',') === '2,1,4,3,6,5') console.log('SW16-OK');
        else console.log('FAIL', Array.from(b).join(','));
        "#,
    );
    assert_marker(&out, "SW16-OK");
}

#[test]
fn buffer_swap32_reverses_byte_quads() {
    let out = run_inline(
        r#"
        const b = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
        b.swap32();
        if (Array.from(b).join(',') === '4,3,2,1,8,7,6,5') console.log('SW32-OK');
        else console.log('FAIL', Array.from(b).join(','));
        "#,
    );
    assert_marker(&out, "SW32-OK");
}

#[test]
fn buffer_swap16_rejects_odd_length() {
    let out = run_inline(
        r#"
        const b = Buffer.from([1, 2, 3]);
        try {
            b.swap16();
            console.log('FAIL no-throw');
        } catch (_) { console.log('SW-RANGE-OK'); }
        "#,
    );
    assert_marker(&out, "SW-RANGE-OK");
}

#[test]
fn buffer_pool_size_is_node_default() {
    let out = run_inline(
        r#"
        if (Buffer.poolSize === 8192) console.log('POOL-OK');
        else console.log('FAIL', Buffer.poolSize);
        "#,
    );
    assert_marker(&out, "POOL-OK");
}

#[test]
fn buffer_alloc_unsafe_slow_returns_buffer_of_size() {
    let out = run_inline(
        r#"
        const b = Buffer.allocUnsafeSlow(64);
        if (Buffer.isBuffer(b) && b.length === 64) console.log('AUS-OK');
        else console.log('FAIL', b.length);
        "#,
    );
    assert_marker(&out, "AUS-OK");
}

#[test]
fn buffer_copy_bytes_from_uint8array_full() {
    let out = run_inline(
        r#"
        const src = new Uint8Array([1, 2, 3, 4, 5]);
        const b = Buffer.copyBytesFrom(src);
        if (b.length === 5 && b[0] === 1 && b[4] === 5) console.log('CB-FULL-OK');
        else console.log('FAIL', Array.from(b));
        "#,
    );
    assert_marker(&out, "CB-FULL-OK");
}

#[test]
fn buffer_copy_bytes_from_uint8array_with_offset_and_length() {
    let out = run_inline(
        r#"
        const src = new Uint8Array([10, 20, 30, 40, 50]);
        const b = Buffer.copyBytesFrom(src, 1, 3);
        if (b.length === 3 && b[0] === 20 && b[1] === 30 && b[2] === 40)
            console.log('CB-SLICE-OK');
        else console.log('FAIL', Array.from(b));
        "#,
    );
    assert_marker(&out, "CB-SLICE-OK");
}

#[test]
fn buffer_copy_bytes_from_uint32array_uses_byte_count() {
    let out = run_inline(
        r#"
        // Two u32 elements (8 bytes), little-endian: 1, 2
        const src = new Uint32Array([1, 2, 3]);
        const b = Buffer.copyBytesFrom(src, 0, 2);
        if (b.length === 8 && b.readUInt32LE(0) === 1 && b.readUInt32LE(4) === 2)
            console.log('CB-U32-OK');
        else console.log('FAIL', b.length);
        "#,
    );
    assert_marker(&out, "CB-U32-OK");
}

#[test]
fn buffer_copy_bytes_from_invalid_view_throws() {
    let out = run_inline(
        r#"
        try {
            Buffer.copyBytesFrom({});
            console.log('FAIL no-throw');
        } catch (_) { console.log('TYPE-OK'); }
        "#,
    );
    assert_marker(&out, "TYPE-OK");
}
