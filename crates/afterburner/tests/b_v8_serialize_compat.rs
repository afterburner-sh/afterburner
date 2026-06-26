// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `v8.serialize` / `v8.deserialize` byte-format coverage.
//!
//! The wire format is V8 ValueSerializer (Node's `value-serializer.cc`),
//! version 15. These tests pin round-trip equivalence for the
//! discriminated value types Node emits + asserts the header bytes
//! match V8's spec so a Node consumer parsing burn's output gets
//! parsing parity for free.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(src)
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
        "burn failed.\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

// ---- header bytes match V8 spec -------------------------------------

#[test]
fn serialize_emits_v8_header_ff_then_version_15() {
    let out = run(r#"
        const buf = require('v8').serialize({a:1});
        if (buf[0] === 0xFF && buf[1] === 15) console.log('HEADER-OK');
    "#);
    assert_marker(&out, "HEADER-OK");
}

// ---- primitives -----------------------------------------------------

#[test]
fn primitives_round_trip() {
    let out = run(r#"
        const v8 = require('v8');
        const cases = [undefined, null, true, false, 0, -1, 2147483647, 0x7FFFFFFF, -3.14];
        let ok = 0;
        for (const c of cases) {
            const back = v8.deserialize(v8.serialize(c));
            if (Object.is(back, c)) ok++;
        }
        if (ok === cases.length) console.log('PRIM-OK');
        else console.log('FAIL', ok, '/', cases.length);
    "#);
    assert_marker(&out, "PRIM-OK");
}

#[test]
fn nan_infinity_double_special_values_preserved() {
    let out = run(r#"
        const v8 = require('v8');
        const a = v8.deserialize(v8.serialize(NaN));
        const b = v8.deserialize(v8.serialize(Infinity));
        const c = v8.deserialize(v8.serialize(-Infinity));
        if (Number.isNaN(a) && b === Infinity && c === -Infinity) console.log('SPECIAL-OK');
    "#);
    assert_marker(&out, "SPECIAL-OK");
}

// ---- strings --------------------------------------------------------

#[test]
fn ascii_string_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        const back = v8.deserialize(v8.serialize('hello, world'));
        if (back === 'hello, world') console.log('ASCII-OK');
    "#);
    assert_marker(&out, "ASCII-OK");
}

#[test]
fn unicode_string_round_trips_with_emoji() {
    let out = run(r#"
        const v8 = require('v8');
        const back = v8.deserialize(v8.serialize('café 🦀 ✨'));
        if (back === 'café 🦀 ✨') console.log('UNICODE-OK');
    "#);
    assert_marker(&out, "UNICODE-OK");
}

// ---- BigInt ---------------------------------------------------------

#[test]
fn bigint_positive_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        if (v8.deserialize(v8.serialize(42n)) === 42n) console.log('BIGINT-POS-OK');
    "#);
    assert_marker(&out, "BIGINT-POS-OK");
}

#[test]
fn bigint_negative_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        if (v8.deserialize(v8.serialize(-12345n)) === -12345n) console.log('BIGINT-NEG-OK');
    "#);
    assert_marker(&out, "BIGINT-NEG-OK");
}

#[test]
fn bigint_large_value_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        const big = (1n << 200n) - 1n;
        if (v8.deserialize(v8.serialize(big)) === big) console.log('BIGINT-LARGE-OK');
    "#);
    assert_marker(&out, "BIGINT-LARGE-OK");
}

// ---- compound -------------------------------------------------------

#[test]
fn plain_object_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        const back = v8.deserialize(v8.serialize({a:1, b:'two', c:[1,2,3]}));
        if (back.a === 1 && back.b === 'two' && back.c.length === 3) console.log('OBJ-OK');
    "#);
    assert_marker(&out, "OBJ-OK");
}

#[test]
fn dense_array_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        const back = v8.deserialize(v8.serialize([1,'two',3.14,true,null]));
        if (back.length === 5 && back[0] === 1 && back[1] === 'two'
            && back[3] === true && back[4] === null) console.log('ARR-OK');
    "#);
    assert_marker(&out, "ARR-OK");
}

#[test]
fn date_preserves_milliseconds_since_epoch() {
    let out = run(r#"
        const v8 = require('v8');
        const d = new Date(1700000000000);
        const back = v8.deserialize(v8.serialize(d));
        if (back instanceof Date && back.getTime() === d.getTime()) console.log('DATE-OK');
    "#);
    assert_marker(&out, "DATE-OK");
}

#[test]
fn regexp_preserves_pattern_and_flags() {
    let out = run(r#"
        const v8 = require('v8');
        const back = v8.deserialize(v8.serialize(/abc.def/gimsy));
        if (back instanceof RegExp && back.source === 'abc.def'
            && back.global && back.ignoreCase && back.multiline
            && back.dotAll && back.sticky) console.log('REGEXP-OK');
    "#);
    assert_marker(&out, "REGEXP-OK");
}

#[test]
fn map_preserves_keys_values_and_order() {
    let out = run(r#"
        const v8 = require('v8');
        const m = new Map([['k1', 1], ['k2', 'two'], [42, [1,2,3]]]);
        const back = v8.deserialize(v8.serialize(m));
        if (back instanceof Map && back.size === 3
            && back.get('k1') === 1 && back.get('k2') === 'two'
            && back.get(42).length === 3) console.log('MAP-OK');
    "#);
    assert_marker(&out, "MAP-OK");
}

#[test]
fn set_preserves_elements() {
    let out = run(r#"
        const v8 = require('v8');
        const s = new Set([1, 'two', 3.14, true]);
        const back = v8.deserialize(v8.serialize(s));
        if (back instanceof Set && back.size === 4 && back.has(1) && back.has('two')
            && back.has(3.14) && back.has(true)) console.log('SET-OK');
    "#);
    assert_marker(&out, "SET-OK");
}

// ---- binary types ---------------------------------------------------

#[test]
fn array_buffer_round_trips_raw_bytes() {
    let out = run(r#"
        const v8 = require('v8');
        const ab = new ArrayBuffer(8);
        new Uint8Array(ab).set([1,2,3,4,5,6,7,8]);
        const back = v8.deserialize(v8.serialize(ab));
        const u = new Uint8Array(back);
        if (back instanceof ArrayBuffer && u.length === 8 && u[0] === 1 && u[7] === 8)
            console.log('AB-OK');
    "#);
    assert_marker(&out, "AB-OK");
}

#[test]
fn typed_array_round_trips_with_view_kind() {
    let out = run(r#"
        const v8 = require('v8');
        const arr = new Int32Array([1, -1, 2147483647, -2147483648]);
        const back = v8.deserialize(v8.serialize(arr));
        if (back instanceof Int32Array && back.length === 4
            && back[0] === 1 && back[2] === 2147483647 && back[3] === -2147483648)
            console.log('I32-OK');
    "#);
    assert_marker(&out, "I32-OK");
}

#[test]
fn typed_array_float64_preserves_precision() {
    let out = run(r#"
        const v8 = require('v8');
        const arr = new Float64Array([1.1, 2.2, 3.3, Math.PI]);
        const back = v8.deserialize(v8.serialize(arr));
        if (back instanceof Float64Array && back.length === 4
            && back[0] === 1.1 && back[3] === Math.PI) console.log('F64-OK');
    "#);
    assert_marker(&out, "F64-OK");
}

#[test]
fn uint8_array_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        const arr = new Uint8Array([255, 0, 127, 1]);
        const back = v8.deserialize(v8.serialize(arr));
        if (back instanceof Uint8Array && back.length === 4
            && back[0] === 255 && back[1] === 0 && back[2] === 127) console.log('U8-OK');
    "#);
    assert_marker(&out, "U8-OK");
}

// ---- error reproduction ---------------------------------------------

#[test]
fn type_error_round_trips_with_message_and_class() {
    let out = run(r#"
        const v8 = require('v8');
        const back = v8.deserialize(v8.serialize(new TypeError('expected x')));
        if (back instanceof TypeError && back.message === 'expected x') console.log('ERR-OK');
    "#);
    assert_marker(&out, "ERR-OK");
}

#[test]
fn range_error_specific_subclass_preserved() {
    let out = run(r#"
        const v8 = require('v8');
        const back = v8.deserialize(v8.serialize(new RangeError('out')));
        if (back instanceof RangeError && back.message === 'out') console.log('RANGE-OK');
    "#);
    assert_marker(&out, "RANGE-OK");
}

// ---- nesting --------------------------------------------------------

#[test]
fn deeply_nested_mixed_value_round_trips() {
    let out = run(r#"
        const v8 = require('v8');
        const v = {
            a: 1,
            arr: [new Map([['k', new Set([1,2,3])]])],
            buf: new Uint8Array([1,2,3]),
            d: new Date(1700000000000),
            re: /x/g,
        };
        const back = v8.deserialize(v8.serialize(v));
        if (back.a === 1 && back.arr[0].get('k').has(2)
            && back.buf.length === 3 && back.d.getTime() === 1700000000000
            && back.re.source === 'x' && back.re.global)
            console.log('DEEP-OK');
        else console.log('FAIL', JSON.stringify(back, (k,v) => v?.constructor?.name || v));
    "#);
    assert_marker(&out, "DEEP-OK");
}

// ---- error path -----------------------------------------------------

#[test]
fn deserialize_truncated_input_throws() {
    let out = run(r#"
        const v8 = require('v8');
        try {
            v8.deserialize(Buffer.from([0xFF, 15, 0x22 /* one-byte string tag */, 0x10]));
            console.log('FAIL no-throw');
        } catch (_) {
            console.log('TRUNC-OK');
        }
    "#);
    assert_marker(&out, "TRUNC-OK");
}
