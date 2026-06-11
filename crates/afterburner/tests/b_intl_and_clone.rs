// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Minimal Intl stubs + type-preserving structuredClone.
//!
//! QuickJS doesn't ship ICU, so full Intl conformance isn't on the
//! menu. The polyfill covers the constructors real apps probe at
//! module init (`typeof Intl !== 'undefined'`) plus the canonical
//! English-locale code paths so `new Intl.NumberFormat()` and
//! friends produce sensible output. Non-en locales fall back to the
//! same English formatting; `resolvedOptions().locale` reflects what
//! the caller asked for.
//!
//! structuredClone now preserves Date / Map / Set / TypedArray /
//! ArrayBuffer / RegExp / Error rather than flattening through
//! JSON.

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

// ---- Intl ----------------------------------------------------------

#[test]
fn intl_number_format_groups_thousands() {
    let out = run_inline(
        r#"
        const s = new Intl.NumberFormat('en-US').format(1234567.89);
        if (s === '1,234,567.89') console.log('NF-OK');
        else console.log('FAIL', s);
        "#,
    );
    assert_marker(&out, "NF-OK");
}

#[test]
fn intl_plural_rules_select_one_and_other() {
    let out = run_inline(
        r#"
        const pr = new Intl.PluralRules();
        if (pr.select(1) === 'one' && pr.select(2) === 'other' && pr.select(0) === 'other')
            console.log('PR-OK');
        else console.log('FAIL', pr.select(1), pr.select(2), pr.select(0));
        "#,
    );
    assert_marker(&out, "PR-OK");
}

#[test]
fn intl_relative_time_format_emits_canonical_phrases() {
    let out = run_inline(
        r#"
        const r = new Intl.RelativeTimeFormat();
        if (r.format(-3, 'day') === '3 days ago' && r.format(2, 'hour') === 'in 2 hours' &&
            r.format(0, 'minute') === 'this minute') {
            console.log('RTF-OK');
        } else {
            console.log('FAIL', r.format(-3, 'day'), '|', r.format(2, 'hour'), '|', r.format(0, 'minute'));
        }
        "#,
    );
    assert_marker(&out, "RTF-OK");
}

#[test]
fn intl_list_format_conjoins_with_and() {
    let out = run_inline(
        r#"
        const lf = new Intl.ListFormat();
        if (lf.format(['a']) === 'a' &&
            lf.format(['a','b']) === 'a and b' &&
            lf.format(['a','b','c']) === 'a, b, and c') console.log('LF-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "LF-OK");
}

#[test]
fn intl_collator_compare_returns_signed_int() {
    let out = run_inline(
        r#"
        const c = new Intl.Collator();
        if (c.compare('a', 'b') < 0 && c.compare('b', 'a') > 0 && c.compare('a', 'a') === 0)
            console.log('COL-OK');
        else console.log('FAIL', c.compare('a', 'b'));
        "#,
    );
    assert_marker(&out, "COL-OK");
}

#[test]
fn intl_segmenter_word_grain_emits_segments() {
    let out = run_inline(
        r#"
        const seg = new Intl.Segmenter('en-US', { granularity: 'word' });
        const tokens = [];
        for (const t of seg.segment('hi there friend')) tokens.push(t.segment);
        if (tokens.length >= 3 && tokens.includes('hi') && tokens.includes('friend'))
            console.log('SEG-OK');
        else console.log('FAIL', JSON.stringify(tokens));
        "#,
    );
    assert_marker(&out, "SEG-OK");
}

#[test]
fn intl_get_canonical_locales_returns_array() {
    let out = run_inline(
        r#"
        const c = Intl.getCanonicalLocales(['en-US', 'fr-FR']);
        if (Array.isArray(c) && c.length === 2 && c[0] === 'en-US') console.log('GCL-OK');
        else console.log('FAIL', JSON.stringify(c));
        "#,
    );
    assert_marker(&out, "GCL-OK");
}

// ---- structuredClone -----------------------------------------------

#[test]
fn structured_clone_preserves_typed_array_constructor() {
    let out = run_inline(
        r#"
        const u = new Uint8Array([1, 2, 3]);
        const c = structuredClone(u);
        if (c instanceof Uint8Array && c.length === 3 && c[0] === 1 && c[2] === 3) console.log('TA-OK');
        else console.log('FAIL', c.constructor && c.constructor.name);
        "#,
    );
    assert_marker(&out, "TA-OK");
}

#[test]
fn structured_clone_preserves_map_keys_and_values() {
    let out = run_inline(
        r#"
        const m = new Map();
        m.set('k', 'v');
        m.set(42, [1, 2, 3]);
        const c = structuredClone(m);
        if (c instanceof Map && c.get('k') === 'v' && Array.isArray(c.get(42)) && c.get(42)[2] === 3)
            console.log('MAP-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "MAP-OK");
}

#[test]
fn structured_clone_preserves_set() {
    let out = run_inline(
        r#"
        const s = new Set([1, 2, 3]);
        const c = structuredClone(s);
        if (c instanceof Set && c.has(1) && c.has(2) && c.has(3) && c.size === 3) console.log('SET-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SET-OK");
}

#[test]
fn structured_clone_preserves_date_value() {
    let out = run_inline(
        r#"
        const d = new Date(1700000000000);
        const c = structuredClone(d);
        if (c instanceof Date && c.getTime() === d.getTime()) console.log('DATE-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "DATE-OK");
}

#[test]
fn structured_clone_does_not_share_inner_buffers() {
    let out = run_inline(
        r#"
        const u = new Uint8Array([10, 20, 30]);
        const c = structuredClone(u);
        c[0] = 99;
        if (u[0] === 10 && c[0] === 99) console.log('ISO-OK');
        else console.log('FAIL', u[0], c[0]);
        "#,
    );
    assert_marker(&out, "ISO-OK");
}

#[test]
fn structured_clone_preserves_regexp() {
    let out = run_inline(
        r#"
        const r = /abc/gi;
        const c = structuredClone(r);
        if (c instanceof RegExp && c.source === 'abc' && c.flags === 'gi') console.log('RE-OK');
        else console.log('FAIL', c.source, c.flags);
        "#,
    );
    assert_marker(&out, "RE-OK");
}
