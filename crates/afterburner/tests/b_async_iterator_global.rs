// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `AsyncIterator` global (Stage 3 / Node 22+).

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
fn async_iterator_global_is_function() {
    let out = run_inline(
        r#"
        if (typeof AsyncIterator === 'function') console.log('AI-FN-OK');
        else console.log('FAIL', typeof AsyncIterator);
        "#,
    );
    assert_marker(&out, "AI-FN-OK");
}

#[test]
fn async_generator_inherits_from_async_iterator_prototype() {
    let out = run_inline(
        r#"
        async function* gen() { yield 1; }
        const it = gen();
        if (it instanceof AsyncIterator) console.log('AI-INSTANCE-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "AI-INSTANCE-OK");
}

#[test]
fn async_iterator_direct_construction_throws() {
    let out = run_inline(
        r#"
        try { new AsyncIterator(); console.log('FAIL no-throw'); }
        catch (e) { if (e instanceof TypeError) console.log('CTOR-OK'); else console.log('FAIL', e.constructor.name); }
        "#,
    );
    assert_marker(&out, "CTOR-OK");
}

#[test]
fn async_iterator_from_iterable_yields_values() {
    let out = run_inline(
        r#"
        const ai = AsyncIterator.from([10, 20, 30]);
        (async () => {
            const got = [];
            for await (const v of ai) got.push(v);
            if (JSON.stringify(got) === '[10,20,30]') console.log('AI-FROM-OK');
            else console.log('FAIL', got);
        })();
        "#,
    );
    assert_marker(&out, "AI-FROM-OK");
}

#[test]
fn async_iterator_subclass_is_constructible() {
    let out = run_inline(
        r#"
        class MyAI extends AsyncIterator {
            constructor() { super(); this._n = 0; }
            async next() {
                if (this._n >= 3) return { value: undefined, done: true };
                return { value: this._n++, done: false };
            }
        }
        const it = new MyAI();
        (async () => {
            const got = [];
            for await (const v of it) got.push(v);
            if (JSON.stringify(got) === '[0,1,2]') console.log('AI-SUBCLASS-OK');
            else console.log('FAIL', got);
        })();
        "#,
    );
    assert_marker(&out, "AI-SUBCLASS-OK");
}
