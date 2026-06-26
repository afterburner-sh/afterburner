// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Stage-3 Iterator Helpers - `Iterator.from`, plus
//! `Iterator.prototype.{map,filter,take,drop,reduce,toArray,forEach,
//! every,some,find,flatMap}`.

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", src])
        .output()
        .expect("spawn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains(marker),
        "missing `{marker}`\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn iterator_from_basic() {
    let src = r#"
        const it = Iterator.from([10, 20, 30]);
        const arr = it.toArray();
        if (JSON.stringify(arr) !== '[10,20,30]') {
            console.error('arr=', JSON.stringify(arr)); process.exit(2);
        }
        console.log('FROM_OK');
    "#;
    assert_marker(&run_inline(src), "FROM_OK");
}

#[test]
#[serial]
fn iterator_map_filter_take() {
    let src = r#"
        function* nat() { let i = 1; while (true) yield i++; }
        const it = Iterator.from(nat()).map(x => x * x).filter(x => x % 2 === 1).take(4);
        const arr = it.toArray();
        if (JSON.stringify(arr) !== '[1,9,25,49]') {
            console.error('arr=', JSON.stringify(arr)); process.exit(2);
        }
        console.log('CHAIN_OK');
    "#;
    assert_marker(&run_inline(src), "CHAIN_OK");
}

#[test]
#[serial]
fn iterator_drop_reduce_forEach_flatMap() {
    let src = r#"
        const drops = Iterator.from([1,2,3,4,5]).drop(2).toArray();
        if (JSON.stringify(drops) !== '[3,4,5]') {
            console.error('drop:', drops); process.exit(2);
        }
        const sum = Iterator.from([1,2,3,4]).reduce((a,b) => a + b, 10);
        if (sum !== 20) { console.error('sum=', sum); process.exit(3); }
        const seen = [];
        Iterator.from(['a','b','c']).forEach((v, i) => seen.push(i + ':' + v));
        if (JSON.stringify(seen) !== '["0:a","1:b","2:c"]') {
            console.error('forEach:', seen); process.exit(4);
        }
        const flat = Iterator.from([1,2,3]).flatMap(x => [x, x*10]).toArray();
        if (JSON.stringify(flat) !== '[1,10,2,20,3,30]') {
            console.error('flat:', flat); process.exit(5);
        }
        console.log('TERMINALS_OK');
    "#;
    assert_marker(&run_inline(src), "TERMINALS_OK");
}

#[test]
#[serial]
fn iterator_every_some_find() {
    let src = r#"
        const all = Iterator.from([2,4,6]).every(x => x % 2 === 0);
        if (all !== true) { console.error('every:', all); process.exit(2); }
        const any = Iterator.from([1,2,3]).some(x => x > 2);
        if (any !== true) { console.error('some:', any); process.exit(3); }
        const found = Iterator.from([10,20,30,40]).find(x => x > 15);
        if (found !== 20) { console.error('find:', found); process.exit(4); }
        const noMatch = Iterator.from([1,2,3]).find(x => x > 99);
        if (noMatch !== undefined) { console.error('noMatch:', noMatch); process.exit(5); }
        console.log('PRED_OK');
    "#;
    assert_marker(&run_inline(src), "PRED_OK");
}
