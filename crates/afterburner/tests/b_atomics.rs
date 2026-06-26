// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `Atomics` single-threaded shim. Burn runs JS single-threaded
//! per shard; the spec atomics are degenerate but the operations
//! still need to work correctly on the typed-array (load/store/
//! add/sub/and/or/xor/exchange/compareExchange).

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
fn atomics_load_store_round_trips() {
    let out = run_inline(
        r#"
        const arr = new Int32Array(2);
        Atomics.store(arr, 0, 42);
        Atomics.store(arr, 1, 7);
        if (Atomics.load(arr, 0) === 42 && Atomics.load(arr, 1) === 7) console.log('LS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "LS-OK");
}

#[test]
fn atomics_add_sub_returns_old_value() {
    let out = run_inline(
        r#"
        const a = new Int32Array(1);
        Atomics.store(a, 0, 10);
        const old = Atomics.add(a, 0, 5);
        if (old === 10 && a[0] === 15) {
            const old2 = Atomics.sub(a, 0, 3);
            if (old2 === 15 && a[0] === 12) console.log('AS-OK');
            else console.log('FAIL2', old2, a[0]);
        } else console.log('FAIL', old, a[0]);
        "#,
    );
    assert_marker(&out, "AS-OK");
}

#[test]
fn atomics_compare_exchange_swaps_on_match() {
    let out = run_inline(
        r#"
        const a = new Int32Array(1);
        Atomics.store(a, 0, 42);
        const v = Atomics.compareExchange(a, 0, 42, 99);
        if (v === 42 && a[0] === 99) {
            const v2 = Atomics.compareExchange(a, 0, 0, 1);
            if (v2 === 99 && a[0] === 99) console.log('CAS-OK');
            else console.log('FAIL2', v2, a[0]);
        } else console.log('FAIL1', v, a[0]);
        "#,
    );
    assert_marker(&out, "CAS-OK");
}

#[test]
fn atomics_bitwise_ops() {
    let out = run_inline(
        r#"
        const a = new Int32Array(1);
        Atomics.store(a, 0, 0b1100);
        Atomics.and(a, 0, 0b1010);
        if (a[0] !== 0b1000) { console.log('FAIL and', a[0]); process.exit(1); }
        Atomics.or(a, 0, 0b0011);
        if (a[0] !== 0b1011) { console.log('FAIL or', a[0]); process.exit(1); }
        Atomics.xor(a, 0, 0b1111);
        if (a[0] !== 0b0100) { console.log('FAIL xor', a[0]); process.exit(1); }
        console.log('BIT-OK');
        "#,
    );
    assert_marker(&out, "BIT-OK");
}

#[test]
fn atomics_exchange_returns_old_value() {
    let out = run_inline(
        r#"
        const a = new Int32Array(1);
        Atomics.store(a, 0, 42);
        const old = Atomics.exchange(a, 0, 7);
        if (old === 42 && a[0] === 7) console.log('XCHG-OK');
        else console.log('FAIL', old, a[0]);
        "#,
    );
    assert_marker(&out, "XCHG-OK");
}

#[test]
fn atomics_is_lock_free_returns_true() {
    let out = run_inline(
        r#"
        if (Atomics.isLockFree(4) === true) console.log('LF-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "LF-OK");
}

#[test]
fn atomics_wait_throws_in_single_threaded() {
    let out = run_inline(
        r#"
        const a = new Int32Array(1);
        try {
            Atomics.wait(a, 0, 0);
            console.log('FAIL no-throw');
        } catch (_) { console.log('WAIT-THROWS-OK'); }
        "#,
    );
    assert_marker(&out, "WAIT-THROWS-OK");
}
