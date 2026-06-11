// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `os.availableParallelism()` (Node 19+) and
//! `timers/promises.scheduler` / `setInterval` async-iterator
//! (Node 18+).

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
fn os_available_parallelism_returns_positive_integer() {
    let out = run_inline(
        r#"
        const n = require('os').availableParallelism();
        if (Number.isInteger(n) && n >= 1) console.log('AP-OK');
        else console.log('FAIL', n);
        "#,
    );
    assert_marker(&out, "AP-OK");
}

#[test]
fn timers_promises_scheduler_wait_resolves_after_delay() {
    let out = run_inline(
        r#"
        async function main() {
            const tp = require('timers/promises');
            const t0 = Date.now();
            await tp.scheduler.wait(40);
            const dt = Date.now() - t0;
            if (dt >= 30) console.log('TP-WAIT-OK');
            else console.log('FAIL', dt);
        }
        main();
        "#,
    );
    assert_marker(&out, "TP-WAIT-OK");
}

#[test]
fn timers_promises_scheduler_yield_returns_microtask() {
    let out = run_inline(
        r#"
        async function main() {
            const tp = require('timers/promises');
            let after = false;
            tp.scheduler.yield().then(() => { after = true; });
            await Promise.resolve();
            await Promise.resolve();
            if (after) console.log('YIELD-OK');
            else console.log('FAIL');
        }
        main();
        "#,
    );
    assert_marker(&out, "YIELD-OK");
}

#[test]
fn timers_promises_set_interval_async_iter_yields_until_abort() {
    let out = run_inline(
        r#"
        async function main() {
            const tp = require('timers/promises');
            const ac = new AbortController();
            setTimeout(() => ac.abort(), 80);
            let count = 0;
            for await (const _ of tp.setInterval(20, 'x', { signal: ac.signal })) {
                count++;
                if (count > 10) break;
            }
            if (count >= 2 && count <= 6) console.log('INT-OK');
            else console.log('FAIL', count);
        }
        main();
        "#,
    );
    assert_marker(&out, "INT-OK");
}
