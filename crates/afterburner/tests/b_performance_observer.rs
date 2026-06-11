// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `PerformanceObserver` / `PerformanceEntry` / `PerformanceMark` /
//! `PerformanceMeasure` / `PerformanceObserverEntryList` — Web
//! Performance API for subscribing to mark/measure events.

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
fn performance_observer_constructor_and_supported_entry_types() {
    let out = run_inline(
        r#"
        if (typeof PerformanceObserver === 'function' &&
            Array.isArray(PerformanceObserver.supportedEntryTypes) &&
            PerformanceObserver.supportedEntryTypes.includes('mark')) console.log('PO-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "PO-OK");
}

#[test]
fn performance_observer_fires_for_marks() {
    let out = run_inline(
        r#"
        const seen = [];
        const obs = new PerformanceObserver(list => {
            list.getEntries().forEach(e => seen.push(e.name));
        });
        obs.observe({ entryTypes: ['mark'] });
        performance.mark('a');
        performance.mark('b');
        setTimeout(() => {
            obs.disconnect();
            if (seen.includes('a') && seen.includes('b')) console.log('FIRE-OK');
            else console.log('FAIL', JSON.stringify(seen));
            process.exit(0);
        }, 100);
        "#,
    );
    assert_marker(&out, "FIRE-OK");
}

#[test]
fn performance_observer_buffered_replays_existing_entries() {
    let out = run_inline(
        r#"
        performance.mark('pre1');
        performance.mark('pre2');
        const seen = [];
        const obs = new PerformanceObserver(list => {
            list.getEntries().forEach(e => seen.push(e.name));
        });
        obs.observe({ entryTypes: ['mark'], buffered: true });
        setTimeout(() => {
            obs.disconnect();
            if (seen.includes('pre1') && seen.includes('pre2')) console.log('BUF-OK');
            else console.log('FAIL', JSON.stringify(seen));
            process.exit(0);
        }, 100);
        "#,
    );
    assert_marker(&out, "BUF-OK");
}

#[test]
fn performance_observer_disconnect_stops_callbacks() {
    let out = run_inline(
        r#"
        let count = 0;
        const obs = new PerformanceObserver(list => { count += list.getEntries().length; });
        obs.observe({ entryTypes: ['mark'] });
        performance.mark('one');
        setTimeout(() => {
            obs.disconnect();
            performance.mark('two');
            setTimeout(() => {
                if (count === 1) console.log('DISC-OK');
                else console.log('FAIL', count);
                process.exit(0);
            }, 50);
        }, 50);
        "#,
    );
    assert_marker(&out, "DISC-OK");
}

#[test]
fn performance_entry_classes_exist() {
    let out = run_inline(
        r#"
        if (typeof PerformanceEntry === 'function' && typeof PerformanceMark === 'function' &&
            typeof PerformanceMeasure === 'function' && typeof PerformanceObserverEntryList === 'function')
            console.log('CLASSES-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CLASSES-OK");
}
