// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `scheduler.wait` / `scheduler.postTask` / `DisposableStack` /
//! `AsyncDisposableStack` / `reportError` - Node 22+ globals around
//! task scheduling and explicit resource management.

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
fn scheduler_wait_resolves_after_delay() {
    let out = run_inline(
        r#"
        async function main() {
            const t0 = performance.now();
            await scheduler.wait(50);
            const dt = performance.now() - t0;
            if (dt >= 30) console.log('WAIT-OK');
            else console.log('FAIL', dt);
        }
        main();
        "#,
    );
    assert_marker(&out, "WAIT-OK");
}

#[test]
fn scheduler_wait_rejects_on_signal_abort() {
    let out = run_inline(
        r#"
        async function main() {
            const ac = new AbortController();
            queueMicrotask(() => ac.abort());
            try {
                await scheduler.wait(1000, { signal: ac.signal });
                console.log('FAIL no-throw');
            } catch (_) { console.log('WAIT-ABORT-OK'); }
        }
        main();
        "#,
    );
    assert_marker(&out, "WAIT-ABORT-OK");
}

#[test]
fn scheduler_post_task_resolves_with_callback_return() {
    let out = run_inline(
        r#"
        async function main() {
            const v = await scheduler.postTask(() => 'hello');
            if (v === 'hello') console.log('POST-TASK-OK');
            else console.log('FAIL', v);
        }
        main();
        "#,
    );
    assert_marker(&out, "POST-TASK-OK");
}

#[test]
fn disposable_stack_runs_cleanups_in_lifo() {
    let out = run_inline(
        r#"
        const order = [];
        const stack = new DisposableStack();
        stack.use({ [Symbol.dispose]() { order.push('a'); } });
        stack.use({ [Symbol.dispose]() { order.push('b'); } });
        stack.defer(() => order.push('c-deferred'));
        stack.dispose();
        if (order.join(',') === 'c-deferred,b,a') console.log('LIFO-OK');
        else console.log('FAIL', order.join(','));
        "#,
    );
    assert_marker(&out, "LIFO-OK");
}

#[test]
fn disposable_stack_swallows_errors_and_continues() {
    let out = run_inline(
        r#"
        const order = [];
        const stack = new DisposableStack();
        stack.use({ [Symbol.dispose]() { order.push('first'); } });
        stack.use({ [Symbol.dispose]() { throw new Error('boom'); } });
        stack.use({ [Symbol.dispose]() { order.push('last'); } });
        stack.dispose();
        if (order.join(',') === 'last,first') console.log('SWALLOW-OK');
        else console.log('FAIL', order.join(','));
        "#,
    );
    assert_marker(&out, "SWALLOW-OK");
}

#[test]
fn async_disposable_stack_awaits_each_cleanup() {
    let out = run_inline(
        r#"
        async function main() {
            const order = [];
            const stack = new AsyncDisposableStack();
            stack.use({
                async [Symbol.asyncDispose]() {
                    await Promise.resolve();
                    order.push('async-1');
                },
            });
            stack.use({ [Symbol.dispose]() { order.push('sync-2'); } });
            await stack.disposeAsync();
            if (order.join(',') === 'sync-2,async-1') console.log('ADS-OK');
            else console.log('FAIL', order.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "ADS-OK");
}

#[test]
fn report_error_dispatches_error_event() {
    let out = run_inline(
        r#"
        let captured = null;
        addEventListener('error', e => { captured = e; });
        reportError(new Error('synthetic'));
        // Allow microtask flush.
        Promise.resolve().then(() => {
            if (captured && captured.message === 'synthetic') console.log('REPORT-OK');
            else console.log('FAIL', captured && captured.message);
            process.exit(0);
        });
        "#,
    );
    assert_marker(&out, "REPORT-OK");
}
