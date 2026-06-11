// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Engine ceiling #3 close: `async_hooks.createHook({init,before,after})`
//! now fires for every native `await` expression. The ESM transpiler
//! wraps each `await EXPR` as `await __ab_await_track(EXPR)` so the
//! awaited value flows through user-patched `Promise.prototype.then`,
//! which is the only path the engine's internal await resolution
//! exposes to user hooks.

use serial_test::serial;
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn write_temp(dir: &TempDir, name: &str, source: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(source.as_bytes()).expect("write");
    path
}

#[test]
#[serial]
fn hooks_fire_for_await_expressions() {
    // The await rewrite only kicks in for files that go through the
    // ESM transpile pass. A `.mjs` file always does. Bare `import`
    // declarations on a `.js` file also trigger it.
    let dir = TempDir::new().expect("tempdir");
    let entry = write_temp(
        &dir,
        "await.mjs",
        r#"
            const ah = await import('async_hooks');
            let initPromise = 0, before = 0, after = 0;
            const hook = ah.createHook({
                init: (_id, type) => { if (type === 'PROMISE') initPromise++; },
                before: () => before++,
                after: () => after++,
            }).enable();
            async function run() {
                await Promise.resolve(1);
                await Promise.resolve(2);
                await Promise.resolve(3);
                return 'done';
            }
            run().then((r) => {
                if (r !== 'done') {
                    console.error('result:', r); process.exit(2);
                }
                if (initPromise === 0) {
                    console.error('no init for PROMISE: init=', initPromise); process.exit(3);
                }
                if (before === 0) {
                    console.error('no before fired'); process.exit(4);
                }
                if (after === 0) {
                    console.error('no after fired'); process.exit(5);
                }
                console.log('AWAIT_HOOK_OK init=' + initPromise + ' before=' + before + ' after=' + after);
                hook.disable();
                process.exit(0);
            });
            setTimeout(() => process.exit(99), 30000);
        "#,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", entry.to_str().unwrap()])
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("AWAIT_HOOK_OK"),
        "missing AWAIT_HOOK_OK\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}
