// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `Symbol.dispose` / `Symbol.asyncDispose` — Node 20+ TC39
//! explicit-resource-management well-known symbols.

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
fn symbol_dispose_is_a_well_known_symbol() {
    let out = run_inline(
        r#"
        if (typeof Symbol.dispose !== 'symbol') { console.log('FAIL', typeof Symbol.dispose); process.exit(1); }
        if (typeof Symbol.asyncDispose !== 'symbol') { console.log('FAIL'); process.exit(1); }
        // Per spec, the symbol is the same value across realms — `for`-shared.
        if (Symbol.dispose === Symbol.for('Symbol.dispose')) console.log('SHARED-OK');
        else console.log('FAIL not-shared');
        "#,
    );
    assert_marker(&out, "SHARED-OK");
}

#[test]
fn class_method_keyed_on_symbol_dispose_is_callable() {
    let out = run_inline(
        r#"
        let disposed = false;
        class R {
            [Symbol.dispose]() { disposed = true; }
        }
        const r = new R();
        r[Symbol.dispose]();
        if (disposed) console.log('CALLED-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CALLED-OK");
}

#[test]
fn async_dispose_resolves_on_invocation() {
    let out = run_inline(
        r#"
        async function main() {
            class R {
                async [Symbol.asyncDispose]() {
                    await Promise.resolve();
                    return 'gone';
                }
            }
            const r = new R();
            const v = await r[Symbol.asyncDispose]();
            if (v === 'gone') console.log('ASYNC-DISPOSE-OK');
        }
        main();
        "#,
    );
    assert_marker(&out, "ASYNC-DISPOSE-OK");
}
