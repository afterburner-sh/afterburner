// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Final API close: `URL.createObjectURL(blob)` + `URL.revokeObjectURL`
//! + `fetch(blob:burn/...)` round-trip.

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
fn createObjectURL_returns_blob_url() {
    let src = r#"
        const blob = new Blob(['hello world'], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        if (!url || !url.startsWith('blob:burn/')) {
            console.error('bad url:', url); process.exit(2);
        }
        console.log('BLOB_URL_OK ' + url);
    "#;
    assert_marker(&run_inline(src), "BLOB_URL_OK");
}

#[test]
#[serial]
fn fetch_blob_url_returns_bytes() {
    let src = r#"
        const blob = new Blob(['burn-payload'], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        fetch(url).then(r => r.text()).then(t => {
            if (t !== 'burn-payload') {
                console.error('text:', JSON.stringify(t)); process.exit(2);
            }
            console.log('FETCH_BLOB_OK');
            process.exit(0);
        }).catch(e => { console.error('err:', e.message); process.exit(3); });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_marker(&run_inline(src), "FETCH_BLOB_OK");
}

#[test]
#[serial]
fn revokeObjectURL_drops_entry() {
    let src = r#"
        const blob = new Blob(['x'], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        URL.revokeObjectURL(url);
        fetch(url).then(r => {
            console.error('unexpected success:', r); process.exit(2);
        }).catch(e => {
            if (e && e.message && e.message.indexOf('revoked') >= 0) {
                console.log('REVOKE_OK');
                process.exit(0);
            } else {
                console.error('wrong err:', e.message); process.exit(3);
            }
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_marker(&run_inline(src), "REVOKE_OK");
}
