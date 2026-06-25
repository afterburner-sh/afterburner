// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `require('crypto').constants` (OpenSSL flag bits + RSA padding +
//! PSS salt + DH point format) and `Readable.toWeb` / `fromWeb`
//! Node ↔ Web Streams bridge.

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
fn crypto_constants_exposes_canonical_rsa_padding_values() {
    let out = run_inline(
        r#"
        const c = require('crypto').constants;
        if (c.RSA_PKCS1_PADDING === 1 && c.RSA_NO_PADDING === 3 &&
            c.RSA_PKCS1_OAEP_PADDING === 4 && c.RSA_PKCS1_PSS_PADDING === 6 &&
            c.RSA_PSS_SALTLEN_DIGEST === -1) console.log('CRYPTO-CONST-OK');
        else console.log('FAIL', JSON.stringify({
            pk: c.RSA_PKCS1_PADDING, np: c.RSA_NO_PADDING,
            oaep: c.RSA_PKCS1_OAEP_PADDING, pss: c.RSA_PKCS1_PSS_PADDING,
        }));
        "#,
    );
    assert_marker(&out, "CRYPTO-CONST-OK");
}

#[test]
fn crypto_constants_includes_dh_check_flags() {
    let out = run_inline(
        r#"
        const c = require('crypto').constants;
        if (c.DH_CHECK_P_NOT_PRIME === 1 && c.DH_CHECK_P_NOT_SAFE_PRIME === 2 &&
            c.POINT_CONVERSION_COMPRESSED === 2 && c.POINT_CONVERSION_UNCOMPRESSED === 4)
            console.log('DH-CONST-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "DH-CONST-OK");
}

#[test]
fn readable_to_web_returns_a_readable_stream() {
    let out = run_inline(
        r#"
        async function main() {
            const stream = require('stream');
            const node = stream.Readable.from([Buffer.from('hello'), Buffer.from(', world')]);
            const web = stream.Readable.toWeb(node);
            const reader = web.getReader();
            let acc = '';
            while (true) {
                const r = await reader.read();
                if (r.done) break;
                acc += Buffer.from(r.value).toString('utf8');
            }
            if (acc === 'hello, world') console.log('TOWEB-OK');
            else console.log('FAIL', JSON.stringify(acc));
        }
        main().catch(e => console.log('ERR', e.message));
        "#,
    );
    assert_marker(&out, "TOWEB-OK");
}

#[test]
fn readable_from_web_yields_data_events() {
    let out = run_inline(
        r#"
        async function main() {
            const stream = require('stream');
            const web = new ReadableStream({
                start(c) {
                    c.enqueue(new Uint8Array([1, 2, 3]));
                    c.enqueue(new Uint8Array([4, 5]));
                    c.close();
                },
            });
            const node = stream.Readable.fromWeb(web);
            const collected = [];
            node.on('data', chunk => { collected.push(...chunk); });
            node.on('end', () => {
                if (collected.join(',') === '1,2,3,4,5') console.log('FROMWEB-OK');
                else console.log('FAIL', collected.join(','));
                process.exit(0);
            });
        }
        main().catch(e => console.log('ERR', e.message));
        "#,
    );
    assert_marker(&out, "FROMWEB-OK");
}
