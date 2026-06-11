// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! End-to-end integration tests for the WASM sandbox's node-compat
//! layer — fs/crypto calls go through the `afterburner:host` imports
//! gated by `Manifold`.

use afterburner_core::{Combustor, FsAccess, FuelGauge, Manifold};
use afterburner_wasi::{WasmCombustor, WasmConfig};
use serde_json::json;
use std::path::PathBuf;

fn combustor() -> WasmCombustor {
    WasmCombustor::new(WasmConfig::default()).unwrap()
}

fn run(source: &str, manifold: Manifold) -> serde_json::Value {
    let c = combustor();
    let id = c.ignite(source).unwrap();
    let limits = FuelGauge {
        manifold,
        ..FuelGauge::default()
    };
    c.thrust(&id, &json!(null), &limits).unwrap()
}

fn temp_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "afterburner-wasi-node-compat-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn wasm_sealed_fs_is_denied() {
    let src = r#"
        module.exports = () => {
            try { require('fs').readFileSync('/etc/hostname'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let out = run(src, Manifold::sealed())
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        out.contains("permission denied"),
        "expected denial; got {out}"
    );
}

#[test]
fn wasm_fs_roundtrip_under_readwrite() {
    let root = temp_root();
    let file = root.join("hello.txt");
    let path = file.to_string_lossy().into_owned();
    let src = format!(
        r#"
        module.exports = () => {{
            const fs = require('fs');
            fs.writeFileSync({p:?}, 'wasm-sandbox');
            return fs.readFileSync({p:?}, 'utf8');
        }};
        "#,
        p = path
    );
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let out = run(&src, m);
    assert_eq!(out, json!("wasm-sandbox"));
}

#[test]
fn wasm_fs_write_outside_roots_is_rejected() {
    let root = temp_root();
    let outside = std::env::temp_dir().join("afterburner-wasm-outside.txt");
    let src = format!(
        r#"
        module.exports = () => {{
            try {{
                require('fs').writeFileSync({o:?}, 'nope');
                return 'unexpected';
            }} catch (e) {{ return e.message; }}
        }};
        "#,
        o = outside.to_string_lossy()
    );
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let out = run(&src, m).as_str().unwrap().to_lowercase();
    assert!(
        out.contains("outside allowed roots") || out.contains("permission denied"),
        "expected root-jail denial; got {out}"
    );
}

fn fresh_rsa_keypair() -> (String, String) {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let pub_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();
    (priv_pem, pub_pem)
}

fn fresh_p256_keypair() -> (String, String) {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rand::rngs::OsRng;
    let priv_key = SigningKey::random(&mut OsRng);
    let pub_key = VerifyingKey::from(&priv_key);
    let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let pub_pem = pub_key.to_public_key_pem(LineEnding::LF).unwrap();
    (priv_pem, pub_pem)
}

#[test]
fn wasm_streaming_hash_matches_one_shot() {
    let src = r#"
        module.exports = () => {
            try {
                const crypto = require('crypto');
                const parts = [];
                for (let i = 0; i < 100; i++) parts.push('chunk-' + i + '-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
                const joined = parts.join('');
                const algos = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5'];
                const out = {};
                for (const algo of algos) {
                    const streamed = (function () {
                        const h = crypto.createHash(algo);
                        for (const p of parts) h.update(p);
                        return h.digest('hex');
                    })();
                    const oneShot = crypto.createHash(algo).update(joined).digest('hex');
                    out[algo] = { equal: streamed === oneShot, digestLen: streamed.length };
                }
                return out;
            } catch (e) { return { err: e.message }; }
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    assert_eq!(out["sha1"], json!({ "equal": true, "digestLen": 40 }));
    assert_eq!(out["sha224"], json!({ "equal": true, "digestLen": 56 }));
    assert_eq!(out["sha256"], json!({ "equal": true, "digestLen": 64 }));
    assert_eq!(out["sha384"], json!({ "equal": true, "digestLen": 96 }));
    assert_eq!(out["sha512"], json!({ "equal": true, "digestLen": 128 }));
    assert_eq!(out["md5"], json!({ "equal": true, "digestLen": 32 }));
}

#[test]
fn wasm_streaming_hmac_matches_one_shot() {
    let src = r#"
        module.exports = () => {
            try {
                const crypto = require('crypto');
                const parts = [];
                for (let i = 0; i < 100; i++) parts.push('row-' + i + '-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
                const joined = parts.join('');
                const key = 'super-secret-key';
                const algos = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5'];
                const out = {};
                for (const algo of algos) {
                    const streamed = (function () {
                        const h = crypto.createHmac(algo, key);
                        for (const p of parts) h.update(p);
                        return h.digest('hex');
                    })();
                    const oneShot = crypto.createHmac(algo, key).update(joined).digest('hex');
                    out[algo] = { equal: streamed === oneShot };
                }
                return out;
            } catch (e) { return { err: e.message }; }
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    assert_eq!(out["sha1"], json!({ "equal": true }));
    assert_eq!(out["sha224"], json!({ "equal": true }));
    assert_eq!(out["sha256"], json!({ "equal": true }));
    assert_eq!(out["sha384"], json!({ "equal": true }));
    assert_eq!(out["sha512"], json!({ "equal": true }));
    assert_eq!(out["md5"], json!({ "equal": true }));
}

#[test]
fn wasm_hash_streaming_surfaces_permission_denied() {
    // Under sealed manifold, createHash must fail with an EACCES-coded
    // permission-denied error. Regresses if the polyfill stops reading
    // __host_last_error on a failed streaming open.
    let src = r#"
        module.exports = () => {
            try { require('crypto').createHash('sha256'); return 'unexpected'; }
            catch (e) { return { msg: e.message, code: e.code }; }
        };
    "#;
    let out = run(src, Manifold::sealed());
    let msg = out["msg"].as_str().unwrap().to_lowercase();
    assert!(
        msg.contains("permission denied"),
        "expected denial; got {msg}"
    );
    assert_eq!(out["code"], json!("EACCES"));
}

#[test]
fn wasm_rsa_streaming_sign_matches_one_shot() {
    // End-to-end proof of Pitfall #12 fix: streaming `createSign` must
    // produce the same PKCS#1 v1.5 signature as the one-shot path when
    // both see the same bytes. If the host handle store leaks chunks
    // across thrusts or the digest isn't accumulated properly, this
    // assertion is the canary.
    let (priv_pem, pub_pem) = fresh_rsa_keypair();
    let src = format!(
        r#"
        module.exports = () => {{
            try {{
                const crypto = require('crypto');
                const parts = ['first-', 'second-', 'third-', 'LAST'];
                const joined = parts.join('');

                const signer = crypto.createSign('RS256');
                for (const p of parts) signer.update(p);
                const streamed = signer.sign({priv:?});

                const oneShot = crypto.sign('RS256', {priv:?}, joined);

                const verifier = crypto.createVerify('RS256');
                for (const p of parts) verifier.update(p);

                return {{
                    equal: streamed.compare(oneShot) === 0,
                    verifyStreamed: crypto.verify('RS256', {pub:?}, joined, streamed),
                    streamedVerifier: verifier.verify({pub:?}, oneShot),
                }};
            }} catch (e) {{ return {{ err: e.message, stack: e.stack }}; }}
        }};
        "#,
        priv = priv_pem,
        pub = pub_pem,
    );
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(&src, m);
    assert_eq!(
        out,
        json!({
            "equal": true,
            "verifyStreamed": true,
            "streamedVerifier": true,
        }),
        "WASM streaming mismatch: {out}"
    );
}

#[test]
fn wasm_ecdsa_streaming_verify_roundtrips_one_shot() {
    let (priv_pem, pub_pem) = fresh_p256_keypair();
    let src = format!(
        r#"
        module.exports = () => {{
            const crypto = require('crypto');
            const parts = ['aaa', 'bbb', 'ccc'];
            const joined = parts.join('');

            const signer = crypto.createSign('ES256');
            for (const p of parts) signer.update(p);
            const streamed = signer.sign({priv:?});
            const oneShot = crypto.sign('ES256', {priv:?}, joined);

            const verifier = crypto.createVerify('ES256');
            for (const p of parts) verifier.update(p);
            const streamedVerified = verifier.verify({pub:?}, oneShot);

            return {{
                oneShotVerifiesStreamed: crypto.verify('ES256', {pub:?}, joined, streamed),
                streamedVerifiesOneShot: streamedVerified,
            }};
        }};
        "#,
        priv = priv_pem,
        pub = pub_pem,
    );
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(&src, m);
    assert_eq!(
        out,
        json!({ "oneShotVerifiesStreamed": true, "streamedVerifiesOneShot": true }),
        "WASM ECDSA streaming mismatch: {out}"
    );
}

#[test]
fn wasm_crypto_sha256_known_vector() {
    let src = r#"
        module.exports = () =>
            require('crypto').createHash('sha256').update('abc').digest('hex');
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let out = run(src, m);
    assert_eq!(out, json!(expected));
}

#[test]
fn wasm_crypto_denied_under_sealed() {
    let src = r#"
        module.exports = () => {
            try { require('crypto').createHash('sha256').update('x').digest('hex'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let out = run(src, Manifold::sealed())
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        out.contains("permission denied"),
        "expected denial; got {out}"
    );
}

#[test]
fn wasm_state_store_persists_across_thrusts() {
    use afterburner_core::{Combustor, InMemoryStateStore};
    let store = InMemoryStateStore::shared();
    let cfg = WasmConfig {
        state_store: Some(store.clone()),
        ..WasmConfig::default()
    };
    let c = WasmCombustor::new(cfg).unwrap();
    let id = c
        .ignite("module.exports = () => require('afterburner:state').increment('hits')")
        .unwrap();
    let limits = FuelGauge {
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    assert_eq!(c.thrust(&id, &json!(null), &limits).unwrap(), json!(1));
    assert_eq!(c.thrust(&id, &json!(null), &limits).unwrap(), json!(2));
    assert_eq!(c.thrust(&id, &json!(null), &limits).unwrap(), json!(3));
    assert_eq!(String::from_utf8(store.get("hits").unwrap()).unwrap(), "3");
}

#[test]
fn wasm_state_store_set_get_json() {
    let src = r#"
        module.exports = () => {
            const s = require('afterburner:state');
            s.setJSON('user', { id: 7, tags: ['x'] });
            return s.getJSON('user');
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!({ "id": 7, "tags": ["x"] }));
}

#[test]
fn wasm_process_event_emitter() {
    let src = r#"
        module.exports = () => {
            let captured = null;
            process.on('custom', (msg) => { captured = msg; });
            process.emit('custom', 'wasm');
            return captured;
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!("wasm"));
}

#[test]
fn wasm_fs_stream_roundtrip() {
    let root = temp_root();
    let in_file = root.join("in.txt");
    let out_file = root.join("out.txt");
    std::fs::write(&in_file, "x".repeat(40_000)).unwrap();

    let src = format!(
        r#"
        module.exports = () => {{
            const fs = require('fs');
            const w = fs.createWriteStream({out:?});
            const r = fs.createReadStream({in:?}, {{ highWaterMark: 8 * 1024 }});
            const counts = {{ chunks: 0, bytes: 0 }};
            r.on('end',  () => {{ w.end(); }});
            r.on('data', (chunk) => {{ counts.chunks++; counts.bytes += chunk.length; w.write(chunk); }});
            counts.copied = fs.readFileSync({out:?}).length;
            return counts;
        }};
        "#,
        in = in_file.to_string_lossy(),
        out = out_file.to_string_lossy(),
    );
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let out = run(&src, m);
    assert_eq!(out["bytes"], json!(40_000));
    assert_eq!(out["copied"], json!(40_000));
    let chunks = out["chunks"].as_u64().unwrap();
    assert!((4..=6).contains(&chunks), "got {chunks}");
}

#[test]
fn wasm_aes_gcm_roundtrip() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            const { Buffer } = require('buffer');
            const key = Buffer.alloc(32, 9);
            const iv  = Buffer.alloc(12, 0);
            const enc = crypto.createCipheriv('aes-256-gcm', key, iv);
            enc.update('sandboxed');
            const ct = enc.final();
            const tag = enc.getAuthTag();
            const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
            dec.setAuthTag(tag);
            dec.update(ct);
            return dec.final().toString('utf8');
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    assert_eq!(out, json!("sandboxed"));
}

#[test]
fn wasm_pbkdf2_sync_works() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            return crypto.pbkdf2Sync('pw', 'salt', 1, 32, 'sha256').toString('hex');
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    assert!(out.as_str().unwrap().len() == 64);
}

#[test]
fn wasm_abort_controller() {
    let src = r#"
        module.exports = () => {
            const c = new AbortController();
            let hits = 0;
            c.signal.addEventListener('abort', () => { hits++; });
            c.abort();
            c.abort(); // second call should not re-fire
            return hits;
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!(1));
}

#[test]
fn wasm_every_node_builtin_loads() {
    // Round-2 Node 20 coverage shipped real polyfills for every
    // built-in. This test asserts the contract: `require(<name>)`
    // for any name in `Module.builtinModules` returns a non-null
    // object, with no module surfacing the sandbox-default
    // "module not supported" error any more.
    let src = r#"
        module.exports = () => {
            const names = require('module').builtinModules;
            const failed = [];
            for (const name of names) {
                try {
                    const m = require(name);
                    if (m === null) failed.push(name + ': null');
                } catch (e) {
                    failed.push(name + ': ' + (e && e.message || e));
                }
            }
            return failed;
        };
    "#;
    let out = run(src, Manifold::sealed());
    let failures = out.as_array().expect("array");
    assert!(
        failures.is_empty(),
        "expected every builtin to load, but: {failures:?}"
    );
}

#[test]
fn wasm_buffer_readwrite_numeric() {
    let src = r#"
        module.exports = () => {
            const { Buffer } = require('buffer');
            const b = Buffer.alloc(4);
            b.writeUInt32BE(0x01020304, 0);
            return b.toString('hex');
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!("01020304"));
}

#[test]
fn wasm_fs_permission_denied_message_does_not_leak_path() {
    let src = r#"
        module.exports = () => {
            try { require('fs').readFileSync('/root/.ssh/id_rsa'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let msg = run(src, Manifold::sealed());
    let lower = msg.as_str().unwrap().to_lowercase();
    assert!(lower.contains("permission denied") || lower.contains("not available"));
    assert!(
        !lower.contains("id_rsa") && !lower.contains("/root/.ssh"),
        "permission-denied leaked path: {lower}"
    );
}

#[test]
fn wasm_create_write_stream_with_w_flag_truncates_existing_file() {
    // Regression for Bug #1: flags='w' must overwrite, not leave tail
    // bytes. Pre-write 100 bytes of garbage, then writeStream 10 bytes,
    // expect the final file to be exactly 10 bytes.
    let root = temp_root();
    let file = root.join("truncate-probe.txt");
    std::fs::write(&file, vec![b'z'; 100]).unwrap();

    let src = format!(
        r#"
        module.exports = () => {{
            const fs = require('fs');
            const w = fs.createWriteStream({p:?});
            w.write('abcdefghij');
            w.end();
            const after = fs.readFileSync({p:?}, 'utf8');
            return {{ after: after, len: after.length }};
        }};
        "#,
        p = file.to_string_lossy()
    );
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let out = run(&src, m);
    assert_eq!(out["after"], json!("abcdefghij"));
    assert_eq!(out["len"], json!(10));
}

#[test]
fn wasm_zlib_gzip_roundtrip() {
    let src = r#"
        module.exports = () => {
            const zlib = require('zlib');
            const payload = 'wasm-zlib ' + 'y'.repeat(1000);
            const compressed = zlib.gzipSync(payload);
            const decompressed = zlib.gunzipSync(compressed).toString('utf8');
            return {
                ok: decompressed === payload,
                shrunk: compressed.length < payload.length,
            };
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out["ok"], json!(true));
    assert_eq!(out["shrunk"], json!(true));
}

#[test]
fn wasm_os_platform_returns_host_value() {
    let src = r#"module.exports = () => require('os').platform();"#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!(std::env::consts::OS));
}

/// Serve a single HTTP/1.1 response with `body` bytes and close. Returns
/// the listening port. The thread exits after handling one connection,
/// so the test can join without hanging.
fn spawn_one_shot_http_server(body: Vec<u8>) -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Drain the request — ureq sends a well-formed HTTP request we
        // don't care to parse; we only need to wait until the headers
        // complete before replying.
        let mut buf = [0u8; 4096];
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
        let _ = stream.read(&mut buf);
        let hdr = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(hdr.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    port
}

// JS snippet run under both native and WASM paths. Can't use
// `async`/`await` or `.then()` — Javy's runtime doesn't enable the
// event loop, so microtasks don't drain in a thrust. The fetch polyfill
// goes through `__host_http_request` synchronously; we call that host
// function directly to verify `body_b64` carries arbitrary bytes
// losslessly through the wire.
const BINARY_BODY_SCRIPT: &str = r#"
    module.exports = () => {
        try {
            const { Buffer } = require('buffer');
            const raw = globalThis.__host_http_request('GET', __URL__, null);
            const parsed = JSON.parse(raw);
            const b = Buffer.from(parsed.body_b64 || '', 'base64');
            let sum = 0;
            for (let i = 0; i < b.length; i++) sum += b[i];
            return {
                status: parsed.status,
                length: b.length,
                sum: sum,
                first: b[0],
                last: b[b.length - 1],
                byte128: b[128],
                byte200: b[200],
            };
        } catch (e) { return { err: String(e.message), stack: e.stack }; }
    };
"#;

#[test]
fn wasm_fetch_binary_body_roundtrips_losslessly() {
    // End-to-end proof that `body_b64` carries bytes losslessly through
    // the `__host_http_request` bridge — every byte 0..=255 including
    // the high-bit values that utf8-lossy would replace with U+FFFD.
    let body: Vec<u8> = (0u8..=255).collect();
    let port = spawn_one_shot_http_server(body.clone());
    let expected_sum: u64 = body.iter().map(|&b| b as u64).sum();

    let url = format!("http://127.0.0.1:{port}/");
    let src = BINARY_BODY_SCRIPT.replace("__URL__", &format!("{url:?}"));
    let mut m = Manifold::sealed();
    m.net = afterburner_core::NetAccess::OutboundHttp(None);
    let out = run(&src, m);
    assert_eq!(
        out,
        json!({
            "status": 200,
            "length": 256,
            "sum": expected_sum,
            "first": 0,
            "last": 255,
            "byte128": 128,
            "byte200": 200,
        }),
        "binary body mangled: {out}"
    );
}

#[test]
fn native_fetch_binary_body_roundtrips_losslessly() {
    use afterburner_ignite::NativeCombustor;
    let body: Vec<u8> = (0u8..=255).collect();
    let port = spawn_one_shot_http_server(body.clone());
    let expected_sum: u64 = body.iter().map(|&b| b as u64).sum();

    let url = format!("http://127.0.0.1:{port}/");
    let src = BINARY_BODY_SCRIPT.replace("__URL__", &format!("{url:?}"));
    let c = NativeCombustor::new().unwrap();
    let id = c.ignite(&src).unwrap();
    let mut m = Manifold::sealed();
    m.net = afterburner_core::NetAccess::OutboundHttp(None);
    let limits = FuelGauge {
        manifold: m,
        ..FuelGauge::default()
    };
    let out = c.thrust(&id, &json!(null), &limits).unwrap();
    assert_eq!(
        out,
        json!({
            "status": 200,
            "length": 256,
            "sum": expected_sum,
            "first": 0,
            "last": 255,
            "byte128": 128,
            "byte200": 200,
        }),
        "native binary body mangled: {out}"
    );
}
