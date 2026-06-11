// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Integration tests for host-backed Node built-ins on the native path.
//! Verifies that `Manifold::sealed` denies access and that an explicit
//! `FsAccess::ReadWrite(roots)` grants scoped access.

use afterburner_core::{Combustor, FsAccess, FuelGauge, Manifold};
use afterburner_ignite::NativeCombustor;
use serde_json::json;
use std::path::PathBuf;

fn run(source: &str, manifold: Manifold) -> serde_json::Value {
    let c = NativeCombustor::new().unwrap();
    let id = c.ignite(source).unwrap();
    let limits = FuelGauge {
        manifold,
        ..FuelGauge::default()
    };
    c.thrust(&id, &json!(null), &limits).unwrap()
}

fn temp_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "afterburner-node-compat-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn sealed_manifold_denies_fs_read() {
    let src = r#"
        module.exports = () => {
            try { require('fs').readFileSync('/etc/hostname'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let msg = run(src, Manifold::sealed())
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        msg.contains("permission denied") || msg.contains("not available"),
        "expected permission denial; got {msg}"
    );
}

#[test]
fn fs_read_write_roundtrip_under_readwrite_policy() {
    let root = temp_root();
    let file = root.join("greeting.txt");
    let path = file.to_string_lossy().into_owned();

    let src = format!(
        r#"
        module.exports = () => {{
            const fs = require('fs');
            fs.writeFileSync({path:?}, 'hello afterburner');
            return fs.readFileSync({path:?}, 'utf8');
        }};
        "#,
        path = path,
    );

    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root.clone()]);
    let out = run(&src, m);
    assert_eq!(out, json!("hello afterburner"));
}

#[test]
fn fs_write_outside_roots_is_rejected() {
    let root = temp_root();
    let outside = std::env::temp_dir().join("afterburner-node-compat-outside.txt");

    let src = format!(
        r#"
        module.exports = () => {{
            try {{
                require('fs').writeFileSync({out:?}, 'should fail');
                return 'unexpected';
            }} catch (e) {{ return e.message; }}
        }};
        "#,
        out = outside.to_string_lossy()
    );

    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let out = run(&src, m).as_str().unwrap().to_lowercase();
    assert!(
        out.contains("outside allowed roots") || out.contains("permission denied"),
        "expected root-jail denial; got {out}"
    );
}

#[test]
fn fs_read_only_rejects_writes() {
    let root = temp_root();
    let file = root.join("ro.txt");
    std::fs::write(&file, b"seeded").unwrap();

    let src = format!(
        r#"
        module.exports = () => {{
            const fs = require('fs');
            const read = fs.readFileSync({p:?}, 'utf8');
            try {{
                fs.writeFileSync({p:?}, 'nope');
                return {{ read: read, wrote: true }};
            }} catch (e) {{ return {{ read: read, err: e.message }}; }}
        }};
        "#,
        p = file.to_string_lossy()
    );

    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadOnly(vec![root]);
    let out = run(&src, m);
    assert_eq!(out["read"], json!("seeded"));
    assert!(out["err"].as_str().unwrap().contains("read-only"));
}

#[test]
fn crypto_hash_sha256_matches_known_vector() {
    let src = r#"
        module.exports = () => require('crypto').createHash('sha256').update('abc').digest('hex');
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    // Known SHA-256("abc")
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let out = run(src, m);
    assert_eq!(out, json!(expected));
}

#[test]
fn crypto_hmac_sha256_matches_known_vector() {
    let src = r#"
        module.exports = () => require('crypto').createHmac('sha256', 'key').update('The quick brown fox jumps over the lazy dog').digest('hex');
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";
    let out = run(src, m);
    assert_eq!(out, json!(expected));
}

#[test]
fn crypto_random_uuid_is_v4() {
    let src = r#"module.exports = () => require('crypto').randomUUID();"#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    let s = out.as_str().unwrap();
    // v4 format: 8-4-4-4-12 hex with '4' in 13th char and [89ab] in 17th.
    assert_eq!(s.len(), 36);
    assert_eq!(s.as_bytes()[14] as char, '4');
    assert!("89ab".contains(s.as_bytes()[19] as char));
}

#[test]
fn crypto_denied_when_manifold_crypto_false() {
    let src = r#"
        module.exports = () => {
            try { require('crypto').createHash('sha256').update('x').digest('hex'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let msg = run(src, Manifold::sealed())
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        msg.contains("permission denied"),
        "expected crypto permission denial; got {msg}"
    );
}

#[test]
fn os_platform_returns_host_value() {
    let src = r#"module.exports = () => require('os').platform();"#;
    let out = run(src, Manifold::sealed());
    // os is not capability-gated; should match `std::env::consts::OS`.
    assert_eq!(out, json!(std::env::consts::OS));
}

#[test]
fn child_process_denied_when_manifold_disabled() {
    let src = r#"
        module.exports = () => {
            try { require('child_process').execSync('/bin/true'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let msg = run(src, Manifold::sealed())
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        msg.contains("permission denied"),
        "expected child_process denial; got {msg}"
    );
}

#[test]
fn child_process_exec_sync_runs_under_trusted_manifold() {
    let src = r#"
        module.exports = () => require('child_process').execSync('echo afterburner').trim();
    "#;
    let mut m = Manifold::sealed();
    m.child_process = true;
    let out = run(src, m);
    assert_eq!(out, json!("afterburner"));
}

#[test]
fn dns_denied_when_manifold_net_none() {
    let src = r#"
        module.exports = () => {
            try { require('dns').lookup('localhost'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let msg = run(src, Manifold::sealed())
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        msg.contains("permission denied"),
        "expected dns denial; got {msg}"
    );
}

#[test]
fn state_store_persists_across_thrusts() {
    use afterburner_core::{Combustor, InMemoryStateStore};
    use afterburner_ignite::NativeCombustor;
    use serde_json::json;
    let store = InMemoryStateStore::shared();
    let c = NativeCombustor::with_state_store(store.clone()).unwrap();

    let inc = c
        .ignite("module.exports = () => require('afterburner:state').increment('hits')")
        .unwrap();
    let limits = FuelGauge {
        manifold: Manifold::sealed(),
        ..FuelGauge::default()
    };
    assert_eq!(c.thrust(&inc, &json!(null), &limits).unwrap(), json!(1));
    assert_eq!(c.thrust(&inc, &json!(null), &limits).unwrap(), json!(2));
    assert_eq!(c.thrust(&inc, &json!(null), &limits).unwrap(), json!(3));

    // Direct host-side observation.
    let raw = store.get("hits").unwrap();
    assert_eq!(String::from_utf8(raw).unwrap(), "3");
}

#[test]
fn state_store_set_get_json() {
    let src = r#"
        module.exports = () => {
            const s = require('afterburner:state');
            s.setJSON('user', { id: 42, tags: ['a','b'] });
            return s.getJSON('user');
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!({ "id": 42, "tags": ["a", "b"] }));
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
fn streaming_hash_matches_one_shot() {
    // Chunked createHash('sha256') produces the same hex digest as
    // one-shot crypto.hash on the concatenated payload. Covers all four
    // supported algorithms (sha256/384/512/md5) so we don't regress any.
    let src = r#"
        module.exports = () => {
            try {
                const crypto = require('crypto');
                const parts = [];
                // ~10 KB payload split across 100 chunks
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
fn streaming_hmac_matches_one_shot() {
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
fn hash_digest_called_twice_throws() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            const h = crypto.createHash('sha256').update('abc');
            h.digest('hex');
            try { h.digest('hex'); return 'unexpected'; }
            catch (e) { return e.message; }
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m).as_str().unwrap().to_lowercase();
    assert!(out.contains("already called"), "got {out}");
}

#[test]
fn rsa_sign_verify_roundtrip() {
    let (priv_pem, pub_pem) = fresh_rsa_keypair();
    let src = format!(
        r#"
        module.exports = () => {{
            const crypto = require('crypto');
            try {{
                const sig = crypto.sign('RS256', {priv:?}, 'payload');
                return {{ ok: crypto.verify('RS256', {pub:?}, 'payload', sig) }};
            }} catch (e) {{ return {{ err: e.message }}; }}
        }};
        "#,
        priv = priv_pem,
        pub = pub_pem
    );
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(&src, m);
    assert_eq!(out, json!({ "ok": true }), "got {out}");
}

#[test]
fn rsa_streaming_sign_matches_one_shot() {
    // RS256 (PKCS#1 v1.5) is deterministic, so feeding the same bytes
    // through `createSign().update(...)` chunks MUST produce the exact
    // signature as the one-shot `crypto.sign(...)`. This proves the
    // host-side streaming digest accumulates the hash correctly across
    // chunk boundaries.
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

                // `streamed.compare(oneShot)` is the instance-method form;
                // we don't polyfill static `Buffer.compare`.
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
        "streaming mismatch: {out}"
    );
}

#[test]
fn ecdsa_streaming_verify_roundtrips_one_shot() {
    // ECDSA signatures are non-deterministic (nonce), so we can't assert
    // byte equality — but streaming sign ↔ one-shot verify (and the
    // reverse) must both succeed if the digest streams correctly.
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
        "ECDSA streaming mismatch: {out}"
    );
}

#[test]
fn ecdsa_p256_sign_verify_roundtrip() {
    let (priv_pem, pub_pem) = fresh_p256_keypair();
    let src = format!(
        r#"
        module.exports = () => {{
            const crypto = require('crypto');
            const sig = crypto.sign('ES256', {priv:?}, 'payload');
            return crypto.verify('ES256', {pub:?}, 'payload', sig);
        }};
        "#,
        priv = priv_pem,
        pub = pub_pem
    );
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(&src, m);
    assert_eq!(out, json!(true));
}

#[test]
fn process_is_event_emitter() {
    let src = r#"
        module.exports = () => {
            let captured = null;
            process.on('custom', (msg) => { captured = msg; });
            process.emit('custom', 'hello');
            return captured;
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!("hello"));
}

#[test]
fn fs_create_read_stream_emits_chunks() {
    // Sandbox has no event loop: the convention is to attach `end`
    // (and `error`) listeners *before* `data` — emission fires
    // synchronously when the first `data` listener attaches.
    let root = temp_root();
    let file = root.join("stream-in.txt");
    let payload: String = "x".repeat(150_000);
    std::fs::write(&file, &payload).unwrap();

    let src = format!(
        r#"
        module.exports = () => {{
            const fs = require('fs');
            const out = {{ chunks: 0, total: 0, ended: false }};
            const s = fs.createReadStream({p:?}, {{ highWaterMark: 32 * 1024 }});
            s.on('end',  () => {{ out.ended = true; }});
            s.on('data', (c) => {{ out.chunks++; out.total += c.length; }});
            return out;
        }};
        "#,
        p = file.to_string_lossy()
    );
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadOnly(vec![root]);
    let out = run(&src, m);
    assert_eq!(out["total"], json!(150_000));
    assert_eq!(out["ended"], json!(true));
    let chunks = out["chunks"].as_u64().unwrap();
    assert!((4..=6).contains(&chunks), "got {chunks} chunks");
}

#[test]
fn fs_create_write_stream_writes_chunks() {
    let root = temp_root();
    let file = root.join("stream-out.txt");
    let path = file.to_string_lossy().into_owned();
    let src = format!(
        r#"
        module.exports = () => {{
            const fs = require('fs');
            const w = fs.createWriteStream({p:?});
            w.write('hello ');
            w.write('streaming');
            w.end();
            return fs.readFileSync({p:?}, 'utf8');
        }};
        "#,
        p = path
    );
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let out = run(&src, m);
    assert_eq!(out, json!("hello streaming"));
}

#[test]
fn buffer_numeric_read_write() {
    let src = r#"
        module.exports = () => {
            const { Buffer } = require('buffer');
            const b = Buffer.alloc(8);
            b.writeUInt32LE(0xDEADBEEF, 0);
            b.writeUInt32BE(0xCAFEBABE, 4);
            return {
                le: b.readUInt32LE(0),
                be: b.readUInt32BE(4),
                hex: b.toString('hex'),
            };
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out["le"], json!(0xDEADBEEFu32));
    assert_eq!(out["be"], json!(0xCAFEBABEu32));
    assert_eq!(out["hex"], json!("efbeaddecafebabe"));
}

#[test]
fn buffer_compare_indexof() {
    let src = r#"
        module.exports = () => {
            const { Buffer } = require('buffer');
            const b = Buffer.from('hello world');
            return {
                idx: b.indexOf('world'),
                cmp_eq: b.compare(Buffer.from('hello world')),
                cmp_lt: b.compare(Buffer.from('zebra')),
                includes: b.includes('world'),
            };
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out["idx"], json!(6));
    assert_eq!(out["cmp_eq"], json!(0));
    assert_eq!(out["cmp_lt"], json!(-1));
    assert_eq!(out["includes"], json!(true));
}

#[test]
fn every_node_builtin_loads() {
    // Round-2 Node 20 coverage shipped real polyfills for every
    // built-in. `require(<name>)` for any name listed in
    // `Module.builtinModules` returns a non-null object — no
    // module remains stubbed.
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
fn abort_controller_fires_listener() {
    let src = r#"
        module.exports = () => {
            const c = new AbortController();
            let aborted = false;
            c.signal.addEventListener('abort', () => { aborted = true; });
            c.abort(new Error('stop'));
            return { aborted: aborted, reasonMsg: c.signal.reason.message };
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out["aborted"], json!(true));
    assert_eq!(out["reasonMsg"], json!("stop"));
}

#[test]
fn base64_encoder_decoder_roundtrip() {
    let src = r#"
        module.exports = () => {
            const s = 'afterburner!';
            return atob(btoa(s));
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!("afterburner!"));
}

#[test]
fn aes_gcm_encrypt_decrypt_roundtrip() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            const { Buffer } = require('buffer');
            const key = Buffer.alloc(32, 7);
            const iv  = Buffer.alloc(12, 0);
            const enc = crypto.createCipheriv('aes-256-gcm', key, iv);
            enc.setAAD(Buffer.from('hdr'));
            enc.update('hello');
            const cipher = enc.final();
            const tag = enc.getAuthTag();

            const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
            dec.setAAD(Buffer.from('hdr'));
            dec.setAuthTag(tag);
            dec.update(cipher);
            const plain = dec.final();

            return { ok: plain.toString('utf8') === 'hello', tagLen: tag.length };
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    assert_eq!(out["ok"], json!(true));
    assert_eq!(out["tagLen"], json!(16));
}

#[test]
fn aes_cbc_encrypt_decrypt_roundtrip() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            const { Buffer } = require('buffer');
            const key = Buffer.alloc(16, 1);
            const iv  = Buffer.alloc(16, 2);
            const enc = crypto.createCipheriv('aes-128-cbc', key, iv);
            enc.update('the message');
            const ct = enc.final();
            const dec = crypto.createDecipheriv('aes-128-cbc', key, iv);
            dec.update(ct);
            const pt = dec.final();
            return pt.toString('utf8');
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    assert_eq!(out, json!("the message"));
}

#[test]
fn pbkdf2_known_vector() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            // RFC 6070 vector: P="password", S="salt", c=2, dkLen=20, sha1 not
            // supported — use sha256 with a simpler self-test.
            return crypto.pbkdf2Sync('password', 'salt', 1, 32, 'sha256').toString('hex');
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    assert_eq!(
        out,
        json!("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    );
}

#[test]
fn scrypt_known_vector() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            // RFC 7914 test vector: password="", salt="", N=16, r=1, p=1,
            // dkLen=64.
            return crypto.scryptSync('', '', 64, { N: 16, r: 1, p: 1 }).toString('hex');
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    let hex = out.as_str().unwrap();
    assert!(hex.starts_with("77d6576238657b203b19"), "got {hex}");
}

#[test]
fn fs_permission_denied_message_does_not_leak_path() {
    // Regression: under sealed/readonly policy, the permission-denied
    // error must NOT echo the user's requested path verbatim. Logs in
    // shared sinks could otherwise leak sensitive filenames.
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
        "permission-denied message leaked the requested path: {lower}"
    );
}

#[test]
fn fs_write_outside_roots_message_does_not_leak_path() {
    let root = temp_root();
    let outside = std::env::temp_dir().join("afterburner-leak-probe-xyz");
    let src = format!(
        r#"
        module.exports = () => {{
            try {{ require('fs').writeFileSync({o:?}, 'x'); return 'unexpected'; }}
            catch (e) {{ return e.message; }}
        }};
        "#,
        o = outside.to_string_lossy()
    );
    let mut m = Manifold::sealed();
    m.fs = FsAccess::ReadWrite(vec![root]);
    let out = run(&src, m);
    let lower = out.as_str().unwrap().to_lowercase();
    assert!(lower.contains("outside allowed roots"));
    assert!(
        !lower.contains("afterburner-leak-probe-xyz"),
        "outside-roots message leaked the path: {lower}"
    );
}

#[test]
fn scrypt_rejects_non_power_of_two_n() {
    let src = r#"
        module.exports = () => {
            const crypto = require('crypto');
            try {
                crypto.scryptSync('pw', 'salt', 32, { N: 1000, r: 8, p: 1 });
                return 'unexpected';
            } catch (e) { return e.message; }
        };
    "#;
    let mut m = Manifold::sealed();
    m.crypto = true;
    let out = run(src, m);
    let lower = out.as_str().unwrap().to_lowercase();
    assert!(
        lower.contains("power of 2"),
        "expected power-of-2 rejection; got {lower}"
    );
}

#[test]
fn zlib_gzip_roundtrip() {
    let src = r#"
        module.exports = () => {
            const zlib = require('zlib');
            const { Buffer } = require('buffer');
            const payload = 'hello afterburner ' + 'x'.repeat(1000);
            const compressed = zlib.gzipSync(payload);
            const decompressed = zlib.gunzipSync(compressed).toString('utf8');
            return {
                ok: decompressed === payload,
                shrunk: compressed.length < payload.length,
                original_len: payload.length,
                compressed_len: compressed.length,
            };
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out["ok"], json!(true));
    assert_eq!(out["shrunk"], json!(true));
}

#[test]
fn zlib_deflate_inflate_roundtrip() {
    let src = r#"
        module.exports = () => {
            const zlib = require('zlib');
            const d = zlib.deflateSync('The quick brown fox jumps over the lazy dog');
            return zlib.inflateSync(d).toString('utf8');
        };
    "#;
    let out = run(src, Manifold::sealed());
    assert_eq!(out, json!("The quick brown fox jumps over the lazy dog"));
}

#[test]
fn dns_lookup_localhost_resolves_under_net_manifold() {
    use afterburner_core::NetAccess;
    let src = r#"
        module.exports = () => require('dns').lookup('localhost').address;
    "#;
    let mut m = Manifold::sealed();
    m.net = NetAccess::OutboundHttp(None);
    let out = run(src, m);
    let addr = out.as_str().unwrap();
    assert!(
        addr == "127.0.0.1" || addr == "::1",
        "expected loopback; got {addr}"
    );
}
