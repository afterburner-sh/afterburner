// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `__host_crypto_*` globals - hash, sign/verify, AES, KDFs.

use alloc::format;
use alloc::string::String;
use javy_plugin_api::javy::quickjs::{Object, prelude::Func};

use super::{call_read, read_last_error};
use crate::host_api::*;

pub fn install<'js>(globals: &Object<'js>) {
    install_oneshot(globals);
    install_streaming(globals);
}

fn install_oneshot<'js>(globals: &Object<'js>) {
    let _ = globals.set(
        "__host_crypto_hash",
        Func::from(
            |algo: String, data: String, _enc: Option<String>| -> String {
                let ab = algo.as_bytes();
                let db = data.as_bytes();
                match call_read(|out, cap| unsafe {
                    host_crypto_hash(
                        ab.as_ptr(),
                        ab.len() as u32,
                        db.as_ptr(),
                        db.len() as u32,
                        out,
                        cap,
                    )
                }) {
                    Ok(s) => s,
                    Err(e) => format!("__HOST_ERR__:{e}"),
                }
            },
        ),
    );

    let _ = globals.set(
        "__host_crypto_random_bytes",
        Func::from(|len: u32, _enc: Option<String>| -> String {
            match call_read(|out, cap| unsafe { host_crypto_random_bytes(len, out, cap) }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    // AES-GCM (supports optional AAD).
    macro_rules! bind_gcm {
        ($name:literal, $fn:ident) => {
            let _ = globals.set(
                $name,
                Func::from(
                    |algo: String,
                     key_b64: String,
                     nonce_b64: String,
                     data_b64: String,
                     aad_b64: Option<String>|
                     -> String {
                        let ab = algo.as_bytes();
                        let kb = key_b64.as_bytes();
                        let nb = nonce_b64.as_bytes();
                        let db = data_b64.as_bytes();
                        let aad = aad_b64.unwrap_or_default();
                        let aadb = aad.as_bytes();
                        match call_read(|out, cap| unsafe {
                            $fn(
                                ab.as_ptr(),
                                ab.len() as u32,
                                kb.as_ptr(),
                                kb.len() as u32,
                                nb.as_ptr(),
                                nb.len() as u32,
                                db.as_ptr(),
                                db.len() as u32,
                                aadb.as_ptr(),
                                aadb.len() as u32,
                                out,
                                cap,
                            )
                        }) {
                            Ok(s) => s,
                            Err(e) => format!("__HOST_ERR__:{e}"),
                        }
                    },
                ),
            );
        };
    }
    bind_gcm!("__host_crypto_aes_gcm_encrypt", host_crypto_aes_gcm_encrypt);
    bind_gcm!("__host_crypto_aes_gcm_decrypt", host_crypto_aes_gcm_decrypt);

    // AES-CBC.
    macro_rules! bind_cbc {
        ($name:literal, $fn:ident) => {
            let _ = globals.set(
                $name,
                Func::from(
                    |algo: String, key_b64: String, iv_b64: String, data_b64: String| -> String {
                        let ab = algo.as_bytes();
                        let kb = key_b64.as_bytes();
                        let ib = iv_b64.as_bytes();
                        let db = data_b64.as_bytes();
                        match call_read(|out, cap| unsafe {
                            $fn(
                                ab.as_ptr(),
                                ab.len() as u32,
                                kb.as_ptr(),
                                kb.len() as u32,
                                ib.as_ptr(),
                                ib.len() as u32,
                                db.as_ptr(),
                                db.len() as u32,
                                out,
                                cap,
                            )
                        }) {
                            Ok(s) => s,
                            Err(e) => format!("__HOST_ERR__:{e}"),
                        }
                    },
                ),
            );
        };
    }
    bind_cbc!("__host_crypto_aes_cbc_encrypt", host_crypto_aes_cbc_encrypt);
    bind_cbc!("__host_crypto_aes_cbc_decrypt", host_crypto_aes_cbc_decrypt);

    // Subtle Crypto dispatcher - single host fn, JSON args.
    let _ = globals.set(
        "__host_crypto_subtle_op",
        Func::from(|op: String, args_json: String| -> String {
            let ob = op.as_bytes();
            let jb = args_json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_crypto_subtle_op(
                    ob.as_ptr(),
                    ob.len() as u32,
                    jb.as_ptr(),
                    jb.len() as u32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_crypto_check_prime",
        Func::from(|candidate_hex: String, checks: u32| -> i32 {
            // JS sends hex; the host decodes hex back to BE bytes.
            // Hex is ASCII so the bytes the host reads are valid UTF-8.
            let hb = candidate_hex.as_bytes();
            unsafe { host_crypto_check_prime(hb.as_ptr(), hb.len() as u32, checks) }
        }),
    );

    let _ = globals.set(
        "__host_crypto_generate_prime",
        Func::from(|bits: u32, safe: bool| -> String {
            let safe_i = if safe { 1 } else { 0 };
            match call_read(|out, cap| unsafe {
                host_crypto_generate_prime(bits, safe_i, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    // V8 serialize/deserialize - JSON tree → base64 wire bytes (and back).
    // `node:quic` / `http3.createServer().listen()` - bind a QUIC
    // endpoint with TLS-1.3 + ALPN "h3". Two-step: stash cert+key,
    // then call listen with the port. This keeps the wasm trampoline
    // argument count low (two i32 strings + one u32 was triggering a
    // wasmtime trampoline misbehaviour we couldn't repro elsewhere).
    let _ = globals.set(
        "__host_http3_request",
        Func::from(|url: String, method: String, body_b64: String| -> String {
            let ub = url.as_bytes();
            let mb = method.as_bytes();
            let bb = body_b64.as_bytes();
            match call_read(|out, cap| unsafe {
                host_http3_request(
                    ub.as_ptr(),
                    ub.len() as u32,
                    mb.as_ptr(),
                    mb.len() as u32,
                    bb.as_ptr(),
                    bb.len() as u32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_http3_listen",
        Func::from(
            |port: u32, server_id: i32, cert_pem: String, key_pem: String| -> i32 {
                let cb = cert_pem.as_bytes();
                let kb = key_pem.as_bytes();
                let stash = unsafe {
                    host_http3_listen_set_cert(
                        cb.as_ptr(),
                        cb.len() as u32,
                        kb.as_ptr(),
                        kb.len() as u32,
                    )
                };
                if stash != 0 {
                    return -3;
                }
                unsafe { host_http3_listen(port, server_id) }
            },
        ),
    );

    let _ = globals.set(
        "__host_v8_serialize",
        Func::from(|json: String| -> String {
            let jb = json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_v8_serialize(jb.as_ptr(), jb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_v8_deserialize",
        Func::from(|b64: String| -> String {
            let bb = b64.as_bytes();
            match call_read(|out, cap| unsafe {
                host_v8_deserialize(bb.as_ptr(), bb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_crypto_pbkdf2_sync",
        Func::from(
            |digest: String,
             password: String,
             salt_b64: String,
             iters: u32,
             key_len: u32|
             -> String {
                let db = digest.as_bytes();
                let pb = password.as_bytes();
                let sb = salt_b64.as_bytes();
                match call_read(|out, cap| unsafe {
                    host_crypto_pbkdf2_sync(
                        db.as_ptr(),
                        db.len() as u32,
                        pb.as_ptr(),
                        pb.len() as u32,
                        sb.as_ptr(),
                        sb.len() as u32,
                        iters,
                        key_len,
                        out,
                        cap,
                    )
                }) {
                    Ok(s) => s,
                    Err(e) => format!("__HOST_ERR__:{e}"),
                }
            },
        ),
    );

    let _ = globals.set(
        "__host_crypto_scrypt_sync",
        Func::from(
            |password: String, salt_b64: String, n: u32, r: u32, p: u32, key_len: u32| -> String {
                let pb = password.as_bytes();
                let sb = salt_b64.as_bytes();
                match call_read(|out, cap| unsafe {
                    host_crypto_scrypt_sync(
                        pb.as_ptr(),
                        pb.len() as u32,
                        sb.as_ptr(),
                        sb.len() as u32,
                        n,
                        r,
                        p,
                        key_len,
                        out,
                        cap,
                    )
                }) {
                    Ok(s) => s,
                    Err(e) => format!("__HOST_ERR__:{e}"),
                }
            },
        ),
    );

    // Sign / verify (RSA + ECDSA).
    let _ = globals.set(
        "__host_crypto_sign",
        Func::from(
            |algo: String, key_pem: String, data_b64: String| -> String {
                let ab = algo.as_bytes();
                let kb = key_pem.as_bytes();
                let db = data_b64.as_bytes();
                match call_read(|out, cap| unsafe {
                    host_crypto_sign(
                        ab.as_ptr(),
                        ab.len() as u32,
                        kb.as_ptr(),
                        kb.len() as u32,
                        db.as_ptr(),
                        db.len() as u32,
                        out,
                        cap,
                    )
                }) {
                    Ok(s) => s,
                    Err(e) => format!("__HOST_ERR__:{e}"),
                }
            },
        ),
    );

    let _ = globals.set(
        "__host_crypto_verify",
        Func::from(
            |algo: String, key_pem: String, data_b64: String, sig_b64: String| -> i32 {
                let ab = algo.as_bytes();
                let kb = key_pem.as_bytes();
                let db = data_b64.as_bytes();
                let sb = sig_b64.as_bytes();
                unsafe {
                    host_crypto_verify(
                        ab.as_ptr(),
                        ab.len() as u32,
                        kb.as_ptr(),
                        kb.len() as u32,
                        db.as_ptr(),
                        db.len() as u32,
                        sb.as_ptr(),
                        sb.len() as u32,
                    )
                }
            },
        ),
    );
}

fn install_streaming<'js>(globals: &Object<'js>) {
    // Streaming sign / verify. The JS polyfill opens a handle once,
    // feeds chunks via `update`, and finalizes with the key. Handles
    // are scoped to the host-side `SignHandleStore` (per-thrust in
    // WASM, thread-local on the native path).
    let _ = globals.set(
        "__host_crypto_sign_open",
        Func::from(|algo: String| -> f64 {
            let ab = algo.as_bytes();
            let h = unsafe { host_crypto_sign_open(ab.as_ptr(), ab.len() as u32) };
            // 0 = error (JS falsy); the polyfill throws on that.
            // Negative is also "not supported" - surface as 0 too.
            if h <= 0 { 0.0 } else { h as f64 }
        }),
    );

    let _ = globals.set(
        "__host_crypto_sign_update",
        Func::from(|handle: f64, data_b64: String| -> String {
            let h = handle as i64;
            let db = data_b64.as_bytes();
            let code = unsafe { host_crypto_sign_update(h, db.as_ptr(), db.len() as u32) };
            if code >= 0 {
                String::new()
            } else {
                format!("__HOST_ERR__:{}", read_last_error(code))
            }
        }),
    );

    let _ = globals.set(
        "__host_crypto_sign_finalize",
        Func::from(|handle: f64, algo: String, key_pem: String| -> String {
            let h = handle as i64;
            let ab = algo.as_bytes();
            let kb = key_pem.as_bytes();
            match call_read(|out, cap| unsafe {
                host_crypto_sign_finalize(
                    h,
                    ab.as_ptr(),
                    ab.len() as u32,
                    kb.as_ptr(),
                    kb.len() as u32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_crypto_verify_finalize",
        Func::from(
            |handle: f64, algo: String, key_pem: String, sig_b64: String| -> i32 {
                let h = handle as i64;
                let ab = algo.as_bytes();
                let kb = key_pem.as_bytes();
                let sb = sig_b64.as_bytes();
                unsafe {
                    host_crypto_verify_finalize(
                        h,
                        ab.as_ptr(),
                        ab.len() as u32,
                        kb.as_ptr(),
                        kb.len() as u32,
                        sb.as_ptr(),
                        sb.len() as u32,
                    )
                }
            },
        ),
    );

    // Streaming createHash / createHmac.
    let _ = globals.set(
        "__host_crypto_hash_open",
        Func::from(|algo: String| -> f64 {
            let ab = algo.as_bytes();
            let h = unsafe { host_crypto_hash_open(ab.as_ptr(), ab.len() as u32) };
            if h <= 0 { 0.0 } else { h as f64 }
        }),
    );

    let _ = globals.set(
        "__host_crypto_hmac_open",
        Func::from(|algo: String, key_b64: String| -> f64 {
            let ab = algo.as_bytes();
            let kb = key_b64.as_bytes();
            let h = unsafe {
                host_crypto_hmac_open(ab.as_ptr(), ab.len() as u32, kb.as_ptr(), kb.len() as u32)
            };
            if h <= 0 { 0.0 } else { h as f64 }
        }),
    );

    let _ = globals.set(
        "__host_crypto_hash_update",
        Func::from(|handle: f64, data_b64: String| -> String {
            let h = handle as i64;
            let db = data_b64.as_bytes();
            let code = unsafe { host_crypto_hash_update(h, db.as_ptr(), db.len() as u32) };
            if code >= 0 {
                String::new()
            } else {
                format!("__HOST_ERR__:{}", read_last_error(code))
            }
        }),
    );

    let _ = globals.set(
        "__host_crypto_hash_digest",
        Func::from(|handle: f64, enc: Option<String>| -> String {
            let h = handle as i64;
            let enc_s = enc.unwrap_or_default();
            let eb = enc_s.as_bytes();
            match call_read(|out, cap| unsafe {
                host_crypto_hash_digest(h, eb.as_ptr(), eb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );
}
