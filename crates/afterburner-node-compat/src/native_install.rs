// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Install host-backed globals (`__host_fs_*`, `__host_crypto_*`,
//! `__host_os_*`, `__host_http_request`) on an rquickjs `Context`.
//!
//! Called once per [`crate::active_manifold`]-enabled `Context` - i.e.,
//! once per thread-local Runtime on the native path. Each global is a
//! thin closure that reads the thread-local active manifold, delegates
//! to the corresponding Rust `*_host` module, and translates errors
//! into JS exceptions via `Exception::throw_message`.

use crate::hash_handles::HashHandleStore;
use crate::sign_handles::SignHandleStore;
use crate::{
    active_manifold, child_process_host, crypto_host, dns_host, fs_host, host_context_active,
    http_host, os_host, state_active, zlib_host,
};

// Thread-local handle stores. Each thread-local `ThreadRuntime` owns
// its own - handles never cross thread boundaries. `SIGN_HANDLES` is
// for streaming sign/verify; `HASH_HANDLES` is for streaming
// createHash/createHmac.
thread_local! {
    static SIGN_HANDLES: SignHandleStore = SignHandleStore::new();
    static HASH_HANDLES: HashHandleStore = HashHandleStore::new();
}
use afterburner_core::AfterburnerError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rquickjs::{Ctx, Exception, Function};

/// Install every `__host_*` global onto `ctx`.
pub fn register_native_builtins(ctx: &Ctx<'_>) -> Result<(), AfterburnerError> {
    let g = ctx.globals();

    // ---- fs ---------------------------------------------------------------
    g.set(
        "__host_fs_read_file_sync",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, path: String, encoding: Option<String>| {
                // Match the WASM plugin's error contract: on host
                // error, return a `__HOST_ERR__:<msg>` string so the
                // polyfill's `checkHostError` can rethrow with the
                // right `e.code` (EACCES / ENOENT). Throwing a native
                // QuickJS Exception here would bypass that mapping
                // and leave `e.code` undefined.
                let bytes = match active_manifold::with(|m| fs_host::read_file_sync(&path, m)) {
                    Ok(b) => b,
                    Err(e) => return Ok(format!("__HOST_ERR__:{e}")),
                };
                match encoding
                    .as_deref()
                    .unwrap_or("utf8")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "utf8" | "utf-8" => Ok(String::from_utf8_lossy(&bytes).into_owned()),
                    "base64" => Ok(base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &bytes,
                    )),
                    "hex" => Ok(hex::encode(&bytes)),
                    "binary" | "latin1" => Ok(bytes.iter().map(|b| *b as char).collect()),
                    other => Err(Exception::throw_message(
                        &ctx,
                        &format!("unsupported encoding '{other}'"),
                    )),
                }
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_write_file_sync",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, path: String, data: String, encoding: Option<String>| {
                let bytes = match encoding
                    .as_deref()
                    .unwrap_or("utf8")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "utf8" | "utf-8" => data.into_bytes(),
                    "base64" => base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        data.as_bytes(),
                    )
                    .map_err(|e| Exception::throw_message(&ctx, &format!("base64: {e}")))?,
                    "hex" => hex::decode(data.as_bytes())
                        .map_err(|e| Exception::throw_message(&ctx, &format!("hex: {e}")))?,
                    other => {
                        return Err(Exception::throw_message(
                            &ctx,
                            &format!("unsupported encoding '{other}'"),
                        ));
                    }
                };
                active_manifold::with(|m| fs_host::write_file_sync(&path, &bytes, m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_exists_sync",
        Function::new(ctx.clone(), |path: String| -> bool {
            active_manifold::with(|m| Ok::<bool, AfterburnerError>(fs_host::exists_sync(&path, m)))
                .unwrap_or(false)
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // Stat returns a JSON string so the JS glue can parse it once - avoids
    // the rquickjs lifetime shuffle for returning `Object<'js>` from a
    // closure captured in a long-lived Context.
    g.set(
        "__host_fs_stat_sync",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, path: String| {
            let s = active_manifold::with(|m| fs_host::stat_sync(&path, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(format!(
                r#"{{"size":{},"isFile":{},"isDirectory":{},"mtimeMs":{}}}"#,
                s.size, s.is_file, s.is_dir, s.mtime_ms
            ))
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_readdir_sync",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, path: String| {
            active_manifold::with(|m| fs_host::readdir_sync(&path, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_mkdir_sync",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, path: String, recursive: Option<bool>| {
                active_manifold::with(|m| {
                    fs_host::mkdir_sync(&path, recursive.unwrap_or(false), m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_unlink_sync",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, path: String| {
            active_manifold::with(|m| fs_host::unlink_sync(&path, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(())
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_rename_sync",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, from: String, to: String| {
            active_manifold::with(|m| fs_host::rename_sync(&from, &to, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(())
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_realpath_sync",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, path: String| {
            active_manifold::with(|m| fs_host::realpath_sync(&path, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_readlink_sync",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, path: String| {
            active_manifold::with(|m| fs_host::readlink_sync(&path, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_cp",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, src: String, dst: String, force: Option<bool>| {
                active_manifold::with(|m| {
                    fs_host::cp_recursive(&src, &dst, force.unwrap_or(false), m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_opendir_sync",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, path: String| {
            let entries = active_manifold::with(|m| fs_host::opendir_sync(&path, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            // Marshal to a JSON string so the polyfill's parsing path is
            // identical between native and WASM. JSON.parse on the JS
            // side rebuilds the array of `{name, isFile, isDir, isSymlink}`.
            let mut json = String::from("[");
            for (i, e) in entries.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    "{{\"name\":{},\"isFile\":{},\"isDir\":{},\"isSymlink\":{}}}",
                    js_string_literal(&e.name),
                    e.is_file,
                    e.is_dir,
                    e.is_symlink
                ));
            }
            json.push(']');
            Ok::<_, rquickjs::Error>(json)
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_watch_poll",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, path: String, interval_ms: f64| {
                let interval = interval_ms.max(0.0) as u32;
                let events = active_manifold::with(|m| fs_host::watch_poll(&path, interval, m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                let mut json = String::from("[");
                for (i, e) in events.iter().enumerate() {
                    if i > 0 {
                        json.push(',');
                    }
                    json.push_str(&format!(
                        "{{\"kind\":{},\"filename\":{}}}",
                        js_string_literal(e.kind.as_str()),
                        js_string_literal(&e.filename)
                    ));
                }
                json.push(']');
                Ok::<_, rquickjs::Error>(json)
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- crypto ----------------------------------------------------------
    g.set(
        "__host_crypto_hash",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, algo: String, data: String, enc: Option<String>| {
                let bytes = active_manifold::with(|m| crypto_host::hash(&algo, data.as_bytes(), m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                encode_bytes(&ctx, &bytes, enc.as_deref())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_hmac",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, algo: String, key: String, data: String, enc: Option<String>| {
                let bytes = active_manifold::with(|m| {
                    crypto_host::hmac(&algo, key.as_bytes(), data.as_bytes(), m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                encode_bytes(&ctx, &bytes, enc.as_deref())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_random_bytes",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, len: usize, enc: Option<String>| {
                let bytes = active_manifold::with(|m| crypto_host::random_bytes(len, m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                encode_bytes(&ctx, &bytes, enc.as_deref())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_random_uuid",
        Function::new(ctx.clone(), |ctx: Ctx<'_>| {
            active_manifold::with(crypto_host::random_uuid)
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_timing_safe_equal",
        Function::new(ctx.clone(), |a: String, b: String| -> bool {
            crypto_host::timing_safe_equal(a.as_bytes(), b.as_bytes())
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // The Subtle Crypto dispatcher mirrors the wasi `host_crypto_subtle_op`
    // import so JS code that runs on either path sees identical behaviour.
    // Output is always a base64url string (or `[<b64>,<b64>]` JSON for
    // keypair ops); the JS shim decodes.
    g.set(
        "__host_crypto_subtle_op",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, op: String, args_json: String| -> rquickjs::Result<String> {
                active_manifold::with(|m| crate::subtle_host::subtle_op(&op, &args_json, m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_check_prime",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, candidate_hex: String, checks: u32| -> rquickjs::Result<i32> {
                let bytes = match hex::decode(&candidate_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        return Err(Exception::throw_message(
                            &ctx,
                            &format!("checkPrime: hex decode: {e}"),
                        ));
                    }
                };
                active_manifold::with(|m| {
                    crate::prime_host::check_prime(&bytes, checks as usize, m)
                })
                .map(|ok| if ok { 1 } else { 0 })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_generate_prime",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, bits: u32, safe: bool| -> rquickjs::Result<String> {
                let bytes = active_manifold::with(|m| {
                    crate::prime_host::generate_prime(bits as usize, safe, m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok(hex::encode(&bytes))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // QUIC / HTTP/3 listener - native path stub. The native runtime
    // doesn't run a daemon (no event loop), so the API path always
    // surfaces the no-daemon error and JS callers land in the
    // "use the daemon CLI" branch.
    g.set(
        "__host_http3_listen",
        Function::new(
            ctx.clone(),
            |_ctx: Ctx<'_>,
             _port: u32,
             _server_id: i32,
             _cert: String,
             _key: String|
             -> rquickjs::Result<i32> { Ok(-1) },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_http3_listen_set_cert",
        Function::new(
            ctx.clone(),
            |_ctx: Ctx<'_>, _cert: String, _key: String| -> rquickjs::Result<i32> { Ok(0) },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // Native (rquickjs) path doesn't run a tokio runtime, so the
    // outbound H3 client surfaces the no-daemon sentinel - JS callers
    // either fall back to fetch() (which is wired) or run via the
    // daemon CLI / library API where a tokio handle is attached.
    g.set(
        "__host_http3_request",
        Function::new(
            ctx.clone(),
            |_ctx: Ctx<'_>,
             _url: String,
             _method: String,
             _body_b64: String|
             -> rquickjs::Result<String> { Ok("__HOST_ERR__:no-daemon".into()) },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_v8_serialize",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, json: String| -> rquickjs::Result<String> {
                crate::v8_host::serialize_json(&json)
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_v8_deserialize",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, b64: String| -> rquickjs::Result<String> {
                crate::v8_host::deserialize_to_json(&b64)
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- os --------------------------------------------------------------
    g.set(
        "__host_os_platform",
        Function::new(ctx.clone(), || os_host::platform().to_string()).map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;
    g.set(
        "__host_os_arch",
        Function::new(ctx.clone(), || os_host::arch().to_string()).map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;
    g.set(
        "__host_os_hostname",
        Function::new(ctx.clone(), os_host::hostname).map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;
    g.set(
        "__host_os_tmpdir",
        Function::new(ctx.clone(), os_host::tmpdir).map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;
    g.set(
        "__host_os_cpus",
        Function::new(ctx.clone(), || os_host::cpus() as f64).map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;
    g.set(
        "__host_os_home_dir",
        Function::new(ctx.clone(), os_host::home_dir).map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- child_process (sync) -------------------------------------------
    // Argv crosses as a JSON-encoded string so the wire shape matches
    // the wasm host import. This avoids two divergent argv-encoding
    // paths and keeps the polyfill's `callHost` single-shape.
    g.set(
        "__host_child_process_exec_sync",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, command: String, argv_json: String| {
                let argv_owned: Vec<String> = serde_json::from_str(&argv_json).map_err(|e| {
                    Exception::throw_message(&ctx, &format!("child_process: argv parse: {e}"))
                })?;
                let argv: Vec<&str> = argv_owned.iter().map(String::as_str).collect();
                let result =
                    active_manifold::with(|m| child_process_host::exec_sync(&command, &argv, m))
                        .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(format!(
                    r#"{{"status":{},"stdout":{},"stderr":{}}}"#,
                    result.status,
                    js_string_literal(&result.stdout),
                    js_string_literal(&result.stderr)
                ))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- crypto (ciphers, KDFs) -----------------------------------------
    g.set(
        "__host_crypto_aes_gcm_encrypt",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>,
             algo: String,
             key_b64: String,
             nonce_b64: String,
             data_b64: String,
             aad_b64: Option<String>| {
                let key = B64
                    .decode(key_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("key b64: {e}")))?;
                let nonce = B64
                    .decode(nonce_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("nonce b64: {e}")))?;
                let data = B64
                    .decode(data_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("data b64: {e}")))?;
                let aad = match aad_b64 {
                    Some(s) => B64
                        .decode(s.as_bytes())
                        .map_err(|e| Exception::throw_message(&ctx, &format!("aad b64: {e}")))?,
                    None => Vec::new(),
                };
                let out = active_manifold::with(|m| {
                    crypto_host::aes_gcm_encrypt(&algo, &key, &nonce, &data, &aad, m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&out))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_aes_gcm_decrypt",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>,
             algo: String,
             key_b64: String,
             nonce_b64: String,
             data_b64: String,
             aad_b64: Option<String>| {
                let key = B64
                    .decode(key_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("key b64: {e}")))?;
                let nonce = B64
                    .decode(nonce_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("nonce b64: {e}")))?;
                let data = B64
                    .decode(data_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("data b64: {e}")))?;
                let aad = match aad_b64 {
                    Some(s) => B64
                        .decode(s.as_bytes())
                        .map_err(|e| Exception::throw_message(&ctx, &format!("aad b64: {e}")))?,
                    None => Vec::new(),
                };
                let out = active_manifold::with(|m| {
                    crypto_host::aes_gcm_decrypt(&algo, &key, &nonce, &data, &aad, m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&out))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    for (name, encrypt) in [
        ("__host_crypto_aes_cbc_encrypt", true),
        ("__host_crypto_aes_cbc_decrypt", false),
    ] {
        g.set(
            name,
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      algo: String,
                      key_b64: String,
                      iv_b64: String,
                      data_b64: String| {
                    let key = B64
                        .decode(key_b64.as_bytes())
                        .map_err(|e| Exception::throw_message(&ctx, &format!("key b64: {e}")))?;
                    let iv = B64
                        .decode(iv_b64.as_bytes())
                        .map_err(|e| Exception::throw_message(&ctx, &format!("iv b64: {e}")))?;
                    let data = B64
                        .decode(data_b64.as_bytes())
                        .map_err(|e| Exception::throw_message(&ctx, &format!("data b64: {e}")))?;
                    let out = active_manifold::with(|m| {
                        if encrypt {
                            crypto_host::aes_cbc_encrypt(&algo, &key, &iv, &data, m)
                        } else {
                            crypto_host::aes_cbc_decrypt(&algo, &key, &iv, &data, m)
                        }
                    })
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                    Ok::<_, rquickjs::Error>(B64.encode(&out))
                },
            )
            .map_err(err_to_ab)?,
        )
        .map_err(err_to_ab)?;
    }

    // ---- crypto streaming sign / verify ---------------------------------
    g.set(
        "__host_crypto_sign_open",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, algo: String| {
            let id = SIGN_HANDLES
                .with(|s| s.open(&algo))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(id as f64)
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_sign_update",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, handle: f64, data_b64: String| {
                let data = B64
                    .decode(data_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("data b64: {e}")))?;
                SIGN_HANDLES
                    .with(|s| s.update(handle as u64, &data))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_sign_finalize",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, handle: f64, algo: String, key_pem: String| {
                let state = SIGN_HANDLES
                    .with(|s| s.take(handle as u64))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                let sig = active_manifold::with(|m| {
                    crypto_host::sign_finalize(&algo, &key_pem, state, m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&sig))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_verify_finalize",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>,
             handle: f64,
             algo: String,
             key_pem: String,
             sig_b64: String|
             -> rquickjs::Result<i32> {
                let sig = B64
                    .decode(sig_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("sig b64: {e}")))?;
                let state = SIGN_HANDLES
                    .with(|s| s.take(handle as u64))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                let ok = active_manifold::with(|m| {
                    crypto_host::verify_finalize(&algo, &key_pem, state, &sig, m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok(if ok { 1 } else { 0 })
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- crypto streaming hash / hmac -----------------------------------
    // Permission-gated at open time: if the manifold denies crypto, the
    // `open` call throws and no handle is allocated. No need to re-check
    // on every update/finalize.
    g.set(
        "__host_crypto_hash_open",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, algo: String| {
            active_manifold::with(|m| {
                if !m.crypto {
                    return Err(AfterburnerError::PermissionDenied(
                        "crypto.createHash".into(),
                    ));
                }
                Ok(())
            })
            .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            let id = HASH_HANDLES
                .with(|s| s.open_digest(&algo))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(id as f64)
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_hmac_open",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, algo: String, key_b64: String| {
                active_manifold::with(|m| {
                    if !m.crypto {
                        return Err(AfterburnerError::PermissionDenied(
                            "crypto.createHmac".into(),
                        ));
                    }
                    Ok(())
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                let key = B64
                    .decode(key_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("hmac key b64: {e}")))?;
                let id = HASH_HANDLES
                    .with(|s| s.open_hmac(&algo, &key))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(id as f64)
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_hash_update",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, handle: f64, data_b64: String| {
                let data = B64
                    .decode(data_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("data b64: {e}")))?;
                HASH_HANDLES
                    .with(|s| s.update(handle as u64, &data))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_hash_digest",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, handle: f64, enc: Option<String>| {
                let bytes = HASH_HANDLES
                    .with(|s| s.finalize(handle as u64))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                encode_bytes(&ctx, &bytes, enc.as_deref())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- crypto one-shot sign / verify (RSA + ECDSA) --------------------
    g.set(
        "__host_crypto_sign",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, algo: String, key_pem: String, data_b64: String| {
                let data = B64
                    .decode(data_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("data b64: {e}")))?;
                let sig = active_manifold::with(|m| crypto_host::sign(&algo, &key_pem, &data, m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&sig))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_verify",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>,
             algo: String,
             key_pem: String,
             data_b64: String,
             sig_b64: String|
             -> rquickjs::Result<i32> {
                let data = B64
                    .decode(data_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("data b64: {e}")))?;
                let sig = B64
                    .decode(sig_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("sig b64: {e}")))?;
                let ok =
                    active_manifold::with(|m| crypto_host::verify(&algo, &key_pem, &data, &sig, m))
                        .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                // Return i32 (1/0) to match the WASM path's i32 ABI so
                // the JS polyfill sees the same shape regardless of engine.
                Ok(if ok { 1 } else { 0 })
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- state store ----------------------------------------------------
    g.set(
        "__host_state_get",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, key: String| {
            let value = state_active::with(|store| Ok(store.get(&key)))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(value.map(|bs| B64.encode(&bs)))
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_state_set",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, key: String, value_b64: String| {
                let value = B64
                    .decode(value_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("value b64: {e}")))?;
                state_active::with(|store| {
                    store.set(&key, value);
                    Ok(())
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_state_delete",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, key: String| {
            state_active::with(|store| {
                store.delete(&key);
                Ok(())
            })
            .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(())
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_state_increment",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, key: String, delta: f64| {
            let new_value = state_active::with(|store| Ok(store.increment_i64(&key, delta as i64)))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(new_value as f64)
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- chunked fs (stream support) ------------------------------------
    g.set(
        "__host_fs_read_chunk",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, path: String, offset: f64, len: f64| {
                let bytes = active_manifold::with(|m| {
                    fs_host::read_chunk(&path, offset as u64, len as usize, m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&bytes))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_write_chunk",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, path: String, offset: f64, data_b64: String| {
                let data = B64
                    .decode(data_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("b64: {e}")))?;
                active_manifold::with(|m| fs_host::write_chunk(&path, offset as u64, &data, m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_fs_size",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, path: String| {
            let size = active_manifold::with(|m| fs_host::file_size(&path, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(size as f64)
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_pbkdf2_sync",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>,
             digest: String,
             password: String,
             salt_b64: String,
             iters: u32,
             key_len: u32| {
                let salt = B64
                    .decode(salt_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("salt b64: {e}")))?;
                let out = active_manifold::with(|m| {
                    crypto_host::pbkdf2_sync(
                        &digest,
                        password.as_bytes(),
                        &salt,
                        iters,
                        key_len as usize,
                        m,
                    )
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&out))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_crypto_scrypt_sync",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>,
             password: String,
             salt_b64: String,
             n: u32,
             r: u32,
             p: u32,
             key_len: u32| {
                let salt = B64
                    .decode(salt_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("salt b64: {e}")))?;
                let out = active_manifold::with(|m| {
                    crypto_host::scrypt_sync(
                        password.as_bytes(),
                        &salt,
                        n,
                        r,
                        p,
                        key_len as usize,
                        m,
                    )
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&out))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- zlib (no Manifold gate - pure compute) --------------------------
    for (name, kind) in [
        ("__host_zlib_deflate_sync", ZlibOp::Deflate),
        ("__host_zlib_inflate_sync", ZlibOp::Inflate),
        ("__host_zlib_gzip_sync", ZlibOp::Gzip),
        ("__host_zlib_gunzip_sync", ZlibOp::Gunzip),
    ] {
        g.set(
            name,
            Function::new(ctx.clone(), move |ctx: Ctx<'_>, input_b64: String| {
                let input = B64
                    .decode(input_b64.as_bytes())
                    .map_err(|e| Exception::throw_message(&ctx, &format!("base64: {e}")))?;
                let result = match kind {
                    ZlibOp::Deflate => zlib_host::deflate_sync(&input),
                    ZlibOp::Inflate => zlib_host::inflate_sync(&input),
                    ZlibOp::Gzip => zlib_host::gzip_sync(&input),
                    ZlibOp::Gunzip => zlib_host::gunzip_sync(&input),
                }
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(B64.encode(&result))
            })
            .map_err(err_to_ab)?,
        )
        .map_err(err_to_ab)?;
    }

    // ---- dns -------------------------------------------------------------
    g.set(
        "__host_dns_lookup",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, hostname: String| {
            let ip = active_manifold::with(|m| dns_host::lookup(&hostname, m))
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
            Ok::<_, rquickjs::Error>(ip)
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // Record-type-aware resolvers - same JSON-encoded result shape as
    // the WASM bridges. `servers_csv` is a comma-separated address
    // list; empty string means "use system /etc/resolv.conf with a
    // Cloudflare fallback." The split happens here so dns_host stays
    // string-list-typed regardless of which JS runtime called us.
    fn split_servers(csv: &str) -> Vec<String> {
        csv.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect()
    }

    macro_rules! native_dns_string_list {
        ($name:literal, $impl:expr) => {
            g.set(
                $name,
                Function::new(
                    ctx.clone(),
                    |ctx: Ctx<'_>, hostname: String, servers_csv: String| {
                        let servers = split_servers(&servers_csv);
                        let list = active_manifold::with(|m| $impl(&hostname, &servers, m))
                            .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                        Ok::<_, rquickjs::Error>(
                            serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()),
                        )
                    },
                )
                .map_err(err_to_ab)?,
            )
            .map_err(err_to_ab)?;
        };
    }

    native_dns_string_list!("__host_dns_resolve4", dns_host::resolve4);
    native_dns_string_list!("__host_dns_resolve6", dns_host::resolve6);
    native_dns_string_list!("__host_dns_resolve_cname", dns_host::resolve_cname);
    native_dns_string_list!("__host_dns_resolve_ns", dns_host::resolve_ns);
    native_dns_string_list!("__host_dns_reverse", dns_host::reverse);

    g.set(
        "__host_dns_resolve_soa",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, hostname: String, servers_csv: String| {
                let servers = split_servers(&servers_csv);
                let v = active_manifold::with(|m| dns_host::resolve_soa(&hostname, &servers, m))
                    .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                Ok::<_, rquickjs::Error>(v.to_string())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_dns_resolve_mx",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, hostname: String, servers_csv: String| {
                let servers = split_servers(&servers_csv);
                let records =
                    active_manifold::with(|m| dns_host::resolve_mx(&hostname, &servers, m))
                        .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                let v: Vec<serde_json::Value> = records.iter().map(|r| r.to_json()).collect();
                Ok::<_, rquickjs::Error>(
                    serde_json::to_string(&serde_json::Value::Array(v))
                        .unwrap_or_else(|_| "[]".into()),
                )
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_dns_resolve_txt",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, hostname: String, servers_csv: String| {
                let servers = split_servers(&servers_csv);
                let records =
                    active_manifold::with(|m| dns_host::resolve_txt(&hostname, &servers, m))
                        .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                // Node's TXT shape: string[][].
                let v: Vec<serde_json::Value> = records
                    .into_iter()
                    .map(|fragments| {
                        serde_json::Value::Array(
                            fragments
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        )
                    })
                    .collect();
                Ok::<_, rquickjs::Error>(
                    serde_json::to_string(&serde_json::Value::Array(v))
                        .unwrap_or_else(|_| "[]".into()),
                )
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // ---- host context (embedder-facing hooks) -------------------------
    // Scripts call these via require('afterburner:host') - the host
    // wires a HostContext implementation; default NullHost returns
    // empty column / ignores emitted rows.
    g.set(
        "__host_read_column",
        Function::new(ctx.clone(), |name: String| -> String {
            let rows = host_context_active::with(|ctx| match ctx {
                Some(c) => c.read_column(&name),
                None => Vec::new(),
            });
            serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into())
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_emit_row",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, row_json: String| -> rquickjs::Result<()> {
                let row: serde_json::Value = serde_json::from_str(&row_json)
                    .map_err(|e| Exception::throw_message(&ctx, &format!("emit_row json: {e}")))?;
                host_context_active::with(|c| {
                    if let Some(ctx) = c {
                        ctx.emit_row(row);
                    }
                });
                Ok(())
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    g.set(
        "__host_get_env",
        Function::new(ctx.clone(), |key: String| -> Option<String> {
            host_context_active::with(|c| c.and_then(|ctx| ctx.get_env(&key)))
        })
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    // HTTP returns JSON text with `body_b64` carrying the authoritative
    // bytes (base64) and `body` left as lossy-UTF-8 for backward-compat
    // with callers that want a string view. Binary responses roundtrip
    // cleanly through `body_b64`.
    g.set(
        "__host_http_request",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'_>, method: String, url: String, body: Option<String>| {
                let resp = active_manifold::with(|m| {
                    http_host::request(&method, &url, &[], body.as_deref().map(str::as_bytes), m)
                })
                .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?;
                let body_text = String::from_utf8_lossy(&resp.body).into_owned();
                let body_b64 = B64.encode(&resp.body);
                Ok::<_, rquickjs::Error>(format!(
                    r#"{{"status":{},"body":{},"body_b64":{}}}"#,
                    resp.status,
                    js_string_literal(&body_text),
                    js_string_literal(&body_b64),
                ))
            },
        )
        .map_err(err_to_ab)?,
    )
    .map_err(err_to_ab)?;

    Ok(())
}

fn encode_bytes(ctx: &Ctx<'_>, bytes: &[u8], encoding: Option<&str>) -> rquickjs::Result<String> {
    match encoding.unwrap_or("hex").to_ascii_lowercase().as_str() {
        "hex" => Ok(hex::encode(bytes)),
        "base64" => Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bytes,
        )),
        "binary" | "latin1" => Ok(bytes.iter().map(|b| *b as char).collect()),
        "utf8" | "utf-8" => Ok(String::from_utf8_lossy(bytes).into_owned()),
        other => Err(Exception::throw_message(
            ctx,
            &format!("unsupported encoding '{other}'"),
        )),
    }
}

#[derive(Clone, Copy)]
enum ZlibOp {
    Deflate,
    Inflate,
    Gzip,
    Gunzip,
}

fn err_to_ab(e: rquickjs::Error) -> AfterburnerError {
    AfterburnerError::Engine(format!("rquickjs: {e}"))
}

/// Escape a Rust string into a JSON-compatible string literal (for
/// inlining into a JSON object literal we hand back to JS).
fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
