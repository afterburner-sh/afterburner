// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Grab-bag globals: `os`, `http`, `dns`, `zlib`, host-context hooks
//! (`readColumn` / `emitRow` / `getEnv`), the state store, and the
//! error-message bridge (`__host_last_error`). The per-thrust input
//! bridges live in `globals::input`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use javy_plugin_api::javy::quickjs::{Object, prelude::Func};

use super::call_read;
use crate::host_api::*;
use base64::Engine as _;

pub fn install<'js>(globals: &Object<'js>) {
    install_diagnostics(globals);
    install_os(globals);
    install_http_dns(globals);
    install_zlib(globals);
    install_hostctx(globals);
    install_state(globals);
}

fn install_diagnostics<'js>(globals: &Object<'js>) {
    // Expose the host's `last_error` slot as a JS-callable global.
    // Useful when a host call returns a sentinel (0 handle, -N code)
    // and the polyfill needs the detailed message - e.g. to distinguish
    // "permission denied" from "algorithm not supported" on a failed
    // `createHash` open.
    let _ = globals.set(
        "__host_last_error",
        Func::from(|| -> String {
            let mut buf = vec![0u8; 4096];
            let n = unsafe { host_last_error(buf.as_mut_ptr(), buf.len() as u32) };
            if n >= 0 {
                buf.truncate(n as usize);
                String::from_utf8_lossy(&buf).into_owned()
            } else {
                String::new()
            }
        }),
    );

    // Per-thrust input bridges (`__AB_GET_INPUT__` /
    // `__AB_GET_INPUT_VALUE__`) live in `globals::input`.

    // Daemon-mode envelope getter. Same shape as __AB_GET_INPUT__ but
    // routes to `HostState::pending_envelope` - the long-lived Store
    // re-entry channel. Plugin's `daemon_step` export calls this at
    // the top of every dispatch.
    let _ = globals.set(
        "__AB_GET_ENVELOPE__",
        Func::from(|| -> String {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = unsafe { host_get_envelope(buf.as_mut_ptr(), buf.len() as u32) };
                if n >= 0 {
                    buf.truncate(n as usize);
                    return String::from_utf8_lossy(&buf).into_owned();
                }
                if n == -4 {
                    let new_cap = buf.len().saturating_mul(2);
                    buf.resize(new_cap, 0);
                    continue;
                }
                return String::new();
            }
        }),
    );

    // HTTP-server host imports. JS polyfill calls these from
    // `http.createServer().listen(...)` and the `ServerResponse.end()`
    // path. `f64` across the ABI boundary is the JS-number → i64
    // bridge (rquickjs exposes integers through f64 for portability).
    let _ = globals.set(
        "__host_http_listen",
        Func::from(|port: f64| -> f64 { unsafe { host_http_listen(port as u32) as f64 } }),
    );
    let _ = globals.set(
        "__host_http_reply",
        Func::from(|req_id: f64, resp_json: String| -> i32 {
            let b = resp_json.as_bytes();
            unsafe { host_http_reply(req_id as i64, b.as_ptr(), b.len() as u32) }
        }),
    );
    // server.close() - releases the port + aborts the axum task.
    let _ = globals.set(
        "__host_http_close",
        Func::from(|server_id: f64| -> f64 { unsafe { host_http_close(server_id as i32) as f64 } }),
    );

    // require() calls this for TS / ESM files. Returns the
    // transpiled JS string, or a host-error-prefixed string if the
    // transpile hook is absent / failed.
    let _ = globals.set(
        "__host_ts_transpile",
        Func::from(|source: String, path: String| -> String {
            let src_bytes = source.as_bytes();
            let path_bytes = path.as_bytes();
            // Generous cap - transpile output is usually under 4x
            // input for common TS+ESM code. If it exceeds the
            // buffer the import returns -2 and we surface the error.
            let cap: u32 = core::cmp::max(src_bytes.len() * 4, 16 * 1024) as u32;
            let mut buf = alloc::vec![0u8; cap as usize];
            let n = unsafe {
                host_ts_transpile(
                    src_bytes.as_ptr(),
                    src_bytes.len() as u32,
                    path_bytes.as_ptr(),
                    path_bytes.len() as u32,
                    buf.as_mut_ptr(),
                    cap,
                )
            };
            if n < 0 {
                // Surface the structured error string the JS side
                // already looks for (`__HOST_ERR__:` prefix lets the
                // require resolver convert to a typed Error).
                let detail = match n {
                    -1 => {
                        alloc::string::String::from("no transpile hook (build with `ts` feature)")
                    }
                    -2 => {
                        alloc::string::String::from("transpile output too large for guest buffer")
                    }
                    _ => {
                        let mut err_buf = alloc::vec![0u8; 2048];
                        let err_n =
                            unsafe { host_last_error(err_buf.as_mut_ptr(), err_buf.len() as u32) };
                        if err_n > 0 {
                            String::from_utf8(err_buf[..err_n as usize].to_vec())
                                .unwrap_or_else(|_| alloc::string::String::from("transpile error"))
                        } else {
                            alloc::string::String::from("transpile error")
                        }
                    }
                };
                return alloc::format!("__HOST_ERR__:{detail}");
            }
            match String::from_utf8(buf[..n as usize].to_vec()) {
                Ok(s) => s,
                Err(_) => alloc::string::String::from("__HOST_ERR__:transpile output not utf-8"),
            }
        }),
    );

    // ---- L3 shadow: bcrypt -------------------------------------------
    //
    // Reads `host_last_error` off the host and returns it with the
    // `__HOST_ERR__:` prefix the require resolver / shadow polyfill
    // both look for. Fallback message used when the host didn't set
    // anything (should never happen in practice).
    fn host_err_or_default(fallback: &str) -> alloc::string::String {
        let mut buf = alloc::vec![0u8; 2048];
        let n = unsafe { host_last_error(buf.as_mut_ptr(), buf.len() as u32) };
        let detail = if n > 0 {
            alloc::string::String::from_utf8(buf[..n as usize].to_vec())
                .unwrap_or_else(|_| fallback.into())
        } else {
            fallback.into()
        };
        alloc::format!("__HOST_ERR__:{detail}")
    }

    //
    // Always-present globals that dispatch through the host's
    // shadow-bcrypt import. The imports themselves return -1 with a
    // structured error when the host wasn't built with the feature.
    let _ = globals.set(
        "__host_shadow_bcrypt_hash",
        Func::from(|password: String, cost: f64| -> String {
            let pw = password.as_bytes();
            let cap: u32 = 128;
            let mut buf = alloc::vec![0u8; cap as usize];
            let n = unsafe {
                host_shadow_bcrypt_hash(
                    pw.as_ptr(),
                    pw.len() as u32,
                    cost as i32,
                    buf.as_mut_ptr(),
                    cap,
                )
            };
            if n < 0 {
                return host_err_or_default("bcrypt hash failed");
            }
            match String::from_utf8(buf[..n as usize].to_vec()) {
                Ok(s) => s,
                Err(_) => alloc::string::String::from("__HOST_ERR__:bcrypt hash output not utf-8"),
            }
        }),
    );
    let _ = globals.set(
        "__host_shadow_bcrypt_verify",
        Func::from(|password: String, hash: String| -> f64 {
            let pw = password.as_bytes();
            let h = hash.as_bytes();
            let n = unsafe {
                host_shadow_bcrypt_verify(pw.as_ptr(), pw.len() as u32, h.as_ptr(), h.len() as u32)
            };
            // `-1`/`0`/`1` preserved across the f64 bridge; JS side
            // branches on the value.
            n as f64
        }),
    );
    let _ = globals.set(
        "__host_shadow_bcrypt_gen_salt",
        Func::from(|rounds: f64| -> String {
            let cap: u32 = 64;
            let mut buf = alloc::vec![0u8; cap as usize];
            let n = unsafe { host_shadow_bcrypt_gen_salt(rounds as i32, buf.as_mut_ptr(), cap) };
            if n < 0 {
                return host_err_or_default("bcrypt gen_salt failed");
            }
            match String::from_utf8(buf[..n as usize].to_vec()) {
                Ok(s) => s,
                Err(_) => alloc::string::String::from("__HOST_ERR__:bcrypt gen_salt not utf-8"),
            }
        }),
    );

    // ---- L3 shadow: argon2 ------------------------------------------
    //
    // PHC-formatted output can be ~160 bytes for default params
    // (m=65536, t=3, p=4) + salt + hash; 256 is plenty.
    let _ = globals.set(
        "__host_shadow_argon2_hash",
        Func::from(
            |password: String,
             ty: f64,
             time_cost: f64,
             memory_cost: f64,
             parallelism: f64|
             -> String {
                let pw = password.as_bytes();
                let cap: u32 = 256;
                let mut buf = alloc::vec![0u8; cap as usize];
                let n = unsafe {
                    host_shadow_argon2_hash(
                        pw.as_ptr(),
                        pw.len() as u32,
                        ty as i32,
                        time_cost as i32,
                        memory_cost as i32,
                        parallelism as i32,
                        buf.as_mut_ptr(),
                        cap,
                    )
                };
                if n < 0 {
                    return host_err_or_default("argon2 hash failed");
                }
                match String::from_utf8(buf[..n as usize].to_vec()) {
                    Ok(s) => s,
                    Err(_) => alloc::string::String::from("__HOST_ERR__:argon2 hash not utf-8"),
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_shadow_argon2_verify",
        Func::from(|hash: String, password: String| -> f64 {
            let h = hash.as_bytes();
            let pw = password.as_bytes();
            let n = unsafe {
                host_shadow_argon2_verify(h.as_ptr(), h.len() as u32, pw.as_ptr(), pw.len() as u32)
            };
            n as f64
        }),
    );
    let _ = globals.set(
        "__host_shadow_argon2_needs_rehash",
        Func::from(
            |hash: String, ty: f64, time_cost: f64, memory_cost: f64, parallelism: f64| -> f64 {
                let h = hash.as_bytes();
                let n = unsafe {
                    host_shadow_argon2_needs_rehash(
                        h.as_ptr(),
                        h.len() as u32,
                        ty as i32,
                        time_cost as i32,
                        memory_cost as i32,
                        parallelism as i32,
                    )
                };
                n as f64
            },
        ),
    );

    // ---- L3 shadow: jsonwebtoken ------------------------------------
    //
    // JWT output is typically under 2 KB; 4 KB buffer covers all
    // reasonable payloads including ~2 KB RSA signatures.
    let _ = globals.set(
        "__host_shadow_jwt_sign",
        Func::from(
            |payload_json: String, secret: String, opts_json: String| -> String {
                let pj = payload_json.as_bytes();
                let s = secret.as_bytes();
                let oj = opts_json.as_bytes();
                let cap: u32 = 4096;
                let mut buf = alloc::vec![0u8; cap as usize];
                let n = unsafe {
                    host_shadow_jwt_sign(
                        pj.as_ptr(),
                        pj.len() as u32,
                        s.as_ptr(),
                        s.len() as u32,
                        oj.as_ptr(),
                        oj.len() as u32,
                        buf.as_mut_ptr(),
                        cap,
                    )
                };
                if n < 0 {
                    return host_err_or_default("jwt sign failed");
                }
                match String::from_utf8(buf[..n as usize].to_vec()) {
                    Ok(s) => s,
                    Err(_) => alloc::string::String::from("__HOST_ERR__:jwt sign not utf-8"),
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_shadow_jwt_verify",
        Func::from(
            |token: String, secret: String, opts_json: String| -> String {
                let t = token.as_bytes();
                let s = secret.as_bytes();
                let oj = opts_json.as_bytes();
                let cap: u32 = 16 * 1024;
                let mut buf = alloc::vec![0u8; cap as usize];
                let n = unsafe {
                    host_shadow_jwt_verify(
                        t.as_ptr(),
                        t.len() as u32,
                        s.as_ptr(),
                        s.len() as u32,
                        oj.as_ptr(),
                        oj.len() as u32,
                        buf.as_mut_ptr(),
                        cap,
                    )
                };
                if n < 0 {
                    return host_err_or_default("jwt verify failed");
                }
                match String::from_utf8(buf[..n as usize].to_vec()) {
                    Ok(s) => s,
                    Err(_) => alloc::string::String::from("__HOST_ERR__:jwt verify not utf-8"),
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_shadow_jwt_decode",
        Func::from(|token: String| -> String {
            let t = token.as_bytes();
            let cap: u32 = 16 * 1024;
            let mut buf = alloc::vec![0u8; cap as usize];
            let n = unsafe {
                host_shadow_jwt_decode(t.as_ptr(), t.len() as u32, buf.as_mut_ptr(), cap)
            };
            if n < 0 {
                return host_err_or_default("jwt decode failed");
            }
            match String::from_utf8(buf[..n as usize].to_vec()) {
                Ok(s) => s,
                Err(_) => alloc::string::String::from("__HOST_ERR__:jwt decode not utf-8"),
            }
        }),
    );

    // process.exit - never returns; the host traps with I32Exit.
    let _ = globals.set(
        "__host_process_exit",
        Func::from(|code: f64| unsafe { host_process_exit(code as i32) }),
    );

    // timer host imports for daemon mode. Polyfill `timers.js`
    // checks for the presence of `__host_timer_set` to detect daemon
    // mode and route through real host-managed timers.
    let _ = globals.set(
        "__host_timer_set",
        Func::from(|delay_ms: f64, repeat: f64| -> f64 {
            unsafe { host_timer_set(delay_ms as i32, repeat as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_timer_clear",
        Func::from(|timer_id: f64| unsafe { host_timer_clear(timer_id as i32) }),
    );
    let _ = globals.set(
        "__host_timer_unref",
        Func::from(|timer_id: f64| unsafe { host_timer_unref(timer_id as i32) }),
    );
    let _ = globals.set(
        "__host_timer_ref",
        Func::from(|timer_id: f64| unsafe { host_timer_ref(timer_id as i32) }),
    );

    // ---- worker_threads ---------------------------------------
    //
    // The polyfill `polyfills/worker_threads.js` calls these to spawn
    // child `burn` subprocesses (parent role) or to talk back to the
    // parent (child role). All take/return scalars + base64-free
    // strings; large payloads are JSON over the wire.
    let _ = globals.set(
        "__host_worker_spawn",
        Func::from(|path: String, worker_data: String| -> f64 {
            let pb = path.as_bytes();
            let db = worker_data.as_bytes();
            unsafe {
                host_worker_spawn(pb.as_ptr(), pb.len() as u32, db.as_ptr(), db.len() as u32) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_worker_spawn_env",
        Func::from(
            |path: String, worker_data: String, env_json: String| -> f64 {
                let pb = path.as_bytes();
                let db = worker_data.as_bytes();
                let eb = env_json.as_bytes();
                unsafe {
                    host_worker_spawn_env(
                        pb.as_ptr(),
                        pb.len() as u32,
                        db.as_ptr(),
                        db.len() as u32,
                        eb.as_ptr(),
                        eb.len() as u32,
                    ) as f64
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_worker_pid",
        Func::from(|worker_id: f64| -> f64 { unsafe { host_worker_pid(worker_id as i32) as f64 } }),
    );

    // ---- SharedArrayBuffer + Atomics.wait/notify ----------------
    //
    // Numbers cross the JS↔WASM boundary as f64; for region_id /
    // byte_offset / values we cast to i64 inside the call. Bytes
    // travel as base64-encoded strings via `call_read` (auto-doubling
    // buffer) - same shape used by the rest of the byte-payload host
    // imports.
    let _ = globals.set(
        "__host_sab_alloc",
        Func::from(|byte_length: f64| -> f64 {
            unsafe { host_sab_alloc(byte_length as i64) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_sab_open",
        Func::from(|descriptor: String, byte_length: f64| -> f64 {
            let db = descriptor.as_bytes();
            unsafe { host_sab_open(db.as_ptr(), db.len() as u32, byte_length as i64) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_sab_release",
        Func::from(|region_id: f64| -> f64 {
            unsafe { host_sab_release(region_id as i64) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_sab_byte_length",
        Func::from(|region_id: f64| -> f64 {
            unsafe { host_sab_byte_length(region_id as i64) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_sab_descriptor",
        Func::from(|region_id: f64| -> String {
            call_read(|out, cap| unsafe { host_sab_descriptor(region_id as i64, out, cap) })
                .unwrap_or_default()
        }),
    );
    let _ = globals.set(
        "__host_sab_read_b64",
        Func::from(|region_id: f64, offset: f64, len: f64| -> String {
            match call_read(|out, cap| unsafe {
                host_sab_read(region_id as i64, offset as i64, len as i64, out, cap)
            }) {
                Ok(s) => base64::engine::general_purpose::STANDARD.encode(s.as_bytes()),
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_sab_write_b64",
        Func::from(|region_id: f64, offset: f64, bytes_b64: String| -> f64 {
            let bytes = match base64::engine::general_purpose::STANDARD.decode(&bytes_b64) {
                Ok(b) => b,
                Err(_) => return -1.0,
            };
            unsafe {
                host_sab_write(
                    region_id as i64,
                    offset as i64,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                ) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_sab_atomic_load",
        Func::from(|region_id: f64, byte_offset: f64, width: f64| -> f64 {
            unsafe {
                host_sab_atomic_load(region_id as i64, byte_offset as i64, width as i32) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_sab_atomic_store",
        Func::from(
            |region_id: f64, byte_offset: f64, value: f64, width: f64| -> f64 {
                unsafe {
                    host_sab_atomic_store(
                        region_id as i64,
                        byte_offset as i64,
                        value as i64,
                        width as i32,
                    ) as f64
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_sab_atomic_cas",
        Func::from(
            |region_id: f64,
             byte_offset: f64,
             expected: f64,
             replacement: f64,
             width: f64|
             -> f64 {
                unsafe {
                    host_sab_atomic_cas(
                        region_id as i64,
                        byte_offset as i64,
                        expected as i64,
                        replacement as i64,
                        width as i32,
                    ) as f64
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_sab_wait",
        Func::from(
            |region_id: f64, byte_offset: f64, expected: f64, timeout_ms: f64| -> f64 {
                unsafe {
                    host_sab_wait(
                        region_id as i64,
                        byte_offset as i64,
                        expected as i32,
                        timeout_ms as i64,
                    ) as f64
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_sab_notify",
        Func::from(|region_id: f64, byte_offset: f64, count: f64| -> f64 {
            unsafe { host_sab_notify(region_id as i64, byte_offset as i64, count as i64) as f64 }
        }),
    );

    // ---- inspector / Chrome DevTools Protocol ---------------
    let _ = globals.set(
        "__host_inspector_open",
        Func::from(|port: f64| -> f64 { unsafe { host_inspector_open(port as i32) as f64 } }),
    );
    let _ = globals.set(
        "__host_inspector_close",
        Func::from(|| -> f64 { unsafe { host_inspector_close() as f64 } }),
    );
    let _ = globals.set(
        "__host_inspector_send",
        Func::from(|session_id: f64, payload: String| -> f64 {
            let pb = payload.as_bytes();
            unsafe { host_inspector_send(session_id as i32, pb.as_ptr(), pb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_inspector_pause",
        Func::from(|| -> f64 { unsafe { host_inspector_pause() as f64 } }),
    );
    let _ = globals.set(
        "__host_worker_post_message",
        Func::from(|worker_id: f64, payload: String| -> f64 {
            let pb = payload.as_bytes();
            unsafe {
                host_worker_post_message(worker_id as i32, pb.as_ptr(), pb.len() as u32) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_worker_terminate",
        Func::from(|worker_id: f64, force: f64| -> f64 {
            unsafe { host_worker_terminate(worker_id as i32, force as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_worker_post_to_parent",
        Func::from(|payload: String| -> f64 {
            let pb = payload.as_bytes();
            unsafe { host_worker_post_to_parent(pb.as_ptr(), pb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_worker_post_online_to_parent",
        Func::from(|| -> f64 { unsafe { host_worker_post_online_to_parent() as f64 } }),
    );
    let _ = globals.set(
        "__host_worker_post_error_to_parent",
        Func::from(|message: String, stack: String| -> f64 {
            let mb = message.as_bytes();
            let sb = stack.as_bytes();
            unsafe {
                host_worker_post_error_to_parent(
                    mb.as_ptr(),
                    mb.len() as u32,
                    sb.as_ptr(),
                    sb.len() as u32,
                ) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_worker_thread_id",
        Func::from(|| -> f64 { unsafe { host_worker_thread_id() as f64 } }),
    );
    let _ = globals.set(
        "__host_worker_is_main_thread",
        Func::from(|| -> f64 { unsafe { host_worker_is_main_thread() as f64 } }),
    );
    let _ = globals.set(
        "__host_worker_data",
        Func::from(|| -> String {
            // Variable-length read: 64 KiB initial buffer covers nearly
            // every workerData payload; -4 doubles + retries.
            let mut buf = alloc::vec![0u8; 64 * 1024];
            loop {
                let n = unsafe { host_worker_data(buf.as_mut_ptr(), buf.len() as u32) };
                if n >= 0 {
                    buf.truncate(n as usize);
                    return String::from_utf8_lossy(&buf).into_owned();
                }
                if n == -4 {
                    let new_cap = buf.len().saturating_mul(2);
                    buf.resize(new_cap, 0);
                    continue;
                }
                return String::new();
            }
        }),
    );

    // ---- net (raw TCP, B7) ------------------------------------------
    //
    // The polyfill `polyfills/net.js` calls these from `net.connect`,
    // `socket.write`, `net.createServer`, etc. Byte payloads are
    // base64-encoded strings on the wire - same convention used by
    // the zlib + crypto host imports.
    let _ = globals.set(
        "__host_net_connect",
        Func::from(|host: String, port: f64| -> f64 {
            let hb = host.as_bytes();
            unsafe { host_net_connect(hb.as_ptr(), hb.len() as u32, port as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_net_write",
        Func::from(|conn_id: f64, payload_b64: String| -> f64 {
            let pb = payload_b64.as_bytes();
            unsafe { host_net_write(conn_id as i32, pb.as_ptr(), pb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_net_end",
        Func::from(|conn_id: f64| -> f64 { unsafe { host_net_end(conn_id as i32) as f64 } }),
    );
    let _ = globals.set(
        "__host_net_destroy",
        Func::from(|conn_id: f64| -> f64 { unsafe { host_net_destroy(conn_id as i32) as f64 } }),
    );
    let _ = globals.set(
        "__host_net_pending",
        Func::from(|conn_id: f64| -> f64 { unsafe { host_net_pending(conn_id as i32) as f64 } }),
    );
    let _ = globals.set(
        "__host_net_set_no_delay",
        Func::from(|conn_id: f64, enable: f64| -> f64 {
            unsafe { host_net_set_no_delay(conn_id as i32, enable as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_net_set_keep_alive",
        Func::from(|conn_id: f64, enable: f64, delay_ms: f64| -> f64 {
            unsafe {
                host_net_set_keep_alive(conn_id as i32, enable as i32, delay_ms as i32) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_net_listen",
        Func::from(|host: String, port: f64| -> f64 {
            let hb = host.as_bytes();
            unsafe { host_net_listen(hb.as_ptr(), hb.len() as u32, port as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_net_close_server",
        Func::from(|server_id: f64| -> f64 {
            unsafe { host_net_close_server(server_id as i32) as f64 }
        }),
    );

    // ---- tls -------------------------------------------------
    //
    // Connect carries an opts JSON blob (rejectUnauthorized,
    // servername, alpn, ca PEM) so the host can build the rustls
    // ClientConfig in one shot. Server `listen` carries cert+key PEM
    // strings.
    let _ = globals.set(
        "__host_tls_connect",
        Func::from(|host: String, port: f64, opts_json: String| -> f64 {
            let hb = host.as_bytes();
            let ob = opts_json.as_bytes();
            unsafe {
                host_tls_connect(
                    hb.as_ptr(),
                    hb.len() as u32,
                    port as i32,
                    ob.as_ptr(),
                    ob.len() as u32,
                ) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_tls_write",
        Func::from(|conn_id: f64, payload_b64: String| -> f64 {
            let pb = payload_b64.as_bytes();
            unsafe { host_tls_write(conn_id as i32, pb.as_ptr(), pb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_tls_end",
        Func::from(|conn_id: f64| -> f64 { unsafe { host_tls_end(conn_id as i32) as f64 } }),
    );
    let _ = globals.set(
        "__host_tls_destroy",
        Func::from(|conn_id: f64| -> f64 { unsafe { host_tls_destroy(conn_id as i32) as f64 } }),
    );
    let _ = globals.set(
        "__host_tls_pending",
        Func::from(|conn_id: f64| -> f64 { unsafe { host_tls_pending(conn_id as i32) as f64 } }),
    );
    let _ = globals.set(
        "__host_tls_listen",
        Func::from(
            |host: String,
             port: f64,
             cert_pem: String,
             key_pem: String,
             sni_map_json: String|
             -> f64 {
                let hb = host.as_bytes();
                let cb = cert_pem.as_bytes();
                let kb = key_pem.as_bytes();
                let sb = sni_map_json.as_bytes();
                unsafe {
                    host_tls_listen(
                        hb.as_ptr(),
                        hb.len() as u32,
                        port as i32,
                        cb.as_ptr(),
                        cb.len() as u32,
                        kb.as_ptr(),
                        kb.len() as u32,
                        sb.as_ptr(),
                        sb.len() as u32,
                    ) as f64
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_tls_close_server",
        Func::from(|server_id: f64| -> f64 {
            unsafe { host_tls_close_server(server_id as i32) as f64 }
        }),
    );

    // ---- dgram (UDP) -------------------------------------------------
    let _ = globals.set(
        "__host_dgram_bind",
        Func::from(|host: String, port: f64| -> f64 {
            let hb = host.as_bytes();
            unsafe { host_dgram_bind(hb.as_ptr(), hb.len() as u32, port as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_dgram_send",
        Func::from(
            |socket_id: f64, host: String, port: f64, payload_b64: String| -> f64 {
                let hb = host.as_bytes();
                let pb = payload_b64.as_bytes();
                unsafe {
                    host_dgram_send(
                        socket_id as i32,
                        hb.as_ptr(),
                        hb.len() as u32,
                        port as i32,
                        pb.as_ptr(),
                        pb.len() as u32,
                    ) as f64
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_dgram_close",
        Func::from(|socket_id: f64| -> f64 {
            unsafe { host_dgram_close(socket_id as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_dgram_address",
        Func::from(|socket_id: f64| -> String {
            match call_read(|out, cap| unsafe { host_dgram_address(socket_id as i32, out, cap) }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    // ---- child_process (sync) ---------------------------------------
    let _ = globals.set(
        "__host_child_process_exec_sync",
        Func::from(|cmd: String, argv_json: String| -> String {
            let cb = cmd.as_bytes();
            let ab = argv_json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_child_process_exec_sync(
                    cb.as_ptr(),
                    cb.len() as u32,
                    ab.as_ptr(),
                    ab.len() as u32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    // ---- L3 shadow: sqlite3 -----------------------------------------
    //
    // Db ids are i64 host-side; JS represents them as f64 (Number)
    // which exactly preserves any integer up to 2^53. We never reach
    // that - ids increment one per `new Database(...)` and the
    // process recycles long before we run out.
    //
    // `run` / `get` / `all` return JSON strings via `call_read`
    // (auto-doubling buffer up to 16 MiB). On failure they return
    // `__HOST_ERR__:<msg>` - same convention as the dns + os
    // bridges.
    let _ = globals.set(
        "__host_shadow_sqlite3_open",
        Func::from(|path: String| -> f64 {
            let pb = path.as_bytes();
            unsafe { host_shadow_sqlite3_open(pb.as_ptr(), pb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_shadow_sqlite3_run",
        Func::from(|id: f64, sql: String, params_json: String| -> String {
            let id = id as i64;
            let sb = sql.as_bytes();
            let pb = params_json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_shadow_sqlite3_run(
                    id,
                    sb.as_ptr(),
                    sb.len() as u32,
                    pb.as_ptr(),
                    pb.len() as u32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_shadow_sqlite3_get",
        Func::from(|id: f64, sql: String, params_json: String| -> String {
            let id = id as i64;
            let sb = sql.as_bytes();
            let pb = params_json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_shadow_sqlite3_get(
                    id,
                    sb.as_ptr(),
                    sb.len() as u32,
                    pb.as_ptr(),
                    pb.len() as u32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_shadow_sqlite3_all",
        Func::from(|id: f64, sql: String, params_json: String| -> String {
            let id = id as i64;
            let sb = sql.as_bytes();
            let pb = params_json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_shadow_sqlite3_all(
                    id,
                    sb.as_ptr(),
                    sb.len() as u32,
                    pb.as_ptr(),
                    pb.len() as u32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_shadow_sqlite3_exec",
        Func::from(|id: f64, sql: String| -> f64 {
            let id = id as i64;
            let sb = sql.as_bytes();
            unsafe { host_shadow_sqlite3_exec(id, sb.as_ptr(), sb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_shadow_sqlite3_close",
        Func::from(|id: f64| -> f64 {
            let id = id as i64;
            unsafe { host_shadow_sqlite3_close(id) as f64 }
        }),
    );

    // ---- L3 shadow: sharp -------------------------------------------
    //
    // `run` returns base64-encoded image bytes (decoded by polyfill);
    // `metadata` returns a JSON string. Both error paths use the
    // `__HOST_ERR__:` sentinel.
    let _ = globals.set(
        "__host_shadow_sharp_run",
        Func::from(|json: String| -> String {
            let jb = json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_shadow_sharp_run(jb.as_ptr(), jb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_shadow_sharp_metadata",
        Func::from(|json: String| -> String {
            let jb = json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_shadow_sharp_metadata(jb.as_ptr(), jb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_shadow_sharp_stats",
        Func::from(|json: String| -> String {
            let jb = json.as_bytes();
            match call_read(|out, cap| unsafe {
                host_shadow_sharp_stats(jb.as_ptr(), jb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    // ---- WebAssembly loader bridges ---------------------------------
    //
    // Module/Instance ids are i64 host-side; JS sees them as f64
    // (Number - exact through 2^53). Output strings travel via
    // call_read with auto-doubling buffer.
    let _ = globals.set(
        "__host_wasm_compile",
        Func::from(|bytes_b64: String| -> f64 {
            let b = bytes_b64.as_bytes();
            unsafe { host_wasm_compile(b.as_ptr(), b.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_drop_module",
        Func::from(|id: f64| -> f64 { unsafe { host_wasm_drop_module(id as i64) as f64 } }),
    );
    let _ = globals.set(
        "__host_wasm_module_exports",
        Func::from(|id: f64| -> String {
            match call_read(|out, cap| unsafe { host_wasm_module_exports(id as i64, out, cap) }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_module_imports",
        Func::from(|id: f64| -> String {
            match call_read(|out, cap| unsafe { host_wasm_module_imports(id as i64, out, cap) }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_instantiate",
        Func::from(|module_id: f64| -> f64 {
            unsafe { host_wasm_instantiate(module_id as i64) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_drop_instance",
        Func::from(|id: f64| -> f64 { unsafe { host_wasm_drop_instance(id as i64) as f64 } }),
    );
    let _ = globals.set(
        "__host_wasm_call_export",
        Func::from(
            |instance_id: f64, name: String, args_json: String| -> String {
                let nb = name.as_bytes();
                let ab = args_json.as_bytes();
                match call_read(|out, cap| unsafe {
                    host_wasm_call_export(
                        instance_id as i64,
                        nb.as_ptr(),
                        nb.len() as u32,
                        ab.as_ptr(),
                        ab.len() as u32,
                        out,
                        cap,
                    )
                }) {
                    Ok(s) => s,
                    Err(e) => alloc::format!("__HOST_ERR__:{e}"),
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_wasm_memory_read",
        Func::from(|instance_id: f64, offset: f64, len: f64| -> String {
            match call_read(|out, cap| unsafe {
                host_wasm_memory_read(instance_id as i64, offset as i32, len as i32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_memory_write",
        Func::from(|instance_id: f64, offset: f64, b64: String| -> f64 {
            let bb = b64.as_bytes();
            unsafe {
                host_wasm_memory_write(
                    instance_id as i64,
                    offset as i32,
                    bb.as_ptr(),
                    bb.len() as u32,
                ) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_memory_size",
        Func::from(|instance_id: f64| -> f64 {
            unsafe { host_wasm_memory_size(instance_id as i64) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_memory_grow",
        Func::from(|instance_id: f64, delta: f64| -> f64 {
            unsafe { host_wasm_memory_grow(instance_id as i64, delta as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_global_get",
        Func::from(|instance_id: f64, name: String| -> String {
            let nb = name.as_bytes();
            match call_read(|out, cap| unsafe {
                host_wasm_global_get(instance_id as i64, nb.as_ptr(), nb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_global_set",
        Func::from(
            |instance_id: f64, name: String, value_json: String| -> f64 {
                let nb = name.as_bytes();
                let vb = value_json.as_bytes();
                unsafe {
                    host_wasm_global_set(
                        instance_id as i64,
                        nb.as_ptr(),
                        nb.len() as u32,
                        vb.as_ptr(),
                        vb.len() as u32,
                    ) as f64
                }
            },
        ),
    );
    let _ = globals.set(
        "__host_wasm_table_size",
        Func::from(|instance_id: f64, name: String| -> f64 {
            let nb = name.as_bytes();
            unsafe { host_wasm_table_size(instance_id as i64, nb.as_ptr(), nb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_table_get",
        Func::from(|instance_id: f64, name: String, index: f64| -> String {
            let nb = name.as_bytes();
            match call_read(|out, cap| unsafe {
                host_wasm_table_get(
                    instance_id as i64,
                    nb.as_ptr(),
                    nb.len() as u32,
                    index as i32,
                    out,
                    cap,
                )
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_table_grow",
        Func::from(|instance_id: f64, name: String, delta: f64| -> f64 {
            let nb = name.as_bytes();
            unsafe {
                host_wasm_table_grow(
                    instance_id as i64,
                    nb.as_ptr(),
                    nb.len() as u32,
                    delta as i32,
                ) as f64
            }
        }),
    );

    // ---- Standalone WebAssembly resources --------------------
    let _ = globals.set(
        "__host_wasm_mem_new",
        Func::from(|initial: f64, maximum: f64| -> f64 {
            unsafe { host_wasm_mem_new(initial as i32, maximum as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_mem_size",
        Func::from(|id: f64| -> f64 { unsafe { host_wasm_mem_size(id as i64) as f64 } }),
    );
    let _ = globals.set(
        "__host_wasm_mem_grow",
        Func::from(|id: f64, delta: f64| -> f64 {
            unsafe { host_wasm_mem_grow(id as i64, delta as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_mem_read",
        Func::from(|id: f64, offset: f64, len: f64| -> String {
            match call_read(|out, cap| unsafe {
                host_wasm_mem_read(id as i64, offset as i32, len as i32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_mem_write",
        Func::from(|id: f64, offset: f64, bytes_b64: String| -> f64 {
            // Pass the base64 string straight through - the host
            // decodes. Matches the wire shape of the older
            // instance-export `__host_wasm_memory_write`.
            let bb = bytes_b64.as_bytes();
            unsafe {
                host_wasm_mem_write(id as i64, offset as i32, bb.as_ptr(), bb.len() as u32) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_mem_drop",
        Func::from(|id: f64| -> f64 { unsafe { host_wasm_mem_drop(id as i64) as f64 } }),
    );
    let _ = globals.set(
        "__host_wasm_global_new",
        Func::from(|ty: String, mutable: f64, val_json: String| -> f64 {
            let tb = ty.as_bytes();
            let vb = val_json.as_bytes();
            unsafe {
                host_wasm_global_new(
                    tb.as_ptr(),
                    tb.len() as u32,
                    mutable as i32,
                    vb.as_ptr(),
                    vb.len() as u32,
                ) as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_global_get_sa",
        Func::from(|id: f64| -> String {
            match call_read(|out, cap| unsafe { host_wasm_global_get_sa(id as i64, out, cap) }) {
                Ok(s) => s,
                Err(e) => alloc::format!("__HOST_ERR__:{e}"),
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_global_set_sa",
        Func::from(|id: f64, val_json: String| -> f64 {
            let vb = val_json.as_bytes();
            unsafe { host_wasm_global_set_sa(id as i64, vb.as_ptr(), vb.len() as u32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_global_drop",
        Func::from(|id: f64| -> f64 { unsafe { host_wasm_global_drop(id as i64) as f64 } }),
    );
    let _ = globals.set(
        "__host_wasm_table_new",
        Func::from(|elem: String, initial: f64, maximum: f64| -> f64 {
            let eb = elem.as_bytes();
            unsafe {
                host_wasm_table_new(eb.as_ptr(), eb.len() as u32, initial as i32, maximum as i32)
                    as f64
            }
        }),
    );
    let _ = globals.set(
        "__host_wasm_table_size_sa",
        Func::from(|id: f64| -> f64 { unsafe { host_wasm_table_size_sa(id as i64) as f64 } }),
    );
    let _ = globals.set(
        "__host_wasm_table_grow_sa",
        Func::from(|id: f64, delta: f64| -> f64 {
            unsafe { host_wasm_table_grow_sa(id as i64, delta as i32) as f64 }
        }),
    );
    let _ = globals.set(
        "__host_wasm_table_drop",
        Func::from(|id: f64| -> f64 { unsafe { host_wasm_table_drop(id as i64) as f64 } }),
    );
    let _ = globals.set(
        "__host_wasm_run_wasi",
        Func::from(|module_id: f64, cfg: String| -> f64 {
            let cb = cfg.as_bytes();
            unsafe { host_wasm_run_wasi(module_id as i64, cb.as_ptr(), cb.len() as u32) as f64 }
        }),
    );
}

fn install_os<'js>(globals: &Object<'js>) {
    let _ = globals.set(
        "__host_os_platform",
        Func::from(|| -> String {
            match call_read(|out, cap| unsafe { host_os_platform(out, cap) }) {
                Ok(s) => s,
                Err(_) => "unknown".to_string(),
            }
        }),
    );

    let _ = globals.set(
        "__host_os_arch",
        Func::from(|| -> String {
            match call_read(|out, cap| unsafe { host_os_arch(out, cap) }) {
                Ok(s) => s,
                Err(_) => "unknown".to_string(),
            }
        }),
    );
    let _ = globals.set(
        "__host_os_home_dir",
        Func::from(|| -> String {
            match call_read(|out, cap| unsafe { host_os_home_dir(out, cap) }) {
                Ok(s) => s,
                Err(_) => "/".to_string(),
            }
        }),
    );
    let _ = globals.set(
        "__host_os_tmpdir",
        Func::from(|| -> String {
            match call_read(|out, cap| unsafe { host_os_tmpdir(out, cap) }) {
                Ok(s) => s,
                Err(_) => "/tmp".to_string(),
            }
        }),
    );
    let _ = globals.set(
        "__host_os_hostname",
        Func::from(|| -> String {
            match call_read(|out, cap| unsafe { host_os_hostname(out, cap) }) {
                Ok(s) => s,
                Err(_) => "afterburner".to_string(),
            }
        }),
    );
}

fn install_http_dns<'js>(globals: &Object<'js>) {
    let _ = globals.set(
        "__host_http_request",
        Func::from(
            |method: String, url: String, body: Option<String>| -> String {
                let mb = method.as_bytes();
                let ub = url.as_bytes();
                let body_vec: Vec<u8> = body.map(|b| b.into_bytes()).unwrap_or_default();
                match call_read(|out, cap| unsafe {
                    host_http_request(
                        mb.as_ptr(),
                        mb.len() as u32,
                        ub.as_ptr(),
                        ub.len() as u32,
                        body_vec.as_ptr(),
                        body_vec.len() as u32,
                        out,
                        cap,
                    )
                }) {
                    Ok(s) => s,
                    Err(e) => format!(r#"{{"status":0,"body":"__HOST_ERR__:{e}"}}"#),
                }
            },
        ),
    );

    // v2 request path: headers travel as a JSON object; the body is
    // base64-framed (raw bytes cannot cross the JS string boundary
    // unmangled) and the host sends the exact original bytes.
    let _ = globals.set(
        "__host_http_request_v2",
        Func::from(
            |method: String, url: String, headers_json: String, body_b64: String| -> String {
                let mb = method.as_bytes();
                let ub = url.as_bytes();
                let hb = headers_json.as_bytes();
                let bb = body_b64.as_bytes();
                match call_read(|out, cap| unsafe {
                    host_http_request_v2(
                        mb.as_ptr(),
                        mb.len() as u32,
                        ub.as_ptr(),
                        ub.len() as u32,
                        hb.as_ptr(),
                        hb.len() as u32,
                        bb.as_ptr(),
                        bb.len() as u32,
                        out,
                        cap,
                    )
                }) {
                    Ok(s) => s,
                    Err(e) => format!(r#"{{"status":0,"body":"__HOST_ERR__:{e}"}}"#),
                }
            },
        ),
    );

    // Async variant: returns req_id immediately as a number
    // (`-1` when no daemon is attached so the JS shim falls back
    // to the sync path). Response delivery is event-driven via
    // the daemon dispatch loop's `http-response` kind.
    let _ = globals.set(
        "__host_http_request_async",
        Func::from(|method: String, url: String, body: Option<String>| -> i64 {
            let mb = method.as_bytes();
            let ub = url.as_bytes();
            let body_vec: Vec<u8> = body.map(|b| b.into_bytes()).unwrap_or_default();
            unsafe {
                host_http_request_async(
                    mb.as_ptr(),
                    mb.len() as u32,
                    ub.as_ptr(),
                    ub.len() as u32,
                    body_vec.as_ptr(),
                    body_vec.len() as u32,
                )
            }
        }),
    );

    let _ = globals.set(
        "__host_dns_lookup",
        Func::from(|name: String| -> String {
            let nb = name.as_bytes();
            match call_read(|out, cap| unsafe {
                host_dns_lookup(nb.as_ptr(), nb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    // Record-type-aware resolvers. Every bridge takes (hostname,
    // servers_csv) - the polyfill passes an empty string for
    // "use system config" and a comma-separated list otherwise.
    // The bridge returns a JSON string (success) or
    // `__HOST_ERR__:<msg>` (failure); the polyfill is responsible
    // for `JSON.parse`-ing the success path.
    macro_rules! bind_dns_str {
        ($name:literal, $fn:ident) => {
            let _ = globals.set(
                $name,
                Func::from(|name: String, servers_csv: String| -> String {
                    let nb = name.as_bytes();
                    let sb = servers_csv.as_bytes();
                    match call_read(|out, cap| unsafe {
                        $fn(
                            nb.as_ptr(),
                            nb.len() as u32,
                            sb.as_ptr(),
                            sb.len() as u32,
                            out,
                            cap,
                        )
                    }) {
                        Ok(s) => s,
                        Err(e) => format!("__HOST_ERR__:{e}"),
                    }
                }),
            );
        };
    }
    bind_dns_str!("__host_dns_resolve4", host_dns_resolve4);
    bind_dns_str!("__host_dns_resolve6", host_dns_resolve6);
    bind_dns_str!("__host_dns_resolve_mx", host_dns_resolve_mx);
    bind_dns_str!("__host_dns_resolve_txt", host_dns_resolve_txt);
    bind_dns_str!("__host_dns_resolve_cname", host_dns_resolve_cname);
    bind_dns_str!("__host_dns_resolve_ns", host_dns_resolve_ns);
    bind_dns_str!("__host_dns_resolve_soa", host_dns_resolve_soa);
    bind_dns_str!("__host_dns_reverse", host_dns_reverse);
}

fn install_zlib<'js>(globals: &Object<'js>) {
    macro_rules! bind_zlib {
        ($name:literal, $fn:ident) => {
            let _ = globals.set(
                $name,
                Func::from(|data_b64: String| -> String {
                    let db = data_b64.as_bytes();
                    match call_read(|out, cap| unsafe {
                        $fn(db.as_ptr(), db.len() as u32, out, cap)
                    }) {
                        Ok(s) => s,
                        Err(e) => format!("__HOST_ERR__:{e}"),
                    }
                }),
            );
        };
    }
    bind_zlib!("__host_zlib_deflate_sync", host_zlib_deflate_sync);
    bind_zlib!("__host_zlib_inflate_sync", host_zlib_inflate_sync);
    bind_zlib!("__host_zlib_gzip_sync", host_zlib_gzip_sync);
    bind_zlib!("__host_zlib_gunzip_sync", host_zlib_gunzip_sync);
    bind_zlib!(
        "__host_zlib_zstd_compress_sync",
        host_zlib_zstd_compress_sync
    );
    bind_zlib!(
        "__host_zlib_zstd_decompress_sync",
        host_zlib_zstd_decompress_sync
    );
    bind_zlib!(
        "__host_zlib_brotli_compress_sync",
        host_zlib_brotli_compress_sync
    );
    bind_zlib!(
        "__host_zlib_brotli_decompress_sync",
        host_zlib_brotli_decompress_sync
    );
}

fn install_hostctx<'js>(globals: &Object<'js>) {
    let _ = globals.set(
        "__host_read_column",
        Func::from(|name: String| -> String {
            let nb = name.as_bytes();
            match call_read(|out, cap| unsafe {
                host_read_column(nb.as_ptr(), nb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(_) => "[]".to_string(),
            }
        }),
    );

    let _ = globals.set(
        "__host_emit_row",
        Func::from(|row_json: String| -> i32 {
            let rb = row_json.as_bytes();
            unsafe { host_emit_row(rb.as_ptr(), rb.len() as u32) }
        }),
    );

    let _ = globals.set(
        "__host_get_env",
        Func::from(|key: String| -> Option<String> {
            let kb = key.as_bytes();
            call_read(|out, cap| unsafe { host_get_env(kb.as_ptr(), kb.len() as u32, out, cap) })
                .ok()
        }),
    );
}

fn install_state<'js>(globals: &Object<'js>) {
    // State store (afterburner:state). `call_read` returns `Err` on `-2
    // NotFound` (or any other negative code); mapping to None here
    // surfaces the absence as JS `undefined`.
    let _ = globals.set(
        "__host_state_get",
        Func::from(|key: String| -> Option<String> {
            let kb = key.as_bytes();
            call_read(|out, cap| unsafe { host_state_get(kb.as_ptr(), kb.len() as u32, out, cap) })
                .ok()
        }),
    );

    let _ = globals.set(
        "__host_state_set",
        Func::from(|key: String, value_b64: String| -> i32 {
            let kb = key.as_bytes();
            let vb = value_b64.as_bytes();
            unsafe { host_state_set(kb.as_ptr(), kb.len() as u32, vb.as_ptr(), vb.len() as u32) }
        }),
    );

    let _ = globals.set(
        "__host_state_delete",
        Func::from(|key: String| -> i32 {
            let kb = key.as_bytes();
            unsafe { host_state_delete(kb.as_ptr(), kb.len() as u32) }
        }),
    );

    let _ = globals.set(
        "__host_state_increment",
        Func::from(|key: String, delta: f64| -> f64 {
            let kb = key.as_bytes();
            let n = unsafe { host_state_increment(kb.as_ptr(), kb.len() as u32, delta as i64) };
            n as f64
        }),
    );
}
