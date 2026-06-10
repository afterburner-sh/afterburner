// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Wasmtime linker registrations for the `afterburner:host` import
//! module declared by `afterburner-plugin`.
//!
//! Each function follows the plugin's buffer protocol:
//!
//! * Inputs are passed as `(ptr, len)` pairs into guest memory.
//! * Outputs (variable-length) are written into a `(out_ptr, out_cap)`
//!   region supplied by the caller. The return value is either the
//!   number of bytes written, or a negative error code: `-1`
//!   (PermissionDenied), `-2` (NotFound), `-3` (Other), or `-4`
//!   (BufTooSmall).
//!
//! When a negative code is returned, the detailed error message is
//! stashed in `HostState::last_error` and read by the plugin via the
//! `host_last_error` import.

use crate::host::{HostState, TimerSlot};
use afterburner_core::AfterburnerError;
use afterburner_node_compat::{
    child_process_host, crypto_host, dns_host, fs_host, http_host, os_host, prime_host,
    subtle_host, v8_host, zlib_host,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use std::time::{Duration, Instant};
use wasmtime::{Caller, Linker, Memory};
use wasmtime_wasi::I32Exit;

const NS: &str = "afterburner:host";

const E_PERMISSION: i32 = -1;
const E_NOT_FOUND: i32 = -2;
const E_OTHER: i32 = -3;
const E_BUF_TOO_SMALL: i32 = -4;

/// Install every `afterburner:host` function the plugin imports.
pub fn register(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    wrap_fs(linker)?;
    wrap_fs_chunks(linker)?;
    wrap_crypto(linker)?;
    wrap_crypto_ciphers(linker)?;
    wrap_crypto_kdfs(linker)?;
    wrap_crypto_signing(linker)?;
    wrap_crypto_signing_streaming(linker)?;
    wrap_crypto_hash_streaming(linker)?;
    wrap_os(linker)?;
    wrap_http(linker)?;
    wrap_dns(linker)?;
    wrap_zlib(linker)?;
    wrap_b64(linker)?;
    wrap_state(linker)?;
    wrap_host_context(linker)?;
    wrap_last_error(linker)?;
    wrap_input(linker)?;
    wrap_envelope(linker)?;
    wrap_columnar(linker)?;
    wrap_http_server(linker)?;
    wrap_transpile(linker)?;
    wrap_shadow_bcrypt(linker)?;
    wrap_shadow_argon2(linker)?;
    wrap_shadow_jwt(linker)?;
    wrap_process_exit(linker)?;
    wrap_timers(linker)?;
    wrap_workers(linker)?;
    wrap_net(linker)?;
    wrap_tls(linker)?;
    wrap_dgram(linker)?;
    wrap_child_process(linker)?;
    wrap_shadow_sqlite3(linker)?;
    wrap_shadow_sharp(linker)?;
    wrap_wasm_loader(linker)?;
    wrap_inspector(linker)?;
    wrap_sab(linker)?;
    Ok(())
}

// ---- SharedArrayBuffer + Atomics.wait/notify -------------------------
//
// Twelve host imports back the JS-side `SharedArrayBuffer` constructor
// and `Atomics.{load,store,compareExchange,wait,notify}` primitives.
// Memory is mmap-backed so worker subprocesses can attach to the same
// region; wait/notify use the OS futex equivalent for real cross-
// process blocking semantics.

fn wrap_sab(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_sab_alloc",
            |caller: Caller<'_, HostState>, byte_length: i64| -> i64 {
                if byte_length <= 0 || byte_length > (1i64 << 32) {
                    return crate::daemon_sab::ERR_BAD_WIDTH as i64;
                }
                caller.data().daemon_sab.alloc(byte_length as usize)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_open",
            |mut caller: Caller<'_, HostState>,
             desc_ptr: i32,
             desc_len: i32,
             byte_length: i64|
             -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return crate::daemon_sab::ERR_IO as i64;
                };
                let Some(desc) = read_str(&memory, &caller, desc_ptr, desc_len) else {
                    return crate::daemon_sab::ERR_IO as i64;
                };
                if byte_length <= 0 || byte_length > (1i64 << 32) {
                    return crate::daemon_sab::ERR_BAD_WIDTH as i64;
                }
                caller.data().daemon_sab.open(&desc, byte_length as usize)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_release",
            |caller: Caller<'_, HostState>, region_id: i64| -> i32 {
                caller.data().daemon_sab.release(region_id)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_byte_length",
            |caller: Caller<'_, HostState>, region_id: i64| -> i64 {
                caller.data().daemon_sab.byte_length(region_id)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_descriptor",
            |mut caller: Caller<'_, HostState>,
             region_id: i64,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let s = caller.data().daemon_sab.descriptor(region_id);
                write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_read",
            |mut caller: Caller<'_, HostState>,
             region_id: i64,
             offset: i64,
             len: i64,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                if offset < 0 || len < 0 {
                    return crate::daemon_sab::ERR_OUT_OF_BOUNDS;
                }
                let Some(memory) = guest_memory(&mut caller) else {
                    return crate::daemon_sab::ERR_IO;
                };
                let result =
                    caller
                        .data()
                        .daemon_sab
                        .read(region_id, offset as usize, len as usize);
                match result {
                    Ok(bytes) => write_out(&mut caller, &memory, out_ptr, out_cap, &bytes),
                    Err(e) => e,
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_write",
            |mut caller: Caller<'_, HostState>,
             region_id: i64,
             offset: i64,
             bytes_ptr: i32,
             bytes_len: i32|
             -> i32 {
                if offset < 0 {
                    return crate::daemon_sab::ERR_OUT_OF_BOUNDS;
                }
                let Some(memory) = guest_memory(&mut caller) else {
                    return crate::daemon_sab::ERR_IO;
                };
                let Some(bytes) = read_bytes(&memory, &caller, bytes_ptr, bytes_len) else {
                    return crate::daemon_sab::ERR_IO;
                };
                caller
                    .data()
                    .daemon_sab
                    .write(region_id, offset as usize, &bytes)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_atomic_load",
            |caller: Caller<'_, HostState>, region_id: i64, byte_offset: i64, width: i32| -> i64 {
                if byte_offset < 0 {
                    return crate::daemon_sab::ERR_OUT_OF_BOUNDS as i64;
                }
                caller
                    .data()
                    .daemon_sab
                    .atomic_load(region_id, byte_offset as usize, width as u8)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_atomic_store",
            |caller: Caller<'_, HostState>,
             region_id: i64,
             byte_offset: i64,
             value: i64,
             width: i32|
             -> i32 {
                if byte_offset < 0 {
                    return crate::daemon_sab::ERR_OUT_OF_BOUNDS;
                }
                caller.data().daemon_sab.atomic_store(
                    region_id,
                    byte_offset as usize,
                    value,
                    width as u8,
                )
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_atomic_cas",
            |caller: Caller<'_, HostState>,
             region_id: i64,
             byte_offset: i64,
             expected: i64,
             replacement: i64,
             width: i32|
             -> i64 {
                if byte_offset < 0 {
                    return crate::daemon_sab::ERR_OUT_OF_BOUNDS as i64;
                }
                caller.data().daemon_sab.atomic_cas(
                    region_id,
                    byte_offset as usize,
                    expected,
                    replacement,
                    width as u8,
                )
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_wait",
            |caller: Caller<'_, HostState>,
             region_id: i64,
             byte_offset: i64,
             expected: i32,
             timeout_ms: i64|
             -> i32 {
                if byte_offset < 0 {
                    return crate::daemon_sab::ERR_OUT_OF_BOUNDS;
                }
                caller
                    .data()
                    .daemon_sab
                    .wait(region_id, byte_offset as usize, expected, timeout_ms)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_sab_notify",
            |caller: Caller<'_, HostState>, region_id: i64, byte_offset: i64, count: i64| -> i32 {
                if byte_offset < 0 {
                    return crate::daemon_sab::ERR_OUT_OF_BOUNDS;
                }
                caller
                    .data()
                    .daemon_sab
                    .notify(region_id, byte_offset as usize, count)
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- inspector / Chrome DevTools Protocol --------------------------
//
// Three host imports back the `inspector` polyfill's WebSocket bridge:
//
// * `host_inspector_open(port)` → bound port (≥1) | error
// * `host_inspector_close()` → 0 | error
// * `host_inspector_send(session_id, payload)` → 0 | error
//
// The plugin's daemon-event loop also pulls events via
// [`crate::daemon_inspector::DaemonInspector::try_recv_event`] and
// hands them to the JS-side `__ab_inspector_dispatch` hook.

#[cfg(not(feature = "daemon"))]
fn wrap_inspector(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_inspector_open",
            |_caller: Caller<'_, HostState>, _port: i32| -> i32 { -1 },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_inspector_close",
            |_caller: Caller<'_, HostState>| -> i32 { -1 },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_inspector_send",
            |_caller: Caller<'_, HostState>, _sid: i32, _ptr: i32, _len: i32| -> i32 { -1 },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_inspector_pause",
            |_caller: Caller<'_, HostState>| -> i32 { -1 },
        )
        .map_err(link_err)?;
    Ok(())
}

#[cfg(feature = "daemon")]
fn wrap_inspector(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_inspector_open",
            |mut caller: Caller<'_, HostState>, port: i32| -> i32 {
                if !(0..=65535).contains(&port) {
                    caller.data_mut().last_error = format!("inspector.open: invalid port {port}");
                    return crate::daemon_inspector::ERR_BIND;
                }
                let inspector = match caller.data().daemon_inspector.clone() {
                    Some(i) => i,
                    None => {
                        // No coordinator wired in this Store. Surface
                        // a typed error so the JS side keeps the
                        // in-process Session.post path working without
                        // pretending the listener bound.
                        caller.data_mut().last_error =
                            "inspector requires daemon mode; run via `burn foo.js` CLI".into();
                        return crate::daemon_inspector::ERR_NO_RUNTIME;
                    }
                };
                inspector.open(port as u16)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_inspector_close",
            |caller: Caller<'_, HostState>| -> i32 {
                if let Some(i) = caller.data().daemon_inspector.clone() {
                    i.close()
                } else {
                    crate::daemon_inspector::ERR_NOT_OPEN
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_inspector_send",
            |mut caller: Caller<'_, HostState>,
             session_id: i32,
             payload_ptr: i32,
             payload_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let Some(payload) = read_str(&memory, &caller, payload_ptr, payload_len) else {
                    return -1;
                };
                if let Some(i) = caller.data().daemon_inspector.clone() {
                    i.send(session_id, payload);
                    0
                } else {
                    -1
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_inspector_pause",
            |caller: Caller<'_, HostState>| -> i32 {
                if let Some(i) = caller.data().daemon_inspector.clone() {
                    // Blocks the wasmtime instance until the WS reader
                    // intercepts a Debugger.resume / stepX message
                    // and signals the pause channel. Returns the
                    // step-kind code so the JS side can react
                    // (resume / step-over / step-into / step-out).
                    i.pause_block()
                } else {
                    -1
                }
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// `wrap_net` registers either the real tokio-backed coordinator (when
// the `daemon` feature is on) or stubs that always return E_NO_DAEMON
// (when it's off). The plugin's WASM module unconditionally imports
// the eight `host_net_*` symbols, so we must always declare them.
#[cfg(not(feature = "daemon"))]
fn wrap_net(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    const E_NO_DAEMON: i32 = -1;
    linker
        .func_wrap(
            NS,
            "host_net_connect",
            |_: Caller<'_, HostState>, _h_p: i32, _h_l: i32, _port: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_write",
            |_: Caller<'_, HostState>, _id: i32, _p_p: i32, _p_l: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_end",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_destroy",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_pending",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { 0 },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_set_no_delay",
            |_: Caller<'_, HostState>, _id: i32, _en: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_set_keep_alive",
            |_: Caller<'_, HostState>, _id: i32, _en: i32, _d: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_listen",
            |_: Caller<'_, HostState>, _h_p: i32, _h_l: i32, _port: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_net_close_server",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    Ok(())
}

// `wrap_tls` mirrors `wrap_net` — daemon-on registers the real
// coordinator, daemon-off registers stubs returning E_NO_DAEMON. The
// plugin imports these unconditionally so we always declare them.
#[cfg(not(feature = "daemon"))]
fn wrap_tls(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    const E_NO_DAEMON: i32 = -1;
    linker
        .func_wrap(
            NS,
            "host_tls_connect",
            |_: Caller<'_, HostState>,
             _h_p: i32,
             _h_l: i32,
             _port: i32,
             _o_p: i32,
             _o_l: i32|
             -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_tls_write",
            |_: Caller<'_, HostState>, _id: i32, _p_p: i32, _p_l: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_tls_end",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_tls_destroy",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_tls_pending",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { 0 },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_tls_listen",
            |_: Caller<'_, HostState>,
             _h_p: i32,
             _h_l: i32,
             _port: i32,
             _c_p: i32,
             _c_l: i32,
             _k_p: i32,
             _k_l: i32,
             _s_p: i32,
             _s_l: i32|
             -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_tls_close_server",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    Ok(())
}

// `wrap_dgram` matches `wrap_net` / `wrap_tls`: daemon-on installs the
// real coordinator, daemon-off installs stubs returning E_NO_DAEMON.
#[cfg(not(feature = "daemon"))]
fn wrap_dgram(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    const E_NO_DAEMON: i32 = -1;
    linker
        .func_wrap(
            NS,
            "host_dgram_bind",
            |_: Caller<'_, HostState>, _h_p: i32, _h_l: i32, _port: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_dgram_send",
            |_: Caller<'_, HostState>,
             _id: i32,
             _h_p: i32,
             _h_l: i32,
             _port: i32,
             _b64_p: i32,
             _b64_l: i32|
             -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_dgram_close",
            |_: Caller<'_, HostState>, _id: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_dgram_address",
            |_: Caller<'_, HostState>, _id: i32, _o_p: i32, _o_l: i32| -> i32 { E_NO_DAEMON },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- fs ------------------------------------------------------------------

fn wrap_fs(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_fs_exists_sync",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(p) => p,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                if fs_host::exists_sync(&path, &m) {
                    1
                } else {
                    0
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_read_file_sync",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                // The plugin's `call_read` helper UTF-8-decodes the
                // bytes it pulls back through this import. That path
                // is fine for valid-UTF-8 files but would corrupt
                // binary content (PNGs, .wasm, archives, …). To stay
                // binary-safe we base64-encode the bytes here so the
                // wire format is always pure ASCII; the polyfill
                // decodes back to a Buffer (or to the requested
                // text encoding via `Buffer.toString(...)`).
                let Some(memory) = guest_memory(&mut caller) else {
                    record(&mut caller, "memory export missing");
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(p) => p,
                    None => {
                        record(&mut caller, "invalid utf-8 in path");
                        return E_OTHER;
                    }
                };
                let m = caller.data().manifold.clone();
                match fs_host::read_file_sync(&path, &m) {
                    Ok(bytes) => {
                        use base64::Engine as _;
                        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_write_file_sync",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             data_ptr: i32,
             data_len: i32|
             -> i32 {
                // Companion to the binary-safe read path above: the
                // polyfill base64-encodes whatever it received from
                // the user (Buffer or string→Buffer-with-encoding).
                // We decode here before handing bytes to the FS host.
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(p) => p,
                    None => return E_OTHER,
                };
                let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                    Some(s) => s,
                    None => {
                        record(&mut caller, "invalid utf-8 in fs write data");
                        return E_OTHER;
                    }
                };
                use base64::Engine as _;
                let data = match base64::engine::general_purpose::STANDARD.decode(&data_b64) {
                    Ok(b) => b,
                    Err(e) => {
                        record(&mut caller, &format!("fs.write base64: {e}"));
                        return E_OTHER;
                    }
                };
                let m = caller.data().manifold.clone();
                match fs_host::write_file_sync(&path, &data, &m) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_stat_sync",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(p) => p,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::stat_sync(&path, &m) {
                    Ok(s) => {
                        let json = format!(
                            r#"{{"size":{},"isFile":{},"isDirectory":{},"mtimeMs":{}}}"#,
                            s.size, s.is_file, s.is_dir, s.mtime_ms
                        );
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    // Unlink / rename / mkdir / readdir — parity with the native path.
    // Without these, `fs.createWriteStream(path, { flags: 'w' })` cannot
    // truncate existing content before rewriting.
    linker
        .func_wrap(
            NS,
            "host_fs_unlink_sync",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::unlink_sync(&path, &m) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_rename_sync",
            |mut caller: Caller<'_, HostState>,
             from_ptr: i32,
             from_len: i32,
             to_ptr: i32,
             to_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let from = match read_str(&memory, &caller, from_ptr, from_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let to = match read_str(&memory, &caller, to_ptr, to_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::rename_sync(&from, &to, &m) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_mkdir_sync",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32, recursive: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::mkdir_sync(&path, recursive != 0, &m) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_readdir_sync",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::readdir_sync(&path, &m) {
                    Ok(names) => {
                        let mut json = String::from("[");
                        for (i, name) in names.iter().enumerate() {
                            if i > 0 {
                                json.push(',');
                            }
                            json.push_str(&js_string_literal(name));
                        }
                        json.push(']');
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_realpath_sync",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::realpath_sync(&path, &m) {
                    Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_readlink_sync",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::readlink_sync(&path, &m) {
                    Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_cp",
            |mut caller: Caller<'_, HostState>,
             src_ptr: i32,
             src_len: i32,
             dst_ptr: i32,
             dst_len: i32,
             force: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let src = match read_str(&memory, &caller, src_ptr, src_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let dst = match read_str(&memory, &caller, dst_ptr, dst_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::cp_recursive(&src, &dst, force != 0, &m) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_opendir_sync",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::opendir_sync(&path, &m) {
                    Ok(entries) => {
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
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_watch_poll",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             interval_ms: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                if interval_ms < 0 {
                    return E_OTHER;
                }
                let m = caller.data().manifold.clone();
                match fs_host::watch_poll(&path, interval_ms as u32, &m) {
                    Ok(events) => {
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
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- crypto --------------------------------------------------------------

fn wrap_crypto(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_crypto_hash",
            |mut caller: Caller<'_, HostState>,
             algo_ptr: i32,
             algo_len: i32,
             data_ptr: i32,
             data_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data = match read_bytes(&memory, &caller, data_ptr, data_len) {
                    Some(d) => d,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match crypto_host::hash(&algo, &data, &m) {
                    Ok(bytes) => {
                        // Return hex-encoded so the plugin can pass the
                        // string straight back to JS without another
                        // host round-trip.
                        let hex = hex::encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, hex.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_random_bytes",
            |mut caller: Caller<'_, HostState>, len: u32, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let m = caller.data().manifold.clone();
                match crypto_host::random_bytes(len as usize, &m) {
                    Ok(bytes) => {
                        let hex = hex::encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, hex.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_subtle_op",
            |mut caller: Caller<'_, HostState>,
             op_ptr: i32,
             op_len: i32,
             args_ptr: i32,
             args_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let op = match read_str(&memory, &caller, op_ptr, op_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let args = match read_str(&memory, &caller, args_ptr, args_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match subtle_host::subtle_op(&op, &args, &m) {
                    Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_check_prime",
            |mut caller: Caller<'_, HostState>, cand_ptr: i32, cand_len: i32, checks: u32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                // The plugin passes the candidate as a hex-encoded
                // string (matches the convention `host_crypto_hash` /
                // `host_crypto_random_bytes` use for output bytes).
                let s = match read_str(&memory, &caller, cand_ptr, cand_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let cand = match hex::decode(s.trim()) {
                    Ok(b) => b,
                    Err(_) => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match prime_host::check_prime(&cand, checks as usize, &m) {
                    Ok(true) => 1,
                    Ok(false) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    // HTTP/3 listen — two host imports, one to stash the cert+key
    // strings, one to bind. Splitting them keeps the wasm trampoline
    // signature small (single u32 vs five mixed-i32-and-u32 args)
    // which sidesteps a wasmtime trampoline anomaly we hit when
    // `host_http3_listen` was called as a single 5-arg function.
    #[cfg(feature = "http3")]
    linker
        .func_wrap(
            NS,
            "host_http3_listen_set_cert",
            |mut caller: Caller<'_, HostState>,
             cert_ptr: i32,
             cert_len: i32,
             key_ptr: i32,
             key_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let cert = match read_str(&memory, &caller, cert_ptr, cert_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let key = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                crate::daemon_http3::stash_pending_cert(cert, key);
                0
            },
        )
        .map_err(link_err)?;

    #[cfg(feature = "http3")]
    linker
        .func_wrap(
            NS,
            "host_http3_request",
            |mut caller: Caller<'_, HostState>,
             url_ptr: i32,
             url_len: i32,
             method_ptr: i32,
             method_len: i32,
             body_ptr: i32,
             body_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let url = match read_str(&memory, &caller, url_ptr, url_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let method = match read_str(&memory, &caller, method_ptr, method_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let body = match read_bytes(&memory, &caller, body_ptr, body_len) {
                    Some(b) => b,
                    None => return E_OTHER,
                };
                let Some(daemon) = caller.data().daemon_http.clone() else {
                    return crate::daemon_http::LISTEN_ERR_NO_DAEMON;
                };
                match crate::daemon_http3::h3_request_sync(&daemon, &url, &method, &body) {
                    Ok(json) => write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes()),
                    Err(e) => map_err(&mut caller, afterburner_core::AfterburnerError::Host(e)),
                }
            },
        )
        .map_err(link_err)?;

    #[cfg(not(feature = "http3"))]
    linker
        .func_wrap(
            NS,
            "host_http3_request",
            |_caller: Caller<'_, HostState>,
             _url_ptr: i32,
             _url_len: i32,
             _method_ptr: i32,
             _method_len: i32,
             _body_ptr: i32,
             _body_len: i32,
             _out_ptr: i32,
             _out_cap: i32|
             -> i32 { crate::daemon_http::LISTEN_ERR_NO_DAEMON },
        )
        .map_err(link_err)?;

    #[cfg(feature = "http3")]
    linker
        .func_wrap(
            NS,
            "host_http3_listen",
            |caller: Caller<'_, HostState>, port: u32, server_id: i32| -> i32 {
                let Some(daemon) = caller.data().daemon_http.clone() else {
                    return crate::daemon_http::LISTEN_ERR_NO_DAEMON;
                };
                let Some((cert, key)) = crate::daemon_http3::take_pending_cert() else {
                    return crate::daemon_http::LISTEN_ERR_IO;
                };
                crate::daemon_http3::bind_h3_listener(daemon, server_id, port as u16, &cert, &key)
            },
        )
        .map_err(link_err)?;

    // Stubs when the http3 feature is off — keeps plugin instantiation
    // happy (abi_parity test pins both names unconditionally).
    #[cfg(not(feature = "http3"))]
    linker
        .func_wrap(
            NS,
            "host_http3_listen_set_cert",
            |_caller: Caller<'_, HostState>,
             _cert_ptr: i32,
             _cert_len: i32,
             _key_ptr: i32,
             _key_len: i32|
             -> i32 { 0 },
        )
        .map_err(link_err)?;

    #[cfg(not(feature = "http3"))]
    linker
        .func_wrap(
            NS,
            "host_http3_listen",
            |_caller: Caller<'_, HostState>, _port: u32, _server_id: i32| -> i32 {
                crate::daemon_http::LISTEN_ERR_NO_DAEMON
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_v8_serialize",
            |mut caller: Caller<'_, HostState>,
             json_ptr: i32,
             json_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let json = match read_str(&memory, &caller, json_ptr, json_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                match v8_host::serialize_json(&json) {
                    Ok(b64) => write_out(&mut caller, &memory, out_ptr, out_cap, b64.as_bytes()),
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_v8_deserialize",
            |mut caller: Caller<'_, HostState>,
             b64_ptr: i32,
             b64_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let b64 = match read_str(&memory, &caller, b64_ptr, b64_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                match v8_host::deserialize_to_json(&b64) {
                    Ok(json) => write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes()),
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_generate_prime",
            |mut caller: Caller<'_, HostState>,
             bits: u32,
             safe: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let m = caller.data().manifold.clone();
                match prime_host::generate_prime(bits as usize, safe != 0, &m) {
                    Ok(bytes) => {
                        // Hex-encode the BE bytes so JS gets a string —
                        // matches the convention used by `host_crypto_hash`.
                        let hex = hex::encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, hex.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- os ------------------------------------------------------------------

fn wrap_os(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_os_platform",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let s = os_host::platform();
                write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_os_arch",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let s = os_host::arch();
                write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_os_home_dir",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let s = os_host::home_dir();
                write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_os_tmpdir",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let s = os_host::tmpdir();
                write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_os_hostname",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let s = os_host::hostname();
                write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- http ----------------------------------------------------------------

fn wrap_http(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_http_request",
            |mut caller: Caller<'_, HostState>,
             method_ptr: i32,
             method_len: i32,
             url_ptr: i32,
             url_len: i32,
             body_ptr: i32,
             body_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let method = match read_str(&memory, &caller, method_ptr, method_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let url = match read_str(&memory, &caller, url_ptr, url_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let body = if body_len > 0 {
                    match read_bytes(&memory, &caller, body_ptr, body_len) {
                        Some(b) => Some(b),
                        None => return E_OTHER,
                    }
                } else {
                    None
                };
                let m = caller.data().manifold.clone();
                match http_host::request(&method, &url, &[], body.as_deref(), &m) {
                    Ok(resp) => {
                        // Binary bodies must not be lossy-stringified into the envelope:
                        // U+FFFD replacement trebles random bytes and double-encodes
                        // alongside body_b64, blowing the guest read cap on large
                        // responses. body_b64 is authoritative for non-UTF-8 bodies.
                        let body_text = match std::str::from_utf8(&resp.body) {
                            Ok(s) => s.to_owned(),
                            Err(_) => String::new(),
                        };
                        let body_b64 = B64.encode(&resp.body);
                        let json = format!(
                            r#"{{"status":{},"body":{},"body_b64":{}}}"#,
                            resp.status,
                            js_string_literal(&body_text),
                            js_string_literal(&body_b64),
                        );
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    // v2 request path: carries request HEADERS (the legacy import drops
    // them) and frames the body as base64 — arbitrary bytes cannot cross
    // the JS string boundary unmangled (lone surrogates / UTF-8 coercion),
    // so the guest encodes and this import decodes immediately before the
    // request. The wire body is the exact original bytes; headers arrive
    // as a JSON object of name→value.
    linker
        .func_wrap(
            NS,
            "host_http_request_v2",
            |mut caller: Caller<'_, HostState>,
             method_ptr: i32,
             method_len: i32,
             url_ptr: i32,
             url_len: i32,
             headers_ptr: i32,
             headers_len: i32,
             body_b64_ptr: i32,
             body_b64_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let method = match read_str(&memory, &caller, method_ptr, method_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let url = match read_str(&memory, &caller, url_ptr, url_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let headers: Vec<(String, String)> = if headers_len > 0 {
                    let raw = match read_str(&memory, &caller, headers_ptr, headers_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&raw) {
                        Ok(map) => map
                            .into_iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                            .collect(),
                        Err(_) => return E_OTHER,
                    }
                } else {
                    Vec::new()
                };
                let body = if body_b64_len > 0 {
                    let b64 = match read_bytes(&memory, &caller, body_b64_ptr, body_b64_len) {
                        Some(b) => b,
                        None => return E_OTHER,
                    };
                    match B64.decode(&b64) {
                        Ok(decoded) => Some(decoded),
                        Err(_) => return E_OTHER,
                    }
                } else {
                    None
                };
                let m = caller.data().manifold.clone();
                match http_host::request(&method, &url, &headers, body.as_deref(), &m) {
                    Ok(resp) => {
                        // Binary bodies must not be lossy-stringified into the envelope:
                        // U+FFFD replacement trebles random bytes and double-encodes
                        // alongside body_b64, blowing the guest read cap on large
                        // responses. body_b64 is authoritative for non-UTF-8 bodies.
                        let body_text = match std::str::from_utf8(&resp.body) {
                            Ok(s) => s.to_owned(),
                            Err(_) => String::new(),
                        };
                        let body_b64 = B64.encode(&resp.body);
                        let json = format!(
                            r#"{{"status":{},"body":{},"body_b64":{}}}"#,
                            resp.status,
                            js_string_literal(&body_text),
                            js_string_literal(&body_b64),
                        );
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    // ---- async outbound HTTP -----------------------------------------
    //
    // `host_http_request_async` returns the new `req_id` as i64
    // immediately and dispatches the actual round-trip onto the
    // daemon's Tokio runtime. The shard's event loop polls the
    // outbound coordinator each tick; when a response arrives it
    // ships an envelope of kind `http-response` back into JS, where
    // the matching `globalThis.__ab_http_pending[req_id]` Promise
    // resolves. Returns -1 when no daemon is attached (one-shot
    // script mode) so the JS shim falls back to the synchronous
    // `host_http_request` path.
    #[cfg(feature = "daemon")]
    linker
        .func_wrap(
            NS,
            "host_http_request_async",
            |mut caller: Caller<'_, HostState>,
             method_ptr: i32,
             method_len: i32,
             url_ptr: i32,
             url_len: i32,
             body_ptr: i32,
             body_len: i32|
             -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let method = match read_str(&memory, &caller, method_ptr, method_len) {
                    Some(s) => s,
                    None => return -1,
                };
                let url = match read_str(&memory, &caller, url_ptr, url_len) {
                    Some(s) => s,
                    None => return -1,
                };
                let body = if body_len > 0 {
                    match read_bytes(&memory, &caller, body_ptr, body_len) {
                        Some(b) => Some(b),
                        None => return -1,
                    }
                } else {
                    None
                };
                let manifold = caller.data().manifold.clone();
                let Some(coord) = caller.data().daemon_http_outbound.clone() else {
                    return -1;
                };
                coord.request(&method, &url, Vec::new(), body, None, manifold)
            },
        )
        .map_err(link_err)?;

    // Non-daemon builds still need to satisfy the wasm import — the
    // plugin .wasm is a single artifact and declares the import
    // unconditionally. Returning -1 tells the JS shim to fall back to
    // the synchronous `host_http_request` path, matching the
    // "no-daemon-attached" branch above.
    #[cfg(not(feature = "daemon"))]
    linker
        .func_wrap(
            NS,
            "host_http_request_async",
            |_: Caller<'_, HostState>,
             _method_ptr: i32,
             _method_len: i32,
             _url_ptr: i32,
             _url_len: i32,
             _body_ptr: i32,
             _body_len: i32|
             -> i64 { -1 },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- dns -----------------------------------------------------------------
//
// `host_dns_lookup` returns a single IP. The record-type-aware
// resolvers (`host_dns_resolve_*` / `host_dns_reverse`) all return
// JSON-encoded result strings — a uniform cross-boundary shape that
// keeps the i32 ABI stable even as the result list shape varies
// (`["1.2.3.4"]` vs `[{"exchange": "...", "priority": 10}]` vs
// `[["fragment", ...]]`). The plugin's polyfill JSON.parse's the
// payload before handing it to user callbacks.

fn wrap_dns(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_dns_lookup",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let name = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match dns_host::lookup(&name, &m) {
                    Ok(addr) => write_out(&mut caller, &memory, out_ptr, out_cap, addr.as_bytes()),
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    fn write_json(
        caller: &mut Caller<'_, HostState>,
        memory: &Memory,
        out_ptr: i32,
        out_cap: i32,
        value: &serde_json::Value,
    ) -> i32 {
        let json = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(e) => {
                record(caller, &format!("dns: serialize result: {e}"));
                return E_OTHER;
            }
        };
        write_out(caller, memory, out_ptr, out_cap, json.as_bytes())
    }

    // resolve4 / resolve6 / resolveCname / resolveNs / reverse all
    // share the same `(ptr, len, out_ptr, out_cap) -> i32` shape and
    // a `Vec<String>` result. Macro to dedup; the macro body lives at
    // the top of this function so each `func_wrap` keeps a unique
    // closure type.
    /// Decode the comma-separated `servers` string the polyfill
    /// passes through. Empty string → empty list (use system config).
    fn parse_servers_csv(s: &str) -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect()
    }

    macro_rules! wrap_string_list {
        ($name:literal, $impl:expr, $label:literal) => {
            linker
                .func_wrap(
                    NS,
                    $name,
                    |mut caller: Caller<'_, HostState>,
                     ptr: i32,
                     len: i32,
                     servers_ptr: i32,
                     servers_len: i32,
                     out_ptr: i32,
                     out_cap: i32|
                     -> i32 {
                        let Some(memory) = guest_memory(&mut caller) else {
                            return E_OTHER;
                        };
                        let arg = match read_str(&memory, &caller, ptr, len) {
                            Some(s) => s,
                            None => return E_OTHER,
                        };
                        let servers_csv = match read_str(&memory, &caller, servers_ptr, servers_len)
                        {
                            Some(s) => s,
                            None => String::new(),
                        };
                        let servers = parse_servers_csv(&servers_csv);
                        let m = caller.data().manifold.clone();
                        match $impl(&arg, &servers, &m) {
                            Ok(list) => {
                                let v: Vec<serde_json::Value> =
                                    list.into_iter().map(serde_json::Value::String).collect();
                                write_json(
                                    &mut caller,
                                    &memory,
                                    out_ptr,
                                    out_cap,
                                    &serde_json::Value::Array(v),
                                )
                            }
                            Err(e) => {
                                record(&mut caller, &format!("{}: {e}", $label));
                                map_err(&mut caller, e)
                            }
                        }
                    },
                )
                .map_err(link_err)?;
        };
    }

    wrap_string_list!("host_dns_resolve4", dns_host::resolve4, "dns.resolve4");
    wrap_string_list!("host_dns_resolve6", dns_host::resolve6, "dns.resolve6");
    wrap_string_list!(
        "host_dns_resolve_cname",
        dns_host::resolve_cname,
        "dns.resolveCname"
    );
    wrap_string_list!("host_dns_resolve_ns", dns_host::resolve_ns, "dns.resolveNs");
    wrap_string_list!("host_dns_reverse", dns_host::reverse, "dns.reverse");

    // SOA returns a structured record (single object), so it doesn't
    // fit the wrap_string_list shape. Linker emits the JSON directly.
    linker
        .func_wrap(
            NS,
            "host_dns_resolve_soa",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             servers_ptr: i32,
             servers_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let name = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let servers_csv = match read_str(&memory, &caller, servers_ptr, servers_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let servers: Vec<String> = if servers_csv.is_empty() {
                    Vec::new()
                } else {
                    servers_csv
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect()
                };
                let m = caller.data().manifold.clone();
                match dns_host::resolve_soa(&name, &servers, &m) {
                    Ok(v) => write_out(
                        &mut caller,
                        &memory,
                        out_ptr,
                        out_cap,
                        v.to_string().as_bytes(),
                    ),
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_dns_resolve_mx",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             servers_ptr: i32,
             servers_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let name = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let servers_csv =
                    read_str(&memory, &caller, servers_ptr, servers_len).unwrap_or_default();
                let servers = parse_servers_csv(&servers_csv);
                let m = caller.data().manifold.clone();
                match dns_host::resolve_mx(&name, &servers, &m) {
                    Ok(list) => {
                        let v: Vec<serde_json::Value> = list.iter().map(|r| r.to_json()).collect();
                        write_json(
                            &mut caller,
                            &memory,
                            out_ptr,
                            out_cap,
                            &serde_json::Value::Array(v),
                        )
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_dns_resolve_txt",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             servers_ptr: i32,
             servers_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let name = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let servers_csv =
                    read_str(&memory, &caller, servers_ptr, servers_len).unwrap_or_default();
                let servers = parse_servers_csv(&servers_csv);
                let m = caller.data().manifold.clone();
                match dns_host::resolve_txt(&name, &servers, &m) {
                    Ok(records) => {
                        // Node's resolveTxt yields `string[][]` —
                        // outer per RR, inner per character-string.
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
                        write_json(
                            &mut caller,
                            &memory,
                            out_ptr,
                            out_cap,
                            &serde_json::Value::Array(v),
                        )
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- chunked fs (stream support) -----------------------------------------

fn wrap_fs_chunks(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_fs_read_chunk",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             offset_lo: i32,
             offset_hi: i32,
             chunk_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let offset = ((offset_hi as u64) << 32) | (offset_lo as u32 as u64);
                let m = caller.data().manifold.clone();
                match fs_host::read_chunk(&path, offset, chunk_len as usize, &m) {
                    Ok(bytes) => {
                        let encoded = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &bytes,
                        );
                        write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_write_chunk",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             offset_lo: i32,
             offset_hi: i32,
             data_ptr: i32,
             data_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data = match B64.decode(data_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                let offset = ((offset_hi as u64) << 32) | (offset_lo as u32 as u64);
                let m = caller.data().manifold.clone();
                match fs_host::write_chunk(&path, offset, &data, &m) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_fs_size",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let path = match read_str(&memory, &caller, ptr, len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match fs_host::file_size(&path, &m) {
                    Ok(size) => {
                        let s = size.to_string();
                        write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- crypto ciphers + KDFs -----------------------------------------------

type GcmSig = (i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32);
type CbcSig = (i32, i32, i32, i32, i32, i32, i32, i32, i32, i32);

fn wrap_crypto_ciphers(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    for (name, encrypt) in [
        ("host_crypto_aes_gcm_encrypt", true),
        ("host_crypto_aes_gcm_decrypt", false),
    ] {
        linker
            .func_wrap(
                NS,
                name,
                move |mut caller: Caller<'_, HostState>,
                      algo_ptr: i32,
                      algo_len: i32,
                      key_ptr: i32,
                      key_len: i32,
                      nonce_ptr: i32,
                      nonce_len: i32,
                      data_ptr: i32,
                      data_len: i32,
                      aad_ptr: i32,
                      aad_len: i32,
                      out_ptr: i32,
                      out_cap: i32|
                      -> i32 {
                    let _ignore: GcmSig = (
                        algo_ptr, algo_len, key_ptr, key_len, nonce_ptr, nonce_len, data_ptr,
                        data_len, aad_ptr, aad_len, out_ptr, out_cap,
                    );
                    let Some(memory) = guest_memory(&mut caller) else {
                        return E_OTHER;
                    };
                    let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let key_b64 = match read_str(&memory, &caller, key_ptr, key_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let nonce_b64 = match read_str(&memory, &caller, nonce_ptr, nonce_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let aad_b64 = match read_str(&memory, &caller, aad_ptr, aad_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let key = match B64.decode(key_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(_) => return E_OTHER,
                    };
                    let nonce = match B64.decode(nonce_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(_) => return E_OTHER,
                    };
                    let data = match B64.decode(data_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(_) => return E_OTHER,
                    };
                    let aad = match B64.decode(aad_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(_) => return E_OTHER,
                    };
                    let m = caller.data().manifold.clone();
                    let res = if encrypt {
                        crypto_host::aes_gcm_encrypt(&algo, &key, &nonce, &data, &aad, &m)
                    } else {
                        crypto_host::aes_gcm_decrypt(&algo, &key, &nonce, &data, &aad, &m)
                    };
                    match res {
                        Ok(out) => {
                            let encoded = B64.encode(&out);
                            write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                        }
                        Err(e) => map_err(&mut caller, e),
                    }
                },
            )
            .map_err(link_err)?;
    }

    for (name, encrypt) in [
        ("host_crypto_aes_cbc_encrypt", true),
        ("host_crypto_aes_cbc_decrypt", false),
    ] {
        linker
            .func_wrap(
                NS,
                name,
                move |mut caller: Caller<'_, HostState>,
                      algo_ptr: i32,
                      algo_len: i32,
                      key_ptr: i32,
                      key_len: i32,
                      iv_ptr: i32,
                      iv_len: i32,
                      data_ptr: i32,
                      data_len: i32,
                      out_ptr: i32,
                      out_cap: i32|
                      -> i32 {
                    let _ignore: CbcSig = (
                        algo_ptr, algo_len, key_ptr, key_len, iv_ptr, iv_len, data_ptr, data_len,
                        out_ptr, out_cap,
                    );
                    let Some(memory) = guest_memory(&mut caller) else {
                        return E_OTHER;
                    };
                    let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let key_b64 = match read_str(&memory, &caller, key_ptr, key_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let iv_b64 = match read_str(&memory, &caller, iv_ptr, iv_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let key = match B64.decode(key_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(_) => return E_OTHER,
                    };
                    let iv = match B64.decode(iv_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(_) => return E_OTHER,
                    };
                    let data = match B64.decode(data_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(_) => return E_OTHER,
                    };
                    let m = caller.data().manifold.clone();
                    let res = if encrypt {
                        crypto_host::aes_cbc_encrypt(&algo, &key, &iv, &data, &m)
                    } else {
                        crypto_host::aes_cbc_decrypt(&algo, &key, &iv, &data, &m)
                    };
                    match res {
                        Ok(out) => {
                            let encoded = B64.encode(&out);
                            write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                        }
                        Err(e) => map_err(&mut caller, e),
                    }
                },
            )
            .map_err(link_err)?;
    }

    Ok(())
}

fn wrap_crypto_kdfs(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_crypto_pbkdf2_sync",
            |mut caller: Caller<'_, HostState>,
             digest_ptr: i32,
             digest_len: i32,
             password_ptr: i32,
             password_len: i32,
             salt_ptr: i32,
             salt_len: i32,
             iters: u32,
             key_len: u32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let digest = match read_str(&memory, &caller, digest_ptr, digest_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let password = match read_str(&memory, &caller, password_ptr, password_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let salt_b64 = match read_str(&memory, &caller, salt_ptr, salt_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let salt = match B64.decode(salt_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match crypto_host::pbkdf2_sync(
                    &digest,
                    password.as_bytes(),
                    &salt,
                    iters,
                    key_len as usize,
                    &m,
                ) {
                    Ok(bytes) => {
                        let encoded = B64.encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_scrypt_sync",
            |mut caller: Caller<'_, HostState>,
             password_ptr: i32,
             password_len: i32,
             salt_ptr: i32,
             salt_len: i32,
             n: u32,
             r: u32,
             p: u32,
             key_len: u32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let password = match read_str(&memory, &caller, password_ptr, password_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let salt_b64 = match read_str(&memory, &caller, salt_ptr, salt_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let salt = match B64.decode(salt_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match crypto_host::scrypt_sync(
                    password.as_bytes(),
                    &salt,
                    n,
                    r,
                    p,
                    key_len as usize,
                    &m,
                ) {
                    Ok(bytes) => {
                        let encoded = B64.encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- crypto signing (RSA + ECDSA) ---------------------------------------

fn wrap_crypto_signing(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_crypto_sign",
            |mut caller: Caller<'_, HostState>,
             algo_ptr: i32,
             algo_len: i32,
             key_ptr: i32,
             key_len: i32,
             data_ptr: i32,
             data_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let key_pem = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data = match B64.decode(data_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match crypto_host::sign(&algo, &key_pem, &data, &m) {
                    Ok(sig) => {
                        let encoded = B64.encode(&sig);
                        write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_verify",
            |mut caller: Caller<'_, HostState>,
             algo_ptr: i32,
             algo_len: i32,
             key_ptr: i32,
             key_len: i32,
             data_ptr: i32,
             data_len: i32,
             sig_ptr: i32,
             sig_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let key_pem = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let sig_b64 = match read_str(&memory, &caller, sig_ptr, sig_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data = match B64.decode(data_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                let sig = match B64.decode(sig_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                let m = caller.data().manifold.clone();
                match crypto_host::verify(&algo, &key_pem, &data, &sig, &m) {
                    Ok(true) => 1,
                    Ok(false) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- streaming sign / verify --------------------------------------------

fn wrap_crypto_signing_streaming(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_crypto_sign_open",
            |mut caller: Caller<'_, HostState>, algo_ptr: i32, algo_len: i32| -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return 0;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return 0,
                };
                match caller.data().sign_handles.open(&algo) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        record(&mut caller, &e.to_string());
                        0
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_sign_update",
            |mut caller: Caller<'_, HostState>, handle: i64, data_ptr: i32, data_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data = match B64.decode(data_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                match caller.data().sign_handles.update(handle as u64, &data) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_sign_finalize",
            |mut caller: Caller<'_, HostState>,
             handle: i64,
             algo_ptr: i32,
             algo_len: i32,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let key_pem = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let state = match caller.data().sign_handles.take(handle as u64) {
                    Ok(s) => s,
                    Err(e) => return map_err(&mut caller, e),
                };
                let m = caller.data().manifold.clone();
                match crypto_host::sign_finalize(&algo, &key_pem, state, &m) {
                    Ok(sig) => {
                        let encoded = B64.encode(&sig);
                        write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_verify_finalize",
            |mut caller: Caller<'_, HostState>,
             handle: i64,
             algo_ptr: i32,
             algo_len: i32,
             key_ptr: i32,
             key_len: i32,
             sig_ptr: i32,
             sig_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let key_pem = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let sig_b64 = match read_str(&memory, &caller, sig_ptr, sig_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let sig = match B64.decode(sig_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                let state = match caller.data().sign_handles.take(handle as u64) {
                    Ok(s) => s,
                    Err(e) => return map_err(&mut caller, e),
                };
                let m = caller.data().manifold.clone();
                match crypto_host::verify_finalize(&algo, &key_pem, state, &sig, &m) {
                    Ok(true) => 1,
                    Ok(false) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;
    Ok(())
}

/// Streaming `createHash` / `createHmac`. `hash_open` is for plain
/// digests; `hmac_open` takes the key at open time (MAC is constructed
/// once — HMAC doesn't accept a key change mid-stream). Both share the
/// same handle id space, update, and finalize path.
fn wrap_crypto_hash_streaming(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_crypto_hash_open",
            |mut caller: Caller<'_, HostState>, algo_ptr: i32, algo_len: i32| -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return 0;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return 0,
                };
                if !caller.data().manifold.crypto {
                    record(&mut caller, "crypto.createHash: permission denied");
                    return 0;
                }
                match caller.data().hash_handles.open_digest(&algo) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        record(&mut caller, &e.to_string());
                        0
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_hmac_open",
            |mut caller: Caller<'_, HostState>,
             algo_ptr: i32,
             algo_len: i32,
             key_ptr: i32,
             key_len: i32|
             -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return 0;
                };
                let algo = match read_str(&memory, &caller, algo_ptr, algo_len) {
                    Some(s) => s,
                    None => return 0,
                };
                let key_b64 = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return 0,
                };
                let key = match B64.decode(key_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => {
                        record(&mut caller, "hmac key: invalid base64");
                        return 0;
                    }
                };
                if !caller.data().manifold.crypto {
                    record(&mut caller, "crypto.createHmac: permission denied");
                    return 0;
                }
                match caller.data().hash_handles.open_hmac(&algo, &key) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        record(&mut caller, &e.to_string());
                        0
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_hash_update",
            |mut caller: Caller<'_, HostState>, handle: i64, data_ptr: i32, data_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let data_b64 = match read_str(&memory, &caller, data_ptr, data_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let data = match B64.decode(data_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                match caller.data().hash_handles.update(handle as u64, &data) {
                    Ok(()) => 0,
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_crypto_hash_digest",
            |mut caller: Caller<'_, HostState>,
             handle: i64,
             enc_ptr: i32,
             enc_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                // Empty encoding means default — hex. Matches the
                // one-shot host_crypto_hash which always emits hex.
                let enc = if enc_len == 0 {
                    "hex".to_string()
                } else {
                    match read_str(&memory, &caller, enc_ptr, enc_len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    }
                };
                let bytes = match caller.data().hash_handles.finalize(handle as u64) {
                    Ok(b) => b,
                    Err(e) => return map_err(&mut caller, e),
                };
                let encoded: String = match enc.as_str() {
                    "hex" => hex::encode(&bytes),
                    "base64" => B64.encode(&bytes),
                    "binary" | "latin1" => bytes.iter().map(|b| *b as char).collect(),
                    // Parity with the native path's `encode_bytes`. Without
                    // this arm, `crypto.createHash('sha256').digest('utf8')`
                    // works on native but errors on WASM — a silent
                    // cross-engine divergence we don't want to ship.
                    "utf8" | "utf-8" => String::from_utf8_lossy(&bytes).into_owned(),
                    other => {
                        record(
                            &mut caller,
                            &format!("hash.digest: unsupported encoding '{other}'"),
                        );
                        return E_OTHER;
                    }
                };
                write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- state store --------------------------------------------------------

fn wrap_state(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_state_get",
            |mut caller: Caller<'_, HostState>,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let key = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let store = caller.data().state_store.clone();
                match store.get(&key) {
                    Some(bytes) => {
                        let encoded = B64.encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                    }
                    None => -2, // NotFound — JS glue maps to undefined.
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_state_set",
            |mut caller: Caller<'_, HostState>,
             key_ptr: i32,
             key_len: i32,
             value_ptr: i32,
             value_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let key = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let value_b64 = match read_str(&memory, &caller, value_ptr, value_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let value = match B64.decode(value_b64.as_bytes()) {
                    Ok(v) => v,
                    Err(_) => return E_OTHER,
                };
                caller.data().state_store.set(&key, value);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_state_delete",
            |mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let key = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                caller.data().state_store.delete(&key);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_state_increment",
            |mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32, delta: i64| -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return 0;
                };
                let key = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return 0,
                };
                caller.data().state_store.increment_i64(&key, delta)
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- zlib (no manifold gate) ---------------------------------------------

fn wrap_zlib(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    for (name, op) in [
        ("host_zlib_deflate_sync", ZlibOp::Deflate),
        ("host_zlib_inflate_sync", ZlibOp::Inflate),
        ("host_zlib_gzip_sync", ZlibOp::Gzip),
        ("host_zlib_gunzip_sync", ZlibOp::Gunzip),
        ("host_zlib_zstd_compress_sync", ZlibOp::ZstdCompress),
        ("host_zlib_zstd_decompress_sync", ZlibOp::ZstdDecompress),
        ("host_zlib_brotli_compress_sync", ZlibOp::BrotliCompress),
        ("host_zlib_brotli_decompress_sync", ZlibOp::BrotliDecompress),
    ] {
        linker
            .func_wrap(
                NS,
                name,
                move |mut caller: Caller<'_, HostState>,
                      ptr: i32,
                      len: i32,
                      out_ptr: i32,
                      out_cap: i32|
                      -> i32 {
                    let Some(memory) = guest_memory(&mut caller) else {
                        return E_OTHER;
                    };
                    // Bytes come in as a base64 string — matches the
                    // native path wire format.
                    let input_b64 = match read_str(&memory, &caller, ptr, len) {
                        Some(s) => s,
                        None => return E_OTHER,
                    };
                    let input = match B64.decode(input_b64.as_bytes()) {
                        Ok(v) => v,
                        Err(e) => {
                            record(&mut caller, &format!("base64 decode: {e}"));
                            return E_OTHER;
                        }
                    };
                    let result = match op {
                        ZlibOp::Deflate => zlib_host::deflate_sync(&input),
                        ZlibOp::Inflate => zlib_host::inflate_sync(&input),
                        ZlibOp::Gzip => zlib_host::gzip_sync(&input),
                        ZlibOp::Gunzip => zlib_host::gunzip_sync(&input),
                        ZlibOp::ZstdCompress => zlib_host::zstd_compress_sync(&input),
                        ZlibOp::ZstdDecompress => zlib_host::zstd_decompress_sync(&input),
                        ZlibOp::BrotliCompress => zlib_host::brotli_compress_sync(&input),
                        ZlibOp::BrotliDecompress => zlib_host::brotli_decompress_sync(&input),
                    };
                    match result {
                        Ok(bytes) => {
                            let encoded = B64.encode(&bytes);
                            write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
                        }
                        Err(e) => map_err(&mut caller, e),
                    }
                },
            )
            .map_err(link_err)?;
    }
    Ok(())
}

// ---- base64 codec (no manifold gate) --------------------------------------
//
// Unlike the zlib bridges (whose JS-visible API is string-shaped, so they
// frame bytes as base64 on the wire), these two imports *implement* the
// guest's base64 fast path — double-encoding would defeat their purpose.
// They therefore use raw framing: `encode` reads raw bytes from guest
// memory and writes the ASCII encoding into the out region; `decode`
// reads ASCII and writes raw bytes back. Output sizes are exactly
// computable from input sizes, so the guest allocates exact-fit buffers
// and no retry-doubling protocol is needed.

/// Lenient decode engine: accepts both padded and unpadded input and
/// tolerates non-canonical trailing bits, matching the forgiving decode
/// semantics scripts expect from `Buffer.from(str, 'base64')`. Inputs
/// containing characters outside the standard alphabet still fail; the
/// guest falls back to its interpreter-side decoder for those.
const B64_LENIENT: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

fn wrap_b64(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_b64_encode",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                // Encode straight off the guest-memory slice — no input
                // copy. The borrow ends before `write_out` needs `&mut`.
                let encoded = {
                    let Some(input) = guest_slice(&memory, &caller, ptr, len) else {
                        return E_OTHER;
                    };
                    B64.encode(input)
                };
                write_out(&mut caller, &memory, out_ptr, out_cap, encoded.as_bytes())
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_b64_decode",
            |mut caller: Caller<'_, HostState>,
             ptr: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let decoded = {
                    let Some(input) = guest_slice(&memory, &caller, ptr, len) else {
                        return E_OTHER;
                    };
                    B64_LENIENT.decode(input)
                };
                match decoded {
                    Ok(bytes) => write_out(&mut caller, &memory, out_ptr, out_cap, &bytes),
                    Err(e) => {
                        record(&mut caller, &format!("base64 decode: {e}"));
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum ZlibOp {
    Deflate,
    Inflate,
    Gzip,
    Gunzip,
    ZstdCompress,
    ZstdDecompress,
    BrotliCompress,
    BrotliDecompress,
}

// ---- host context (embedder-facing) --------------------------------------

fn wrap_host_context(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    // __host_read_column(name) -> JSON-serialized Vec<Value> (string).
    linker
        .func_wrap(
            NS,
            "host_read_column",
            |mut caller: Caller<'_, HostState>,
             name_ptr: i32,
             name_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let name = match read_str(&memory, &caller, name_ptr, name_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let rows = match caller.data().host_context.as_ref() {
                    Some(ctx) => ctx.read_column(&name),
                    None => Vec::new(),
                };
                let json = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string());
                write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
            },
        )
        .map_err(link_err)?;

    // __host_emit_row(row_json) -> 0 on success.
    linker
        .func_wrap(
            NS,
            "host_emit_row",
            |mut caller: Caller<'_, HostState>, row_ptr: i32, row_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let row_json = match read_str(&memory, &caller, row_ptr, row_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let row: serde_json::Value = match serde_json::from_str(&row_json) {
                    Ok(v) => v,
                    Err(e) => {
                        record(&mut caller, &format!("emit_row: {e}"));
                        return E_OTHER;
                    }
                };
                if let Some(ctx) = caller.data().host_context.as_ref() {
                    ctx.emit_row(row);
                }
                0
            },
        )
        .map_err(link_err)?;

    // __host_get_env(key) -> option<string>. Empty means None.
    linker
        .func_wrap(
            NS,
            "host_get_env",
            |mut caller: Caller<'_, HostState>,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let key = match read_str(&memory, &caller, key_ptr, key_len) {
                    Some(s) => s,
                    None => return E_OTHER,
                };
                let val = caller
                    .data()
                    .host_context
                    .as_ref()
                    .and_then(|ctx| ctx.get_env(&key));
                match val {
                    Some(v) => write_out(&mut caller, &memory, out_ptr, out_cap, v.as_bytes()),
                    None => E_NOT_FOUND,
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- last_error slot -----------------------------------------------------

fn wrap_last_error(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_last_error",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let msg = caller.data().last_error.clone();
                write_out(&mut caller, &memory, out_ptr, out_cap, msg.as_bytes())
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- input slot (bytecode-cache invoke path) ----------------------------
//
// The plugin's bytecode-cache `invoke` mode reads the per-thrust input
// (JSON text or raw bytes, per `host_input_format`) from
// `HostState::pending_input` via this import — which lets us skip the
// per-thrust preamble compile that would otherwise publish the input
// as a JS global. The cached wrapped source calls
// `__AB_GET_INPUT_VALUE__()` (installed in `modify_runtime`) which
// routes here after sizing its buffer via `host_get_input_len`.
fn wrap_input(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_get_input",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                // Clone is required because `write_out` borrows the
                // store mutably for the memory write; we can't hold a
                // shared borrow on `pending_input` simultaneously.
                let input = caller.data().pending_input.clone();
                write_out(&mut caller, &memory, out_ptr, out_cap, &input)
            },
        )
        .map_err(link_err)?;

    // Framing flag for `pending_input` — `InputFormat` discriminant
    // (0 = JSON text, 1 = raw bytes). The plugin's input getter reads
    // this once per invocation to decide whether to materialize a JS
    // string for `JSON.parse` or hand the module a `Uint8Array`.
    linker
        .func_wrap(
            NS,
            "host_input_format",
            |caller: Caller<'_, HostState>| -> i32 { caller.data().input_format as i32 },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- columnar UDF path --------------------------------------------------
//
// The columnar UDF path (`WasmCombustor::thrust_columnar`) feeds the
// guest a binary blob — `BatchHeader` + `ColumnHeader[]` + per-column
// data + validity + names — written into `HostState::pending_input`
// (the same channel the JSON invoke path uses). The plugin's
// `columnar-invoke` mode reads this through the existing
// `host_get_input` import, then uses `host_get_input_len` to know
// the exact size up-front so the JS polyfill can allocate one
// linmem buffer of the right size and avoid the retry loop the
// JSON path tolerates (because JSON inputs are typically tiny).
//
// After the user UDF returns, the polyfill builds the result blob
// inside the guest's linmem and calls `host_columnar_reply` to
// hand the bytes to the host. The host stashes them in
// `HostState::pending_columnar_reply`; `thrust_columnar` reads
// the reply after `_start` returns and decodes via
// `crate::columnar::decode_batch`.
//
// All of this stays inside the Wasmtime sandbox: the only data
// crossing the boundary is one `memcpy` per input column (host →
// linmem at register time of the call) plus one `memcpy` per
// result column (linmem → host at reply time). No JSON, no base64,
// no encoding — just typed contiguous bytes with offset descriptors.
fn wrap_columnar(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    // Length getter — the polyfill calls this *before* it allocates
    // the destination buffer in linmem so it picks exactly the right
    // capacity in one shot. Saves the JSON-style "guess, retry on
    // E_BUF_TOO_SMALL" loop on a path where the input is hundreds of
    // KB and getting the size wrong wastes meaningful cycles.
    linker
        .func_wrap(
            NS,
            "host_get_input_len",
            |caller: Caller<'_, HostState>| -> i32 {
                let n = caller.data().pending_input.len();
                // i32 caps at 2 GiB; per-Store linmem is also bounded
                // (max 4 GiB by wasm32 spec, default 1 GiB). A blob
                // bigger than i32::MAX would be a misconfiguration —
                // surface it as -1 so the polyfill can error cleanly.
                i32::try_from(n).unwrap_or(-1)
            },
        )
        .map_err(link_err)?;

    // Reply receiver — guest writes its result blob into linmem at
    // (blob_ptr, blob_len), then calls this so the host copies the
    // bytes into `pending_columnar_reply`. The host can't share-borrow
    // pending_columnar_reply during the read because we hold a
    // mutable borrow of memory; clone-then-stash is the same pattern
    // the JSON stdout drain uses.
    linker
        .func_wrap(
            NS,
            "host_columnar_reply",
            |mut caller: Caller<'_, HostState>, blob_ptr: i32, blob_len: i32| -> i32 {
                if blob_len < 0 {
                    record(&mut caller, "columnar reply: negative blob_len");
                    return E_OTHER;
                }
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(bytes) = read_bytes(&memory, &caller, blob_ptr, blob_len) else {
                    record(&mut caller, "columnar reply: blob slice out of bounds");
                    return E_OTHER;
                };
                caller.data_mut().pending_columnar_reply = Some(bytes);
                0
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- daemon envelope slot (long-lived-Store re-entry) -------------------
//
// Mirrors `wrap_input` but routes to `HostState::pending_envelope`.
// Daemon mode's `daemon_step` export reads each step's envelope via
// this import rather than stdin, because WASI preview1 has no way
// to reset stdin between calls.
fn wrap_envelope(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_get_envelope",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let env = caller.data().pending_envelope.clone();
                write_out(&mut caller, &memory, out_ptr, out_cap, &env)
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- http server (daemon mode) ------------------------------------------
//
// `host_http_listen` calls into `DaemonHttp::bind_listener` which —
// under the `daemon` feature — binds a real TCP socket and spawns an
// axum task on the stored tokio runtime. Without the feature it
// degrades to an accounting-only stub, matching pre-B2.4 behaviour.
//
// `host_http_reply` parses the JSON payload the JS polyfill handed
// back from `res.end(body)` and forwards it through
// `DaemonHttp::deliver_reply`, waking the per-request reply channel
// the axum task is awaiting.
fn wrap_http_server(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_http_listen",
            |mut caller: Caller<'_, HostState>, port: i32| -> i32 {
                let Some(dh) = caller.data().daemon_http.clone() else {
                    caller.data_mut().last_error =
                        "http.createServer requires daemon mode; run via `burn foo.js` CLI".into();
                    return E_PERMISSION;
                };
                if !(1..=65535).contains(&port) {
                    caller.data_mut().last_error = format!("http.listen: invalid port {port}");
                    return E_OTHER;
                }
                dh.bind_listener(port as u16)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_http_reply",
            |mut caller: Caller<'_, HostState>, req_id: i64, resp_ptr: i32, resp_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(dh) = caller.data().daemon_http.clone() else {
                    return E_OTHER;
                };
                let Some(bytes) = read_bytes(&memory, &caller, resp_ptr, resp_len) else {
                    return E_OTHER;
                };
                let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        caller.data_mut().last_error = format!("http_reply json: {e}");
                        return E_OTHER;
                    }
                };
                let status = parsed.get("status").and_then(|v| v.as_u64()).unwrap_or(500) as u16;
                let headers: Vec<(String, String)> = parsed
                    .get("headers")
                    .and_then(|v| v.as_object())
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();
                let body = parsed
                    .get("body")
                    .and_then(|v| v.as_str())
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                let reply = crate::daemon_http::ReplyEnvelope {
                    status,
                    headers,
                    body,
                };
                dh.deliver_reply(req_id, reply);
                0
            },
        )
        .map_err(link_err)?;

    // `server.close()` in JS → `__host_http_close(server_id)`
    // here. Aborts the axum listener task and releases the port so a
    // subsequent `.listen(port)` in the same process succeeds. Idempotent
    // (second call on the same id is a no-op).
    linker
        .func_wrap(
            NS,
            "host_http_close",
            |caller: Caller<'_, HostState>, server_id: i32| -> i32 {
                let Some(dh) = caller.data().daemon_http.clone() else {
                    return 0;
                };
                if dh.close_listener(server_id) { 1 } else { 0 }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- L3 shadows --------------------------------------------------------
//
// Plugin always ships the `__host_shadow_bcrypt_*` imports; without
// the `shadow-bcrypt` feature they return `-1` and set `last_error`
// to "shadow-bcrypt not enabled". The JS-side polyfill surfaces that
// to users as a clean "enable the feature" error rather than a WASM
// instantiation failure.

fn wrap_shadow_bcrypt(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_shadow_bcrypt_hash",
            |mut caller: Caller<'_, HostState>,
             pw_ptr: i32,
             pw_len: i32,
             cost: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(pw_bytes) = read_bytes(&memory, &caller, pw_ptr, pw_len) else {
                    return E_OTHER;
                };
                let password = match std::str::from_utf8(&pw_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-bcrypt")]
                {
                    let cost_u = if cost <= 0 { 0 } else { cost as u32 };
                    match afterburner_node_compat::shadows::bcrypt::hash(password, cost_u) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-bcrypt"))]
                {
                    let _ = (password, cost, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-bcrypt feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_bcrypt_verify",
            |mut caller: Caller<'_, HostState>,
             pw_ptr: i32,
             pw_len: i32,
             h_ptr: i32,
             h_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(pw_bytes) = read_bytes(&memory, &caller, pw_ptr, pw_len) else {
                    return E_OTHER;
                };
                let Some(h_bytes) = read_bytes(&memory, &caller, h_ptr, h_len) else {
                    return E_OTHER;
                };
                let password = match std::str::from_utf8(&pw_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                let hash = match std::str::from_utf8(&h_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-bcrypt")]
                {
                    match afterburner_node_compat::shadows::bcrypt::verify(password, hash) {
                        Ok(true) => 1,
                        Ok(false) => 0,
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-bcrypt"))]
                {
                    let _ = (password, hash);
                    caller.data_mut().last_error = "shadow-bcrypt feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_bcrypt_gen_salt",
            |mut caller: Caller<'_, HostState>, rounds: i32, out_ptr: i32, out_cap: i32| -> i32 {
                #[cfg(feature = "shadow-bcrypt")]
                {
                    let Some(memory) = guest_memory(&mut caller) else {
                        return E_OTHER;
                    };
                    let cost_u = if rounds <= 0 { 0 } else { rounds as u32 };
                    match afterburner_node_compat::shadows::bcrypt::gen_salt(cost_u) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-bcrypt"))]
                {
                    let _ = (rounds, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-bcrypt feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- L3 shadow: argon2 -------------------------------------------------

fn wrap_shadow_argon2(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_shadow_argon2_hash",
            |mut caller: Caller<'_, HostState>,
             pw_ptr: i32,
             pw_len: i32,
             ty: i32,
             time_cost: i32,
             memory_cost: i32,
             parallelism: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(pw_bytes) = read_bytes(&memory, &caller, pw_ptr, pw_len) else {
                    return E_OTHER;
                };
                let password = match std::str::from_utf8(&pw_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-argon2")]
                {
                    let ty_u = if ty < 0 { 2 } else { ty as u8 };
                    let t_u = if time_cost < 0 { 0 } else { time_cost as u32 };
                    let m_u = if memory_cost < 0 {
                        0
                    } else {
                        memory_cost as u32
                    };
                    let p_u = if parallelism < 0 {
                        0
                    } else {
                        parallelism as u32
                    };
                    match afterburner_node_compat::shadows::argon2::hash(
                        password, ty_u, t_u, m_u, p_u,
                    ) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-argon2"))]
                {
                    let _ = (
                        password,
                        ty,
                        time_cost,
                        memory_cost,
                        parallelism,
                        out_ptr,
                        out_cap,
                    );
                    caller.data_mut().last_error = "shadow-argon2 feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_argon2_verify",
            |mut caller: Caller<'_, HostState>,
             h_ptr: i32,
             h_len: i32,
             pw_ptr: i32,
             pw_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(h_bytes) = read_bytes(&memory, &caller, h_ptr, h_len) else {
                    return E_OTHER;
                };
                let Some(pw_bytes) = read_bytes(&memory, &caller, pw_ptr, pw_len) else {
                    return E_OTHER;
                };
                let hash = match std::str::from_utf8(&h_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                let password = match std::str::from_utf8(&pw_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-argon2")]
                {
                    match afterburner_node_compat::shadows::argon2::verify(hash, password) {
                        Ok(true) => 1,
                        Ok(false) => 0,
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-argon2"))]
                {
                    let _ = (hash, password);
                    caller.data_mut().last_error = "shadow-argon2 feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_argon2_needs_rehash",
            |mut caller: Caller<'_, HostState>,
             h_ptr: i32,
             h_len: i32,
             ty: i32,
             time_cost: i32,
             memory_cost: i32,
             parallelism: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(h_bytes) = read_bytes(&memory, &caller, h_ptr, h_len) else {
                    return E_OTHER;
                };
                let hash = match std::str::from_utf8(&h_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-argon2")]
                {
                    let ty_u = if ty < 0 { 2 } else { ty as u8 };
                    let t_u = if time_cost < 0 { 0 } else { time_cost as u32 };
                    let m_u = if memory_cost < 0 {
                        0
                    } else {
                        memory_cost as u32
                    };
                    let p_u = if parallelism < 0 {
                        0
                    } else {
                        parallelism as u32
                    };
                    match afterburner_node_compat::shadows::argon2::needs_rehash(
                        hash, ty_u, t_u, m_u, p_u,
                    ) {
                        Ok(true) => 1,
                        Ok(false) => 0,
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-argon2"))]
                {
                    let _ = (hash, ty, time_cost, memory_cost, parallelism);
                    caller.data_mut().last_error = "shadow-argon2 feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- L3 shadow: jsonwebtoken -------------------------------------------
//
// Three host imports — sign / verify / decode. Options flow in as
// a JSON blob to keep the ABI narrow; Rust parses only the fields
// it recognizes and ignores unknown keys.

fn wrap_shadow_jwt(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_shadow_jwt_sign",
            |mut caller: Caller<'_, HostState>,
             payload_ptr: i32,
             payload_len: i32,
             secret_ptr: i32,
             secret_len: i32,
             opts_ptr: i32,
             opts_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(payload_bytes) = read_bytes(&memory, &caller, payload_ptr, payload_len)
                else {
                    return E_OTHER;
                };
                let Some(secret) = read_bytes(&memory, &caller, secret_ptr, secret_len) else {
                    return E_OTHER;
                };
                let Some(opts_bytes) = read_bytes(&memory, &caller, opts_ptr, opts_len) else {
                    return E_OTHER;
                };
                let payload_str = match std::str::from_utf8(&payload_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                let opts_str = match std::str::from_utf8(&opts_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-jsonwebtoken")]
                {
                    match afterburner_node_compat::shadows::jsonwebtoken::sign(
                        payload_str,
                        &secret,
                        opts_str,
                    ) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-jsonwebtoken"))]
                {
                    let _ = (payload_str, secret, opts_str, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-jsonwebtoken feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_jwt_verify",
            |mut caller: Caller<'_, HostState>,
             token_ptr: i32,
             token_len: i32,
             secret_ptr: i32,
             secret_len: i32,
             opts_ptr: i32,
             opts_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(token_bytes) = read_bytes(&memory, &caller, token_ptr, token_len) else {
                    return E_OTHER;
                };
                let Some(secret) = read_bytes(&memory, &caller, secret_ptr, secret_len) else {
                    return E_OTHER;
                };
                let Some(opts_bytes) = read_bytes(&memory, &caller, opts_ptr, opts_len) else {
                    return E_OTHER;
                };
                let token_str = match std::str::from_utf8(&token_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                let opts_str = match std::str::from_utf8(&opts_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-jsonwebtoken")]
                {
                    match afterburner_node_compat::shadows::jsonwebtoken::verify(
                        token_str, &secret, opts_str,
                    ) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-jsonwebtoken"))]
                {
                    let _ = (token_str, secret, opts_str, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-jsonwebtoken feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_jwt_decode",
            |mut caller: Caller<'_, HostState>,
             token_ptr: i32,
             token_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(token_bytes) = read_bytes(&memory, &caller, token_ptr, token_len) else {
                    return E_OTHER;
                };
                let token_str = match std::str::from_utf8(&token_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                #[cfg(feature = "shadow-jsonwebtoken")]
                {
                    match afterburner_node_compat::shadows::jsonwebtoken::decode_unverified(
                        token_str,
                    ) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-jsonwebtoken"))]
                {
                    let _ = (token_str, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-jsonwebtoken feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- transpile hook (B8+B9) ---------------------------------------------
//
// `host_ts_transpile(src_ptr, src_len, path_ptr, path_len, out_ptr,
// out_cap) -> i32` invokes the `transpile_hook` stored on HostState
// (wired by the CLI when built with the `ts` feature). Returns the
// number of bytes written into the output buffer, or a negative
// error code if the hook is absent or transpile failed.
//
// Convention: positive = bytes written; 0 = hook returned empty
// string (legitimate); -1 = no hook; -2 = guest buffer too small;
// -3 = transpile error (detail via `host_last_error`).

fn wrap_transpile(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_ts_transpile",
            |mut caller: Caller<'_, HostState>,
             src_ptr: i32,
             src_len: i32,
             path_ptr: i32,
             path_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(src_bytes) = read_bytes(&memory, &caller, src_ptr, src_len) else {
                    return E_OTHER;
                };
                let Some(path_bytes) = read_bytes(&memory, &caller, path_ptr, path_len) else {
                    return E_OTHER;
                };
                let src = match std::str::from_utf8(&src_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                let path = match std::str::from_utf8(&path_bytes) {
                    Ok(s) => s,
                    Err(_) => return E_OTHER,
                };
                let Some(hook) = caller.data().transpile_hook.clone() else {
                    // No hook registered — caller should fall back to
                    // loading the raw source. `-1` signals "no hook".
                    return -1;
                };
                let transpiled = match hook(src, path) {
                    Ok(s) => s,
                    Err(e) => {
                        caller.data_mut().last_error = format!("ts_transpile: {e}");
                        return -3;
                    }
                };
                let bytes = transpiled.into_bytes();
                write_out(&mut caller, &memory, out_ptr, out_cap, &bytes)
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- process.exit --------------------------------------------------
//
// `host_process_exit(code)` never returns — the host traps with
// `I32Exit(code)`, which Wasmtime surfaces as a `wasmtime::Error`
// that `map_daemon_trap` converts to `AfterburnerError::ProcessExit`.
// wasmtime 44 host fns return `wasmtime::Result` rather than
// `anyhow::Result`; the From impl on I32Exit covers the conversion.

fn wrap_process_exit(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_process_exit",
            |_caller: Caller<'_, HostState>, code: i32| -> wasmtime::Result<()> {
                Err(I32Exit(code).into())
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- timers (daemon mode B3) --------------------------------------------

fn wrap_timers(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_timer_set",
            |mut caller: Caller<'_, HostState>, delay_ms: i32, repeat: i32| -> i32 {
                // Timers are only supported in daemon mode. In UDF /
                // one-shot script mode `daemon_http` is None and we
                // return -1 so the JS polyfill surfaces a clear error.
                if caller.data().daemon_http.is_none() {
                    return -1;
                }
                let delay = if delay_ms > 0 {
                    delay_ms as u64
                } else {
                    // Node treats delay <= 0 as 1 for setInterval,
                    // and 0 as immediate for setTimeout. Use 1ms floor.
                    1
                };
                let state = caller.data_mut();
                let id = state.next_timer_id;
                state.next_timer_id += 1;
                state.timers.push(TimerSlot {
                    id,
                    fire_at: Instant::now() + Duration::from_millis(delay),
                    interval_ms: if repeat != 0 { Some(delay) } else { None },
                    is_ref: true,
                });
                id
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_timer_clear",
            |mut caller: Caller<'_, HostState>, timer_id: i32| {
                caller.data_mut().timers.retain(|t| t.id != timer_id);
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_timer_unref",
            |mut caller: Caller<'_, HostState>, timer_id: i32| {
                if let Some(t) = caller
                    .data_mut()
                    .timers
                    .iter_mut()
                    .find(|t| t.id == timer_id)
                {
                    t.is_ref = false;
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_timer_ref",
            |mut caller: Caller<'_, HostState>, timer_id: i32| {
                if let Some(t) = caller
                    .data_mut()
                    .timers
                    .iter_mut()
                    .find(|t| t.id == timer_id)
                {
                    t.is_ref = true;
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- worker_threads -----------------------------------------------
//
// Five host imports back the `worker_threads` polyfill:
//
// * `host_worker_spawn(path, data, opts)` → worker_id (≥1) | error
// * `host_worker_post_message(id, payload)` → 0 | error  (parent → child)
// * `host_worker_terminate(id, force)` → 0 | error
// * `host_worker_post_to_parent(payload)` → 0 | error    (child → parent)
// * `host_worker_post_online_to_parent()` → 0 | error    (child → parent)
//
// All inputs cross the WASM boundary as `(ptr, len)` pairs read from
// guest memory; the JS-side polyfill surfaces the negative codes as
// typed errors. See `crate::daemon_workers::errors` for the full code
// table.

fn wrap_workers(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    use crate::daemon_workers::errors as werr;

    linker
        .func_wrap(
            NS,
            "host_worker_spawn",
            |mut caller: Caller<'_, HostState>,
             path_ptr: i32,
             path_len: i32,
             data_ptr: i32,
             data_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return werr::E_OTHER;
                };
                let Some(path) = read_str(&memory, &caller, path_ptr, path_len) else {
                    record(&mut caller, "worker_spawn: invalid path");
                    return werr::E_OTHER;
                };
                let Some(data) = read_str(&memory, &caller, data_ptr, data_len) else {
                    record(&mut caller, "worker_spawn: invalid worker_data");
                    return werr::E_OTHER;
                };
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    record(
                        &mut caller,
                        "worker_threads requires daemon mode; run via `burn foo.js`",
                    );
                    return werr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = workers.spawn_worker(&path, &data, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_spawn_env",
            |mut caller: Caller<'_, HostState>,
             path_ptr: i32,
             path_len: i32,
             data_ptr: i32,
             data_len: i32,
             env_ptr: i32,
             env_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return werr::E_OTHER;
                };
                let Some(path) = read_str(&memory, &caller, path_ptr, path_len) else {
                    record(&mut caller, "worker_spawn_env: invalid path");
                    return werr::E_OTHER;
                };
                let Some(data) = read_str(&memory, &caller, data_ptr, data_len) else {
                    record(&mut caller, "worker_spawn_env: invalid worker_data");
                    return werr::E_OTHER;
                };
                let env = read_str(&memory, &caller, env_ptr, env_len).unwrap_or_default();
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    record(
                        &mut caller,
                        "worker_threads requires daemon mode; run via `burn foo.js`",
                    );
                    return werr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = workers.spawn_worker_with_env(&path, &data, &env, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_pid",
            |caller: Caller<'_, HostState>, worker_id: i32| -> i32 {
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    return 0;
                };
                workers.worker_pid(worker_id)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_post_message",
            |mut caller: Caller<'_, HostState>,
             worker_id: i32,
             payload_ptr: i32,
             payload_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return werr::E_OTHER;
                };
                let Some(payload) = read_str(&memory, &caller, payload_ptr, payload_len) else {
                    record(&mut caller, "worker_post: invalid payload");
                    return werr::E_OTHER;
                };
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    return werr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = workers.post_message_to_worker(worker_id, &payload, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_terminate",
            |caller: Caller<'_, HostState>, worker_id: i32, force: i32| -> i32 {
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    return werr::E_NO_DAEMON;
                };
                workers.terminate_worker(worker_id, force != 0)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_post_to_parent",
            |mut caller: Caller<'_, HostState>, payload_ptr: i32, payload_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return werr::E_OTHER;
                };
                let Some(payload) = read_str(&memory, &caller, payload_ptr, payload_len) else {
                    record(&mut caller, "worker_post_parent: invalid payload");
                    return werr::E_OTHER;
                };
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    return werr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = workers.post_to_parent(&payload, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_post_online_to_parent",
            |mut caller: Caller<'_, HostState>| -> i32 {
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    return werr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = workers.post_online_to_parent(&mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_post_error_to_parent",
            |mut caller: Caller<'_, HostState>,
             msg_ptr: i32,
             msg_len: i32,
             stack_ptr: i32,
             stack_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return werr::E_OTHER;
                };
                let Some(message) = read_str(&memory, &caller, msg_ptr, msg_len) else {
                    return werr::E_OTHER;
                };
                let Some(stack) = read_str(&memory, &caller, stack_ptr, stack_len) else {
                    return werr::E_OTHER;
                };
                let Some(workers) = caller.data().daemon_workers.clone() else {
                    return werr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = workers.post_error_to_parent(&message, &stack, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_thread_id",
            |caller: Caller<'_, HostState>| -> i32 {
                caller
                    .data()
                    .daemon_workers
                    .as_ref()
                    .map(|w| w.thread_id())
                    .unwrap_or(0)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_is_main_thread",
            |caller: Caller<'_, HostState>| -> i32 {
                caller
                    .data()
                    .daemon_workers
                    .as_ref()
                    .map(|w| if w.is_main_thread() { 1 } else { 0 })
                    .unwrap_or(1)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_worker_data",
            |mut caller: Caller<'_, HostState>, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return werr::E_OTHER;
                };
                let data = caller
                    .data()
                    .daemon_workers
                    .as_ref()
                    .map(|w| w.worker_data().to_string())
                    .unwrap_or_default();
                write_out(&mut caller, &memory, out_ptr, out_cap, data.as_bytes())
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- net (raw TCP, B7) --------------------------------------------------
//
// Nine host imports back the `net` polyfill:
//
//   __host_net_connect(host, port)            -> conn_id | error
//   __host_net_write(conn_id, payload_b64)    -> 0 | error
//   __host_net_end(conn_id)                   -> 0 | error
//   __host_net_destroy(conn_id)               -> 0 | error
//   __host_net_pending(conn_id)               -> bytes (≥0) | 0
//   __host_net_set_no_delay(conn_id, enable)  -> 0 | error
//   __host_net_set_keep_alive(conn_id, en, d) -> 0 | error
//   __host_net_listen(host, port)             -> server_id | error
//   __host_net_close_server(server_id)        -> 0 | error
//
// Manifold gating happens in `DaemonNet::connect`; the coordinator
// also returns `E_NO_DAEMON` from every entry point if the slot on
// `HostState` is `None` (library mode never installs one).

#[cfg(feature = "daemon")]
fn wrap_net(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    use crate::daemon_net::errors as nerr;

    linker
        .func_wrap(
            NS,
            "host_net_connect",
            |mut caller: Caller<'_, HostState>, host_ptr: i32, host_len: i32, port: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return nerr::E_OTHER;
                };
                let Some(host) = read_str(&memory, &caller, host_ptr, host_len) else {
                    record(&mut caller, "net_connect: invalid host");
                    return nerr::E_OTHER;
                };
                if !(1..=65535).contains(&port) {
                    record(&mut caller, &format!("net_connect: invalid port {port}"));
                    return nerr::E_BAD_PORT;
                }
                let Some(net) = caller.data().daemon_net.clone() else {
                    record(&mut caller, "net.connect requires daemon mode");
                    return nerr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = net.connect(&host, port as u16, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_write",
            |mut caller: Caller<'_, HostState>,
             conn_id: i32,
             payload_ptr: i32,
             payload_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return nerr::E_OTHER;
                };
                let Some(payload) = read_str(&memory, &caller, payload_ptr, payload_len) else {
                    record(&mut caller, "net_write: invalid payload");
                    return nerr::E_BAD_PAYLOAD;
                };
                let Some(net) = caller.data().daemon_net.clone() else {
                    return nerr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let bytes = match crate::daemon_net::decode_payload(&payload, &mut last_error) {
                    Some(b) => b,
                    None => {
                        caller.data_mut().last_error = last_error;
                        return nerr::E_BAD_PAYLOAD;
                    }
                };
                let result = net.write(conn_id, bytes, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_end",
            |mut caller: Caller<'_, HostState>, conn_id: i32| -> i32 {
                let Some(net) = caller.data().daemon_net.clone() else {
                    return nerr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = net.end(conn_id, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_destroy",
            |caller: Caller<'_, HostState>, conn_id: i32| -> i32 {
                let Some(net) = caller.data().daemon_net.clone() else {
                    return nerr::E_NO_DAEMON;
                };
                net.destroy(conn_id)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_pending",
            |caller: Caller<'_, HostState>, conn_id: i32| -> i32 {
                caller
                    .data()
                    .daemon_net
                    .as_ref()
                    .map(|n| n.pending_bytes(conn_id))
                    .unwrap_or(0)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_set_no_delay",
            |caller: Caller<'_, HostState>, conn_id: i32, enable: i32| -> i32 {
                let Some(net) = caller.data().daemon_net.clone() else {
                    return nerr::E_NO_DAEMON;
                };
                net.set_no_delay(conn_id, enable != 0)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_set_keep_alive",
            |caller: Caller<'_, HostState>, conn_id: i32, enable: i32, delay_ms: i32| -> i32 {
                let Some(net) = caller.data().daemon_net.clone() else {
                    return nerr::E_NO_DAEMON;
                };
                net.set_keep_alive(conn_id, enable != 0, delay_ms)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_listen",
            |mut caller: Caller<'_, HostState>, host_ptr: i32, host_len: i32, port: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return nerr::E_OTHER;
                };
                let Some(host) = read_str(&memory, &caller, host_ptr, host_len) else {
                    record(&mut caller, "net_listen: invalid host");
                    return nerr::E_OTHER;
                };
                // Accept port 0 here — the OS picks a port and we
                // surface it via the `Listening` event.
                if !(0..=65535).contains(&port) {
                    record(&mut caller, &format!("net_listen: invalid port {port}"));
                    return nerr::E_BAD_PORT;
                }
                let Some(net) = caller.data().daemon_net.clone() else {
                    record(&mut caller, "net.createServer requires daemon mode");
                    return nerr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = net.listen(&host, port as u16, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_net_close_server",
            |caller: Caller<'_, HostState>, server_id: i32| -> i32 {
                let Some(net) = caller.data().daemon_net.clone() else {
                    return nerr::E_NO_DAEMON;
                };
                net.close_server(server_id)
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- tls -----------------------------------------------------------
//
// Seven host imports back the `tls` polyfill:
//
//   __host_tls_connect(host, port, opts_json)        -> conn_id | error
//   __host_tls_write(conn_id, payload_b64)           -> 0 | error
//   __host_tls_end(conn_id)                          -> 0 | error
//   __host_tls_destroy(conn_id)                      -> 0 | error
//   __host_tls_pending(conn_id)                      -> bytes (≥0) | 0
//   __host_tls_listen(host, port, cert_pem, key_pem) -> server_id | error
//   __host_tls_close_server(server_id)               -> 0 | error
//
// The connect-options JSON carries `rejectUnauthorized`, `servername`,
// `alpn` (string array), and `ca` (PEM blob). Schema is locked at the
// polyfill boundary; the host treats every field as optional and
// defensively defaults to safe values (full CA verification ON).

#[cfg(feature = "daemon")]
fn wrap_tls(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    use crate::daemon_tls::errors as terr;

    linker
        .func_wrap(
            NS,
            "host_tls_connect",
            |mut caller: Caller<'_, HostState>,
             host_ptr: i32,
             host_len: i32,
             port: i32,
             opts_ptr: i32,
             opts_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return terr::E_OTHER;
                };
                let Some(host) = read_str(&memory, &caller, host_ptr, host_len) else {
                    record(&mut caller, "tls_connect: invalid host");
                    return terr::E_OTHER;
                };
                if !(1..=65535).contains(&port) {
                    record(&mut caller, &format!("tls_connect: invalid port {port}"));
                    return terr::E_BAD_PORT;
                }
                let opts_json = read_str(&memory, &caller, opts_ptr, opts_len).unwrap_or_default();
                let opts = parse_tls_connect_opts(&opts_json);
                let Some(tls) = caller.data().daemon_tls.clone() else {
                    record(&mut caller, "tls.connect requires daemon mode");
                    return terr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = tls.connect(&host, port as u16, opts, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_tls_write",
            |mut caller: Caller<'_, HostState>,
             conn_id: i32,
             payload_ptr: i32,
             payload_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return terr::E_OTHER;
                };
                let Some(payload) = read_str(&memory, &caller, payload_ptr, payload_len) else {
                    record(&mut caller, "tls_write: invalid payload");
                    return terr::E_BAD_PAYLOAD;
                };
                let Some(tls) = caller.data().daemon_tls.clone() else {
                    return terr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let bytes = match crate::daemon_tls::decode_payload(&payload, &mut last_error) {
                    Some(b) => b,
                    None => {
                        caller.data_mut().last_error = last_error;
                        return terr::E_BAD_PAYLOAD;
                    }
                };
                let result = tls.write(conn_id, bytes, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_tls_end",
            |mut caller: Caller<'_, HostState>, conn_id: i32| -> i32 {
                let Some(tls) = caller.data().daemon_tls.clone() else {
                    return terr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = tls.end(conn_id, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_tls_destroy",
            |caller: Caller<'_, HostState>, conn_id: i32| -> i32 {
                let Some(tls) = caller.data().daemon_tls.clone() else {
                    return terr::E_NO_DAEMON;
                };
                tls.destroy(conn_id)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_tls_pending",
            |caller: Caller<'_, HostState>, conn_id: i32| -> i32 {
                caller
                    .data()
                    .daemon_tls
                    .as_ref()
                    .map(|t| t.pending_bytes(conn_id))
                    .unwrap_or(0)
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_tls_listen",
            |mut caller: Caller<'_, HostState>,
             host_ptr: i32,
             host_len: i32,
             port: i32,
             cert_ptr: i32,
             cert_len: i32,
             key_ptr: i32,
             key_len: i32,
             sni_ptr: i32,
             sni_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return terr::E_OTHER;
                };
                let Some(host) = read_str(&memory, &caller, host_ptr, host_len) else {
                    record(&mut caller, "tls_listen: invalid host");
                    return terr::E_OTHER;
                };
                if !(0..=65535).contains(&port) {
                    record(&mut caller, &format!("tls_listen: invalid port {port}"));
                    return terr::E_BAD_PORT;
                }
                let Some(cert_pem) = read_str(&memory, &caller, cert_ptr, cert_len) else {
                    record(&mut caller, "tls_listen: invalid cert PEM");
                    return terr::E_BAD_CERT;
                };
                let Some(key_pem) = read_str(&memory, &caller, key_ptr, key_len) else {
                    record(&mut caller, "tls_listen: invalid key PEM");
                    return terr::E_BAD_CERT;
                };
                let sni_map_json = read_str(&memory, &caller, sni_ptr, sni_len).unwrap_or_default();
                let Some(tls) = caller.data().daemon_tls.clone() else {
                    record(&mut caller, "tls.createServer requires daemon mode");
                    return terr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = tls.listen(
                    &host,
                    port as u16,
                    &cert_pem,
                    &key_pem,
                    &sni_map_json,
                    &mut last_error,
                );
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_tls_close_server",
            |caller: Caller<'_, HostState>, server_id: i32| -> i32 {
                let Some(tls) = caller.data().daemon_tls.clone() else {
                    return terr::E_NO_DAEMON;
                };
                tls.close_server(server_id)
            },
        )
        .map_err(link_err)?;

    Ok(())
}

#[cfg(feature = "daemon")]
fn parse_tls_connect_opts(json: &str) -> crate::daemon_tls::ConnectOptions {
    use crate::daemon_tls::ConnectOptions;
    let mut out = ConnectOptions {
        // Node default is `rejectUnauthorized: true`. Mirror it: the
        // polyfill always sends the value, but treat missing/invalid
        // JSON as the safe value rather than the "skip verify" one.
        reject_unauthorized: true,
        servername: String::new(),
        alpn: Vec::new(),
        ca_pem: String::new(),
    };
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return out,
    };
    if let Some(b) = v.get("rejectUnauthorized").and_then(|x| x.as_bool()) {
        out.reject_unauthorized = b;
    }
    if let Some(s) = v.get("servername").and_then(|x| x.as_str()) {
        out.servername = s.to_string();
    }
    if let Some(arr) = v.get("alpn").and_then(|x| x.as_array()) {
        out.alpn = arr
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
    }
    if let Some(s) = v.get("ca").and_then(|x| x.as_str()) {
        out.ca_pem = s.to_string();
    }
    out
}

// ---- dgram (UDP) ---------------------------------------------------------
//
// Four host imports back the polyfill:
//
//   __host_dgram_bind(host, port)                      -> socket_id (i32) | E_*
//   __host_dgram_send(id, host, port, payload_b64)    -> bytes_sent (i32) | E_*
//   __host_dgram_close(id)                             -> 0 | E_*
//   __host_dgram_address(id) -> JSON {"address","port"} via out buffer | E_*
//
// Inbound packets surface as `dgram-message` envelopes through the
// daemon event loop, dispatched by the CLI translator into
// `__ab_dgram_handlers[socket_id]`.

#[cfg(feature = "daemon")]
fn wrap_dgram(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    use crate::daemon_dgram::errors as derr;

    linker
        .func_wrap(
            NS,
            "host_dgram_bind",
            |mut caller: Caller<'_, HostState>, host_ptr: i32, host_len: i32, port: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return derr::E_OTHER;
                };
                let Some(host) = read_str(&memory, &caller, host_ptr, host_len) else {
                    record(&mut caller, "dgram.bind: invalid host");
                    return derr::E_BAD_HOST;
                };
                if !(0..=65535).contains(&port) {
                    record(&mut caller, &format!("dgram.bind: invalid port {port}"));
                    return derr::E_BAD_PORT;
                }
                let Some(dgram) = caller.data().daemon_dgram.clone() else {
                    record(&mut caller, "dgram.bind requires daemon mode");
                    return derr::E_NO_DAEMON;
                };
                let mut last_error = String::new();
                let result = dgram.bind(&host, port as u16, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_dgram_send",
            |mut caller: Caller<'_, HostState>,
             socket_id: i32,
             host_ptr: i32,
             host_len: i32,
             port: i32,
             payload_ptr: i32,
             payload_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return derr::E_OTHER;
                };
                let Some(host) = read_str(&memory, &caller, host_ptr, host_len) else {
                    record(&mut caller, "dgram.send: invalid host");
                    return derr::E_BAD_HOST;
                };
                if !(0..=65535).contains(&port) {
                    record(&mut caller, &format!("dgram.send: invalid port {port}"));
                    return derr::E_BAD_PORT;
                }
                let Some(payload_b64) = read_str(&memory, &caller, payload_ptr, payload_len) else {
                    record(&mut caller, "dgram.send: invalid payload");
                    return derr::E_BAD_PAYLOAD;
                };
                let mut last_error = String::new();
                let Some(payload) =
                    crate::daemon_net::decode_payload(&payload_b64, &mut last_error)
                else {
                    if last_error.is_empty() {
                        last_error = "dgram.send: payload decode failed".into();
                    }
                    caller.data_mut().last_error = last_error;
                    return derr::E_BAD_PAYLOAD;
                };
                let Some(dgram) = caller.data().daemon_dgram.clone() else {
                    record(&mut caller, "dgram.send requires daemon mode");
                    return derr::E_NO_DAEMON;
                };
                let result = dgram.send(socket_id, &host, port as u16, &payload, &mut last_error);
                if !last_error.is_empty() {
                    caller.data_mut().last_error = last_error;
                }
                result
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_dgram_close",
            |mut caller: Caller<'_, HostState>, socket_id: i32| -> i32 {
                let Some(dgram) = caller.data().daemon_dgram.clone() else {
                    record(&mut caller, "dgram.close requires daemon mode");
                    return derr::E_NO_DAEMON;
                };
                dgram.close(socket_id);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_dgram_address",
            |mut caller: Caller<'_, HostState>,
             socket_id: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return derr::E_OTHER;
                };
                let Some(dgram) = caller.data().daemon_dgram.clone() else {
                    record(&mut caller, "dgram.address requires daemon mode");
                    return derr::E_NO_DAEMON;
                };
                let Some((addr, port)) = dgram.address(socket_id) else {
                    record(
                        &mut caller,
                        &format!("dgram.address: unknown id {socket_id}"),
                    );
                    return derr::E_BAD_ID;
                };
                let json = format!(
                    "{{\"address\":{},\"port\":{}}}",
                    js_string_literal(&addr),
                    port
                );
                write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- child_process (sync) ------------------------------------------------
//
// Single host import:
//   __host_child_process_exec_sync(cmd, argv_json) -> JSON {status, stdout, stderr}
//
// Argv crosses as a JSON-encoded array string so we don't need a
// guest-side array marshaller. Manifold gating happens inside
// `child_process_host::exec_sync`. The wasm path uses the same
// node_compat host fn the native path uses — process spawning works
// from inside the wasm sandbox because the host (wasmtime caller)
// drives `std::process::Command`, not the guest.

fn wrap_child_process(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_child_process_exec_sync",
            |mut caller: Caller<'_, HostState>,
             cmd_ptr: i32,
             cmd_len: i32,
             argv_json_ptr: i32,
             argv_json_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(cmd) = read_str(&memory, &caller, cmd_ptr, cmd_len) else {
                    return E_OTHER;
                };
                let argv_json =
                    read_str(&memory, &caller, argv_json_ptr, argv_json_len).unwrap_or_default();
                let argv_owned: Vec<String> = if argv_json.is_empty() {
                    Vec::new()
                } else {
                    match serde_json::from_str(&argv_json) {
                        Ok(v) => v,
                        Err(e) => {
                            record(&mut caller, &format!("child_process: argv parse: {e}"));
                            return E_OTHER;
                        }
                    }
                };
                let argv_refs: Vec<&str> = argv_owned.iter().map(String::as_str).collect();
                let m = caller.data().manifold.clone();
                match child_process_host::exec_sync(&cmd, &argv_refs, &m) {
                    Ok(result) => {
                        let json = format!(
                            r#"{{"status":{},"stdout":{},"stderr":{}}}"#,
                            result.status,
                            js_string_literal(&result.stdout),
                            js_string_literal(&result.stderr)
                        );
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => map_err(&mut caller, e),
                }
            },
        )
        .map_err(link_err)?;
    Ok(())
}

// ---- shadow: sqlite3 (L3) -----------------------------------------------
//
// Six host imports back the polyfill:
//
//   __host_shadow_sqlite3_open(path)             -> db_id (i64) | -1
//   __host_shadow_sqlite3_run(id, sql, params)   -> JSON {lastID,changes} | "__HOST_ERR__:..."
//   __host_shadow_sqlite3_get(id, sql, params)   -> JSON row | "null" | "__HOST_ERR__:..."
//   __host_shadow_sqlite3_all(id, sql, params)   -> JSON array | "__HOST_ERR__:..."
//   __host_shadow_sqlite3_exec(id, sql)          -> 0 | -1
//   __host_shadow_sqlite3_close(id)              -> 0 | -1
//
// The path/SQL/params arguments cross as memory ptr+len pairs; the
// JSON outputs cross via the `(out_ptr, out_cap)` write_out
// convention shared with the rest of this file.

fn wrap_shadow_sqlite3(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_shadow_sqlite3_open",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>, path_ptr: i32, path_len: i32| -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let Some(path) = read_str(&memory, &caller, path_ptr, path_len) else {
                    return -1;
                };
                #[cfg(feature = "shadow-sqlite3")]
                {
                    let shadow = caller.data().sqlite3_shadow.clone();
                    match shadow.open(&path) {
                        Ok(id) => id,
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            -1
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sqlite3"))]
                {
                    let _ = path;
                    caller.data_mut().last_error = "shadow-sqlite3 feature not enabled".into();
                    -1
                }
            },
        )
        .map_err(link_err)?;

    #[cfg(feature = "shadow-sqlite3")]
    fn write_json_or_err(
        caller: &mut Caller<'_, HostState>,
        memory: &Memory,
        out_ptr: i32,
        out_cap: i32,
        json: &serde_json::Value,
    ) -> i32 {
        let s = serde_json::to_string(json).unwrap_or_else(|_| "null".into());
        write_out(caller, memory, out_ptr, out_cap, s.as_bytes())
    }

    #[cfg(feature = "shadow-sqlite3")]
    fn parse_params(s: &str) -> Result<Vec<serde_json::Value>, AfterburnerError> {
        let v: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| AfterburnerError::Host(format!("sqlite3: params JSON parse: {e}")))?;
        match v {
            serde_json::Value::Array(arr) => Ok(arr),
            _ => Err(AfterburnerError::Host(
                "sqlite3: params must be a JSON array".into(),
            )),
        }
    }

    linker
        .func_wrap(
            NS,
            "host_shadow_sqlite3_run",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>,
             id: i64,
             sql_ptr: i32,
             sql_len: i32,
             params_ptr: i32,
             params_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(sql) = read_str(&memory, &caller, sql_ptr, sql_len) else {
                    return E_OTHER;
                };
                let Some(params_raw) = read_str(&memory, &caller, params_ptr, params_len) else {
                    return E_OTHER;
                };
                #[cfg(feature = "shadow-sqlite3")]
                {
                    let params = match parse_params(&params_raw) {
                        Ok(p) => p,
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            return E_OTHER;
                        }
                    };
                    let shadow = caller.data().sqlite3_shadow.clone();
                    match shadow.run(id, &sql, params) {
                        Ok(r) => {
                            let v = serde_json::json!({
                                "lastID": r.last_insert_rowid,
                                "changes": r.changes,
                            });
                            write_json_or_err(&mut caller, &memory, out_ptr, out_cap, &v)
                        }
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sqlite3"))]
                {
                    let _ = (id, sql, params_raw, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-sqlite3 feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_sqlite3_get",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>,
             id: i64,
             sql_ptr: i32,
             sql_len: i32,
             params_ptr: i32,
             params_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(sql) = read_str(&memory, &caller, sql_ptr, sql_len) else {
                    return E_OTHER;
                };
                let Some(params_raw) = read_str(&memory, &caller, params_ptr, params_len) else {
                    return E_OTHER;
                };
                #[cfg(feature = "shadow-sqlite3")]
                {
                    let params = match parse_params(&params_raw) {
                        Ok(p) => p,
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            return E_OTHER;
                        }
                    };
                    let shadow = caller.data().sqlite3_shadow.clone();
                    match shadow.get(id, &sql, params) {
                        Ok(opt) => {
                            let v = opt.unwrap_or(serde_json::Value::Null);
                            write_json_or_err(&mut caller, &memory, out_ptr, out_cap, &v)
                        }
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sqlite3"))]
                {
                    let _ = (id, sql, params_raw, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-sqlite3 feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_sqlite3_all",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>,
             id: i64,
             sql_ptr: i32,
             sql_len: i32,
             params_ptr: i32,
             params_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(sql) = read_str(&memory, &caller, sql_ptr, sql_len) else {
                    return E_OTHER;
                };
                let Some(params_raw) = read_str(&memory, &caller, params_ptr, params_len) else {
                    return E_OTHER;
                };
                #[cfg(feature = "shadow-sqlite3")]
                {
                    let params = match parse_params(&params_raw) {
                        Ok(p) => p,
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            return E_OTHER;
                        }
                    };
                    let shadow = caller.data().sqlite3_shadow.clone();
                    match shadow.all(id, &sql, params) {
                        Ok(rows) => {
                            let v = serde_json::Value::Array(rows);
                            write_json_or_err(&mut caller, &memory, out_ptr, out_cap, &v)
                        }
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sqlite3"))]
                {
                    let _ = (id, sql, params_raw, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-sqlite3 feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_sqlite3_exec",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>, id: i64, sql_ptr: i32, sql_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(sql) = read_str(&memory, &caller, sql_ptr, sql_len) else {
                    return E_OTHER;
                };
                #[cfg(feature = "shadow-sqlite3")]
                {
                    let shadow = caller.data().sqlite3_shadow.clone();
                    match shadow.exec(id, &sql) {
                        Ok(()) => 0,
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sqlite3"))]
                {
                    let _ = (id, sql);
                    caller.data_mut().last_error = "shadow-sqlite3 feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_sqlite3_close",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>, id: i64| -> i32 {
                #[cfg(feature = "shadow-sqlite3")]
                {
                    let shadow = caller.data().sqlite3_shadow.clone();
                    match shadow.close(id) {
                        Ok(()) => 0,
                        Err(e) => {
                            caller.data_mut().last_error = e.to_string();
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sqlite3"))]
                {
                    let _ = id;
                    caller.data_mut().last_error = "shadow-sqlite3 feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- shadow: sharp (L3) -------------------------------------------------
//
// Two stateless host imports back the polyfill:
//
//   __host_shadow_sharp_run(pipeline_json)  -> bytes (base64 string) | __HOST_ERR__:...
//   __host_shadow_sharp_metadata(source_json) -> JSON | __HOST_ERR__:...
//
// `run` returns the encoded image bytes as a base64 string so it
// fits the shared `call_read` String-output convention. The polyfill
// converts back to Buffer before handing it to the user.

fn wrap_shadow_sharp(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    linker
        .func_wrap(
            NS,
            "host_shadow_sharp_run",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>,
             json_ptr: i32,
             json_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(json) = read_str(&memory, &caller, json_ptr, json_len) else {
                    return E_OTHER;
                };
                #[cfg(feature = "shadow-sharp")]
                {
                    use base64::Engine as _;
                    match afterburner_node_compat::shadows::sharp::run(&json) {
                        Ok(bytes) => {
                            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                            write_out(&mut caller, &memory, out_ptr, out_cap, b64.as_bytes())
                        }
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sharp"))]
                {
                    let _ = (json, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-sharp feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_sharp_metadata",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>,
             json_ptr: i32,
             json_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(json) = read_str(&memory, &caller, json_ptr, json_len) else {
                    return E_OTHER;
                };
                #[cfg(feature = "shadow-sharp")]
                {
                    match afterburner_node_compat::shadows::sharp::metadata(&json) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sharp"))]
                {
                    let _ = (json, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-sharp feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_shadow_sharp_stats",
            #[allow(unused_variables)]
            |mut caller: Caller<'_, HostState>,
             json_ptr: i32,
             json_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(json) = read_str(&memory, &caller, json_ptr, json_len) else {
                    return E_OTHER;
                };
                #[cfg(feature = "shadow-sharp")]
                {
                    match afterburner_node_compat::shadows::sharp::stats(&json) {
                        Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                        Err(e) => {
                            caller.data_mut().last_error = e;
                            E_OTHER
                        }
                    }
                }
                #[cfg(not(feature = "shadow-sharp"))]
                {
                    let _ = (json, out_ptr, out_cap);
                    caller.data_mut().last_error = "shadow-sharp feature not enabled".into();
                    E_OTHER
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- WebAssembly loader (Node 20 `globalThis.WebAssembly`) ---------------
//
// Nine host imports back the polyfill:
//
//   __host_wasm_compile(bytes_b64)             -> module_id (i64) | -1
//   __host_wasm_module_exports(module_id)      -> JSON | __HOST_ERR__:
//   __host_wasm_module_imports(module_id)      -> JSON | __HOST_ERR__:
//   __host_wasm_instantiate(module_id)         -> instance_id (i64) | -1
//   __host_wasm_call_export(id, name, args)    -> JSON result | __HOST_ERR__:
//   __host_wasm_memory_read(id, off, len)      -> bytes_b64 | __HOST_ERR__:
//   __host_wasm_memory_write(id, off, b64)     -> 0 | -1
//   __host_wasm_memory_size(id)                -> i64 size | -1
//   __host_wasm_drop_module(id)                -> 0
//   __host_wasm_drop_instance(id)              -> 0

fn wrap_wasm_loader(linker: &mut Linker<HostState>) -> Result<(), AfterburnerError> {
    use crate::wasm_loader::WasmValue;
    use base64::Engine as _;

    linker
        .func_wrap(
            NS,
            "host_wasm_compile",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let Some(b64) = read_str(&memory, &caller, ptr, len) else {
                    return -1;
                };
                let bytes = match base64::engine::general_purpose::STANDARD.decode(&b64) {
                    Ok(b) => b,
                    Err(e) => {
                        record(&mut caller, &format!("wasm.compile base64: {e}"));
                        return -1;
                    }
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.compile(&bytes) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_drop_module",
            |caller: Caller<'_, HostState>, id: i64| -> i32 {
                caller.data().wasm_loader.drop_module(id as u64);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_module_exports",
            |mut caller: Caller<'_, HostState>, id: i64, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.module_exports(id as u64) {
                    Ok(list) => {
                        let v: Vec<serde_json::Value> = list
                            .into_iter()
                            .map(|e| {
                                serde_json::json!({
                                    "name": e.name,
                                    "kind": e.kind,
                                    "param_count": e.param_count,
                                    "result_count": e.result_count,
                                })
                            })
                            .collect();
                        let s = serde_json::to_string(&v).unwrap_or_else(|_| "[]".into());
                        write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
                    }
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_module_imports",
            |mut caller: Caller<'_, HostState>, id: i64, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.module_imports(id as u64) {
                    Ok(list) => {
                        let v: Vec<serde_json::Value> = list
                            .into_iter()
                            .map(|e| {
                                serde_json::json!({
                                    "module": e.module,
                                    "name": e.name,
                                    "kind": e.kind,
                                })
                            })
                            .collect();
                        let s = serde_json::to_string(&v).unwrap_or_else(|_| "[]".into());
                        write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
                    }
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_instantiate",
            |mut caller: Caller<'_, HostState>, module_id: i64| -> i64 {
                let loader = caller.data().wasm_loader.clone();
                match loader.instantiate(module_id as u64) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_drop_instance",
            |caller: Caller<'_, HostState>, id: i64| -> i32 {
                caller.data().wasm_loader.drop_instance(id as u64);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_call_export",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             name_ptr: i32,
             name_len: i32,
             args_ptr: i32,
             args_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(name) = read_str(&memory, &caller, name_ptr, name_len) else {
                    return E_OTHER;
                };
                let Some(args_json) = read_str(&memory, &caller, args_ptr, args_len) else {
                    return E_OTHER;
                };
                let args: Vec<WasmValue> =
                    match serde_json::from_str::<serde_json::Value>(&args_json) {
                        Ok(serde_json::Value::Array(arr)) => {
                            let parsed: std::result::Result<Vec<WasmValue>, _> =
                                arr.iter().map(WasmValue::from_json).collect();
                            match parsed {
                                Ok(v) => v,
                                Err(e) => {
                                    caller.data_mut().last_error = e.to_string();
                                    return E_OTHER;
                                }
                            }
                        }
                        _ => {
                            record(&mut caller, "wasm.call: args must be a JSON array");
                            return E_OTHER;
                        }
                    };
                let loader = caller.data().wasm_loader.clone();
                match loader.call_export(instance_id as u64, &name, args) {
                    Ok(results) => {
                        let v: Vec<serde_json::Value> =
                            results.iter().map(WasmValue::to_json).collect();
                        let s = serde_json::to_string(&v).unwrap_or_else(|_| "[]".into());
                        write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
                    }
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_memory_read",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             offset: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_read(instance_id as u64, offset as u32, len as u32) {
                    Ok(bytes) => {
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, b64.as_bytes())
                    }
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_memory_write",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             offset: i32,
             b64_ptr: i32,
             b64_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(b64) = read_str(&memory, &caller, b64_ptr, b64_len) else {
                    return E_OTHER;
                };
                let bytes = match base64::engine::general_purpose::STANDARD.decode(&b64) {
                    Ok(b) => b,
                    Err(e) => {
                        record(&mut caller, &format!("wasm.memory.write base64: {e}"));
                        return E_OTHER;
                    }
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_write(instance_id as u64, offset as u32, &bytes) {
                    Ok(()) => 0,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_memory_size",
            |mut caller: Caller<'_, HostState>, instance_id: i64| -> i64 {
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_size(instance_id as u64) {
                    Ok(n) => n as i64,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_memory_grow",
            |mut caller: Caller<'_, HostState>, instance_id: i64, delta_pages: i32| -> i64 {
                if delta_pages < 0 {
                    return -1;
                }
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_grow(instance_id as u64, delta_pages as u32) {
                    Ok(prev) => prev,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_global_get",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             name_ptr: i32,
             name_len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(name) = read_str(&memory, &caller, name_ptr, name_len) else {
                    return E_OTHER;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.global_get(instance_id as u64, &name) {
                    Ok(v) => {
                        let json = match v {
                            crate::wasm_loader::WasmValue::I32(n) => {
                                serde_json::json!({"type": "i32", "value": n})
                            }
                            crate::wasm_loader::WasmValue::I64(n) => {
                                serde_json::json!({"type": "i64", "value": n.to_string()})
                            }
                            crate::wasm_loader::WasmValue::F32(f) => {
                                serde_json::json!({"type": "f32", "value": f})
                            }
                            crate::wasm_loader::WasmValue::F64(f) => {
                                serde_json::json!({"type": "f64", "value": f})
                            }
                        };
                        let s = json.to_string();
                        write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes())
                    }
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_global_set",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             name_ptr: i32,
             name_len: i32,
             value_ptr: i32,
             value_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(name) = read_str(&memory, &caller, name_ptr, name_len) else {
                    return E_OTHER;
                };
                let Some(value_json) = read_str(&memory, &caller, value_ptr, value_len) else {
                    return E_OTHER;
                };
                let parsed: serde_json::Value = match serde_json::from_str(&value_json) {
                    Ok(v) => v,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        return E_OTHER;
                    }
                };
                let value = match parsed.get("type").and_then(|t| t.as_str()) {
                    Some("i32") => crate::wasm_loader::WasmValue::I32(
                        parsed.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                    ),
                    Some("i64") => {
                        let s = parsed.get("value").and_then(|v| v.as_str()).unwrap_or("0");
                        crate::wasm_loader::WasmValue::I64(s.parse::<i64>().unwrap_or(0))
                    }
                    Some("f32") => crate::wasm_loader::WasmValue::F32(
                        parsed.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
                    ),
                    Some("f64") => crate::wasm_loader::WasmValue::F64(
                        parsed.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    ),
                    _ => {
                        caller.data_mut().last_error =
                            "WebAssembly.Global.set: unknown type".into();
                        return E_OTHER;
                    }
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.global_set(instance_id as u64, &name, value) {
                    Ok(()) => 0,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_table_size",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             name_ptr: i32,
             name_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(name) = read_str(&memory, &caller, name_ptr, name_len) else {
                    return E_OTHER;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.table_size(instance_id as u64, &name) {
                    Ok(n) => n as i32,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_table_get",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             name_ptr: i32,
             name_len: i32,
             index: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(name) = read_str(&memory, &caller, name_ptr, name_len) else {
                    return E_OTHER;
                };
                if index < 0 {
                    return E_OTHER;
                }
                let loader = caller.data().wasm_loader.clone();
                match loader.table_get(instance_id as u64, &name, index as u32) {
                    Ok(s) => write_out(&mut caller, &memory, out_ptr, out_cap, s.as_bytes()),
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_table_grow",
            |mut caller: Caller<'_, HostState>,
             instance_id: i64,
             name_ptr: i32,
             name_len: i32,
             delta: i32|
             -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let Some(name) = read_str(&memory, &caller, name_ptr, name_len) else {
                    return -1;
                };
                if delta < 0 {
                    return -1;
                }
                let loader = caller.data().wasm_loader.clone();
                match loader.table_grow(instance_id as u64, &name, delta as u32) {
                    Ok(prev) => prev,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;

    // ---- Standalone Memory / Table / Global ---------------------
    //
    // `new WebAssembly.Memory(descriptor)` etc. create resources
    // outside an Instance. Each resource lives in its own Store on
    // the host side (the WasmLoader's StandaloneRegistry). The
    // JS-side polyfill calls these to bridge.
    linker
        .func_wrap(
            NS,
            "host_wasm_mem_new",
            |mut caller: Caller<'_, HostState>, initial: i32, maximum: i32| -> i64 {
                if initial < 0 {
                    return -1;
                }
                let max = if maximum < 0 {
                    None
                } else {
                    Some(maximum as u32)
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_standalone_create(initial as u32, max) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_mem_size",
            |caller: Caller<'_, HostState>, id: i64| -> i64 {
                let loader = caller.data().wasm_loader.clone();
                loader
                    .memory_standalone_size(id as u64)
                    .map(|n| n as i64)
                    .unwrap_or(-1)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_mem_grow",
            |mut caller: Caller<'_, HostState>, id: i64, delta: i32| -> i64 {
                if delta < 0 {
                    return -1;
                }
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_standalone_grow(id as u64, delta as u32) {
                    Ok(prev) => prev,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_mem_read",
            |mut caller: Caller<'_, HostState>,
             id: i64,
             offset: i32,
             len: i32,
             out_ptr: i32,
             out_cap: i32|
             -> i32 {
                if offset < 0 || len < 0 {
                    return E_OTHER;
                }
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_standalone_read(id as u64, offset as u32, len as u32) {
                    Ok(bytes) => {
                        // Match the existing instance-memory wire
                        // format: base64-encode the bytes so the JS
                        // side can `Buffer.from(s, 'base64')` to
                        // recover them.
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                        write_out(&mut caller, &memory, out_ptr, out_cap, b64.as_bytes())
                    }
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_mem_write",
            |mut caller: Caller<'_, HostState>,
             id: i64,
             offset: i32,
             bytes_b64_ptr: i32,
             bytes_b64_len: i32|
             -> i32 {
                if offset < 0 {
                    return E_OTHER;
                }
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(b64) = read_str(&memory, &caller, bytes_b64_ptr, bytes_b64_len) else {
                    return E_OTHER;
                };
                let bytes = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                    Ok(b) => b,
                    Err(e) => {
                        caller.data_mut().last_error = format!("mem_write base64: {e}");
                        return E_OTHER;
                    }
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.memory_standalone_write(id as u64, offset as u32, &bytes) {
                    Ok(()) => 0,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_mem_drop",
            |caller: Caller<'_, HostState>, id: i64| -> i32 {
                let loader = caller.data().wasm_loader.clone();
                loader.memory_standalone_drop(id as u64);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_global_new",
            |mut caller: Caller<'_, HostState>,
             ty_ptr: i32,
             ty_len: i32,
             mutable: i32,
             val_ptr: i32,
             val_len: i32|
             -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let Some(ty) = read_str(&memory, &caller, ty_ptr, ty_len) else {
                    return -1;
                };
                let init_str = read_str(&memory, &caller, val_ptr, val_len).unwrap_or_default();
                let init_val: serde_json::Value =
                    serde_json::from_str(&init_str).unwrap_or(serde_json::json!({}));
                let init = match ty.as_str() {
                    "i32" => crate::wasm_loader::WasmValue::I32(
                        init_val.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                    ),
                    "i64" => crate::wasm_loader::WasmValue::I64(
                        init_val
                            .get("value")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<i64>().ok())
                            .or_else(|| init_val.get("value").and_then(|v| v.as_i64()))
                            .unwrap_or(0),
                    ),
                    "f32" => crate::wasm_loader::WasmValue::F32(
                        init_val
                            .get("value")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0) as f32,
                    ),
                    "f64" => crate::wasm_loader::WasmValue::F64(
                        init_val
                            .get("value")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0),
                    ),
                    _ => {
                        caller.data_mut().last_error = format!("Global.new: unknown type {ty}");
                        return -1;
                    }
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.global_standalone_create(&ty, mutable != 0, init) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_global_get_sa",
            |mut caller: Caller<'_, HostState>, id: i64, out_ptr: i32, out_cap: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.global_standalone_get(id as u64) {
                    Ok(v) => {
                        let json = match v {
                            crate::wasm_loader::WasmValue::I32(n) => {
                                serde_json::json!({"type":"i32","value":n})
                            }
                            crate::wasm_loader::WasmValue::I64(n) => {
                                serde_json::json!({"type":"i64","value":n.to_string()})
                            }
                            crate::wasm_loader::WasmValue::F32(f) => {
                                serde_json::json!({"type":"f32","value":f})
                            }
                            crate::wasm_loader::WasmValue::F64(f) => {
                                serde_json::json!({"type":"f64","value":f})
                            }
                        }
                        .to_string();
                        write_out(&mut caller, &memory, out_ptr, out_cap, json.as_bytes())
                    }
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_global_set_sa",
            |mut caller: Caller<'_, HostState>, id: i64, val_ptr: i32, val_len: i32| -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return E_OTHER;
                };
                let Some(val_str) = read_str(&memory, &caller, val_ptr, val_len) else {
                    return E_OTHER;
                };
                let parsed: serde_json::Value =
                    serde_json::from_str(&val_str).unwrap_or(serde_json::json!({}));
                let val = match parsed.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "i32" => crate::wasm_loader::WasmValue::I32(
                        parsed.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                    ),
                    "i64" => crate::wasm_loader::WasmValue::I64(
                        parsed
                            .get("value")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<i64>().ok())
                            .or_else(|| parsed.get("value").and_then(|v| v.as_i64()))
                            .unwrap_or(0),
                    ),
                    "f32" => crate::wasm_loader::WasmValue::F32(
                        parsed.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
                    ),
                    "f64" => crate::wasm_loader::WasmValue::F64(
                        parsed.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    ),
                    _ => return E_OTHER,
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.global_standalone_set(id as u64, val) {
                    Ok(()) => 0,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        E_OTHER
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_global_drop",
            |caller: Caller<'_, HostState>, id: i64| -> i32 {
                let loader = caller.data().wasm_loader.clone();
                loader.global_standalone_drop(id as u64);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_table_new",
            |mut caller: Caller<'_, HostState>,
             elem_ptr: i32,
             elem_len: i32,
             initial: i32,
             maximum: i32|
             -> i64 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let Some(elem) = read_str(&memory, &caller, elem_ptr, elem_len) else {
                    return -1;
                };
                if initial < 0 {
                    return -1;
                }
                let max = if maximum < 0 {
                    None
                } else {
                    Some(maximum as u32)
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.table_standalone_create(&elem, initial as u32, max) {
                    Ok(id) => id as i64,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_table_size_sa",
            |caller: Caller<'_, HostState>, id: i64| -> i32 {
                let loader = caller.data().wasm_loader.clone();
                loader
                    .table_standalone_size(id as u64)
                    .map(|n| n as i32)
                    .unwrap_or(-1)
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_table_grow_sa",
            |mut caller: Caller<'_, HostState>, id: i64, delta: i32| -> i64 {
                if delta < 0 {
                    return -1;
                }
                let loader = caller.data().wasm_loader.clone();
                match loader.table_standalone_grow(id as u64, delta as u32) {
                    Ok(prev) => prev,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;
    linker
        .func_wrap(
            NS,
            "host_wasm_table_drop",
            |caller: Caller<'_, HostState>, id: i64| -> i32 {
                let loader = caller.data().wasm_loader.clone();
                loader.table_standalone_drop(id as u64);
                0
            },
        )
        .map_err(link_err)?;

    linker
        .func_wrap(
            NS,
            "host_wasm_run_wasi",
            |mut caller: Caller<'_, HostState>,
             module_id: i64,
             cfg_ptr: i32,
             cfg_len: i32|
             -> i32 {
                let Some(memory) = guest_memory(&mut caller) else {
                    return -1;
                };
                let Some(cfg) = read_str(&memory, &caller, cfg_ptr, cfg_len) else {
                    return -1;
                };
                let loader = caller.data().wasm_loader.clone();
                match loader.run_wasi(module_id as u64, &cfg) {
                    Ok(code) => code,
                    Err(e) => {
                        caller.data_mut().last_error = e.to_string();
                        -1
                    }
                }
            },
        )
        .map_err(link_err)?;

    Ok(())
}

// ---- helpers -------------------------------------------------------------

fn guest_memory(caller: &mut Caller<'_, HostState>) -> Option<Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
}

fn read_str(memory: &Memory, caller: &Caller<'_, HostState>, ptr: i32, len: i32) -> Option<String> {
    let data = memory.data(caller);
    let slice = data.get((ptr as usize)..((ptr + len) as usize))?;
    std::str::from_utf8(slice).ok().map(String::from)
}

/// Borrow a `(ptr, len)` region of guest memory without copying.
/// Treats `ptr` / `len` as unsigned (wasm32 addresses) and bounds-checks
/// with overflow-safe arithmetic — large payloads high in linear memory
/// must not wrap the range computation.
fn guest_slice<'a>(
    memory: &Memory,
    caller: &'a Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Option<&'a [u8]> {
    let start = ptr as u32 as usize;
    let end = start.checked_add(len as u32 as usize)?;
    memory.data(caller).get(start..end)
}

fn read_bytes(
    memory: &Memory,
    caller: &Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Option<Vec<u8>> {
    let data = memory.data(caller);
    data.get((ptr as usize)..((ptr + len) as usize))
        .map(|s| s.to_vec())
}

fn write_out(
    caller: &mut Caller<'_, HostState>,
    memory: &Memory,
    out_ptr: i32,
    out_cap: i32,
    data: &[u8],
) -> i32 {
    if data.len() > out_cap as usize {
        record(caller, &format!("output {} > cap {}", data.len(), out_cap));
        return E_BUF_TOO_SMALL;
    }
    let start = out_ptr as usize;
    let end = start + data.len();
    let mem = memory.data_mut(caller);
    match mem.get_mut(start..end) {
        Some(slot) => {
            slot.copy_from_slice(data);
            data.len() as i32
        }
        None => {
            // Can't write last_error here — we already hold a &mut into
            // linear memory; borrow checker would reject touching
            // caller.data_mut(). The raw code at least makes the
            // failure deterministic (E_OTHER with no message).
            E_OTHER
        }
    }
}

fn map_err(caller: &mut Caller<'_, HostState>, err: AfterburnerError) -> i32 {
    let code = match &err {
        AfterburnerError::PermissionDenied(_) => E_PERMISSION,
        AfterburnerError::Host(msg) if msg.to_lowercase().contains("not found") => E_NOT_FOUND,
        _ => E_OTHER,
    };
    record(caller, &err.to_string());
    code
}

fn record(caller: &mut Caller<'_, HostState>, msg: &str) {
    caller.data_mut().last_error = msg.to_string();
}

// wasmtime 44 returns its own `wasmtime::Error` from `Linker::func_wrap`
// (a thin wrapper around anyhow's std-error machinery). Using
// `impl Display` here keeps the helper callable from any Display-able
// error type, so the same `.map_err(link_err)` works whether the
// source is wasmtime::Error, anyhow::Error, or std::io::Error.
fn link_err<E: std::fmt::Display>(e: E) -> AfterburnerError {
    AfterburnerError::Engine(format!("linker.func_wrap: {e}"))
}

/// JSON string literal escaping — used for embedding HTTP response
/// bodies inside a JSON result returned to the guest.
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
