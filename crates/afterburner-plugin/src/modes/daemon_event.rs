// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Daemon-event mode: re-enter the long-lived Store with one event.
//!
//! Envelope `{mode: "daemon-event", event: {kind, ...}}`. We compile
//! a tiny dispatch wrapper that reads the full envelope via
//! `__AB_GET_ENVELOPE__()`, parses it, looks up the JS-side handler
//! registered by `daemon-init` code, and invokes it. The response
//! (if any) travels back through host imports (`__host_http_reply`)
//! and this function's own return value is discarded.
//!
//! Top-level `await` resolves through Javy's event loop drain so
//! handlers can be `async` without special wrapping.
//!
//! **Bytecode is compiled once.** The dispatch wrapper is a
//! constant string; recompiling it per event leaks residual parser
//! state into the long-lived Store (interned atoms, source-pos
//! tables, etc.) and exhausts WASM linear memory after a few tens
//! of thousands of requests. We compile lazily on the first event,
//! cache the bytecode in a `OnceCell`, and reuse it forever after.
//! QuickJS bytecode is `Vec<u8>` - owning it across calls doesn't
//! hold any Store references.

use alloc::format;
use alloc::vec::Vec;
use core::cell::OnceCell;

use crate::stdio::write_stderr;

// `OnceCell` is `!Sync`, but the daemon-event path is single-threaded
// inside the WASM Store: Javy's plugin invocation model is one event
// at a time. The host coordinator serialises events through a single
// `daemon_step` call. We use a `static mut` accessed under the same
// safety condition Javy itself relies on (no concurrent re-entry into
// a plugin Store).
static mut DISPATCH_BYTECODE: OnceCell<Vec<u8>> = OnceCell::new();

#[allow(static_mut_refs)]
fn dispatch_bytecode() -> Result<&'static [u8], &'static str> {
    // Safety: see module comment - daemon-event invocations are
    // serialised by the host. We never read while another writer
    // could be running.
    let cell = unsafe { &*core::ptr::addr_of!(DISPATCH_BYTECODE) };
    if let Some(bc) = cell.get() {
        return Ok(bc.as_slice());
    }
    let bc = javy_plugin_api::compile_src(DISPATCH_SOURCE.as_bytes())
        .map_err(|_| "compile_src failed for dispatch wrapper")?;
    unsafe {
        let cell_mut = &mut *core::ptr::addr_of_mut!(DISPATCH_BYTECODE);
        // OK to ignore Err here: a concurrent set is impossible per
        // the serialisation invariant; if it ever happened, the
        // first-set wins and we'd return that.
        let _ = cell_mut.set(bc);
        Ok(cell_mut.get().expect("just set").as_slice())
    }
}

/// JS-side dispatch wrapper. Keeps the Rust dispatcher lean - the JS
/// already has the handler table on globalThis; we just decode the
/// envelope and delegate. The wrapper is compiled fresh on each
/// daemon-event because it's trivial and cache-invalidation across
/// Store state would be error-prone.
const DISPATCH_SOURCE: &str = r#"
(async function() {
    const env = JSON.parse(__AB_GET_ENVELOPE__());
    const ev = env.event || {};
    const kind = ev.kind || '';
    if (kind === 'http-request') {
        const table = globalThis.__ab_http_handlers || {};
        const cb = table[ev.server_id];
        if (!cb) {
            // Handler-missing path: reply with a 500 so axum doesn't
            // hang. `__host_http_reply` is a no-op if the req_id has
            // already been answered.
            if (typeof globalThis.__host_http_reply === 'function') {
                globalThis.__host_http_reply(
                    Number(ev.req_id),
                    JSON.stringify({status: 500, headers: {}, body: 'no handler for server_id ' + ev.server_id})
                );
            }
            return;
        }
        const ReqRes = globalThis.__ab_build_reqres;
        if (typeof ReqRes !== 'function') {
            throw new Error('daemon-event: __ab_build_reqres not installed');
        }
        const { req, res } = ReqRes(ev);
        try {
            await cb(req, res);
        } catch (e) {
            if (!res.writableEnded) {
                res.statusCode = 500;
                res.end(String((e && e.stack) || e));
            }
        }
    } else if (kind === 'timer-fire') {
        // host-managed timer expired. Look up the callback the JS
        // side registered in `__ab_timer_handlers[timer_id]`.
        const table = globalThis.__ab_timer_handlers || {};
        const cb = table[ev.timer_id];
        if (typeof cb === 'function') {
            try {
                await cb();
            } catch (e) {
                try { console.error('timer callback error:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'worker-online') {
        // a child worker finished its handshake.
        const table = globalThis.__ab_worker_handlers || {};
        const w = table[ev.worker_id];
        if (w && typeof w._dispatchOnline === 'function') {
            try { w._dispatchOnline(); } catch (e) {
                try { console.error('worker online dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'worker-message') {
        const table = globalThis.__ab_worker_handlers || {};
        const w = table[ev.worker_id];
        if (w && typeof w._dispatchMessage === 'function') {
            try { w._dispatchMessage(ev.payload || ''); } catch (e) {
                try { console.error('worker message dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'worker-error') {
        const table = globalThis.__ab_worker_handlers || {};
        const w = table[ev.worker_id];
        if (w && typeof w._dispatchError === 'function') {
            try { w._dispatchError(ev.message || '', ev.stack || ''); } catch (e) {
                try { console.error('worker error dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'worker-exit') {
        const table = globalThis.__ab_worker_handlers || {};
        const w = table[ev.worker_id];
        if (w && typeof w._dispatchExit === 'function') {
            try { w._dispatchExit(ev.code | 0); } catch (e) {
                try { console.error('worker exit dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'worker-parent-message') {
        // parent sent us a frame.
        const port = globalThis.__ab_worker_parent_port_handlers;
        if (port && typeof port._dispatchMessage === 'function') {
            try { port._dispatchMessage(ev.payload || ''); } catch (e) {
                try { console.error('parentPort message dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'worker-terminate-requested') {
        // parent has called worker.terminate().
        const port = globalThis.__ab_worker_parent_port_handlers;
        if (port && typeof port._dispatchTerminate === 'function') {
            try { port._dispatchTerminate(); } catch (_) {}
        }
        // The CLI's child event loop also sees this on the Rust side
        // and exits gracefully; the JS-side dispatch is best-effort
        // for user-facing 'close' listeners.
    } else if (kind === 'inspector-cmd') {
        // CDP frame from a connected WebSocket session.
        // Format: { kind, session_id, id, method, params }
        const dispatch = globalThis.__ab_inspector_dispatch;
        if (typeof dispatch === 'function') {
            try {
                dispatch(ev.session_id | 0, ev.id | 0, ev.method || '', ev.params || {});
            } catch (e) {
                try { console.error('inspector dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'net-connect') {
        // outbound TCP connect succeeded.
        const table = globalThis.__ab_net_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchConnect === 'function') {
            try { sock._dispatchConnect(ev.local || null, ev.remote || null); }
            catch (e) { try { console.error('net connect dispatch:', (e && e.stack) || e); } catch (_) {} }
        }
    } else if (kind === 'net-data') {
        const table = globalThis.__ab_net_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchData === 'function') {
            try { sock._dispatchData(ev.payload_b64 || ''); }
            catch (e) { try { console.error('net data dispatch:', (e && e.stack) || e); } catch (_) {} }
        }
    } else if (kind === 'net-end') {
        const table = globalThis.__ab_net_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchEnd === 'function') {
            try { sock._dispatchEnd(); } catch (_) {}
        }
    } else if (kind === 'net-drain') {
        const table = globalThis.__ab_net_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchDrain === 'function') {
            try { sock._dispatchDrain(); } catch (_) {}
        }
    } else if (kind === 'net-error') {
        const table = globalThis.__ab_net_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchError === 'function') {
            try { sock._dispatchError(ev.message || '', ev.code || ''); } catch (_) {}
        }
    } else if (kind === 'net-close') {
        const table = globalThis.__ab_net_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchClose === 'function') {
            try { sock._dispatchClose(!!ev.had_error); } catch (_) {}
        }
    } else if (kind === 'net-listening') {
        const table = globalThis.__ab_net_server_handlers || {};
        const srv = table[ev.server_id];
        if (srv && typeof srv._dispatchListening === 'function') {
            try { srv._dispatchListening(ev.port | 0); } catch (_) {}
        }
    } else if (kind === 'net-connection') {
        const table = globalThis.__ab_net_server_handlers || {};
        const srv = table[ev.server_id];
        if (srv && typeof srv._dispatchConnection === 'function') {
            try { srv._dispatchConnection(ev.conn_id | 0, ev.local || null, ev.remote || null); }
            catch (e) { try { console.error('net connection dispatch:', (e && e.stack) || e); } catch (_) {} }
        }
    } else if (kind === 'net-server-error') {
        const table = globalThis.__ab_net_server_handlers || {};
        const srv = table[ev.server_id];
        if (srv && typeof srv._dispatchServerError === 'function') {
            try { srv._dispatchServerError(ev.message || ''); } catch (_) {}
        }
    } else if (kind === 'tls-connect') {
        // outbound TLS handshake completed.
        const table = globalThis.__ab_tls_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchSecureConnect === 'function') {
            try {
                sock._dispatchSecureConnect(
                    ev.local || null,
                    ev.remote || null,
                    ev.alpn_protocol || null,
                    ev.protocol || null,
                    !!ev.authorized,
                    ev.cipher || null,
                    ev.peer_cert_chain_der_b64 || []
                );
            } catch (e) {
                try { console.error('tls connect dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'tls-data') {
        const table = globalThis.__ab_tls_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchData === 'function') {
            try { sock._dispatchData(ev.payload_b64 || ''); }
            catch (e) { try { console.error('tls data dispatch:', (e && e.stack) || e); } catch (_) {} }
        }
    } else if (kind === 'tls-end') {
        const table = globalThis.__ab_tls_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchEnd === 'function') {
            try { sock._dispatchEnd(); } catch (_) {}
        }
    } else if (kind === 'tls-drain') {
        const table = globalThis.__ab_tls_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchDrain === 'function') {
            try { sock._dispatchDrain(); } catch (_) {}
        }
    } else if (kind === 'tls-error') {
        const table = globalThis.__ab_tls_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchError === 'function') {
            try { sock._dispatchError(ev.message || '', ev.code || ''); } catch (_) {}
        }
    } else if (kind === 'tls-close') {
        const table = globalThis.__ab_tls_handlers || {};
        const sock = table[ev.conn_id];
        if (sock && typeof sock._dispatchClose === 'function') {
            try { sock._dispatchClose(!!ev.had_error); } catch (_) {}
        }
    } else if (kind === 'tls-listening') {
        const table = globalThis.__ab_tls_server_handlers || {};
        const srv = table[ev.server_id];
        if (srv && typeof srv._dispatchListening === 'function') {
            try { srv._dispatchListening(ev.port | 0); } catch (_) {}
        }
    } else if (kind === 'tls-connection') {
        const table = globalThis.__ab_tls_server_handlers || {};
        const srv = table[ev.server_id];
        if (srv && typeof srv._dispatchConnection === 'function') {
            try {
                srv._dispatchConnection(
                    ev.conn_id | 0,
                    ev.local || null,
                    ev.remote || null,
                    ev.alpn_protocol || null,
                    ev.protocol || null,
                    ev.cipher || null,
                    ev.peer_cert_chain_der_b64 || []
                );
            } catch (e) {
                try { console.error('tls connection dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'tls-server-error') {
        const table = globalThis.__ab_tls_server_handlers || {};
        const srv = table[ev.server_id];
        if (srv && typeof srv._dispatchServerError === 'function') {
            try { srv._dispatchServerError(ev.message || ''); } catch (_) {}
        }
    } else if (kind === 'dgram-listening') {
        // No-op on the dispatcher side - the polyfill emits 'listening'
        // synchronously when bind succeeds. The host envelope is
        // informational; we keep it on the wire so future code that
        // needs to react to the event has a path.
    } else if (kind === 'dgram-message') {
        const table = globalThis.__ab_dgram_handlers || {};
        const sock = table[ev.socketId];
        if (sock && typeof sock._dispatchMessage === 'function') {
            try {
                const from = ev.from || {};
                sock._dispatchMessage(ev.payload || '', from.address || '', from.port | 0);
            } catch (e) {
                try { console.error('dgram message dispatch:', (e && e.stack) || e); } catch (_) {}
            }
        }
    } else if (kind === 'dgram-error') {
        const table = globalThis.__ab_dgram_handlers || {};
        const sock = table[ev.socketId];
        if (sock && typeof sock._dispatchError === 'function') {
            try { sock._dispatchError(ev.message || ''); } catch (_) {}
        }
    } else if (kind === 'dgram-close') {
        // Polyfill-side close already emitted the JS event; no-op here.
    } else if (kind === 'http-response') {
        // Outbound HTTP request completed. Look up the matching
        // pending Promise resolver in `globalThis.__ab_http_pending`
        // and feed it the response. The resolver is set up by
        // `polyfills/http.js::requestImpl` when it dispatched the
        // request via `__host_http_request_async`.
        const table = globalThis.__ab_http_pending || {};
        const slot = table[ev.req_id];
        if (slot && typeof slot.resolve === 'function') {
            try {
                slot.resolve({
                    status: ev.status | 0,
                    headers: ev.headers || {},
                    body: ev.body || '',
                    body_b64: ev.body_b64 || '',
                    error: ev.error || '',
                });
            } catch (e) {
                try { console.error('http-response dispatch:', (e && e.stack) || e); } catch (_) {}
            }
            delete table[ev.req_id];
        }
        // Unknown req_id (resolver missing) is silently dropped - the
        // Rust side may have hit a race between the response queue
        // and a JS-side abort that already cleared the slot.
    } else if (kind === 'lifecycle') {
        // Node process shutdown lifecycle, driven by the host when the
        // event loop drains (see daemon_shard_pool::emit_lifecycle).
        // npm - and many CLIs - buffer ALL their output and flush it
        // from a `process.on('exit')` handler, so without this they
        // print nothing and never finalize. 'exit' fires exactly once
        // (guarded so an explicit `process.exit()` can't double-fire
        // it); 'beforeExit' may re-arm the loop and fire again.
        const p = globalThis.process;
        if (p && typeof p.emit === 'function') {
            const name = ev.event_name || '';
            if (name === 'exit') {
                if (!p.__burnExited) {
                    p.__burnExited = true;
                    try { p.emit('exit', ev.code | 0); }
                    catch (e) { try { console.error('exit handler error:', (e && e.stack) || e); } catch (_) {} }
                }
            } else {
                try { p.emit(name, ev.code | 0); }
                catch (e) { try { console.error(name + ' handler error:', (e && e.stack) || e); } catch (_) {} }
            }
        }
    } else {
        // Unknown event kind - surface on stderr for diagnosis.
        try { console.error('daemon-event: unknown kind=' + kind); } catch (_) {}
    }
})();
"#;

pub fn run(_envelope: &serde_json::Value) {
    // Note: we ignore the Rust-side envelope we already parsed -
    // the JS dispatcher re-parses the envelope via __AB_GET_ENVELOPE__()
    // which gives it the authoritative bytes. That keeps the host→JS
    // boundary on exactly one serialization path.
    let bytecode = match dispatch_bytecode() {
        Ok(bc) => bc,
        Err(e) => {
            let msg = format!("compile_src (daemon-event dispatch): {e}\n");
            write_stderr(msg.as_bytes());
            core::arch::wasm32::unreachable()
        }
    };
    if let Err(e) = javy_plugin_api::invoke(bytecode, None) {
        let msg = format!("invoke (daemon-event): {e}\n");
        write_stderr(msg.as_bytes());
        core::arch::wasm32::unreachable()
    }
}
