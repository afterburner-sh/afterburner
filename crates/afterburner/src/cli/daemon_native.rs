// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `burn run` daemon driver for a daemon-shaped native (Rust / Go / C /
//! C++) WASI guest. Counterpart to [`super::daemon`] (the JS path) for
//! the ABI in `docs/wasi-daemon-abi.md`.
//!
//! Much smaller than the JS path on purpose: there is no shard pool (a
//! native daemon runs single-instance - see the design doc's "Scope"
//! section), no bytecode compile, no worker/net/TLS wiring. What it does
//! reuse, unchanged: [`DaemonHttp`] for the listener bind + axum request
//! loop + pending-reply channel, and the same SIGINT/SIGTERM shutdown
//! pattern [`super::daemon::execute`] uses for JS.

use anyhow::{Context, Result};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use afterburner_wasi::daemon_envelopes::{
    http_event_to_envelope, parse_native_dispatch_response, parse_native_init_response,
};
use afterburner_wasi::daemon_http::{DaemonHttp, ReplyEnvelope};
use afterburner_wasi::daemon_runtime_native::NativeDaemonRuntime;
use afterburner_wasi::embedder_vm::WasiCommandOpts;

/// Run `wasm_bytes` as a native daemon. `opts` is the same
/// `WasiCommandOpts` the caller would otherwise pass to
/// `EmbedderVm::run_command` for a one-shot run of this module (its
/// `args[0]` is used as the program label in diagnostics) - a daemon
/// guest gets exactly the capability grants a one-shot run of the same
/// binary would, nothing more. Callers must have already confirmed the
/// module is daemon-shaped (`NativeDaemonShape::Daemon`); this function
/// does not fall back to a one-shot run.
///
/// Exit code follows the same convention as every other `burn run` path:
/// 0 on a clean shutdown, non-zero on an init failure or a fatal
/// in-daemon trap.
pub fn execute(wasm_bytes: &[u8], opts: WasiCommandOpts) -> Result<()> {
    let label = opts
        .args
        .first()
        .cloned()
        .unwrap_or_else(|| "<native daemon>".to_string());

    let mut runtime = NativeDaemonRuntime::instantiate(wasm_bytes, opts)
        .with_context(|| format!("starting native daemon {label}"))?;

    // No argv/env/cwd in the envelope: unlike the JS plugin, a native
    // guest is a real WASI module and already received those through the
    // normal `args_get` / `environ_get` imports `WasiCommandOpts` wired up
    // before instantiation - repeating them here would be a second,
    // driftable source of the same data. See docs/wasi-daemon-abi.md.
    let init_bytes: &[u8] = br#"{"mode":"daemon-init"}"#;

    let mut stdout_hw = 0usize;
    let mut stderr_hw = 0usize;

    let init_resp = match runtime.call_init(init_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            flush_std(&runtime, &mut stdout_hw, &mut stderr_hw);
            anyhow::bail!("{label}: daemon-init: {e}");
        }
    };
    flush_std(&runtime, &mut stdout_hw, &mut stderr_hw);

    let listen = parse_native_init_response(&init_resp)
        .map_err(|e| anyhow::anyhow!("{label}: daemon-init: {e}"))?;

    if listen.is_empty() {
        // No listen intent, same as a JS script with no `.listen()` call:
        // a plain one-shot. `runtime`'s Store is dropped here, cleanly.
        return Ok(());
    }

    // Tokio runtime + DaemonHttp, exactly the shape `cli::daemon::execute`
    // builds for JS - reused unchanged, not reimplemented.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    let daemon_http = DaemonHttp::with_runtime(rt.handle().clone(), 1024);

    let mut bound_ports = Vec::with_capacity(listen.len());
    for spec in &listen {
        let id = daemon_http.bind_listener(spec.port);
        if id < 0 {
            anyhow::bail!(
                "{label}: could not bind port {} ({})",
                spec.port,
                bind_error_reason(id)
            );
        }
        bound_ports.push(spec.port);
    }

    if !std::env::var("BURN_QUIET").is_ok_and(|v| v == "1") {
        let ports = bound_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            std::io::stderr(),
            "burn: native daemon {label} listening on port(s) {ports}"
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = Arc::clone(&shutdown);
        rt.spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.store(true, Ordering::Release);
        });
    }
    #[cfg(unix)]
    {
        let shutdown = Arc::clone(&shutdown);
        rt.spawn(async move {
            if let Ok(mut sigterm) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                let _ = sigterm.recv().await;
                shutdown.store(true, Ordering::Release);
            }
        });
    }

    // Single-instance request loop: park on the shared event channel
    // (same `recv_async_event` the multi-shard pool's dispatcher uses to
    // avoid busy-polling), dispatch synchronously into the one native
    // instance, and reply. A `call_dispatch` error is fatal to the
    // instance (see docs/wasi-daemon-abi.md's "A trap mid-request"): reply
    // 500 to the request that triggered it, then stop serving rather than
    // continue against a Store whose invariants are no longer trustworthy.
    let fatal_error = rt.block_on(async {
        loop {
            if shutdown.load(Ordering::Acquire) {
                break None;
            }
            let event = match tokio::time::timeout(
                Duration::from_millis(250),
                daemon_http.recv_async_event(),
            )
            .await
            {
                Ok(Some(event)) => event,
                Ok(None) => break None, // all senders dropped
                Err(_elapsed) => continue,
            };

            let req_id = event.req_id;
            let envelope = http_event_to_envelope(&event);
            let Ok(req_bytes) = serde_json::to_vec(&envelope) else {
                daemon_http.deliver_reply(
                    req_id,
                    ReplyEnvelope {
                        status: 500,
                        headers: Vec::new(),
                        body: b"burn: could not encode request envelope".to_vec(),
                    },
                );
                continue;
            };

            match runtime.call_dispatch(&req_bytes) {
                Ok(resp_bytes) => {
                    let reply = match parse_native_dispatch_response(&resp_bytes) {
                        Ok(reply) => reply,
                        Err(e) => ReplyEnvelope {
                            status: 500,
                            headers: Vec::new(),
                            body: format!("burn: {label}: {e}").into_bytes(),
                        },
                    };
                    daemon_http.deliver_reply(req_id, reply);
                    flush_std(&runtime, &mut stdout_hw, &mut stderr_hw);
                }
                Err(e) => {
                    daemon_http.deliver_reply(
                        req_id,
                        ReplyEnvelope {
                            status: 500,
                            headers: Vec::new(),
                            body: format!("burn: {label}: daemon crashed: {e}").into_bytes(),
                        },
                    );
                    flush_std(&runtime, &mut stdout_hw, &mut stderr_hw);
                    break Some(e);
                }
            }
        }
    });

    drop(daemon_http);
    rt.shutdown_timeout(Duration::from_secs(2));

    if let Some(e) = fatal_error {
        anyhow::bail!("{label}: daemon crashed: {e}");
    }
    Ok(())
}

/// Human-readable reason for a negative `bind_listener` return, mirroring
/// the meaning of the `LISTEN_ERR_*` constants in `daemon_http.rs`.
fn bind_error_reason(code: i32) -> &'static str {
    match code {
        afterburner_wasi::daemon_http::LISTEN_ERR_ADDR_IN_USE => "address already in use",
        afterburner_wasi::daemon_http::LISTEN_ERR_IO => "I/O error binding the socket",
        afterburner_wasi::daemon_http::LISTEN_ERR_PERMISSION => "permission denied by the sandbox",
        afterburner_wasi::daemon_http::LISTEN_ERR_NO_DAEMON => "no daemon runtime attached",
        _ => "unknown error",
    }
}

/// Flush whatever the guest has newly written to stdout/stderr (past the
/// caller's high-water marks) to the real process streams, then advance
/// the marks. `NativeDaemonRuntime`'s capture buffers are cumulative for
/// the life of the daemon, so a flush must copy only the new tail, not
/// the whole buffer every time - see
/// `afterburner_wasi::daemon_shard_pool::flush_streams`'s identical
/// high-water-mark pattern for the JS path.
fn flush_std(runtime: &NativeDaemonRuntime, stdout_hw: &mut usize, stderr_hw: &mut usize) {
    let out = runtime.drain_stdout_from(*stdout_hw);
    if !out.is_empty() {
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(&out);
        let _ = so.flush();
        *stdout_hw += out.len();
    }
    let err = runtime.drain_stderr_from(*stderr_hw);
    if !err.is_empty() {
        let mut se = std::io::stderr().lock();
        let _ = se.write_all(&err);
        let _ = se.flush();
        *stderr_hw += err.len();
    }
}
