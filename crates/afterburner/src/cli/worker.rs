// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn run --internal-worker FOO.js` — worker-child bootstrap.
//!
//! This codepath is the *only* place a `DaemonWorkers::new_child`
//! coordinator is constructed. The CLI flag is hidden from `--help`
//! and set only by the host's worker-spawn path; running with it by
//! hand will hang waiting for an init frame on stdin.
//!
//! Lifecycle:
//!
//! 1. `DaemonWorkers::new_child` blocks reading the init frame
//!    (`{type:"init",thread_id,worker_data}`) off stdin and starts a
//!    background reader thread that pumps subsequent parent → child
//!    frames into the events channel.
//! 2. We instantiate a `DaemonRuntime` (just like parent daemon mode)
//!    and install the child-role coordinator on its Store.
//! 3. `run_init` evaluates the user's worker script. Because workers
//!    are inherently long-lived (they wait for messages), the polyfill
//!    schedules an `online` heartbeat as a microtask post-eval —
//!    the parent's `worker.on('online')` fires from that.
//! 4. We drive the same event loop the parent uses, but drain
//!    `WorkerEvent::ParentMessage` / `TerminateRequested` instead of
//!    HTTP / timer events. Loop exits when:
//!      - `parent_closed_signaled` is true (parent dropped stdin), AND
//!      - there are no other refs (no listeners / ref'd timers).
//! 5. On exit, the parent's waiter thread sees the child's stdout
//!    close and emits `WorkerEvent::Exit` to the parent's event loop.

use anyhow::{Context, Result};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::AfterburnerError;
use crate::ScriptInvocation;
use crate::wasm::{
    DaemonHttp, DaemonNet, DaemonRuntime, DaemonTls, DaemonWorkers, WasmCombustor, WasmConfig,
};
use afterburner_wasi::daemon_dgram::DgramEvent;
use afterburner_wasi::daemon_net::NetEvent;
use afterburner_wasi::daemon_tls::TlsEvent;
use afterburner_wasi::daemon_workers::WorkerEvent;

use super::args::Cli;
use super::manifold::build_manifold;

/// Entry point for `burn run --internal-worker <file>`. The CLI's
/// dispatcher routes here when `cli.internal_worker == true`.
pub fn execute(cli: &Cli, source: &str, script_label: &str, user_args: &[String]) -> Result<()> {
    let manifold = build_manifold(cli);

    // Bootstrap the child-role worker coordinator. This BLOCKS until
    // the parent writes the init frame to our stdin — that's the
    // contract; the parent always writes the frame immediately after
    // spawn, so the wait is bounded.
    let workers = DaemonWorkers::new_child(
        manifold.clone(),
        afterburner_wasi::daemon_workers::WorkerConfig::default(),
    )
    .context("worker child: init handshake")?;

    // tokio runtime for the inherited daemon-mode plumbing (HTTP
    // listeners, timers). Workers don't bind sockets in this minimal
    // subset, but the Wasm engine path expects a runtime to be present.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    let daemon_http = DaemonHttp::with_runtime(rt.handle().clone(), 64);

    let combustor = WasmCombustor::new(WasmConfig {
        state_store: None,
        host_context: None,
        transpile_hook: super::daemon::ts_transpile_hook(),
    })
    .context("wasm combustor (worker)")?;

    let invocation = build_invocation(cli, script_label, user_args);
    let mut daemon = DaemonRuntime::instantiate(
        combustor.engine(),
        combustor.instance_pre(),
        manifold.clone(),
        Some(combustor.state_store().clone()),
        None,
        daemon_http,
        combustor.transpile_hook(),
    )
    .context("daemon instantiate (worker)")?;
    daemon.install_workers(Arc::clone(&workers));

    // workers can use net too. Inherits the (already-narrowed)
    // manifold from the parent's CLI flags — capability inheritance
    // is enforced one level up at spawn-time, not here.
    let net = DaemonNet::new(rt.handle().clone(), manifold.clone());
    daemon.install_net(Arc::clone(&net));

    // same posture as net.
    let tls = DaemonTls::new(rt.handle().clone(), manifold.clone());
    daemon.install_tls(Arc::clone(&tls));

    // UDP coordinator inherits the same manifold as net.
    let dgram = afterburner_wasi::DaemonDgram::new(rt.handle().clone(), manifold);
    daemon.install_dgram(Arc::clone(&dgram));

    if let Err(e) = daemon.run_init(source, &invocation) {
        flush_streams(&mut daemon)?;
        match e {
            AfterburnerError::ProcessExit(code) => std::process::exit(code),
            other => {
                // Surface the error to the parent over the worker IPC
                // (so worker.on('error') fires) before exiting.
                let mut last = String::new();
                let _ = workers.post_error_to_parent(&other.to_string(), "", &mut last);
                let _ = std::io::stderr().write_all(format!("burn: {other}\n").as_bytes());
                std::process::exit(1);
            }
        }
    }
    flush_streams(&mut daemon)?;

    // Install our own SIGTERM/SIGINT handler so the parent's
    // `worker.terminate(force=true)` SIGKILL fallback isn't the only
    // way out. SIGTERM = graceful: set the shutdown flag and drain
    // pending events.
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

    run_child_event_loop(&mut daemon, &workers, &shutdown)?;
    rt.shutdown_timeout(Duration::from_millis(500));
    flush_streams(&mut daemon)?;
    Ok(())
}

fn run_child_event_loop(
    daemon: &mut DaemonRuntime,
    workers: &Arc<DaemonWorkers>,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let mut did_work = false;

        for _ in 0..256 {
            let Some(evt) = workers.try_recv_event() else {
                break;
            };
            did_work = true;
            let envelope = match &evt {
                WorkerEvent::ParentMessage { payload } => Some(serde_json::json!({
                    "kind": "worker-parent-message",
                    "payload": payload,
                })),
                WorkerEvent::TerminateRequested => {
                    workers.signal_parent_closed();
                    Some(serde_json::json!({"kind": "worker-terminate-requested"}))
                }
                // Child role doesn't see online/message/error/exit on
                // its own channel — those flow only parent-side. Ignore
                // defensively.
                _ => None,
            };
            if let Some(env) = envelope {
                let res = daemon.dispatch_event(env);
                flush_streams(daemon)?;
                if let Err(e) = res {
                    if let AfterburnerError::ProcessExit(code) = &e {
                        std::process::exit(*code);
                    }
                    let _ = std::io::stderr()
                        .write_all(format!("burn worker: dispatch error: {e}\n").as_bytes());
                }
            }
        }

        // Timers can still fire inside a worker.
        let fired = daemon.drain_expired_timers();
        for timer_id in fired {
            did_work = true;
            let envelope = serde_json::json!({"kind": "timer-fire", "timer_id": timer_id});
            let res = daemon.dispatch_event(envelope);
            flush_streams(daemon)?;
            if let Err(e) = res {
                if let AfterburnerError::ProcessExit(code) = &e {
                    std::process::exit(*code);
                }
                let _ = std::io::stderr()
                    .write_all(format!("burn worker: timer error: {e}\n").as_bytes());
            }
        }

        // Net events.
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_net_event() else {
                break;
            };
            did_work = true;
            let (envelope, reap_id) = net_event_to_envelope(&evt);
            let res = daemon.dispatch_event(envelope);
            flush_streams(daemon)?;
            if let Err(e) = res {
                if let AfterburnerError::ProcessExit(code) = &e {
                    std::process::exit(*code);
                }
                let _ = std::io::stderr()
                    .write_all(format!("burn worker: net error: {e}\n").as_bytes());
            }
            if let Some(id) = reap_id {
                daemon.mark_net_closed(id);
            }
        }

        // TLS events.
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_tls_event() else {
                break;
            };
            did_work = true;
            let (envelope, reap_id) = tls_event_to_envelope(&evt);
            let res = daemon.dispatch_event(envelope);
            flush_streams(daemon)?;
            if let Err(e) = res {
                if let AfterburnerError::ProcessExit(code) = &e {
                    std::process::exit(*code);
                }
                let _ = std::io::stderr()
                    .write_all(format!("burn worker: tls error: {e}\n").as_bytes());
            }
            if let Some(id) = reap_id {
                daemon.mark_tls_closed(id);
            }
        }

        // dgram events.
        for _ in 0..256 {
            let Some(evt) = daemon.try_recv_dgram_event() else {
                break;
            };
            did_work = true;
            let envelope = dgram_event_to_envelope(&evt);
            let res = daemon.dispatch_event(envelope);
            flush_streams(daemon)?;
            if let Err(e) = res {
                if let AfterburnerError::ProcessExit(code) = &e {
                    std::process::exit(*code);
                }
                let _ = std::io::stderr()
                    .write_all(format!("burn worker: dgram error: {e}\n").as_bytes());
            }
        }

        // Exit conditions: parent closed our stdin AND nothing else
        // is keeping us alive (no ref'd timer / listener). Workers
        // that registered a `parentPort.on('message')` only stay alive
        // because the stdin pump is still reading — once parent drops
        // its end, parent_closed flips and we can exit.
        if workers.parent_closed_signaled() && !daemon.has_refs() {
            break;
        }

        if !did_work {
            let max_sleep = Duration::from_millis(5);
            let sleep_dur = daemon
                .next_timer_deadline()
                .map(|d| d.saturating_duration_since(Instant::now()).min(max_sleep))
                .unwrap_or(max_sleep);
            std::thread::sleep(sleep_dur);
        }
    }
    Ok(())
}

/// Same shape as `cli::daemon::net_event_to_envelope`. Duplicated to
/// avoid widening the public surface of cli::daemon for one helper.
fn net_event_to_envelope(evt: &NetEvent) -> (serde_json::Value, Option<i32>) {
    fn addr_json(addr: &Option<std::net::SocketAddr>) -> serde_json::Value {
        match addr {
            Some(a) => {
                let family = if a.is_ipv4() { "IPv4" } else { "IPv6" };
                serde_json::json!({
                    "address": a.ip().to_string(),
                    "family": family,
                    "port": a.port(),
                })
            }
            None => serde_json::Value::Null,
        }
    }
    match evt {
        NetEvent::Connect {
            conn_id,
            local,
            remote,
        } => (
            serde_json::json!({
                "kind": "net-connect",
                "conn_id": conn_id,
                "local": addr_json(local),
                "remote": addr_json(remote),
            }),
            None,
        ),
        NetEvent::Connection {
            server_id,
            conn_id,
            local,
            remote,
        } => (
            serde_json::json!({
                "kind": "net-connection",
                "server_id": server_id,
                "conn_id": conn_id,
                "local": addr_json(local),
                "remote": addr_json(remote),
            }),
            None,
        ),
        NetEvent::Data {
            conn_id,
            payload_b64,
        } => (
            serde_json::json!({
                "kind": "net-data",
                "conn_id": conn_id,
                "payload_b64": payload_b64,
            }),
            None,
        ),
        NetEvent::End { conn_id } => (
            serde_json::json!({"kind": "net-end", "conn_id": conn_id}),
            None,
        ),
        NetEvent::Drain { conn_id } => (
            serde_json::json!({"kind": "net-drain", "conn_id": conn_id}),
            None,
        ),
        NetEvent::Close { conn_id, had_error } => (
            serde_json::json!({
                "kind": "net-close",
                "conn_id": conn_id,
                "had_error": had_error,
            }),
            Some(*conn_id),
        ),
        NetEvent::Error {
            conn_id,
            message,
            code,
        } => (
            serde_json::json!({
                "kind": "net-error",
                "conn_id": conn_id,
                "message": message,
                "code": code,
            }),
            None,
        ),
        NetEvent::Listening { server_id, port } => (
            serde_json::json!({
                "kind": "net-listening",
                "server_id": server_id,
                "port": port,
            }),
            None,
        ),
        NetEvent::ServerError { server_id, message } => (
            serde_json::json!({
                "kind": "net-server-error",
                "server_id": server_id,
                "message": message,
            }),
            None,
        ),
    }
}

/// Same shape as `cli::daemon::tls_event_to_envelope`. Duplicated for
/// the same reason as `net_event_to_envelope`.
fn tls_event_to_envelope(evt: &TlsEvent) -> (serde_json::Value, Option<i32>) {
    fn addr_json(addr: &Option<std::net::SocketAddr>) -> serde_json::Value {
        match addr {
            Some(a) => {
                let family = if a.is_ipv4() { "IPv4" } else { "IPv6" };
                serde_json::json!({
                    "address": a.ip().to_string(),
                    "family": family,
                    "port": a.port(),
                })
            }
            None => serde_json::Value::Null,
        }
    }
    match evt {
        TlsEvent::Connect {
            conn_id,
            local,
            remote,
            alpn_protocol,
            protocol,
            authorized,
            cipher,
            peer_cert_chain_der,
        } => {
            use base64::Engine as _;
            let chain: Vec<serde_json::Value> = peer_cert_chain_der
                .iter()
                .map(|d| {
                    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(d))
                })
                .collect();
            (
                serde_json::json!({
                    "kind": "tls-connect",
                    "conn_id": conn_id,
                    "local": addr_json(local),
                    "remote": addr_json(remote),
                    "alpn_protocol": alpn_protocol,
                    "protocol": protocol,
                    "authorized": authorized,
                    "cipher": cipher,
                    "peer_cert_chain_der_b64": chain,
                }),
                None,
            )
        }
        TlsEvent::Connection {
            server_id,
            conn_id,
            local,
            remote,
            alpn_protocol,
            protocol,
            cipher,
            peer_cert_chain_der,
        } => {
            use base64::Engine as _;
            let chain: Vec<serde_json::Value> = peer_cert_chain_der
                .iter()
                .map(|d| {
                    serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(d))
                })
                .collect();
            (
                serde_json::json!({
                    "kind": "tls-connection",
                    "server_id": server_id,
                    "conn_id": conn_id,
                    "local": addr_json(local),
                    "remote": addr_json(remote),
                    "alpn_protocol": alpn_protocol,
                    "protocol": protocol,
                    "cipher": cipher,
                    "peer_cert_chain_der_b64": chain,
                }),
                None,
            )
        }
        TlsEvent::Data {
            conn_id,
            payload_b64,
        } => (
            serde_json::json!({
                "kind": "tls-data",
                "conn_id": conn_id,
                "payload_b64": payload_b64,
            }),
            None,
        ),
        TlsEvent::End { conn_id } => (
            serde_json::json!({"kind": "tls-end", "conn_id": conn_id}),
            None,
        ),
        TlsEvent::Drain { conn_id } => (
            serde_json::json!({"kind": "tls-drain", "conn_id": conn_id}),
            None,
        ),
        TlsEvent::Close { conn_id, had_error } => (
            serde_json::json!({
                "kind": "tls-close",
                "conn_id": conn_id,
                "had_error": had_error,
            }),
            Some(*conn_id),
        ),
        TlsEvent::Error {
            conn_id,
            message,
            code,
        } => (
            serde_json::json!({
                "kind": "tls-error",
                "conn_id": conn_id,
                "message": message,
                "code": code,
            }),
            None,
        ),
        TlsEvent::Listening { server_id, port } => (
            serde_json::json!({
                "kind": "tls-listening",
                "server_id": server_id,
                "port": port,
            }),
            None,
        ),
        TlsEvent::ServerError { server_id, message } => (
            serde_json::json!({
                "kind": "tls-server-error",
                "server_id": server_id,
                "message": message,
            }),
            None,
        ),
    }
}

fn build_invocation(cli: &Cli, script_label: &str, user_args: &[String]) -> ScriptInvocation {
    let mut argv = Vec::with_capacity(2 + user_args.len());
    argv.push("burn".to_string());
    argv.push(script_label.to_string());
    argv.extend(user_args.iter().cloned());
    ScriptInvocation {
        argv,
        env: collect_env(cli),
        cwd: super::script::cli_cwd(),
    }
}

fn collect_env(cli: &Cli) -> std::collections::BTreeMap<String, String> {
    use crate::EnvAccess;
    let manifold = build_manifold(cli);
    match &manifold.env {
        EnvAccess::None => std::collections::BTreeMap::new(),
        EnvAccess::AllowList(keys) => keys
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
            .collect(),
        EnvAccess::Full => std::env::vars().collect(),
    }
}

fn flush_streams(daemon: &mut DaemonRuntime) -> Result<()> {
    // Worker children must not write anything to stdout that isn't a
    // framed IPC payload — that channel belongs to daemon_workers.
    // Forward captured stdout to **stderr** instead so user
    // `console.log` from inside a worker is still visible while the
    // IPC pipe stays clean.
    let stdout = daemon.drain_stdout();
    let stderr = daemon.drain_stderr();
    thread_local! {
        static HW_STDOUT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        static HW_STDERR: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
    let so = HW_STDOUT.with(|c| c.get());
    let se = HW_STDERR.with(|c| c.get());
    if stdout.len() > so {
        std::io::stderr()
            .write_all(&stdout[so..])
            .context("worker stdout->stderr forward")?;
        HW_STDOUT.with(|c| c.set(stdout.len()));
    }
    if stderr.len() > se {
        std::io::stderr()
            .write_all(&stderr[se..])
            .context("worker stderr forward")?;
        HW_STDERR.with(|c| c.set(stderr.len()));
    }
    Ok(())
}

/// Translates daemon-side `DgramEvent`s into `{kind:"dgram-..."}`
/// JSON envelopes that the polyfill's `__ab_dgram_handlers[id]`
/// dispatcher expects.
fn dgram_event_to_envelope(evt: &DgramEvent) -> serde_json::Value {
    match evt {
        DgramEvent::Listening { socket_id, port } => serde_json::json!({
            "kind": "dgram-listening",
            "socketId": socket_id,
            "port": port,
        }),
        DgramEvent::Message {
            socket_id,
            from,
            payload_b64,
        } => {
            let family = if from.is_ipv4() { "IPv4" } else { "IPv6" };
            serde_json::json!({
                "kind": "dgram-message",
                "socketId": socket_id,
                "payload": payload_b64,
                "from": {
                    "address": from.ip().to_string(),
                    "port": from.port(),
                    "family": family,
                },
            })
        }
        DgramEvent::Error {
            socket_id,
            message,
            code,
        } => serde_json::json!({
            "kind": "dgram-error",
            "socketId": socket_id,
            "message": message,
            "code": code,
        }),
        DgramEvent::Close { socket_id } => serde_json::json!({
            "kind": "dgram-close",
            "socketId": socket_id,
        }),
    }
}
