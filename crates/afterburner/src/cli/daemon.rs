// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn <file>` / `burn -e <code>` daemon driver.
//!
//! Every CLI script runs through daemon mode (Q2-A locked decision):
//! `daemon-init` evaluates the user source, and then:
//!
//! * **No refs** (no HTTP listeners, no ref'd timers) → the script is
//!   a plain one-shot. Drain captured stdout/stderr and exit 0.
//! * **At least one ref** (HTTP listener via `.listen()`, or a ref'd
//!   `setInterval` / `setTimeout`) → enter the dispatcher loop,
//!   routing axum events and firing host-managed timers until SIGINT
//!   or until all refs are cleared.
//!
//! `process.exit(n)` propagates the exit code via
//! `AfterburnerError::ProcessExit`; `setInterval` / non-zero
//! `setTimeout` register host-managed timers that keep the event
//! loop alive (ref'd by default, `.unref()` supported).
//!
//! The library API (`Afterburner::run_script`) does **not** use this
//! path - Q2-A locks that to strict one-shot semantics. Only the CLI
//! can auto-transition into daemon mode.

use crate::AfterburnerError;
use crate::wasm::{DaemonHttp, DaemonShardPool, ShardPoolConfig, WasmCombustor, WasmConfig};
use crate::{EnvAccess, ScriptInvocation};
use afterburner_wasi::daemon_workers::WorkerConfig;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::available_parallelism;
use std::time::Duration;

use super::args::Cli;
use super::manifold::build_manifold;

/// Hard ceiling on shard count. Mirrors
/// `afterburner_wasi::daemon_shard_pool::MAX_SHARDS` (pinned to
/// match Wasmtime's `POOL_TOTAL_MEMORIES`); duplicated here so the
/// CLI can input-validate without pulling the wasi constant
/// through every feature gate.
const MAX_SHARDS: usize = 128;

/// Determine how many shards the daemon should spawn.
///
/// Resolution order:
///
/// 1. **`BURN_SHARDS` env var** if set and parseable as a positive
///    integer. Clamped to `[1, MAX_SHARDS]`. Garbage / `0` →
///    fall through with a stderr warning.
/// 2. **`std::thread::available_parallelism()`** - container-aware
///    (cgroup CPU quotas honoured via `sched_getaffinity` on
///    Linux). This is the recommended path: `docker run --cpus=4`
///    produces 4 shards, k8s `cpu: "4"` produces 4 shards.
/// 3. Falls back to `1` if `available_parallelism()` errors (rare).
///
/// `BURN_SHARDS` is the testing / debugging escape hatch - useful
/// for forcing single-shard semantics when comparing against the
/// pre-B1 baseline, A/B benchmarking shard counts without touching
/// the container, or pinning to a specific count under a CI runner
/// with variable core count. **Oversubscribing** (`BURN_SHARDS >
/// available_parallelism()`) is allowed but warns at startup -
/// dedicated-thread shards contend for fewer cores than they
/// claim, incurring context-switch tax with zero throughput
/// benefit.
fn daemon_shard_count() -> usize {
    let auto = available_parallelism().map(|n| n.get()).unwrap_or(1);
    let env = match std::env::var("BURN_SHARDS") {
        Ok(s) => s,
        Err(_) => return auto,
    };
    match env.trim().parse::<usize>() {
        Ok(0) => {
            let _ = writeln!(
                std::io::stderr(),
                "burn: BURN_SHARDS=0 invalid (must be ≥ 1); using auto-detected {auto}"
            );
            auto
        }
        Ok(n) if n > MAX_SHARDS => {
            let _ = writeln!(
                std::io::stderr(),
                "burn: BURN_SHARDS={n} exceeds cap; clamping to {MAX_SHARDS}"
            );
            MAX_SHARDS
        }
        Ok(n) => {
            if n > auto {
                let _ = writeln!(
                    std::io::stderr(),
                    "burn: BURN_SHARDS={n} > available_parallelism()={auto}; \
                     oversubscribing dedicated-thread shards incurs context-switch \
                     tax with no throughput benefit"
                );
            }
            n
        }
        Err(_) => {
            let _ = writeln!(
                std::io::stderr(),
                "burn: BURN_SHARDS={env:?} not a positive integer; using auto-detected {auto}"
            );
            auto
        }
    }
}

/// Run `source` via daemon-init; enter the event loop if the script
/// registered at least one ref (HTTP listener or ref'd timer).
/// Matches script-mode semantics for plain scripts - captured
/// stdout/stderr flushed, exit code from `process.exit(N)` or `0`
/// on clean completion.
pub fn execute(cli: &Cli, source: &str, script_label: &str, user_args: &[String]) -> Result<()> {
    // `burn --mode native` can't host daemon mode (native combustor
    // has no axum hooks). Route such scripts through the library's
    // script mode instead - keeps the `--mode native foo.js` path
    // useful for trusted one-shot scripts.
    if let Some(mode) = cli.mode.as_deref()
        && mode.eq_ignore_ascii_case("native")
    {
        return super::script::execute(
            &super::build::build_afterburner(cli)?,
            source,
            script_label,
            user_args,
            cli,
        );
    }

    let invocation = build_invocation(cli, script_label, user_args);
    let manifold = build_manifold(cli);

    // Start tokio runtime for the axum listeners + signal handler.
    // Multi-thread so axum's spawn happens off the main thread.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    let daemon_http = DaemonHttp::with_runtime(rt.handle().clone(), 1024);

    // The WasmCombustor lives at the CLI level (bypasses the
    // Afterburner facade) because daemon mode needs direct access
    // to the engine + instance_pre that the shard pool seeds onto
    // each per-shard Store.
    let combustor = WasmCombustor::new(WasmConfig {
        state_store: None,
        host_context: None,
        transpile_hook: ts_transpile_hook(),
        compile_cache_dir: None,
    })
    .context("wasm combustor")?;

    // Pre-compile the user source on the host side ONCE. The pool
    // fans out the same `Arc<Vec<u8>>` to every shard's daemon-init
    // step, skipping the per-shard parse + wrap + compile cost.
    // (B4 ships this; the multi-shard pool is its first real
    // consumer.) Compile errors surface here rather than through a
    // daemon-init trap, keeping stderr cleaner.
    let init_bytecode = match combustor.compile_daemon_init_bytecode(source, &invocation) {
        Ok(bc) => Arc::new(bc),
        Err(e) => {
            let msg = format!(
                "{} {}\n",
                super::style::error_prefix(),
                super::style::humanize_error(&e.to_string())
            );
            let _ = std::io::stderr().write_all(msg.as_bytes());
            std::process::exit(1);
        }
    };

    let shard_count = daemon_shard_count();
    let shutdown = Arc::new(AtomicBool::new(false));

    // Resource-budget banner moved to AFTER pool.spawn() - the
    // *actual* shard count depends on whether shard 0's init bound
    // an HTTP listener (non-HTTP daemons stay at 1 even when the
    // user requested more). Reporting before spawn would lie.

    // Spawn the pool. Each shard runs daemon-init from the shared
    // bytecode in parallel; spawn() returns once all shards have
    // reported (success or failure).
    let pool = match DaemonShardPool::spawn(ShardPoolConfig {
        shard_count,
        // Only multi-shard when shard 0's init bound an HTTP
        // listener. Non-HTTP daemons (timer-only scripts, raw
        // TCP/TLS/UDP servers, scripts with init-time
        // `net.connect()` / `setInterval()` etc.) stay
        // single-shard so init-time side effects don't multiply
        // by N. Operators who genuinely want multi-shard for a
        // non-HTTP workload can set `BURN_SHARDS=N` AND
        // structure their script so init is idempotent
        // (handlers register, no top-level side effects).
        expand_only_for_http_listener: true,
        engine: combustor.engine().clone(),
        instance_pre: Arc::clone(combustor.instance_pre()),
        init_bytecode: Arc::clone(&init_bytecode),
        manifold,
        state_store: Some(combustor.state_store().clone()),
        host_context: None,
        daemon_http: Arc::clone(&daemon_http),
        transpile_hook: combustor.transpile_hook(),
        worker_config: WorkerConfig::default(),
        tokio_handle: rt.handle().clone(),
        invocation,
        shutdown: Arc::clone(&shutdown),
        queue_depth_per_shard: None,
    }) {
        Ok(p) => p,
        Err(e) => {
            // Init failed on at least one shard. The pool's spawn
            // already flushed init stdout/stderr to surface the
            // failure cause.
            match e {
                AfterburnerError::ProcessExit(code) => std::process::exit(code),
                other => {
                    let msg = format!(
                        "{} {}\n",
                        super::style::error_prefix(),
                        super::style::humanize_error(&other.to_string())
                    );
                    let _ = std::io::stderr().write_all(msg.as_bytes());
                    std::process::exit(1);
                }
            }
        }
    };

    // Surface the actual shard count now that we know it. The
    // pool may have spawned fewer shards than requested if the
    // script didn't bind an HTTP listener (see
    // `expand_only_for_http_listener`).
    if !std::env::var("BURN_QUIET").is_ok_and(|v| v == "1") {
        let actual = pool.shard_count();
        let source = if std::env::var("BURN_SHARDS").is_ok() {
            "BURN_SHARDS env var"
        } else {
            "auto-detected from available CPUs"
        };
        let _ = writeln!(
            std::io::stderr(),
            "burn: daemon running {actual} shard(s) (requested {shard_count} via {source})\n\
             burn: in-process JS state is per-shard; use require('afterburner:state') for shared state",
        );
    }

    // Flush daemon-init output from each shard in deterministic
    // (shard 0 first) order. Each shard ran init independently;
    // their stdout/stderr were captured per-shard. Surface only
    // shard 0's output (every shard ran the same script with
    // identical side effects, so deduping to shard 0's view
    // matches what a single-shard daemon would print).
    if let Some(first) = pool.init_results().first() {
        // Explicit flush after write_all so the init output reaches
        // the parent's stdout buffer before any subsequent SIGKILL
        // (e.g., test harnesses that drop the child after a timeout)
        // can lose it. std::io::stdout() is block-buffered when
        // piped; without an explicit flush, sub-block writes sit in
        // the buffer until the process exits cleanly.
        let mut so = std::io::stdout().lock();
        let _ = so.write_all(&first.stdout);
        let _ = so.flush();
        drop(so);
        let mut se = std::io::stderr().lock();
        let _ = se.write_all(&first.stderr);
        let _ = se.flush();
        drop(se);
    }

    if !pool.any_has_refs() {
        // Plain script - no listeners and no ref'd timers in any
        // shard. Drop the pool (joins all shards), exit cleanly.
        drop(pool);
        rt.shutdown_timeout(Duration::from_secs(1));
        return Ok(());
    }

    // Daemon mode - install SIGINT/SIGTERM handlers.
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

    // Main thread waits for shutdown signal OR all shards naturally
    // exit (no refs anywhere). Each shard runs its own per-shard
    // event loop (HTTP from mailbox, timers/workers/net/tls/dgram
    // local), so the main thread does no event dispatch - it only
    // observes pool state.
    while !shutdown.load(Ordering::Acquire) {
        if !pool.any_has_refs() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Shutdown: signal all shards, then drop the pool which joins
    // all shard threads. Tokio runtime drains in-flight axum
    // tasks (best-effort, bounded by timeout).
    shutdown.store(true, Ordering::Release);
    drop(pool);
    rt.shutdown_timeout(Duration::from_secs(2));
    Ok(())
}

/// Same shape as [`super::script::build_invocation`]. Duplicated here
/// to avoid tangling the script / daemon modules.
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

fn collect_env(cli: &Cli) -> BTreeMap<String, String> {
    let manifold = build_manifold(cli);
    let mut env: BTreeMap<String, String> = match &manifold.env {
        EnvAccess::None => BTreeMap::new(),
        EnvAccess::AllowList(keys) => keys
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
            .collect(),
        EnvAccess::Full => std::env::vars().collect(),
    };
    // `--env-file=path` (Node 20.6+): merge later-wins; quotes
    // stripped. Same parser as `script::collect_env`.
    for path in &cli.env_file {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some(eq) = line.find('=') else { continue };
                let key = line[..eq].trim();
                if key.is_empty() {
                    continue;
                }
                let mut val = line[eq + 1..].trim();
                if val.len() >= 2
                    && ((val.starts_with('"') && val.ends_with('"'))
                        || (val.starts_with('\'') && val.ends_with('\'')))
                {
                    val = &val[1..val.len() - 1];
                }
                env.insert(key.to_string(), val.to_string());
            }
        }
    }
    env
}

/// Resolve a user-supplied script path to an absolute path suitable
/// for `process.argv[1]`. Falls back to the raw string on failure -
/// matches `super::script::script_label`.
pub fn script_label(path: &Path) -> String {
    path.canonicalize()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

/// Build the transpile hook the require resolver uses to lower
/// `.ts` / `.mts` / `.cts` / `.mjs` files to plain CJS when the CLI
/// is built with the `ts` feature.
#[cfg(feature = "ts")]
pub(super) fn ts_transpile_hook() -> Option<afterburner_wasi::host::TranspileFn> {
    Some(Arc::new(
        |source: &str, path: &str| -> Result<String, String> {
            let p = std::path::PathBuf::from(path);
            // Treat `.mjs`/`.cjs` / plain JS without TS syntax as ESM-
            // lowering-only so `import`/`export` still get rewritten.
            if crate::ts::is_typescript(&p) {
                crate::ts::transpile(source, &p).map_err(|e| e.to_string())
            } else {
                crate::ts::lower_esm_js(source, &p).map_err(|e| e.to_string())
            }
        },
    ))
}

#[cfg(not(feature = "ts"))]
pub(super) fn ts_transpile_hook() -> Option<afterburner_wasi::host::TranspileFn> {
    None
}
