// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Embedded guest-exit policy: a guest `process.exit(code)` reaching a
//! daemon shard's dispatch must, under
//! [`set_exit_process_on_guest_exit(false)`], stop that SHARD - streams
//! flushed, `shards_alive()` drops - and NEVER the host process. Found by an
//! embedder of the shard pool: one daemon package's failed bootstrap called
//! `process.exit(1)` and took the whole host down with it, no error line.
//!
//! This file is deliberately its own test binary: the policy is
//! process-global, and under the DEFAULT (CLI) policy the guest's exit
//! would terminate the test harness itself - which is exactly the behavior
//! difference under test.

#![cfg(feature = "daemon")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use afterburner_core::{Manifold, ScriptInvocation};
use afterburner_wasi::daemon_shard_pool::{
    DaemonShardPool, ShardPoolConfig, set_exit_process_on_guest_exit,
};
use afterburner_wasi::daemon_workers::WorkerConfig;
use afterburner_wasi::{DaemonHttp, WasmCombustor, WasmConfig};

#[test]
fn embedded_policy_guest_exit_stops_the_shard_not_the_host() {
    set_exit_process_on_guest_exit(false);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let daemon_http = DaemonHttp::with_runtime(rt.handle().clone(), 64);

    // The ref'd interval keeps the event loop alive so the shard does not
    // finish by draining; the timer then delivers `process.exit(7)` through
    // the TIMER dispatch arm - the same arm a failing daemon bootstrap's
    // exit rides in an embedding engine.
    let source = r#"
        setInterval(function () {}, 60000);
        setTimeout(function () {
            console.log('guest: exiting with 7');
            process.exit(7);
        }, 25);
    "#;

    let combustor = WasmCombustor::new(WasmConfig::default()).expect("combustor");
    let invocation = ScriptInvocation {
        argv: vec!["burn".to_string(), "embedded-exit-test".to_string()],
        env: BTreeMap::new(),
        cwd: "/".to_string(),
    };
    let init_bytecode = combustor
        .compile_daemon_init_bytecode(source, &invocation)
        .expect("compile daemon-init bytecode");

    let pool = DaemonShardPool::spawn(ShardPoolConfig {
        shard_count: 1,
        expand_only_for_http_listener: true,
        engine: combustor.engine().clone(),
        instance_pre: Arc::clone(combustor.instance_pre()),
        init_bytecode: Arc::new(init_bytecode),
        manifold: Manifold::open(),
        state_store: Some(combustor.state_store().clone()),
        host_context: None,
        daemon_http: Arc::clone(&daemon_http),
        transpile_hook: combustor.transpile_hook(),
        worker_config: WorkerConfig::default(),
        tokio_handle: rt.handle().clone(),
        invocation,
        shutdown: Arc::new(AtomicBool::new(false)),
        queue_depth_per_shard: None,
        #[cfg(unix)]
        unix_coord: None,
    })
    .expect("spawn shard pool");
    assert_eq!(pool.shards_alive(), 1, "shard must be up before the exit");

    // Deadline + bounded backoff (never a fixed sleep): the shard stops
    // the moment the timer-fired exit dispatches.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut backoff = Duration::from_millis(10);
    while pool.shards_alive() != 0 {
        assert!(
            Instant::now() < deadline,
            "shard never stopped after guest process.exit(7); shards_alive={}",
            pool.shards_alive()
        );
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(100));
    }

    // Reaching this line IS the headline assertion: the host process
    // survived the guest's exit. Under the default (CLI) policy the
    // harness would have exited with code 7 before the loop ever ended.
    assert_eq!(pool.shards_alive(), 0);
    rt.shutdown_timeout(Duration::from_secs(2));
}
