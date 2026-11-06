// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! An embedder's thread budget caps the daemon shard pool: a daemon asking for
//! 8 shards under a budget of 2 runs exactly 2 shard threads, each placed
//! through the installed [`ThreadHooks`].
//!
//! Its own test binary: the hooks and budget are installed once per process.

#![cfg(feature = "daemon")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use afterburner_core::threads::{self, ThreadBudget, ThreadHooks, ThreadKind, ThreadSpec};
use afterburner_core::{Manifold, ScriptInvocation};
use afterburner_wasi::daemon_shard_pool::{DaemonShardPool, ShardPoolConfig};
use afterburner_wasi::daemon_workers::WorkerConfig;
use afterburner_wasi::{DaemonHttp, WasmCombustor, WasmConfig};

#[derive(Default)]
struct CountingHooks {
    shard_starts: AtomicUsize,
    shard_indexes: AtomicUsize,
}

impl ThreadHooks for CountingHooks {
    fn on_start(&self, spec: &ThreadSpec<'_>) {
        if spec.kind == ThreadKind::DaemonShard {
            assert_eq!(spec.name, format!("burn-shard-{}", spec.index));
            self.shard_starts.fetch_add(1, Ordering::SeqCst);
            // Indexes 0 and 1 set bits 0 and 1.
            self.shard_indexes
                .fetch_or(1 << spec.index, Ordering::SeqCst);
        }
    }
}

#[test]
fn shard_pool_runs_at_most_the_budgeted_shards_each_placed_by_the_hook() {
    let hooks = Arc::new(CountingHooks::default());
    let budget = ThreadBudget {
        daemon_shards: 2,
        ..ThreadBudget::for_cores(2)
    };
    threads::install(hooks.clone(), budget).expect("first install");

    let rt = nuclei::Runtime::new().expect("build nuclei runtime");
    let daemon_http = DaemonHttp::with_runtime(rt.handle(), 64);

    // An HTTP listener lets the pool expand past shard 0.
    let port = 49500 + (std::process::id() % 5000) as u16;
    let source = format!(
        r#"
        const http = require('node:http');
        http.createServer(function(_req, res) {{ res.end('ok'); }}).listen({port});
        "#
    );

    let combustor = WasmCombustor::new(WasmConfig::default()).expect("combustor");
    let invocation = ScriptInvocation {
        argv: vec!["burn".to_string(), "thread-budget-test".to_string()],
        env: BTreeMap::new(),
        cwd: "/".to_string(),
    };
    let init_bytecode = combustor
        .compile_daemon_init_bytecode(&source, &invocation)
        .expect("compile daemon-init bytecode");

    let pool = DaemonShardPool::spawn(ShardPoolConfig {
        shard_count: 8,
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
        runtime: rt.handle(),
        invocation,
        shutdown: Arc::new(AtomicBool::new(false)),
        queue_depth_per_shard: None,
        #[cfg(unix)]
        unix_coord: None,
    })
    .expect("spawn shard pool");

    assert_eq!(
        pool.shard_count(),
        2,
        "budget of 2 must cap 8 requested shards"
    );
    assert_eq!(hooks.shard_starts.load(Ordering::SeqCst), 2);
    assert_eq!(hooks.shard_indexes.load(Ordering::SeqCst), 0b11);
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
}
