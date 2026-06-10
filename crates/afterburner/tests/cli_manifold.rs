// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Integration tests for the CLI's `--allow-*` / `--sandbox` flag
//! translation into a [`Manifold`]. Migrated here from the inline
//! `#[cfg(test)]` module in `src/bin/burn.rs` per §4.7 of
//! `IMPL_PLAN_BURN_RUNTIME.md`.
//!
//! Semantics tested: Q1-D — the CLI defaults to `Manifold::open()`;
//! `--sandbox` or any `--allow-*` flag flips to sealed + explicit
//! grants; `-A` is a shortcut for open.

#![cfg(feature = "bin")]

use afterburner::cli::{Cli, build_manifold, is_implicit_open, parse_allow_list};
use afterburner::{EnvAccess, FsAccess, ListenAccess, NetAccess};
use std::path::PathBuf;

#[derive(Default)]
struct CliBuilder {
    allow_all: bool,
    sandbox: bool,
    quiet: bool,
    allow_net: Option<String>,
    allow_listen: Option<String>,
    allow_fs: Option<String>,
    allow_env: Option<String>,
}

impl CliBuilder {
    fn allow_all(mut self) -> Self {
        self.allow_all = true;
        self
    }
    fn sandbox(mut self) -> Self {
        self.sandbox = true;
        self
    }
    fn net(mut self, s: &str) -> Self {
        self.allow_net = Some(s.into());
        self
    }
    fn listen(mut self, s: &str) -> Self {
        self.allow_listen = Some(s.into());
        self
    }
    fn fs(mut self, s: &str) -> Self {
        self.allow_fs = Some(s.into());
        self
    }
    fn env(mut self, s: &str) -> Self {
        self.allow_env = Some(s.into());
        self
    }
    fn build(self) -> Cli {
        Cli {
            command: None,
            file: None,
            eval_code: None,
            mode: None,
            fuel: None,
            memory: None,
            timeout_ms: None,
            allow_net: self.allow_net,
            allow_listen: self.allow_listen,
            allow_fs: self.allow_fs,
            allow_env: self.allow_env,
            allow_all: self.allow_all,
            sandbox: self.sandbox,
            quiet: self.quiet,
            watch: false,
            env_file: Vec::new(),
            require: Vec::new(),
            import: Vec::new(),
            permission: false,
            allow_fs_read: None,
            allow_fs_write: None,
            allow_child_process: false,
            allow_worker: false,
            allow_crypto: false,
            internal_worker: false,
            worker_thread_id: None,
            rest_args: Vec::new(),
        }
    }
}

#[test]
fn parse_allow_list_trims_and_drops_empty() {
    assert_eq!(
        parse_allow_list("a, b ,,c"),
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
    assert!(parse_allow_list("").is_empty());
    assert!(parse_allow_list("  ,  ,").is_empty());
}

#[test]
fn default_manifold_is_open_per_q1d() {
    // CLI default is OPEN (Q1-D). Library default stays sealed;
    // that's tested separately in the builder tests.
    let m = build_manifold(&CliBuilder::default().build());
    assert!(matches!(m.fs, FsAccess::ReadWrite(_)));
    assert!(matches!(m.net, NetAccess::OutboundFull(_)));
    assert!(matches!(m.env, EnvAccess::Full));
}

#[test]
fn default_is_implicit_open() {
    assert!(is_implicit_open(&CliBuilder::default().build()));
}

#[test]
fn allow_all_is_not_implicit_open() {
    // `-A` is an EXPLICIT open; banner should not fire for it.
    assert!(!is_implicit_open(
        &CliBuilder::default().allow_all().build()
    ));
}

#[test]
fn sandbox_is_not_implicit_open() {
    assert!(!is_implicit_open(&CliBuilder::default().sandbox().build()));
}

#[test]
fn any_allow_flag_is_not_implicit_open() {
    assert!(!is_implicit_open(&CliBuilder::default().net("foo").build()));
}

#[test]
fn sandbox_flag_is_sealed() {
    let m = build_manifold(&CliBuilder::default().sandbox().build());
    assert!(matches!(m.fs, FsAccess::None));
    assert!(matches!(m.net, NetAccess::None));
    assert!(matches!(m.env, EnvAccess::None));
}

#[test]
fn allow_all_opens_every_flap() {
    let m = build_manifold(&CliBuilder::default().allow_all().build());
    assert!(matches!(m.fs, FsAccess::ReadWrite(_)));
    assert!(matches!(m.net, NetAccess::OutboundFull(_)));
    assert!(matches!(m.env, EnvAccess::Full));
}

#[test]
fn allow_net_wildcard_is_unrestricted_under_implicit_sandbox() {
    // `--allow-net=*` without `--sandbox` still implicitly sandboxes
    // other axes — net is the only thing granted.
    let m = build_manifold(&CliBuilder::default().net("*").build());
    match m.net {
        NetAccess::OutboundFull(None) => {}
        other => panic!("expected OutboundFull(None), got {other:?}"),
    }
    assert!(matches!(m.fs, FsAccess::None));
    assert!(matches!(m.env, EnvAccess::None));
}

#[test]
fn allow_net_host_list_is_restricted() {
    let m = build_manifold(&CliBuilder::default().net("api.foo.com,*.bar.io").build());
    match m.net {
        NetAccess::OutboundFull(Some(hosts)) => {
            assert_eq!(
                hosts,
                vec!["api.foo.com".to_string(), "*.bar.io".to_string()]
            );
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn allow_fs_paths_become_roots() {
    let m = build_manifold(&CliBuilder::default().fs("/tmp,/var/lib").build());
    match m.fs {
        FsAccess::ReadWrite(roots) => {
            assert_eq!(
                roots,
                vec![PathBuf::from("/tmp"), PathBuf::from("/var/lib")]
            );
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn allow_env_without_wildcard_is_allow_list() {
    let m = build_manifold(&CliBuilder::default().env("HOME,PATH").build());
    match m.env {
        EnvAccess::AllowList(keys) => {
            assert_eq!(keys, vec!["HOME".to_string(), "PATH".to_string()]);
        }
        other => panic!("got {other:?}"),
    }
}

#[test]
fn allow_env_wildcard_is_full() {
    let m = build_manifold(&CliBuilder::default().env("*").build());
    assert!(matches!(m.env, EnvAccess::Full));
}

#[test]
fn sandbox_default_denies_listen() {
    let m = build_manifold(&CliBuilder::default().sandbox().build());
    assert!(matches!(m.listen, ListenAccess::None));
}

#[test]
fn allow_listen_is_a_sandbox_trigger() {
    // `--allow-listen` alone implies `--sandbox`: every other axis
    // seals, only listening on the named ports is granted.
    let cli = CliBuilder::default().listen("8080").build();
    assert!(!is_implicit_open(&cli));
    let m = build_manifold(&cli);
    assert!(matches!(m.fs, FsAccess::None));
    assert!(matches!(m.net, NetAccess::None));
    assert!(matches!(m.env, EnvAccess::None));
    assert_eq!(m.listen, ListenAccess::Ports(vec![8080]));
}

#[test]
fn allow_listen_port_list_becomes_ports() {
    let m = build_manifold(&CliBuilder::default().listen("8080, 9090").build());
    assert_eq!(m.listen, ListenAccess::Ports(vec![8080, 9090]));
}

#[test]
fn allow_listen_single_range_becomes_port_range() {
    let m = build_manifold(&CliBuilder::default().listen("9000-9100").build());
    assert_eq!(m.listen, ListenAccess::PortRange(9000, 9100));
}

#[test]
fn allow_listen_wildcard_is_any() {
    let m = build_manifold(&CliBuilder::default().listen("*").build());
    assert_eq!(m.listen, ListenAccess::Any);
}

#[test]
fn allow_all_grants_listen_any() {
    let m = build_manifold(&CliBuilder::default().allow_all().build());
    assert_eq!(m.listen, ListenAccess::Any);
}

#[test]
fn sandbox_with_allow_net_grants_only_net() {
    let m = build_manifold(&CliBuilder::default().sandbox().net("api.x.com").build());
    assert!(matches!(m.fs, FsAccess::None));
    assert!(matches!(m.env, EnvAccess::None));
    match m.net {
        NetAccess::OutboundFull(Some(hosts)) => {
            assert_eq!(hosts, vec!["api.x.com".to_string()]);
        }
        other => panic!("got {other:?}"),
    }
}
