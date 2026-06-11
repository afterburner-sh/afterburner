// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! B7 — `dns` record-type-aware resolution.
//!
//! Hits real public resolvers via the system `/etc/resolv.conf`,
//! falling back to Cloudflare. Tests pin queries against well-known
//! stable infrastructure (`cloudflare.com`, `dns.google`, `8.8.8.8`)
//! that has had the same record shape for years and is unlikely to
//! disappear before this codebase does.
//!
//! When network DNS is unavailable (CI without egress, isolated
//! containers), the affected tests are no-ops via an early skip
//! check — `_can_resolve` runs a fast `dns.lookup` against
//! `cloudflare.com` and short-circuits the whole file's DNS asserts
//! when it fails.

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Probe whether the host can reach a public DNS resolver. Tests skip
/// gracefully when this returns false (CI without egress).
fn can_resolve() -> bool {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                try {
                    const r = dns.lookup('cloudflare.com');
                    if (r && r.address) { console.log('OK'); }
                } catch (_) {}
            "#,
        ])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains("OK"),
        Err(_) => false,
    }
}

#[test]
#[serial]
fn resolve4_returns_ipv4_array() {
    if !can_resolve() {
        eprintln!("skip resolve4: no network");
        return;
    }
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                const ips = dns.resolve4('cloudflare.com');
                if (Array.isArray(ips) && ips.length > 0 && /^\d+\.\d+\.\d+\.\d+$/.test(ips[0])) {
                    console.log('R4_OK count=' + ips.length);
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("R4_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn resolve_mx_yields_priority_and_exchange() {
    if !can_resolve() {
        eprintln!("skip resolveMx: no network");
        return;
    }
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                const mx = dns.resolveMx('cloudflare.com');
                if (Array.isArray(mx) && mx.length > 0) {
                    const r = mx[0];
                    if (typeof r.exchange === 'string' && typeof r.priority === 'number') {
                        console.log('MX_OK first=' + r.exchange + '@' + r.priority);
                    }
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("MX_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn resolve_txt_yields_array_of_arrays() {
    if !can_resolve() {
        eprintln!("skip resolveTxt: no network");
        return;
    }
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                const txt = dns.resolveTxt('cloudflare.com');
                // Node's TXT shape: array of arrays. We don't assert
                // a specific record content (Cloudflare rotates SPF
                // entries) — we just want the *shape*.
                if (Array.isArray(txt) && txt.length > 0 && Array.isArray(txt[0])) {
                    console.log('TXT_OK records=' + txt.length);
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("TXT_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn reverse_lookup_returns_hostname() {
    if !can_resolve() {
        eprintln!("skip reverse: no network");
        return;
    }
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                // 8.8.8.8 → dns.google. (Google's resolver, stable.)
                const names = dns.reverse('8.8.8.8');
                if (Array.isArray(names) && names.some(n => /google/i.test(n))) {
                    console.log('REV_OK first=' + names[0]);
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("REV_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn resolve_dispatches_by_rrtype() {
    if !can_resolve() {
        eprintln!("skip resolve dispatcher: no network");
        return;
    }
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                const a = dns.resolve('cloudflare.com', 'A');
                const aaaa = dns.resolve('cloudflare.com', 'AAAA');
                if (Array.isArray(a) && Array.isArray(aaaa)) {
                    console.log('DISP_OK a=' + a.length + ' aaaa=' + aaaa.length);
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("DISP_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn callback_form_fires_with_result() {
    if !can_resolve() {
        eprintln!("skip callback form: no network");
        return;
    }
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                let called = false;
                dns.resolveMx('cloudflare.com', (err, list) => {
                    called = true;
                    if (err) { console.error('cb err:', err.message); process.exit(2); }
                    if (Array.isArray(list) && list.length > 0) {
                        console.log('CB_OK count=' + list.length);
                    }
                });
                if (!called) {
                    // Our resolver is sync; the callback fired before we got here.
                    console.error('callback never invoked — sync expectation broken');
                    process.exit(3);
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("CB_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn promises_form_resolves() {
    if !can_resolve() {
        eprintln!("skip promises form: no network");
        return;
    }
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                dns.promises.resolve4('cloudflare.com').then((ips) => {
                    if (Array.isArray(ips) && ips.length > 0) {
                        console.log('P_OK count=' + ips.length);
                    }
                }).catch((e) => {
                    console.error('promise reject:', e.message);
                    process.exit(2);
                });
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("P_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn sealed_manifold_blocks_all_resolvers() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "--sandbox",
            "-e",
            r#"
                const dns = require('dns');
                let denials = 0;
                const probes = [
                    () => dns.resolve4('example.com'),
                    () => dns.resolve6('example.com'),
                    () => dns.resolveMx('example.com'),
                    () => dns.resolveTxt('example.com'),
                    () => dns.resolveCname('example.com'),
                    () => dns.resolveNs('example.com'),
                    () => dns.reverse('8.8.8.8'),
                ];
                for (const p of probes) {
                    try { p(); }
                    catch (e) {
                        if (e.code === 'EACCES') denials++;
                        else { console.error('wrong code:', e.code, e.message); process.exit(2); }
                    }
                }
                if (denials === probes.length) {
                    console.log('ALL_DENIED count=' + denials);
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("ALL_DENIED count=7"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
#[serial]
fn resolver_setServers_targets_custom_dns() {
    if !can_resolve() {
        eprintln!("skip Resolver.setServers: no network");
        return;
    }
    // Point a `dns.Resolver` at Cloudflare explicitly. Even with the
    // system /etc/resolv.conf pointing somewhere else, this one
    // instance asks 1.1.1.1 directly.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                const r = new dns.Resolver();
                r.setServers(['1.1.1.1', '1.0.0.1']);
                if (JSON.stringify(r.getServers()) !== '["1.1.1.1","1.0.0.1"]') {
                    console.error('getServers:', r.getServers()); process.exit(2);
                }
                const ips = r.resolve4('cloudflare.com');
                if (!Array.isArray(ips) || ips.length === 0) {
                    console.error('ips:', ips); process.exit(3);
                }
                console.log('SET_SERVERS_OK count=' + ips.length);
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("SET_SERVERS_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn module_setServers_round_trips() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                dns.setServers(['8.8.8.8', '8.8.4.4']);
                const got = dns.getServers();
                if (got.length !== 2 || got[0] !== '8.8.8.8' || got[1] !== '8.8.4.4') {
                    console.error('got:', got); process.exit(2);
                }
                console.log('MODULE_SET_OK');
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("MODULE_SET_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn resolver_setServers_rejects_non_array() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                const r = new dns.Resolver();
                try {
                    r.setServers('1.1.1.1');
                    console.error('expected throw'); process.exit(2);
                } catch (e) {
                    if (!(e instanceof TypeError)) {
                        console.error('wrong err:', e); process.exit(3);
                    }
                    console.log('TYPECHECK_OK');
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("TYPECHECK_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn invalid_rrtype_throws_enotimp() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "-A",
            "-e",
            r#"
                const dns = require('dns');
                try {
                    dns.resolve('example.com', 'BOGUS');
                    console.error('LEAK: bogus rrtype accepted');
                    process.exit(1);
                } catch (e) {
                    if (e.code === 'ENOTIMP') {
                        console.log('ENOTIMP_OK');
                    } else {
                        console.error('wrong code:', e.code, e.message);
                        process.exit(2);
                    }
                }
            "#,
        ])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("ENOTIMP_OK"), "stdout: {stdout}");
}
