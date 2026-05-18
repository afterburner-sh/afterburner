// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Round 4 Node 26 surface fills — pins the additions made in this
//! batch so they don't silently regress when the polyfill bundle is
//! refreshed. Each test exercises a single named API so a failure
//! immediately points at the broken polyfill.

#![cfg(all(feature = "bin", feature = "ts"))]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed. stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

// ---- ES2024 globals --------------------------------------------------

#[test]
fn promise_with_resolvers_returns_triplet() {
    let out = run_inline(
        r#"
        const { promise, resolve, reject } = Promise.withResolvers();
        if (typeof resolve !== 'function' || typeof reject !== 'function') process.exit(1);
        if (!(promise instanceof Promise)) process.exit(2);
        resolve('value');
        promise.then(v => { if (v === 'value') console.log('PWR-OK'); });
        "#,
    );
    assert_marker(&out, "PWR-OK");
}

#[test]
fn object_groupby_buckets_items_by_key() {
    let out = run_inline(
        r#"
        const g = Object.groupBy([1,2,3,4,5], x => x % 2 === 0 ? 'e' : 'o');
        if (g.o.join(',') === '1,3,5' && g.e.join(',') === '2,4') console.log('GROUPBY-OK');
        "#,
    );
    assert_marker(&out, "GROUPBY-OK");
}

#[test]
fn map_groupby_returns_real_map() {
    let out = run_inline(
        r#"
        const g = Map.groupBy([{k:'a',v:1},{k:'b',v:2},{k:'a',v:3}], x => x.k);
        if (g instanceof Map && g.get('a').length === 2 && g.get('b').length === 1)
            console.log('MAP-GROUPBY-OK');
        "#,
    );
    assert_marker(&out, "MAP-GROUPBY-OK");
}

#[test]
fn set_intersection_union_difference() {
    let out = run_inline(
        r#"
        const a = new Set([1,2,3]);
        const b = new Set([2,3,4]);
        const inter = [...a.intersection(b)].sort().join(',');
        const uni = [...a.union(b)].sort().join(',');
        const diff = [...a.difference(b)].sort().join(',');
        if (inter === '2,3' && uni === '1,2,3,4' && diff === '1') console.log('SET-OP-OK');
        "#,
    );
    assert_marker(&out, "SET-OP-OK");
}

#[test]
fn set_subset_superset_disjoint_predicates() {
    let out = run_inline(
        r#"
        const small = new Set([1,2]);
        const big   = new Set([1,2,3]);
        const other = new Set([99]);
        if (small.isSubsetOf(big) && big.isSupersetOf(small) && small.isDisjointFrom(other))
            console.log('SET-PRED-OK');
        "#,
    );
    assert_marker(&out, "SET-PRED-OK");
}

// ---- URLPattern ------------------------------------------------------

#[test]
fn url_pattern_matches_named_segment() {
    let out = run_inline(
        r#"
        const p = new URLPattern({ pathname: '/users/:id' });
        const m = p.exec('https://x.com/users/42');
        if (m && m.pathname.groups.id === '42') console.log('URLP-OK');
        else console.log('URLP-FAIL', JSON.stringify(m));
        "#,
    );
    assert_marker(&out, "URLP-OK");
}

#[test]
fn url_pattern_rejects_non_match() {
    let out = run_inline(
        r#"
        const p = new URLPattern({ pathname: '/api/:resource' });
        if (!p.test('https://x.com/health')) console.log('URLP-NEG-OK');
        "#,
    );
    assert_marker(&out, "URLP-NEG-OK");
}

// ---- import.meta -----------------------------------------------------

#[test]
fn import_meta_dirname_filename_url() {
    use std::fs;
    let dir = std::env::temp_dir().join(format!(
        "burn_imeta_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let script = dir.join("entry.mjs");
    fs::write(
        &script,
        b"console.log('DIR=' + import.meta.dirname);\
          console.log('FILE=' + import.meta.filename);\
          console.log('URL-PREFIX=' + import.meta.url.startsWith('file://'));\
          console.log('RESOLVE-FN=' + (typeof import.meta.resolve));\n",
    )
    .unwrap();
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg(script.to_str().unwrap())
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn exited non-zero: {stdout}");
    assert!(stdout.contains("DIR="), "no DIR= line: {stdout}");
    assert!(stdout.contains("FILE="), "no FILE= line: {stdout}");
    assert!(
        stdout.contains("URL-PREFIX=true"),
        "url not file://: {stdout}"
    );
    assert!(
        stdout.contains("RESOLVE-FN=function"),
        "resolve not fn: {stdout}"
    );
}

// ---- util Node 22+ ---------------------------------------------------

#[test]
fn util_style_text_emits_ansi() {
    let out = run_inline(
        r#"
        const { styleText } = require('util');
        const s = styleText('red', 'hi', { validateStream: false });
        if (s.includes('\x1b[31m') && s.includes('hi') && s.includes('\x1b[39m'))
            console.log('STYLE-OK');
        "#,
    );
    assert_marker(&out, "STYLE-OK");
}

#[test]
fn util_mime_type_parses_essence_and_params() {
    let out = run_inline(
        r#"
        const { MIMEType } = require('util');
        const m = new MIMEType('Text/HTML; charset=utf-8; boundary="x y"');
        if (m.essence === 'text/html' && m.params.get('charset') === 'utf-8' &&
            m.params.get('boundary') === 'x y') console.log('MIME-OK');
        else console.log('MIME-FAIL', m.essence, m.params.get('charset'), m.params.get('boundary'));
        "#,
    );
    assert_marker(&out, "MIME-OK");
}

#[test]
fn util_parse_args_named_and_positionals() {
    let out = run_inline(
        r#"
        const { parseArgs } = require('util');
        const r = parseArgs({
            args: ['--name', 'x', '--flag', 'rest1', 'rest2'],
            options: { name: { type: 'string' }, flag: { type: 'boolean' } },
            allowPositionals: true,
        });
        if (r.values.name === 'x' && r.values.flag === true &&
            r.positionals.length === 2 && r.positionals[0] === 'rest1')
            console.log('PARSEARGS-OK');
        "#,
    );
    assert_marker(&out, "PARSEARGS-OK");
}

#[test]
fn util_aborted_resolves_on_signal() {
    let out = run_inline(
        r#"
        const { aborted } = require('util');
        const ac = new AbortController();
        aborted(ac.signal, {}).catch(() => console.log('ABORTED-OK'));
        ac.abort();
        "#,
    );
    assert_marker(&out, "ABORTED-OK");
}

// ---- net.BlockList / SocketAddress ----------------------------------

#[test]
fn net_block_list_address_range_subnet() {
    let out = run_inline(
        r#"
        const { BlockList } = require('net');
        const bl = new BlockList();
        bl.addAddress('10.0.0.1');
        bl.addRange('192.168.1.1', '192.168.1.255');
        bl.addSubnet('172.16.0.0', 12);
        if (bl.check('10.0.0.1') && bl.check('192.168.1.42') &&
            bl.check('172.16.5.5') && !bl.check('8.8.8.8'))
            console.log('BLOCKLIST-OK');
        "#,
    );
    assert_marker(&out, "BLOCKLIST-OK");
}

#[test]
fn net_socket_address_parse_ipv4() {
    let out = run_inline(
        r#"
        const { SocketAddress } = require('net');
        const sa = SocketAddress.parse('1.2.3.4:80');
        if (sa.address === '1.2.3.4' && sa.port === 80 && sa.family === 'ipv4')
            console.log('SADDR-OK');
        "#,
    );
    assert_marker(&out, "SADDR-OK");
}

// ---- worker_threads env data ----------------------------------------

#[test]
fn worker_threads_environment_data_roundtrips() {
    let out = run_inline(
        r#"
        const wt = require('worker_threads');
        wt.setEnvironmentData('k', { v: 1, s: 'x' });
        const got = wt.getEnvironmentData('k');
        if (got && got.v === 1 && got.s === 'x') console.log('WTENV-OK');
        "#,
    );
    assert_marker(&out, "WTENV-OK");
}

// ---- fs.statfsSync ---------------------------------------------------

#[test]
fn fs_statfs_sync_returns_filesystem_info_shape() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        const sf = fs.statfsSync('/tmp');
        if (typeof sf.bsize === 'number' && typeof sf.bfree === 'number' &&
            typeof sf.files === 'number') console.log('STATFS-OK');
        "#,
    );
    assert_marker(&out, "STATFS-OK");
}

// ---- zlib.zstd ------------------------------------------------------

#[test]
fn zlib_zstd_compress_and_decompress_round_trips() {
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        const data = Buffer.from('the quick brown fox '.repeat(64));
        const enc = zlib.zstdCompressSync(data);
        if (enc.length >= data.length) { console.log('FAIL no-compress', enc.length, data.length); process.exit(1); }
        const dec = zlib.zstdDecompressSync(enc);
        if (dec.toString('utf8') === data.toString('utf8')) console.log('ZSTD-OK');
        else console.log('ZSTD-FAIL');
        "#,
    );
    assert_marker(&out, "ZSTD-OK");
}

#[test]
fn zlib_zstd_async_promise_form() {
    let out = run_inline(
        r#"
        const zlib = require('zlib');
        const data = Buffer.from('async zstd round-trip');
        zlib.zstdCompress(data).then(zlib.zstdDecompress).then(b => {
            if (b.toString('utf8') === 'async zstd round-trip') console.log('ZSTD-ASYNC-OK');
        });
        "#,
    );
    assert_marker(&out, "ZSTD-ASYNC-OK");
}

// ---- http.Server[Symbol.asyncDispose] -------------------------------

#[test]
fn http_server_async_dispose_closes_listener() {
    let out = run_inline(
        r#"
        const http = require('http');
        const srv = http.createServer(() => {});
        const fn = srv[Symbol.asyncDispose];
        if (typeof fn === 'function') console.log('ASYNC-DISPOSE-OK');
        "#,
    );
    assert_marker(&out, "ASYNC-DISPOSE-OK");
}
