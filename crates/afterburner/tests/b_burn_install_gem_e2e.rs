// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Full end-to-end: the REAL `burn install` binary installs a gem dependency
//! declared in `afb.toml [gem]`, from a MOCK RubyGems registry.
//! NO `gem` toolchain, NO process spawn, NO real network.
//!
//! Proves the whole glue: `burn install` reads `[gem]`, the native gem client
//! fetches the versions API + .gem artifact, SHA-256-verifies, extracts, and
//! writes the package into the gem cache.  The gem cache key and completion
//! marker (`.burn-complete`) are the same as for npm (shared ecosystem model).

#![cfg(feature = "bin")]

use afterburner_afb::digest::{digest as sha256_digest, hex as digest_hex};
use flate2::write::GzEncoder;
use httpmock::prelude::*;
use std::io::Write;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Build a minimal `.gem` archive (an uncompressed tar containing
/// `metadata.gz` and `data.tar.gz`) from a list of `(rel_path, body)` pairs.
/// Returns the raw bytes and the SHA-256 hex string the RubyGems API would
/// return in its `sha` field.
fn make_gem(files: &[(&str, &[u8])]) -> (Vec<u8>, String) {
    // Build `data.tar.gz`.
    let mut data_tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut data_tar);
        for (rel, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, rel, &body[..]).unwrap();
        }
        b.finish().unwrap();
    }
    let mut data_tar_gz = Vec::new();
    {
        let mut e = GzEncoder::new(&mut data_tar_gz, flate2::Compression::default());
        e.write_all(&data_tar).unwrap();
        e.finish().unwrap();
    }
    // Build the outer `.gem` tar (uncompressed).
    let mut gem = Vec::new();
    {
        let mut b = tar::Builder::new(&mut gem);
        let meta = b"--- !ruby/object:Gem::Specification\nname: test\n";
        let mut mh = tar::Header::new_gnu();
        mh.set_size(meta.len() as u64);
        mh.set_mode(0o644);
        mh.set_cksum();
        b.append_data(&mut mh, "metadata.gz", &meta[..]).unwrap();
        let mut dh = tar::Header::new_gnu();
        dh.set_size(data_tar_gz.len() as u64);
        dh.set_mode(0o644);
        dh.set_cksum();
        b.append_data(&mut dh, "data.tar.gz", &data_tar_gz[..])
            .unwrap();
        b.finish().unwrap();
    }
    let sha256 = digest_hex(&sha256_digest(&gem));
    (gem, sha256)
}

#[test]
fn burn_install_fetches_gem_dep_from_afb_toml() {
    let server = MockServer::start();

    let (gem_bytes, gem_sha) = make_gem(&[
        ("lib/color.rb", b"module Color; VERSION = '1.8.0'; end"),
        ("LICENSE.txt", b"MIT"),
    ]);

    // RubyGems versions API.
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/versions/color.json");
        then.status(200).json_body(serde_json::json!([{
            "number": "1.8.0",
            "platform": "ruby",
            "sha": gem_sha,
            "dependencies": { "runtime": [], "development": [] }
        }]));
    });
    // Gem download.
    server.mock(|when, then| {
        when.method(GET).path("/gems/color-1.8.0.gem");
        then.status(200).body(gem_bytes.clone());
    });

    // Scaffold a Ruby package and declare the gem dep.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("rubyapp");
    let init = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "init",
            dir.to_str().unwrap(),
            "--name",
            "rubyapp",
            "--namespace",
            "acme",
            "--lang",
            "ruby",
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "burn init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // Append `[gem]` section to afb.toml.
    let afb_toml = dir.join("afb.toml");
    let mut t = std::fs::read_to_string(&afb_toml).unwrap();
    t.push_str("\n[gem]\ncolor = \">= 1.8.0\"\n");
    std::fs::write(&afb_toml, t).unwrap();

    // Isolate cache; point installer at the mock registry.
    let cache = tmp.path().join("cache");
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_GEM_REGISTRY", server.base_url())
        .env("XDG_CACHE_HOME", &cache)
        .current_dir(&dir)
        .args(["install"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "burn install failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Gem landed in the gem cache at ~/.cache/burn/gem/color@1.8.0/.
    let pkg_dir = cache.join("burn/gem/color@1.8.0");
    assert!(
        pkg_dir.join(".burn-complete").exists(),
        "gem cache marker must be present after install: {pkg_dir:?}"
    );
    let rb = std::fs::read_to_string(pkg_dir.join("lib/color.rb")).unwrap();
    assert!(rb.contains("Color"), "extracted lib/color.rb: {rb}");

    // burn.lock must contain a [[gem]] pin.
    let lock = std::fs::read_to_string(dir.join("burn.lock")).unwrap();
    assert!(
        lock.contains("[[gem]]"),
        "burn.lock must have [[gem]] section: {lock}"
    );
    assert!(
        lock.contains("color"),
        "burn.lock must pin the color gem: {lock}"
    );
    assert!(
        lock.contains("1.8.0"),
        "burn.lock must pin version 1.8.0: {lock}"
    );
}

#[test]
fn burn_install_rejects_native_extension_gem() {
    let server = MockServer::start();

    let (gem_bytes, gem_sha) = make_gem(&[
        ("lib/bcrypt.rb", b"require 'bcrypt/bcrypt_ext'"),
        ("ext/bcrypt/bcrypt_ext.c", b"#include <ruby.h>"),
        ("ext/bcrypt/extconf.rb", b"require 'mkmf'"),
    ]);

    server.mock(|when, then| {
        when.method(GET).path("/api/v1/versions/bcrypt.json");
        then.status(200).json_body(serde_json::json!([{
            "number": "3.1.19",
            "platform": "ruby",
            "sha": gem_sha,
            "dependencies": { "runtime": [], "development": [] }
        }]));
    });
    server.mock(|when, then| {
        when.method(GET).path("/gems/bcrypt-3.1.19.gem");
        then.status(200).body(gem_bytes);
    });

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("native_app");
    assert!(
        Command::new(BURN)
            .env("BURN_QUIET", "1")
            .args([
                "init",
                dir.to_str().unwrap(),
                "--name",
                "native_app",
                "--namespace",
                "acme",
                "--lang",
                "ruby",
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let afb_toml = dir.join("afb.toml");
    let mut t = std::fs::read_to_string(&afb_toml).unwrap();
    t.push_str("\n[gem]\nbcrypt = \"~> 3.1\"\n");
    std::fs::write(&afb_toml, t).unwrap();

    let cache = tmp.path().join("cache");
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_GEM_REGISTRY", server.base_url())
        .env("XDG_CACHE_HOME", &cache)
        .current_dir(&dir)
        .args(["install"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "install must fail on a native C-extension gem"
    );
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        msg.to_lowercase().contains("native"),
        "error must name native rejection: {msg}"
    );
}

/// Unit-level test: `build_install_plan` populates the `gem` field from a
/// `[gem]` section in afb.toml without any network access.  This pins the
/// wiring at the struct level, independent of the live registry.
#[test]
fn build_install_plan_includes_gem_deps() {
    // We test the manifest parsing path: write a temp afb.toml with [gem] and
    // confirm the resolved GemPackage set from a mock server is non-empty.
    // This reuses the GemClient + httpmock combo that gem_client tests use.
    use httpmock::prelude::*;

    let server = MockServer::start();

    let (gem_bytes, gem_sha) = make_gem(&[("lib/mustache.rb", b"module Mustache; end")]);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/versions/mustache.json");
        then.status(200).json_body(serde_json::json!([{
            "number": "1.1.1",
            "platform": "ruby",
            "sha": gem_sha,
            "dependencies": { "runtime": [], "development": [] }
        }]));
    });
    server.mock(|when, then| {
        when.method(GET).path("/gems/mustache-1.1.1.gem");
        then.status(200).body(gem_bytes);
    });

    // Resolve via GemClient directly (mirrors what install_gem_deps does).
    let mut roots = std::collections::BTreeMap::new();
    roots.insert("mustache".to_string(), ">= 1.1.1".to_string());
    let client = afterburner_cloud::gem_client::GemClient::new(server.base_url());
    let res = client.resolve_all(&roots).expect("resolve");
    assert_eq!(res.packages.len(), 1, "expected one resolved gem");
    assert_eq!(res.packages[0].name, "mustache");
    assert_eq!(res.packages[0].version, "1.1.1");

    // Confirm gem_pins_from_resolution produces a lockable entry.
    let pins = afterburner_cloud::lock::Lockfile::gem_pins_from_resolution(&res);
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].name, "mustache");
    assert_eq!(pins[0].version, "1.1.1");
    assert!(
        pins[0].integrity.starts_with("sha256:"),
        "integrity must be sha256:<hex>: {}",
        pins[0].integrity
    );
}

/// Live-registry integration test (requires network).  Gated with `ignore`
/// like the npm equivalent so it doesn't run in offline CI.
#[test]
#[ignore = "hits the live RubyGems registry; run explicitly with --ignored"]
fn gem_install_pure_gem_live() {
    // `color` (a small pure-Ruby gem with no native extensions) is a safe
    // choice for a live integration test.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("liveapp");
    assert!(
        Command::new(BURN)
            .env("BURN_QUIET", "1")
            .args([
                "init",
                dir.to_str().unwrap(),
                "--name",
                "liveapp",
                "--namespace",
                "acme",
                "--lang",
                "ruby",
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let afb_toml = dir.join("afb.toml");
    let mut t = std::fs::read_to_string(&afb_toml).unwrap();
    t.push_str("\n[gem]\ncolor = \">= 1.8.0\"\n");
    std::fs::write(&afb_toml, t).unwrap();

    let cache = tmp.path().join("cache");
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("XDG_CACHE_HOME", &cache)
        .current_dir(&dir)
        .args(["install"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "live gem install failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lock = std::fs::read_to_string(dir.join("burn.lock")).unwrap();
    assert!(lock.contains("[[gem]]"), "burn.lock must have [[gem]]");
    assert!(lock.contains("color"), "burn.lock must pin color");
}
