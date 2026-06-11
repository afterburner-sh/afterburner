// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Full end-to-end: the REAL `burn install` binary installs an npm
//! dependency declared in `afb.toml [npm]`, from a MOCK npm registry -
//! NO `npm` toolchain, NO process spawn, NO real network.
//!
//! Proves the whole glue: `burn install` reads `[npm]`, the native client
//! fetches the packument + tarball, integrity-checks, extracts, and writes
//! the package into the npm cache that the runtime linker reads from.

#![cfg(feature = "bin")]

use flate2::write::GzEncoder;
use httpmock::prelude::*;
use sha1::{Digest, Sha1};
use std::io::Write;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn make_tarball(files: &[(&str, &[u8])]) -> (Vec<u8>, String) {
    let mut tar_buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_buf);
        for (rel, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, format!("package/{rel}"), &body[..])
                .unwrap();
        }
        b.finish().unwrap();
    }
    let mut gz = Vec::new();
    let mut e = GzEncoder::new(&mut gz, flate2::Compression::default());
    e.write_all(&tar_buf).unwrap();
    e.finish().unwrap();
    let sha: String = Sha1::digest(&gz)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    (gz, sha)
}

#[test]
fn burn_install_fetches_npm_dep_from_afb_toml() {
    let server = MockServer::start();

    let (tar, sha) = make_tarball(&[
        (
            "package.json",
            br#"{"name":"leftpad","version":"1.3.0","main":"index.js"}"#,
        ),
        (
            "index.js",
            b"module.exports = (s, n) => String(s).padStart(n, '0');",
        ),
    ]);
    let tarball_url = server.url("/leftpad/-/leftpad-1.3.0.tgz");
    server.mock(|when, then| {
        when.method(GET).path("/leftpad");
        then.status(200).json_body(serde_json::json!({
            "name": "leftpad",
            "versions": { "1.3.0": {
                "name": "leftpad", "version": "1.3.0",
                "dist": { "tarball": tarball_url, "shasum": sha }
            }}
        }));
    });
    server.mock(|when, then| {
        when.method(GET).path("/leftpad/-/leftpad-1.3.0.tgz");
        then.status(200).body(tar);
    });

    // Scaffold a package and declare the npm dep.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("app");
    let init = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "init",
            dir.to_str().unwrap(),
            "--name",
            "app",
            "--namespace",
            "nyquist",
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let afb_toml = dir.join("afb.toml");
    let mut t = std::fs::read_to_string(&afb_toml).unwrap();
    t.push_str("\n[npm]\nleftpad = \"^1.0.0\"\n");
    std::fs::write(&afb_toml, t).unwrap();

    // Isolate the cache so the test is hermetic, and point the installer
    // at the mock registry.
    let cache = tmp.path().join("cache");
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_NPM_REGISTRY", server.base_url())
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

    // The package landed in the npm cache, extracted (no `package/` prefix),
    // and is byte-correct.
    let pkg_dir = cache.join("burn/npm/leftpad@1.3.0");
    assert!(
        pkg_dir.join(".burn-complete").exists(),
        "cache marker present"
    );
    let idx = std::fs::read_to_string(pkg_dir.join("index.js")).unwrap();
    assert!(idx.contains("padStart"), "extracted index.js: {idx}");
    assert!(pkg_dir.join("package.json").exists());
}

#[test]
fn burn_install_rejects_npm_native_addon() {
    let server = MockServer::start();
    let (tar, sha) = make_tarball(&[
        ("package.json", br#"{"name":"bcrypt","version":"5.1.0"}"#),
        ("index.js", b"module.exports = 1;"),
        ("build/Release/bcrypt.node", b"\0\0native"),
    ]);
    let url = server.url("/bcrypt/-/bcrypt-5.1.0.tgz");
    server.mock(|when, then| {
        when.method(GET).path("/bcrypt");
        then.status(200).json_body(serde_json::json!({
            "name": "bcrypt",
            "versions": { "5.1.0": { "name":"bcrypt","version":"5.1.0",
                "dist": { "tarball": url, "shasum": sha } } }
        }));
    });
    server.mock(|when, then| {
        when.method(GET).path("/bcrypt/-/bcrypt-5.1.0.tgz");
        then.status(200).body(tar);
    });

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("app");
    assert!(
        Command::new(BURN)
            .env("BURN_QUIET", "1")
            .args([
                "init",
                dir.to_str().unwrap(),
                "--name",
                "app",
                "--namespace",
                "nyquist"
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let afb_toml = dir.join("afb.toml");
    let mut t = std::fs::read_to_string(&afb_toml).unwrap();
    t.push_str("\n[npm]\nbcrypt = \"^5.0.0\"\n");
    std::fs::write(&afb_toml, t).unwrap();

    let cache = tmp.path().join("cache");
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_NPM_REGISTRY", server.base_url())
        .env("XDG_CACHE_HOME", &cache)
        .current_dir(&dir)
        .args(["install"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "install must fail on a native npm addon"
    );
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(
        msg.to_lowercase().contains("native"),
        "error must name native rejection: {msg}"
    );
}
