// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 vertexclique

//! End-to-end coverage for the NATIVE npm installer against a mock npm
//! registry (httpmock) - NO `npm` binary, NO process spawn, NO real
//! network. Proves the real install path: packument → version pick →
//! tarball download → integrity check → extract → transitive deps →
//! native rejection.

use afterburner_cloud::npm::NpmClient;
use flate2::write::GzEncoder;
use httpmock::prelude::*;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::io::Write;

/// Build a gzipped npm-style tarball (`package/<rel>` entries) and return
/// (bytes, sha1-hex) - the shasum the registry would advertise.
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
    {
        let mut e = GzEncoder::new(&mut gz, flate2::Compression::default());
        e.write_all(&tar_buf).unwrap();
        e.finish().unwrap();
    }
    let sha = hex(&Sha1::digest(&gz));
    (gz, sha)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn installs_a_package_with_transitive_dep_from_mock_registry() {
    let server = MockServer::start();

    // dependency `dep@1.2.0` (a leaf)
    let (dep_tar, dep_sha) = make_tarball(&[
        (
            "package.json",
            br#"{"name":"dep","version":"1.2.0","main":"index.js"}"#,
        ),
        ("index.js", b"module.exports = 7;"),
    ]);
    let dep_tarball_url = server.url("/dep/-/dep-1.2.0.tgz");
    server.mock(|when, then| {
        when.method(GET).path("/dep");
        then.status(200).json_body(serde_json::json!({
            "name": "dep",
            "versions": {
                "1.2.0": {
                    "name": "dep", "version": "1.2.0",
                    "dist": { "tarball": dep_tarball_url, "shasum": dep_sha }
                }
            }
        }));
    });
    server.mock(|when, then| {
        when.method(GET).path("/dep/-/dep-1.2.0.tgz");
        then.status(200).body(dep_tar);
    });

    // root `widget@2.0.1` depends on dep ^1.0.0
    let (w_tar, w_sha) = make_tarball(&[
        (
            "package.json",
            br#"{"name":"widget","version":"2.0.1","main":"index.js"}"#,
        ),
        ("index.js", b"module.exports = require('dep') + 1;"),
    ]);
    let w_tarball_url = server.url("/widget/-/widget-2.0.1.tgz");
    server.mock(|when, then| {
        when.method(GET).path("/widget");
        then.status(200).json_body(serde_json::json!({
            "name": "widget",
            "versions": {
                "1.5.0": {
                    "name": "widget", "version": "1.5.0",
                    "dist": { "tarball": "http://unused", "shasum": "00" },
                    "dependencies": { "dep": "^1.0.0" }
                },
                "2.0.1": {
                    "name": "widget", "version": "2.0.1",
                    "dist": { "tarball": w_tarball_url, "shasum": w_sha },
                    "dependencies": { "dep": "^1.0.0" }
                }
            }
        }));
    });
    server.mock(|when, then| {
        when.method(GET).path("/widget/-/widget-2.0.1.tgz");
        then.status(200).body(w_tar);
    });

    let client = NpmClient::new(server.base_url());
    let mut roots = BTreeMap::new();
    roots.insert("widget".to_string(), "^2.0.0".to_string()); // picks 2.0.1, not 1.5.0
    let res = client.resolve_all(&roots).expect("resolve");

    // both the root and its transitive dep are resolved + extracted
    let widget = res.packages.get("widget").expect("widget resolved");
    assert_eq!(widget.version, "2.0.1");
    assert_eq!(
        widget.files.get("index.js").map(|v| v.as_slice()),
        Some(&b"module.exports = require('dep') + 1;"[..])
    );
    let dep = res.packages.get("dep").expect("transitive dep resolved");
    assert_eq!(dep.version, "1.2.0");
    assert_eq!(
        dep.files.get("index.js").map(|v| v.as_slice()),
        Some(&b"module.exports = 7;"[..])
    );
}

#[test]
fn corrupt_tarball_fails_integrity_check() {
    let server = MockServer::start();
    let (_tar, real_sha) = make_tarball(&[("index.js", b"x")]);
    // advertise the real sha but serve different bytes
    let bad_tar = make_tarball(&[("index.js", b"TAMPERED")]).0;
    let url = server.url("/evil/-/evil-1.0.0.tgz");
    server.mock(|when, then| {
        when.method(GET).path("/evil");
        then.status(200).json_body(serde_json::json!({
            "name": "evil",
            "versions": { "1.0.0": { "name":"evil","version":"1.0.0",
                "dist": { "tarball": url, "shasum": real_sha } } }
        }));
    });
    server.mock(|when, then| {
        when.method(GET).path("/evil/-/evil-1.0.0.tgz");
        then.status(200).body(bad_tar);
    });

    let client = NpmClient::new(server.base_url());
    let mut roots = BTreeMap::new();
    roots.insert("evil".to_string(), "1.0.0".to_string());
    let err = client.resolve_all(&roots).unwrap_err();
    assert!(
        format!("{err}").contains("integrity"),
        "tampered tarball must fail integrity: {err}"
    );
}

#[test]
fn native_addon_in_npm_package_is_rejected() {
    let server = MockServer::start();
    let (tar, sha) = make_tarball(&[
        ("package.json", br#"{"name":"bcrypt","version":"5.0.0"}"#),
        ("index.js", b"module.exports = 1;"),
        ("build/Release/bcrypt.node", b"\0\0native"),
    ]);
    let url = server.url("/bcrypt/-/bcrypt-5.0.0.tgz");
    server.mock(|when, then| {
        when.method(GET).path("/bcrypt");
        then.status(200).json_body(serde_json::json!({
            "name": "bcrypt",
            "versions": { "5.0.0": { "name":"bcrypt","version":"5.0.0",
                "dist": { "tarball": url, "shasum": sha } } }
        }));
    });
    server.mock(|when, then| {
        when.method(GET).path("/bcrypt/-/bcrypt-5.0.0.tgz");
        then.status(200).body(tar);
    });

    let client = NpmClient::new(server.base_url());
    let mut roots = BTreeMap::new();
    roots.insert("bcrypt".to_string(), "^5.0.0".to_string());
    let err = client.resolve_all(&roots).unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("native"),
        "native addon must be rejected: {err}"
    );
}

#[test]
fn missing_package_is_a_clear_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/nope");
        then.status(404).body("not found");
    });
    let client = NpmClient::new(server.base_url());
    let mut roots = BTreeMap::new();
    roots.insert("nope".to_string(), "*".to_string());
    let err = client.resolve_all(&roots).unwrap_err();
    assert!(format!("{err}").contains("not found"), "got: {err}");
}
