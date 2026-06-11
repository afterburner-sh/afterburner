// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 vertexclique

//! Linked-source composition: turn a multi-file / dependency-bearing
//! package into ONE JavaScript source for engines that deliver a single
//! compiled module per package (the invoke envelope ships exactly one
//! bytecode blob).
//!
//! Dependencies are NOT packed in the `.afb` (cargo model): a package
//! carries only its own `source/**`. At LOAD time the linker composes
//! that source with its resolved dependencies - afb packages (digest-
//! pinned, from the burn cache) and npm packages (from the npm cache) -
//! into one source carrying the whole virtual tree as *data*:
//!
//! ```text
//! globalThis.__afb_files = JSON.parse("{ '/afb/source/main.js': …, … }");
//! globalThis.__afb_links = { "ns/dep": "/afb/burn_modules/ns/dep/source/main.js" };
//! module.exports = require("/afb/source/main.js");
//! ```
//!
//! The plenum `require()` consults `__afb_files` before the host
//! filesystem (a `/afb/…` path never reaches the fs bridge at all) and
//! `__afb_links` for bare dependency coordinates, so the full Node
//! resolution algorithm - package.json `exports`, the extension ladder,
//! caching, circular-require semantics - runs unchanged over the virtual
//! tree.
//!
//! ## Security model
//!
//! * **The manifold is untouched.** Everything in the composed source is
//!   inert data inside the sandbox; vendored npm code and dependency
//!   packages run under the ROOT package's manifold only. Network and
//!   real-filesystem access still go through the same host gates - a
//!   dependency can never widen the grants it runs under.
//! * **Digest pins are enforced here.** Every coordinate in
//!   `manifest.dependencies` (root's, and each dependency's own -
//!   transitively) must be present in `deps` with a content digest equal
//!   to its `sha256:…` pin, or composition fails. Substituting a
//!   different build of a dependency is structurally impossible.

use crate::{Afb, AfbError, Result, hex};
use std::collections::BTreeMap;

/// Virtual filesystem root the composed tree mounts under.
const VROOT: &str = "/afb";

impl Afb {
    /// Whether this package needs linked composition to run correctly on
    /// a single-bytecode engine: true when it declares dependencies or
    /// carries more than just its entry file.
    pub fn needs_linking(&self) -> bool {
        !self.manifest.dependencies.is_empty() || self.source.len() > 1
    }

    /// Compose this package plus its resolved dependencies into one JS
    /// source. Dependencies are NOT packed in the `.afb` (cargo model) -
    /// they are resolved + cached by `burn install` and passed here at
    /// load time:
    ///
    /// * `deps` - afb dependency packages, keyed by `namespace/name`. Each
    ///   must cover every coordinate in the manifest's `[dependencies]`
    ///   closure and is digest-checked against its pin. Mounted under
    ///   `/afb/burn_modules/<coord>/` and exposed by exact coordinate
    ///   through `__afb_links`.
    /// * `npm` - resolved npm packages as `(name, files)` where `files`
    ///   keys are package-root-relative (`index.js`, `lib/x.js`). Mounted
    ///   under `/afb/source/node_modules/<name>/`, so the package's own
    ///   `require('name')` resolves by the normal node_modules walk.
    ///
    /// Every npm file is native-rejected first: a `.node`/`.so`/etc. in a
    /// resolved npm tree fails composition (the WASM sandbox can't load
    /// it). Binary (non-UTF-8) files are skipped (not `require()`-able).
    pub fn linked_source(
        &self,
        deps: &[(&str, &Afb)],
        npm: &[(&str, &BTreeMap<String, Vec<u8>>)],
    ) -> Result<String> {
        let by_coord: BTreeMap<&str, &Afb> = deps.iter().map(|(c, a)| (*c, *a)).collect();
        if by_coord.len() != deps.len() {
            return Err(AfbError::Dependency {
                coord: "<deps>".into(),
                detail: "duplicate coordinate in dependency set".into(),
            });
        }

        validate_pins(&self.manifest.dependencies, &by_coord)?;
        for afb in by_coord.values() {
            validate_pins(&afb.manifest.dependencies, &by_coord)?;
        }

        let mut files: BTreeMap<String, String> = BTreeMap::new();
        add_tree(&mut files, &format!("{VROOT}/"), self);
        let mut links: BTreeMap<String, String> = BTreeMap::new();
        for (coord, afb) in &by_coord {
            let base = format!("{VROOT}/burn_modules/{coord}/");
            add_tree(&mut files, &base, afb);
            links.insert(
                (*coord).to_string(),
                format!("{base}{}", afb.manifest.package.entry),
            );
        }

        // Resolved npm packages mount inside the root package's virtual
        // node_modules so bare `require('name')` resolves normally.
        for (name, tree) in npm {
            crate::native::reject_native(tree.keys().map(String::as_str))?;
            let base = format!("{VROOT}/source/node_modules/{name}/");
            for (rel, bytes) in tree.iter() {
                if let Ok(text) = std::str::from_utf8(bytes) {
                    files.insert(format!("{base}{rel}"), text.to_string());
                }
            }
        }

        let entry = format!("{VROOT}/{}", self.manifest.package.entry);

        // Files ride as one JSON string parsed at startup (QuickJS's
        // native JSON.parse beats compiling a giant object literal).
        let files_json = serde_json::to_string(&files)
            .map_err(|e| AfbError::Corrupt(format!("vfs serialization failed: {e}")))?;
        let files_lit = serde_json::to_string(&files_json)
            .map_err(|e| AfbError::Corrupt(format!("vfs literal failed: {e}")))?;
        let links_json = serde_json::to_string(&links)
            .map_err(|e| AfbError::Corrupt(format!("links serialization failed: {e}")))?;
        let entry_lit = serde_json::to_string(&entry)
            .map_err(|e| AfbError::Corrupt(format!("entry literal failed: {e}")))?;

        Ok(format!(
            "globalThis.__afb_files = JSON.parse({files_lit});\n\
             globalThis.__afb_links = {links_json};\n\
             module.exports = require({entry_lit});\n"
        ))
    }
}

/// Map every UTF-8 file of `afb` into the virtual tree under `base`
/// (which ends with '/'). Archive keys are already root-relative
/// (`source/main.js`), so the virtual path is simply `base + key`.
fn add_tree(files: &mut BTreeMap<String, String>, base: &str, afb: &Afb) {
    for (path, bytes) in &afb.source {
        if let Ok(text) = std::str::from_utf8(bytes) {
            files.insert(format!("{base}{path}"), text.to_string());
        }
    }
}

/// Every pinned coordinate must be present with the exact pinned digest.
fn validate_pins(pins: &BTreeMap<String, String>, by_coord: &BTreeMap<&str, &Afb>) -> Result<()> {
    for (coord, pin) in pins {
        let dep = by_coord
            .get(coord.as_str())
            .ok_or_else(|| AfbError::Dependency {
                coord: coord.clone(),
                detail: "missing from the provided dependency set (the full \
                     transitive closure must be supplied)"
                    .into(),
            })?;
        let actual = format!("sha256:{}", hex(&dep.digest));
        if &actual != pin {
            return Err(AfbError::Dependency {
                coord: coord.clone(),
                detail: format!("digest pin mismatch: manifest pins {pin}, got {actual}"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::pack::Builder;
    use crate::{Afb, AfbError, Manifest, hex};
    use afterburner_core::Manifold;

    fn build(ns: &str, name: &str, files: &[(&str, &str)]) -> Afb {
        let manifest_toml = format!(
            r#"
[format]
version = "1.0"
[package]
name = "{name}"
namespace = "{ns}"
version = "0.1.0"
language = "javascript"
entry = "source/main.js"
[runtime]
min = "0.1.0"
"#
        );
        let manifest = Manifest::parse(&manifest_toml).unwrap();
        let mut b = Builder::new(manifest, Manifold::default());
        for (p, c) in files {
            b = b.source(*p, c.as_bytes().to_vec());
        }
        let (bytes, _) = b.build().unwrap();
        Afb::from_bytes(&bytes).unwrap()
    }

    fn with_dep(ns: &str, name: &str, dep_coord: &str, dep: &Afb) -> Afb {
        let manifest_toml = format!(
            r#"
[format]
version = "1.0"
[package]
name = "{name}"
namespace = "{ns}"
version = "0.1.0"
language = "javascript"
entry = "source/main.js"
[runtime]
min = "0.1.0"
[dependencies]
"{dep_coord}" = "sha256:{}"
"#,
            hex(&dep.digest)
        );
        let manifest = Manifest::parse(&manifest_toml).unwrap();
        let (bytes, _) = Builder::new(manifest, Manifold::default())
            .source(
                "source/main.js",
                format!("module.exports = () => require('{dep_coord}')();").into_bytes(),
            )
            .build()
            .unwrap();
        Afb::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn single_entry_needs_no_linking() {
        let a = build("t", "solo", &[("source/main.js", "module.exports = 1;")]);
        assert!(!a.needs_linking());
    }

    #[test]
    fn multi_file_and_deps_need_linking() {
        let a = build(
            "t",
            "multi",
            &[
                ("source/main.js", "module.exports = require('./util');"),
                ("source/util.js", "module.exports = 42;"),
            ],
        );
        assert!(a.needs_linking());
    }

    #[test]
    fn linked_source_maps_files_and_entry() {
        let a = build(
            "t",
            "multi",
            &[
                ("source/main.js", "module.exports = require('./util');"),
                ("source/util.js", "module.exports = 42;"),
            ],
        );
        let s = a.linked_source(&[], &[]).unwrap();
        assert!(s.contains("/afb/source/main.js"));
        assert!(s.contains("/afb/source/util.js"));
        assert!(s.ends_with("module.exports = require(\"/afb/source/main.js\");\n"));
        // deterministic
        assert_eq!(s, a.linked_source(&[], &[]).unwrap());
    }

    #[test]
    fn dependency_link_and_pin_enforced() {
        let dep = build(
            "t",
            "dep",
            &[("source/main.js", "module.exports = () => 7;")],
        );
        let root = with_dep("t", "root", "t/dep", &dep);
        let s = root.linked_source(&[("t/dep", &dep)], &[]).unwrap();
        assert!(s.contains("\"t/dep\":\"/afb/burn_modules/t/dep/source/main.js\""));

        // missing dep
        let err = root.linked_source(&[], &[]).unwrap_err();
        assert!(matches!(err, AfbError::Dependency { .. }));

        // wrong bytes under the same coordinate
        let imposter = build(
            "t",
            "dep",
            &[("source/main.js", "module.exports = () => 8;")],
        );
        let err = root
            .linked_source(&[("t/dep", &imposter)], &[])
            .unwrap_err();
        assert!(
            matches!(err, AfbError::Dependency { .. }),
            "pin must reject imposter"
        );
    }
}
