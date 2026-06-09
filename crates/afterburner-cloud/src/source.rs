// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! A resolver [`Source`] backed by the live registry HTTP API. It turns
//! `GET /packages/{ns}/{name}` (the version list) plus the per-version metadata
//! (which carries the pinned dependency map) into the [`Candidate`] set the
//! [`crate::resolve`] solver consumes.

use crate::client::RegistryClient;
use crate::error::{CloudError, Result};
use crate::resolve::{Candidate, Req, Source};
use semver::Version;

/// Resolver [`Source`] over a [`RegistryClient`]: one `GET /packages/{ns}/{name}`
/// for the version list, then one `GET …/{ver}` per non-yanked version for its
/// pinned dependencies (the list endpoint omits them). The solver memoizes per
/// coord, so an install only ever touches its own subgraph.
pub struct RegistrySource<'a> {
    client: &'a RegistryClient,
}

impl<'a> RegistrySource<'a> {
    pub fn new(client: &'a RegistryClient) -> Self {
        Self { client }
    }
}

impl Source for RegistrySource<'_> {
    fn candidates(&self, coord: &str) -> Result<Vec<Candidate>> {
        let (ns, name) = coord
            .split_once('/')
            .ok_or_else(|| CloudError::BadCoord(format!("{coord:?} must be namespace/name")))?;
        let meta = self.client.get_package(ns, name)?;

        let mut out = Vec::with_capacity(meta.versions.len());
        for vs in &meta.versions {
            let version = Version::parse(&vs.version).map_err(|e| {
                CloudError::Resolve(format!(
                    "registry sent a non-semver version {:?} for {coord}: {e}",
                    vs.version
                ))
            })?;
            let runtime_min = parse_opt_version(vs.runtime_min.as_deref(), coord)?;

            // Yanked versions are never selected, so their deps are never read.
            let deps = if vs.yanked {
                Vec::new()
            } else {
                let vm = self.client.get_version(ns, name, &vs.version)?;
                deps_from_json(&vm.dependencies, coord)?
            };

            out.push(Candidate {
                version,
                digest: vs.digest.clone(),
                yanked: vs.yanked,
                runtime_min,
                deps,
            });
        }
        Ok(out)
    }
}

fn parse_opt_version(s: Option<&str>, coord: &str) -> Result<Option<Version>> {
    match s {
        None => Ok(None),
        Some(r) => Version::parse(r.trim())
            .map(Some)
            .map_err(|e| CloudError::Resolve(format!("bad runtime_min {r:?} for {coord}: {e}"))),
    }
}

/// Parse a dependency map (`"ns/name" -> "sha256:…"` or a semver range string)
/// into the resolver's `(coord, Req)` pairs.
fn deps_from_json(v: &serde_json::Value, coord: &str) -> Result<Vec<(String, Req)>> {
    let mut deps = Vec::new();
    if let Some(map) = v.as_object() {
        for (dcoord, val) in map {
            let spec = val.as_str().ok_or_else(|| {
                CloudError::Resolve(format!(
                    "{coord}: dependency {dcoord} value must be a string"
                ))
            })?;
            deps.push((dcoord.clone(), Req::parse(spec)?));
        }
    }
    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::resolve;
    use httpmock::prelude::*;
    use serde_json::json;

    fn rt() -> Version {
        Version::parse("1.0.0").unwrap()
    }

    #[test]
    fn lists_candidates_with_deps_and_skips_yanked_dep_fetch() {
        let server = MockServer::start();
        let pkg = server.mock(|when, then| {
            when.method(GET).path("/api/v1/packages/psila/a");
            then.status(200).json_body(json!({
                "namespace": "psila", "name": "a",
                "versions": [
                    {"version": "1.0.0", "digest": "aa", "yanked": false, "runtime_min": "0.1.0"},
                    {"version": "2.0.0", "digest": "bb", "yanked": true}
                ]
            }));
        });
        let v1 = server.mock(|when, then| {
            when.method(GET).path("/api/v1/packages/psila/a/1.0.0");
            then.status(200).json_body(json!({
                "namespace": "psila", "name": "a", "version": "1.0.0", "digest": "aa",
                "dependencies": {"psila/b": "sha256:cc"}
            }));
        });

        let client = RegistryClient::new(server.base_url(), None);
        let src = RegistrySource::new(&client);
        let cands = src.candidates("psila/a").unwrap();

        assert_eq!(cands.len(), 2);
        let v1c = cands
            .iter()
            .find(|c| c.version.to_string() == "1.0.0")
            .unwrap();
        assert_eq!(v1c.deps.len(), 1);
        assert_eq!(v1c.deps[0].0, "psila/b");
        assert!(matches!(v1c.deps[0].1, Req::Digest(_)));
        assert_eq!(v1c.runtime_min.as_ref().unwrap().to_string(), "0.1.0");
        let v2c = cands
            .iter()
            .find(|c| c.version.to_string() == "2.0.0")
            .unwrap();
        assert!(v2c.yanked && v2c.deps.is_empty());

        pkg.assert();
        v1.assert();
    }

    #[test]
    fn resolves_a_small_graph_end_to_end() {
        // a@1.0.0 depends on b (pinned by digest); b@1.0.0 is a leaf.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/packages/psila/a");
            then.status(200).json_body(json!({
                "namespace": "psila", "name": "a",
                "versions": [{"version": "1.0.0", "digest": "aa", "yanked": false}]
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/packages/psila/a/1.0.0");
            then.status(200).json_body(json!({
                "namespace": "psila", "name": "a", "version": "1.0.0", "digest": "aa",
                "dependencies": {"psila/b": "sha256:bb"}
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/packages/psila/b");
            then.status(200).json_body(json!({
                "namespace": "psila", "name": "b",
                "versions": [{"version": "1.0.0", "digest": "bb", "yanked": false}]
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/packages/psila/b/1.0.0");
            then.status(200).json_body(json!({
                "namespace": "psila", "name": "b", "version": "1.0.0", "digest": "bb",
                "dependencies": {}
            }));
        });

        let client = RegistryClient::new(server.base_url(), None);
        let src = RegistrySource::new(&client);
        let res = resolve(
            &[("psila/a".to_string(), Req::from_cli_version(None).unwrap())],
            &src,
            &rt(),
        )
        .unwrap();

        assert_eq!(res.selected.len(), 2);
        assert_eq!(res.selected["psila/a"].version.to_string(), "1.0.0");
        assert_eq!(res.selected["psila/b"].version.to_string(), "1.0.0");
        // b is a dependency of a, so it must load first.
        let pos = |c: &str| res.order.iter().position(|x| x == c).unwrap();
        assert!(pos("psila/b") < pos("psila/a"));
    }

    #[test]
    fn missing_package_surfaces_not_found() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/packages/psila/ghost");
            then.status(404).json_body(json!({"error": "not found"}));
        });
        let client = RegistryClient::new(server.base_url(), None);
        let src = RegistrySource::new(&client);
        assert!(matches!(
            src.candidates("psila/ghost"),
            Err(CloudError::NotFound)
        ));
    }
}
