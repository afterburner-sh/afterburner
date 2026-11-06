// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Fence: the workspace and every example run on nuclei, so Tokio and the
//! hyper/h2/axum stack must never reappear in a lockfile, not even through a
//! dev-dependency. A hit names the dependency chain that pulled it in.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

/// Exact package names; the workspace's own renamed `afterburner-h2` is not `h2`.
const BANNED: &[&str] = &[
    "tokio",
    "tokio-util",
    "tokio-macros",
    "tokio-rustls",
    "hyper",
    "hyper-util",
    "h2",
    "axum",
];

fn dep_name(entry: &str) -> &str {
    entry.split_whitespace().next().unwrap_or(entry)
}

/// The dependency chain from a root package down to `banned`, shortest first.
fn chain(banned: &str, dependents: &BTreeMap<&str, BTreeSet<&str>>) -> String {
    let mut toward_banned: BTreeMap<&str, &str> = BTreeMap::new();
    let mut queue = VecDeque::from([banned]);
    let mut root = banned;
    while let Some(node) = queue.pop_front() {
        let Some(parents) = dependents.get(node) else {
            root = node;
            break;
        };
        for parent in parents {
            if *parent != banned && !toward_banned.contains_key(parent) {
                toward_banned.insert(parent, node);
                queue.push_back(parent);
            }
        }
    }
    let mut path = vec![root];
    let mut cur = root;
    while let Some(&next) = toward_banned.get(cur) {
        path.push(next);
        cur = next;
    }
    path.join(" -> ")
}

/// One line per banned package present in `lock`, naming its chain.
fn offenders(lock: &str) -> Vec<String> {
    let doc: toml::Table = lock.parse().expect("the lockfile must be valid TOML");
    let packages = doc
        .get("package")
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut names = BTreeSet::new();
    let mut dependents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for package in packages {
        let Some(name) = package.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        names.insert(name);
        let deps = package
            .get("dependencies")
            .and_then(|d| d.as_array())
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str());
        for dep in deps {
            dependents.entry(dep_name(dep)).or_default().insert(name);
        }
    }
    BANNED
        .iter()
        .copied()
        .filter(|banned| names.contains(banned))
        .map(|banned| format!("`{banned}` via {}", chain(banned, &dependents)))
        .collect()
}

fn lock_offenders(path: &Path) -> Vec<String> {
    let lock = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read lockfile {}: {e}", path.display()));
    offenders(&lock)
        .into_iter()
        .map(|o| format!("{}: {o}", path.display()))
        .collect()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collect_lockfiles(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read directory {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != "node_modules" {
                collect_lockfiles(&path, out);
            }
        } else if name == "Cargo.lock" {
            out.push(path);
        }
    }
}

#[test]
fn workspace_lockfile_has_no_tokio() {
    let found = lock_offenders(&workspace_root().join("Cargo.lock"));
    assert!(found.is_empty(), "Tokio is back:\n{}", found.join("\n"));
}

#[test]
fn example_lockfiles_have_no_tokio() {
    let mut locks = Vec::new();
    collect_lockfiles(&workspace_root().join("examples"), &mut locks);
    assert!(!locks.is_empty(), "no example lockfile found to check");
    let found: Vec<String> = locks.iter().flat_map(|l| lock_offenders(l)).collect();
    assert!(found.is_empty(), "Tokio is back:\n{}", found.join("\n"));
}

#[test]
fn detector_names_the_chain_and_ignores_afterburner_h2() {
    let lock = r#"
[[package]]
name = "app"
dependencies = ["afterburner-h2", "mock 1.0.0 (registry+https://x)"]

[[package]]
name = "afterburner-h2"

[[package]]
name = "mock"
dependencies = ["hyper-util"]

[[package]]
name = "hyper-util"
dependencies = ["tokio 1.0.0"]

[[package]]
name = "tokio"
"#;
    assert_eq!(
        offenders(lock),
        vec![
            "`tokio` via app -> mock -> hyper-util -> tokio".to_string(),
            "`hyper-util` via app -> mock -> hyper-util".to_string(),
        ]
    );
}
