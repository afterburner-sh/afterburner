// SPDX-License-Identifier: Apache-2.0
//! `afb.lock` - reproducible dependency lockfile.
//!
//! The lockfile records the full resolved closure produced by
//! [`crate::resolve::resolve_closure`]: one entry per coordinate with the
//! chosen version and its content digest. Reproducible builds read the lock
//! first; `pack` writes it when the lock is absent or stale.
//!
//! Format (TOML):
//! ```toml
//! lock_version = 1
//!
//! [[package]]
//! coord = "burn/geo"
//! version = "0.3.0"
//! digest = "sha256:aabb..."
//! ```

use crate::error::{AfbError, Result};
use crate::resolve::Resolved;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Lockfile format version. Bump on breaking changes to the on-disk schema.
pub const LOCK_VERSION: u32 = 1;

/// A single resolved package entry in the lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockEntry {
    pub coord: String,
    pub version: String,
    /// `"sha256:<64hex>"`.
    pub digest: String,
}

/// A parsed `afb.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub lock_version: u32,
    #[serde(rename = "package", default)]
    pub packages: Vec<LockEntry>,
}

/// Render a resolved closure to a canonical `afb.lock` TOML string.
pub fn render_lock(closure: &BTreeMap<String, Resolved>) -> String {
    let packages: Vec<LockEntry> = closure
        .iter()
        .map(|(coord, r)| LockEntry {
            coord: coord.clone(),
            version: r.version.to_string(),
            digest: format!("sha256:{}", crate::hex(&r.digest)),
        })
        .collect();
    let lock = Lock {
        lock_version: LOCK_VERSION,
        packages,
    };
    // toml::to_string always succeeds for this shape; the only way it could
    // fail is if a field contained a value that toml cannot encode (none here).
    toml::to_string(&lock).expect("lockfile serialization is infallible")
}

/// Parse an `afb.lock` from its TOML source.
pub fn parse_lock(src: &str) -> Result<Lock> {
    toml::from_str::<Lock>(src)
        .map_err(|e| AfbError::ManifestParse(format!("afb.lock parse error: {e}")))
}

impl Lock {
    /// Return true if every dep in `deps` is satisfied by an entry in this lock.
    ///
    /// A dep is satisfied when the lock has an entry for the coordinate whose
    /// recorded version/digest matches the declared range or pin:
    /// - Range: the lock entry's version must satisfy the semver requirement.
    /// - Pin: the lock entry's digest must equal the pin value.
    ///
    /// A dep with no matching lock entry is not satisfied.
    pub fn satisfies(&self, deps: &BTreeMap<String, String>) -> bool {
        use crate::manifest::{DepReq, parse_dep_req};
        for (coord, value) in deps {
            let req = match parse_dep_req(value) {
                Ok(r) => r,
                Err(_) => return false, // invalid dep value is never satisfied
            };
            let entry = match self.packages.iter().find(|e| &e.coord == coord) {
                Some(e) => e,
                None => return false, // coord not in lock
            };
            let ok = match req {
                DepReq::Pin(ref pin) => &entry.digest == pin,
                DepReq::Range(ref vreq) => match semver::Version::parse(&entry.version) {
                    Ok(v) => vreq.matches(&v),
                    Err(_) => false,
                },
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::Resolved;

    fn d(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn sample_closure() -> BTreeMap<String, Resolved> {
        let mut m = BTreeMap::new();
        m.insert(
            "burn/geo".into(),
            Resolved {
                version: semver::Version::parse("0.3.0").unwrap(),
                digest: d(1),
            },
        );
        m.insert(
            "burn/merkle".into(),
            Resolved {
                version: semver::Version::parse("1.2.0").unwrap(),
                digest: d(2),
            },
        );
        m
    }

    #[test]
    fn render_and_parse_roundtrip() {
        let closure = sample_closure();
        let rendered = render_lock(&closure);
        let lock = parse_lock(&rendered).expect("render -> parse roundtrip");
        assert_eq!(lock.lock_version, LOCK_VERSION);
        assert_eq!(lock.packages.len(), 2);
        // BTreeMap iteration is sorted, so packages are in order.
        assert_eq!(lock.packages[0].coord, "burn/geo");
        assert_eq!(lock.packages[0].version, "0.3.0");
        assert_eq!(
            lock.packages[0].digest,
            format!("sha256:{}", crate::hex(&d(1)))
        );
    }

    #[test]
    fn satisfies_range_matching() {
        let closure = sample_closure();
        let lock = parse_lock(&render_lock(&closure)).unwrap();

        let mut deps = BTreeMap::new();
        deps.insert("burn/geo".into(), "^0.3.0".into());
        assert!(lock.satisfies(&deps), "^0.3.0 should match 0.3.0");

        deps.insert("burn/geo".into(), "^0.4.0".into());
        assert!(!lock.satisfies(&deps), "^0.4.0 should not match 0.3.0");
    }

    #[test]
    fn satisfies_pin_matching() {
        let closure = sample_closure();
        let lock = parse_lock(&render_lock(&closure)).unwrap();

        let pin = format!("sha256:{}", crate::hex(&d(2)));
        let mut deps = BTreeMap::new();
        deps.insert("burn/merkle".into(), pin.clone());
        assert!(lock.satisfies(&deps), "exact pin should match");

        let wrong_pin = format!("sha256:{}", crate::hex(&d(99)));
        deps.insert("burn/merkle".into(), wrong_pin);
        assert!(!lock.satisfies(&deps), "wrong pin should not match");
    }

    #[test]
    fn satisfies_missing_coord_returns_false() {
        let closure = sample_closure();
        let lock = parse_lock(&render_lock(&closure)).unwrap();

        let mut deps = BTreeMap::new();
        deps.insert("burn/absent".into(), "^1.0.0".into());
        assert!(!lock.satisfies(&deps));
    }

    #[test]
    fn empty_deps_always_satisfied() {
        let lock = parse_lock(&render_lock(&BTreeMap::new())).unwrap();
        assert!(lock.satisfies(&BTreeMap::new()));
    }
}
