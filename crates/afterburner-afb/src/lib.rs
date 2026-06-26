// SPDX-License-Identifier: Apache-2.0
//! The `.afb` package format for Afterburner.
//!
//! An `.afb` is a zstd-compressed, `ustar` tar that bundles a JavaScript
//! module, its [`Manifest`], and its sandbox [`Manifold`] together. It is
//! **content-addressed**: the SHA-256 of the compressed bytes is the package
//! identity, the same key the runtime and registry use.
//!
//! This crate has no Wasmtime/rquickjs dependency. It reuses
//! [`afterburner_core::Manifold`] directly so a sealed manifest cannot widen
//! on a round trip.

pub mod digest;
pub mod error;
pub mod link;
pub mod lock;
pub mod manifest;
pub mod native;
pub mod pack;
pub mod resolve;
pub mod specifier;
pub mod unpack;
pub mod version;

pub use afterburner_core::Manifold;
pub use digest::{digest, hex};
pub use error::{AfbError, Result};
pub use lock::{Lock, parse_lock, render_lock};
pub use manifest::{DepReq, Manifest, parse_dep_req};
pub use resolve::Resolved;
pub use specifier::{
    GemClause, GemOp, GemRequirement, Pep440Clause, Pep440Op, Pep440Specifier,
    parse_gem_requirement, parse_pip_specifier,
};

use std::collections::BTreeMap;

/// `[format] version` is `"MAJOR.MINOR"`. The compatibility contract (see
/// `FORMAT.md`), modeled on Python wheels / npm / Cargo editions:
///
/// - **MAJOR** is the compatibility gate. A reader accepts only its own
///   major and **refuses any other major loudly** - never misparses a format
///   it does not understand. A breaking change (a field removed, repurposed,
///   or one that must not be ignored) bumps MAJOR.
/// - **MINOR** is additive-only. A reader accepts a *greater* minor (it just
///   doesn't act on fields it predates); new optional manifest fields or new
///   ignorable archive members bump MINOR.
/// - A package that needs a feature that is *not* safe to ignore sets
///   `[format] min_reader = "MAJOR.MINOR"` to force a hard fail on old
///   readers ([`AfbError::ReaderTooOld`]).
pub const FORMAT_MAJOR: u32 = 1;
/// Highest minor this reader knows. A package may declare a higher minor;
/// it is accepted (additive contract), this reader simply ignores anything
/// it postdates.
///
/// Changed from 0 to 1: additive - `[dependencies]` values may now be semver
/// range strings (e.g. `"^0.1.0"`) in addition to the existing `"sha256:<hex>"`
/// pins. Old readers tolerate the change because the field is descriptive and
/// never processed until `resolve_dep_closure`; `min_reader` is NOT bumped
/// (an old reader that cannot resolve ranges simply skips validation and the
/// built `.afb` always carries resolved `sha256:` pins).
///
/// Changed from 1 to 2: additive - an `.afb` may now include members under
/// `precompiled/<target>/main.wasm` (optional pre-compiled WASM modules), and
/// `[runtime] target` names the bundled target. Old readers silently skip
/// `precompiled/*` entries (they were already documented-ignorable); the entry
/// bytes still flow through the capped decoder so zip-bomb protection holds.
/// `min_reader` is NOT bumped: a package that ships only a `precompiled/`
/// member still requires source, and an old reader that ignores the module
/// simply runs the source as before.
///
/// Changed from 2 to 3: additive - an `.afb` may now carry `vendor/pip/*.whl`
/// and `vendor/gem/**` members (vendored Python wheels and Ruby gems), and
/// `[pip]`/`[gem]` manifest tables. Old readers (minor <= 2) skip the
/// `vendor/*` members (their `wanted` predicate does not match them) while the
/// entry bytes still flow through the capped decoder so zip-bomb protection
/// holds. `min_reader` is NOT bumped: a package that imports vendored wheels
/// will fail loudly at import on an old reader (mount produces nothing), never
/// silently produce wrong output. That loud failure satisfies the additive
/// contract.
pub const FORMAT_MINOR: u32 = 3;

/// This reader's `"MAJOR.MINOR"`.
pub fn reader_format_version() -> String {
    format!("{FORMAT_MAJOR}.{FORMAT_MINOR}")
}

/// Hard cap on a compressed `.afb`, mirroring the registry's published-package
/// limit (50 MiB). `from_bytes` rejects anything larger before touching zstd.
pub const MAX_AFB_BYTES: usize = 50 * 1024 * 1024;

/// Hard cap on total decompressed bytes - zip-bomb defense (§3.3: 256 MiB).
pub const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on a single tar entry. Smaller than the total so one entry can
/// never be the whole budget.
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// Hard cap on the number of tar entries (Step 35).
pub const MAX_ENTRIES: usize = 1000;

/// zstd decode window ceiling (2^24 = 16 MiB). Bounds decoder memory and
/// rejects archives crafted with an oversized window. Comfortably above the
/// window a level-19 pack produces, so legitimate packages decode fine.
pub const WINDOW_LOG_MAX: u32 = 24;

/// A parsed, verified `.afb` package.
///
/// Construction only happens through [`Afb::from_bytes`], so every `Afb`
/// in memory has already passed digest, size, path, and manifold checks.
// No `Eq`: `Manifest` carries `toml::Table` (TOML floats aren't `Eq`).
#[derive(Debug, Clone, PartialEq)]
pub struct Afb {
    /// SHA-256 of the exact compressed bytes this was parsed from.
    pub digest: [u8; 32],
    /// The `afb.toml` manifest.
    pub manifest: Manifest,
    /// The sandbox capability set, deserialized from `manifold.json` via the
    /// runtime's own `Manifold` type (no schema duplication).
    pub manifold: Manifold,
    /// `source/` files, keyed by their archive-relative path
    /// (e.g. `source/main.js`), sorted for reproducible iteration. Stored
    /// **byte-exact** so binary bundled assets (images, fonts, …) survive.
    pub source: BTreeMap<String, Vec<u8>>,
    /// Pre-compiled WASM modules (FORMAT_MINOR >= 2), keyed by their
    /// archive-relative path (e.g. `"precompiled/wasm32-wasip1/main.wasm"`).
    /// Empty for packages that carry no pre-compiled artifact. An `.afb` built
    /// without any `precompiled/` member unpacks to an empty map so callers
    /// need not branch on the minor version.
    pub precompiled: BTreeMap<String, Vec<u8>>,
    /// Vendored ecosystem artifacts (FORMAT_MINOR >= 3), keyed by their
    /// archive-relative path (e.g. `"vendor/pip/requests-2.31.0-py3-none-any.whl"`
    /// or `"vendor/gem/sinatra-3.1.0.gem"`). Empty for packages that carry no
    /// vendored artifacts. Populated by [`pack::Builder::vendor`] and materialized
    /// at run time by the Python and Ruby runners into their respective
    /// site-packages / load paths. An `.afb` with no `vendor/` members unpacks
    /// to an empty map so callers need not branch on the minor version.
    pub vendor: BTreeMap<String, Vec<u8>>,
}

impl Afb {
    /// Parse and fully verify a compressed `.afb` from memory.
    ///
    /// Hostile-input safe: enforces the compressed-size cap, a bounded zstd
    /// window, the decompressed-size cap (streamed, aborts early), entry and
    /// per-entry caps, and rejects path-escape / absolute / symlink /
    /// non-regular entries. The `runtime.min` gate is enforced against
    /// [`afterburner_core::VERSION`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        unpack::unpack(bytes)
    }

    /// The entry-point source named by `manifest.package.entry` (always JS, so
    /// UTF-8). Errors if the entry is missing or not valid UTF-8.
    pub fn entry_source(&self) -> Result<&str> {
        let bytes = self
            .source
            .get(&self.manifest.package.entry)
            .ok_or_else(|| AfbError::EntryMissing(self.manifest.package.entry.clone()))?;
        std::str::from_utf8(bytes).map_err(|_| {
            AfbError::Corrupt(format!(
                "entry {:?} is not UTF-8",
                self.manifest.package.entry
            ))
        })
    }

    /// Raw bytes of a bundled `source/` file by archive path (e.g.
    /// `source/assets/logo.png`), if present. Lets a package read its own
    /// bundled assets, binary or text.
    pub fn asset(&self, path: &str) -> Option<&[u8]> {
        self.source.get(path).map(Vec::as_slice)
    }

    /// `namespace/name` - the registry-facing package identifier.
    pub fn qualified_name(&self) -> String {
        format!(
            "{}/{}",
            self.manifest.package.namespace, self.manifest.package.name
        )
    }
}
