// SPDX-License-Identifier: Apache-2.0
//! Typed errors for `.afb` pack/unpack.
//!
//! Every hostile-input rejection path has its own variant so tests read as a
//! spec and callers (e.g. `burndb`) can map failures to precise host errors.

use thiserror::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, AfbError>;

/// Everything that can go wrong building or parsing an `.afb`.
#[derive(Debug, Error)]
pub enum AfbError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("compressed .afb is {size} bytes, exceeds the {max}-byte limit")]
    TooLarge { size: usize, max: usize },

    #[error("archive is corrupt: {0}")]
    Corrupt(String),

    #[error("decompressed payload exceeds the {0}-byte limit (possible zip bomb)")]
    DecompressedTooLarge(u64),

    #[error("entry {path:?} is {size} bytes, exceeds the {max}-byte per-entry limit")]
    EntryTooLarge { path: String, size: u64, max: u64 },

    #[error("archive has more than {max} entries")]
    TooManyEntries { max: usize },

    #[error("entry path escapes the archive root: {0:?}")]
    PathEscape(String),

    #[error("disallowed tar entry type for {0:?} (only regular files and dirs allowed)")]
    DisallowedEntryType(String),

    #[error("dependency {coord:?}: {detail}")]
    Dependency { coord: String, detail: String },

    #[error("native addon rejected: {detail}")]
    NativeAddon { detail: String },

    #[error("unsupported .afb format version {found} (this reader supports {supported})")]
    FormatVersion { found: String, supported: String },

    #[error("package requires an .afb reader >= {required}, but this reader is {running}")]
    ReaderTooOld { required: String, running: String },

    #[error("afb.toml is missing or invalid: {0}")]
    ManifestParse(String),

    #[error("manifold.json is missing or invalid: {0}")]
    ManifoldParse(String),

    #[error("required archive member missing: {0}")]
    MissingFile(&'static str),

    #[error("entry-point source {0:?} declared in afb.toml is not in the archive")]
    EntryMissing(String),

    #[error("package requires runtime >= {required}, but this engine is {running}")]
    RuntimeTooOld { required: String, running: String },

    #[error("invalid semver in afb.toml [runtime] min = {0:?}: {1}")]
    InvalidVersion(String, String),
}
