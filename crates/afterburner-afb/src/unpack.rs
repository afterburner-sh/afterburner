// SPDX-License-Identifier: Apache-2.0
//! Parsing and fully verifying a `.afb` (Step 35).
//!
//! Hostile-input safe. The decode pipeline is, in order:
//!
//! 1. compressed-size cap (before zstd is even touched);
//! 2. zstd decode with a **bounded window** (caps decoder memory, rejects
//!    window-bomb archives);
//! 3. a counting reader that **aborts at 256 MiB** of output (zip bomb),
//!    streamed straight into the tar reader (no full intermediate buffer);
//! 4. per-entry: count cap, size cap, path-escape / symlink / non-regular
//!    rejection;
//! 5. manifest parse + `[format] version` + `[runtime] min` gates;
//! 6. `Manifold` deserialized via the runtime's own type.

use crate::digest::digest;
use crate::error::{AfbError, Result};
use crate::manifest::Manifest;
use crate::version::check_runtime_min;
use crate::{
    Afb, MAX_AFB_BYTES, MAX_DECOMPRESSED_BYTES, MAX_ENTRIES, MAX_ENTRY_BYTES, Manifold,
    WINDOW_LOG_MAX,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Component, Path};
use std::rc::Rc;

/// Reader that counts bytes and trips a shared flag once the decompressed
/// total would exceed [`MAX_DECOMPRESSED_BYTES`]. The flag lets `unpack`
/// tell a zip bomb apart from ordinary corruption after the fact.
struct CappedReader<R> {
    inner: R,
    remaining: u64,
    tripped: Rc<Cell<bool>>,
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.remaining {
            self.tripped.set(true);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "afb: decompressed size cap exceeded",
            ));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Reject absolute paths, `..`, drive prefixes, and empty paths; return the
/// archive-relative path as a forward-slash string.
fn safe_rel_path(p: &Path) -> Result<String> {
    if p.is_absolute() {
        return Err(AfbError::PathEscape(p.display().to_string()));
    }
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => {
                let s = s
                    .to_str()
                    .ok_or_else(|| AfbError::PathEscape(p.display().to_string()))?;
                parts.push(s);
            }
            // `..`, `/`, `C:` — anything that could escape the root.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AfbError::PathEscape(p.display().to_string()));
            }
            Component::CurDir => {}
        }
    }
    if parts.is_empty() {
        return Err(AfbError::PathEscape(p.display().to_string()));
    }
    Ok(parts.join("/"))
}

pub(crate) fn unpack(bytes: &[u8]) -> Result<Afb> {
    if bytes.len() > MAX_AFB_BYTES {
        return Err(AfbError::TooLarge {
            size: bytes.len(),
            max: MAX_AFB_BYTES,
        });
    }

    let mut decoder =
        zstd::stream::read::Decoder::new(bytes).map_err(|e| AfbError::Corrupt(e.to_string()))?;
    // Bound decoder memory and reject oversized-window archives.
    decoder
        .set_parameter(zstd::stream::raw::DParameter::WindowLogMax(WINDOW_LOG_MAX))
        .map_err(|e| AfbError::Corrupt(e.to_string()))?;

    let tripped = Rc::new(Cell::new(false));
    let capped = CappedReader {
        inner: decoder,
        remaining: MAX_DECOMPRESSED_BYTES,
        tripped: Rc::clone(&tripped),
    };

    let mut archive = tar::Archive::new(capped);
    let mut manifest_toml: Option<String> = None;
    let mut manifold_json: Option<String> = None;
    let mut source: BTreeMap<String, String> = BTreeMap::new();

    let to_afb_err = |e: io::Error| {
        if tripped.get() {
            AfbError::DecompressedTooLarge(MAX_DECOMPRESSED_BYTES)
        } else {
            AfbError::Corrupt(e.to_string())
        }
    };

    let entries = archive.entries().map_err(&to_afb_err)?;
    let mut count = 0usize;
    for entry in entries {
        let mut entry = entry.map_err(&to_afb_err)?;

        count += 1;
        if count > MAX_ENTRIES {
            return Err(AfbError::TooManyEntries { max: MAX_ENTRIES });
        }

        let etype = entry.header().entry_type();
        let raw_path = entry.path().map_err(&to_afb_err)?;
        let display = raw_path.display().to_string();

        if etype.is_dir() {
            continue; // structural only; nothing to read
        }
        if !etype.is_file() {
            // symlink, hardlink, char/block/fifo, sparse, …
            return Err(AfbError::DisallowedEntryType(display));
        }

        let rel = safe_rel_path(&raw_path)?;

        let size = entry.header().size().map_err(&to_afb_err)?;
        if size > MAX_ENTRY_BYTES {
            return Err(AfbError::EntryTooLarge {
                path: rel,
                size,
                max: MAX_ENTRY_BYTES,
            });
        }

        // Only materialize what v0.1 consumes. Other regular files (e.g.
        // precompiled/*) are skipped — but their bytes still flow through
        // the capped decoder as the iterator advances, so a bomb hidden in
        // an ignored entry is still caught.
        let wanted = rel == "afb.toml" || rel == "manifold.json" || rel.starts_with("source/");
        if !wanted {
            continue;
        }

        let mut buf = Vec::with_capacity(size.min(64 * 1024) as usize);
        entry.read_to_end(&mut buf).map_err(&to_afb_err)?;

        match rel.as_str() {
            "afb.toml" => {
                manifest_toml = Some(
                    String::from_utf8(buf)
                        .map_err(|_| AfbError::ManifestParse("afb.toml is not UTF-8".into()))?,
                );
            }
            "manifold.json" => {
                manifold_json =
                    Some(String::from_utf8(buf).map_err(|_| {
                        AfbError::ManifoldParse("manifold.json is not UTF-8".into())
                    })?);
            }
            _ => {
                let text = String::from_utf8(buf)
                    .map_err(|_| AfbError::Corrupt(format!("source file {rel:?} is not UTF-8")))?;
                source.insert(rel, text);
            }
        }
    }

    let manifest_toml = manifest_toml.ok_or(AfbError::MissingFile("afb.toml"))?;
    let manifold_json = manifold_json.ok_or(AfbError::MissingFile("manifold.json"))?;

    let manifest = Manifest::parse(&manifest_toml)?;
    check_runtime_min(&manifest.runtime.min)?;

    let manifold: Manifold =
        serde_json::from_str(&manifold_json).map_err(|e| AfbError::ManifoldParse(e.to_string()))?;

    if !source.contains_key(&manifest.package.entry) {
        return Err(AfbError::EntryMissing(manifest.package.entry.clone()));
    }

    Ok(Afb {
        digest: digest(bytes),
        manifest,
        manifold,
        source,
    })
}
