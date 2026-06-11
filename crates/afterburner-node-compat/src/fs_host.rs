// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Filesystem host functions.
//!
//! Every call takes a [`Manifold`] and refuses access when the capability
//! is not granted. Paths are resolved via [`std::fs::canonicalize`] so
//! `..`/symlink traversal cannot escape the configured roots.

use afterburner_core::{AfterburnerError, FsAccess, Manifold, Result};
use std::path::{Component, Path, PathBuf};

/// Read the entire file at `path`.
pub fn read_file_sync(path: &str, m: &Manifold) -> Result<Vec<u8>> {
    let resolved = validate_read(path, &m.fs)?;
    std::fs::read(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.readFileSync({path}): {e}")))
}

/// Write `data` to `path`, creating or overwriting.
pub fn write_file_sync(path: &str, data: &[u8], m: &Manifold) -> Result<()> {
    let resolved = validate_write(path, &m.fs)?;
    std::fs::write(&resolved, data)
        .map_err(|e| AfterburnerError::Host(format!("fs.writeFileSync({path}): {e}")))
}

/// `true` if the path exists and is reachable under the active FS policy.
pub fn exists_sync(path: &str, m: &Manifold) -> bool {
    validate_read(path, &m.fs)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Stat: returns (size_bytes, is_file, is_dir, mtime_ms).
pub fn stat_sync(path: &str, m: &Manifold) -> Result<FileStat> {
    let resolved = validate_read(path, &m.fs)?;
    let meta = std::fs::metadata(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.statSync({path}): {e}")))?;
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Ok(FileStat {
        size: meta.len(),
        is_file: meta.is_file(),
        is_dir: meta.is_dir(),
        mtime_ms,
    })
}

pub fn readdir_sync(path: &str, m: &Manifold) -> Result<Vec<String>> {
    let resolved = validate_read(path, &m.fs)?;
    let iter = std::fs::read_dir(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.readdirSync({path}): {e}")))?;
    let mut names = Vec::new();
    for entry in iter {
        let e =
            entry.map_err(|e| AfterburnerError::Host(format!("fs.readdirSync({path}): {e}")))?;
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

pub fn mkdir_sync(path: &str, recursive: bool, m: &Manifold) -> Result<()> {
    let resolved = validate_write(path, &m.fs)?;
    let res = if recursive {
        std::fs::create_dir_all(&resolved)
    } else {
        std::fs::create_dir(&resolved)
    };
    res.map_err(|e| AfterburnerError::Host(format!("fs.mkdirSync({path}): {e}")))
}

pub fn unlink_sync(path: &str, m: &Manifold) -> Result<()> {
    let resolved = validate_write(path, &m.fs)?;
    std::fs::remove_file(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.unlinkSync({path}): {e}")))
}

pub fn rename_sync(from: &str, to: &str, m: &Manifold) -> Result<()> {
    let src = validate_write(from, &m.fs)?;
    let dst = validate_write(to, &m.fs)?;
    std::fs::rename(&src, &dst)
        .map_err(|e| AfterburnerError::Host(format!("fs.renameSync({from} → {to}): {e}")))
}

/// Read up to `len` bytes from `offset`. Backs `fs.createReadStream`.
pub fn read_chunk(path: &str, offset: u64, len: usize, m: &Manifold) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let resolved = validate_read(path, &m.fs)?;
    let mut f = std::fs::File::open(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.read_chunk({path}): {e}")))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| AfterburnerError::Host(format!("fs.read_chunk({path}): seek {e}")))?;
    let mut buf = vec![0u8; len];
    let n = f
        .read(&mut buf)
        .map_err(|e| AfterburnerError::Host(format!("fs.read_chunk({path}): read {e}")))?;
    buf.truncate(n);
    Ok(buf)
}

/// Write `data` at `offset`. Creates the file when missing. Backs
/// `fs.createWriteStream` (append-style; offset is supplied by JS).
pub fn write_chunk(path: &str, offset: u64, data: &[u8], m: &Manifold) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let resolved = validate_write(path, &m.fs)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.write_chunk({path}): {e}")))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| AfterburnerError::Host(format!("fs.write_chunk({path}): seek {e}")))?;
    f.write_all(data)
        .map_err(|e| AfterburnerError::Host(format!("fs.write_chunk({path}): write {e}")))
}

pub fn file_size(path: &str, m: &Manifold) -> Result<u64> {
    let resolved = validate_read(path, &m.fs)?;
    let meta = std::fs::metadata(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.size({path}): {e}")))?;
    Ok(meta.len())
}

/// Canonicalize `path` (resolves `..` segments + symlinks) and return
/// the absolute resolved path as a String. Backs `fs.realpath` /
/// `fs.realpathSync` / `fs.promises.realpath`.
pub fn realpath_sync(path: &str, m: &Manifold) -> Result<String> {
    let resolved = validate_read(path, &m.fs)?;
    let canon = std::fs::canonicalize(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.realpath({path}): {e}")))?;
    Ok(canon.to_string_lossy().into_owned())
}

/// Read the target of a symbolic link. Returns the literal stored
/// target (relative or absolute, as on disk) — does not canonicalise.
/// Backs `fs.readlinkSync` / `fs.readlink` / `fs.promises.readlink`.
///
/// The default `validate_read` canonicalises through symlinks, which
/// would resolve the link before we ever called `read_link` on it.
/// For symlink ops we validate the *parent* directory instead — the
/// symlink itself is allowed to point anywhere; the manifold only
/// gates which directories the caller can list.
pub fn readlink_sync(path: &str, m: &Manifold) -> Result<String> {
    use std::path::PathBuf;
    let requested = PathBuf::from(path);
    let absolute = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map(|c| c.join(&requested))
            .map_err(|e| AfterburnerError::Host(format!("fs.readlink: cwd: {e}")))?
    };
    // Canonicalise the parent so the manifold check sees the real
    // directory, not any sym-traversal trickery in the prefix.
    let parent = absolute
        .parent()
        .ok_or_else(|| AfterburnerError::Host(format!("fs.readlink({path}): no parent")))?;
    let parent_canon = std::fs::canonicalize(parent)
        .map_err(|e| AfterburnerError::Host(format!("fs.readlink({path}): parent: {e}")))?;
    // Run the parent through the same root-allow-list check as a read
    // so `Manifold::fs = ReadOnly([..])` still gates link inspection.
    let _ = validate_read(
        parent_canon.to_str().ok_or_else(|| {
            AfterburnerError::Host(format!("fs.readlink({path}): parent path utf8"))
        })?,
        &m.fs,
    )?;
    let final_path = parent_canon.join(
        absolute
            .file_name()
            .ok_or_else(|| AfterburnerError::Host(format!("fs.readlink({path}): no filename")))?,
    );
    let target = std::fs::read_link(&final_path)
        .map_err(|e| AfterburnerError::Host(format!("fs.readlink({path}): {e}")))?;
    Ok(target.to_string_lossy().into_owned())
}

/// Recursively copy `src` to `dst`. Files are written byte-for-byte;
/// directories are created on demand; nested entries recursed.
/// `force` overwrites existing destination files (matches Node's
/// `fs.cp({force: true})`); without `force`, existing files at the
/// destination cause an error.
///
/// Both `src` and `dst` go through `validate_write` so the active
/// FS manifold has to admit *both* paths — copying *out of* a
/// read-only root into a read-write one is allowed (read on src,
/// write on dst), so we use validate_read for src.
pub fn cp_recursive(src: &str, dst: &str, force: bool, m: &Manifold) -> Result<()> {
    let src_resolved = validate_read(src, &m.fs)?;
    let dst_resolved = validate_write(dst, &m.fs)?;
    cp_recursive_resolved(&src_resolved, &dst_resolved, force)
        .map_err(|e| AfterburnerError::Host(format!("fs.cp({src} → {dst}): {e}")))
}

fn cp_recursive_resolved(src: &Path, dst: &Path, force: bool) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let child_src = entry.path();
            let child_dst = dst.join(entry.file_name());
            cp_recursive_resolved(&child_src, &child_dst, force)?;
        }
    } else {
        if dst.exists() && !force {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination exists and force=false",
            ));
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

/// Directory entry returned by [`opendir_sync`] / `readdirSync({withFileTypes:
/// true})`. Carries enough info for `Dirent` to expose `isFile`/`isDirectory`/
/// `isSymbolicLink` without an extra per-entry stat call.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Enumerate `path` and return rich entries. Backs `fs.opendir`,
/// `fs.opendirSync`, `fs.promises.opendir`, and the `withFileTypes:
/// true` variant of `readdir(Sync)`.
pub fn opendir_sync(path: &str, m: &Manifold) -> Result<Vec<DirEntry>> {
    let resolved = validate_read(path, &m.fs)?;
    let iter = std::fs::read_dir(&resolved)
        .map_err(|e| AfterburnerError::Host(format!("fs.opendir({path}): {e}")))?;
    let mut out = Vec::new();
    for entry in iter {
        let e = entry.map_err(|e| AfterburnerError::Host(format!("fs.opendir({path}): {e}")))?;
        let ft = e
            .file_type()
            .map_err(|e| AfterburnerError::Host(format!("fs.opendir({path}): file_type {e}")))?;
        out.push(DirEntry {
            name: e.file_name().to_string_lossy().into_owned(),
            is_file: ft.is_file(),
            is_dir: ft.is_dir(),
            is_symlink: ft.is_symlink(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Watch event delivered to `fs.watch` listeners. Captures the
/// platform-agnostic minimum: a kind tag (`rename` or `change`) and
/// the affected file's basename relative to the watched root, matching
/// Node's `fs.FSWatcher` 'change' event signature.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    pub kind: WatchKind,
    pub filename: String,
}

#[derive(Debug, Clone, Copy)]
pub enum WatchKind {
    Rename,
    Change,
}

impl WatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WatchKind::Rename => "rename",
            WatchKind::Change => "change",
        }
    }
}

/// Single-shot poll for changes to `path`. Compares two stat snapshots
/// taken `interval_ms` apart and returns any deltas observed. This is
/// the polling-based fallback fs.watch — burn never installs an
/// inotify/kqueue/FSEvents subscription because:
///
/// 1. inotify file descriptors don't survive the Wasmtime instance
///    boundary cleanly (each engine instance gets its own caps);
/// 2. polling is platform-agnostic and works the same on every OS
///    Wasmtime supports;
/// 3. the audience for `fs.watch` inside burn (UDF/per-row scripts)
///    almost never needs sub-second latency.
///
/// Returns `Vec<WatchEvent>` so a single host call can surface both
/// 'rename' (mtime jump on the directory itself) and 'change' (mtime
/// jump on a child) deltas in one envelope.
pub fn watch_poll(path: &str, interval_ms: u32, m: &Manifold) -> Result<Vec<WatchEvent>> {
    let resolved = validate_read(path, &m.fs)?;
    let snap_a = snapshot_dir(&resolved);
    std::thread::sleep(std::time::Duration::from_millis(interval_ms as u64));
    let snap_b = snapshot_dir(&resolved);
    Ok(diff_snapshots(&snap_a, &snap_b))
}

#[derive(Default)]
struct DirSnapshot {
    /// (name, mtime_ms, size, kind) per child.
    entries: Vec<(String, u64, u64, char)>,
}

fn snapshot_dir(p: &Path) -> DirSnapshot {
    let mut snap = DirSnapshot::default();
    if let Ok(meta) = std::fs::metadata(p)
        && meta.is_file()
    {
        // Single-file watch: record the file itself with its
        // basename so diff still produces 'change' deltas.
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        snap.entries.push((name, mtime, meta.len(), 'F'));
        return snap;
    }
    if let Ok(iter) = std::fs::read_dir(p) {
        for e in iter.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let (mtime, size, kind) = match e.metadata() {
                Ok(meta) => {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    let kind = if meta.is_dir() {
                        'D'
                    } else if meta.is_file() {
                        'F'
                    } else {
                        '?'
                    };
                    (mtime, meta.len(), kind)
                }
                Err(_) => (0, 0, '?'),
            };
            snap.entries.push((name, mtime, size, kind));
        }
    }
    snap.entries.sort();
    snap
}

fn diff_snapshots(a: &DirSnapshot, b: &DirSnapshot) -> Vec<WatchEvent> {
    use std::collections::HashMap;
    let map_a: HashMap<&str, &(String, u64, u64, char)> =
        a.entries.iter().map(|e| (e.0.as_str(), e)).collect();
    let map_b: HashMap<&str, &(String, u64, u64, char)> =
        b.entries.iter().map(|e| (e.0.as_str(), e)).collect();
    let mut out = Vec::new();
    // Additions / deletions surface as 'rename' events to match Node.
    for name in map_b.keys() {
        if !map_a.contains_key(name) {
            out.push(WatchEvent {
                kind: WatchKind::Rename,
                filename: (*name).to_string(),
            });
        }
    }
    for name in map_a.keys() {
        if !map_b.contains_key(name) {
            out.push(WatchEvent {
                kind: WatchKind::Rename,
                filename: (*name).to_string(),
            });
        }
    }
    // Mtime/size deltas on persisted entries surface as 'change'.
    for (name, a_entry) in &map_a {
        if let Some(b_entry) = map_b.get(name)
            && (a_entry.1 != b_entry.1 || a_entry.2 != b_entry.2)
        {
            out.push(WatchEvent {
                kind: WatchKind::Change,
                filename: (*name).to_string(),
            });
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
pub struct FileStat {
    pub size: u64,
    pub is_file: bool,
    pub is_dir: bool,
    pub mtime_ms: u64,
}

/// Resolve `path` to an absolute, normalized PathBuf and ensure it lives
/// under one of the FS policy's roots. `None` / `ReadOnly` / `ReadWrite`
/// all allow reads when the policy admits it.
///
/// Redaction policy: permission-denied messages never echo the caller's
/// path. The user already knows what they asked for; logs captured in
/// shared sinks must not leak sensitive paths (`/home/user/.ssh/*`,
/// credential-file locations, etc.).
fn validate_read(path: &str, access: &FsAccess) -> Result<PathBuf> {
    let roots: &[PathBuf] = match access {
        FsAccess::None => {
            return Err(AfterburnerError::PermissionDenied(
                "fs read denied by manifold".into(),
            ));
        }
        FsAccess::ReadOnly(r) | FsAccess::ReadWrite(r) => r.as_slice(),
    };
    resolve_within(path, roots, "fs read")
}

fn validate_write(path: &str, access: &FsAccess) -> Result<PathBuf> {
    let roots: &[PathBuf] = match access {
        FsAccess::None => {
            return Err(AfterburnerError::PermissionDenied(
                "fs write denied by manifold".into(),
            ));
        }
        FsAccess::ReadOnly(_) => {
            return Err(AfterburnerError::PermissionDenied(
                "fs write denied: read-only policy".into(),
            ));
        }
        FsAccess::ReadWrite(r) => r.as_slice(),
    };
    resolve_within(path, roots, "fs write")
}

/// Normalize `path` (absolute form, no `..`, no symlink escape) and
/// verify it is inside one of the `roots`. If `roots` is empty, no root
/// constraint is applied (open policy from `Manifold::open`).
fn resolve_within(path: &str, roots: &[PathBuf], op: &str) -> Result<PathBuf> {
    let requested = PathBuf::from(path);
    let absolute = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map(|c| c.join(&requested))
            .map_err(|e| AfterburnerError::Host(format!("cwd: {e}")))?
    };

    // Canonicalize the path if it exists; otherwise canonicalize the
    // deepest existing ancestor and append the remainder. This lets us
    // validate write targets that don't yet exist.
    let canonical = canonicalize_with_fallback(&absolute);

    if !is_normalized(&canonical) {
        return Err(AfterburnerError::PermissionDenied(format!(
            "{op}: path has unresolved components"
        )));
    }

    if roots.is_empty() {
        return Ok(canonical);
    }

    for root in roots {
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.clone());
        if canonical.starts_with(&root_canon) {
            return Ok(canonical);
        }
    }

    Err(AfterburnerError::PermissionDenied(format!(
        "{op}: path outside allowed roots"
    )))
}

fn canonicalize_with_fallback(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let mut cursor: PathBuf = path.to_path_buf();
    let mut trailing: Vec<PathBuf> = Vec::new();
    while !cursor.exists() {
        if let Some(parent) = cursor.parent().map(|p| p.to_path_buf()) {
            let name = cursor.file_name().map(PathBuf::from).unwrap_or_default();
            trailing.push(name);
            cursor = parent;
        } else {
            return path.to_path_buf();
        }
    }
    let mut resolved = cursor.canonicalize().unwrap_or(cursor);
    while let Some(n) = trailing.pop() {
        resolved.push(n);
    }
    resolved
}

fn is_normalized(p: &Path) -> bool {
    !p.components().any(|c| matches!(c, Component::ParentDir))
}
