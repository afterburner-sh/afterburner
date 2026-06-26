// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! In-memory virtual filesystem for Emscripten-compiled modules.
//!
//! ## Design
//!
//! A single `InMemFs` holds:
//!
//! - A path tree: `HashMap<String, FsNode>` where each key is an absolute,
//!   canonicalized path (no trailing `/`, no double slashes). The root `/`
//!   itself is always a `Dir` entry.
//! - A file-descriptor table: `Vec<Option<FdEntry>>` indexed by fd number.
//!   fds 0/1/2 (stdin/stdout/stderr) are reserved as `None` so that open()
//!   never hands them out and close()/read() return EBADF for them.
//!
//! ## Errno values (musl/Linux for wasm32-emscripten)
//!
//! These are the negative values returned by `__syscall_*` functions:
//!
//! - `-2`  ENOENT  - no such file or directory
//! - `-9`  EBADF   - bad file descriptor
//! - `-20` ENOTDIR - not a directory
//! - `-21` EISDIR  - is a directory
//! - `-22` EINVAL  - invalid argument
//! - `-28` ENOSPC  - no space left (not used here)
//! - `-38` ENOSYS  - function not implemented
//! - `-59` ENOTTY  - not a tty (returned by ioctl TIOCGWINSZ etc.)
//!
//! ## Emscripten stat buffer layout (doStat, little-endian)
//!
//! This is the layout Emscripten's `doStat()` function writes into the guest
//! buffer passed to `__syscall_stat64` / `__syscall_fstat64` / etc. It is
//! NOT the musl C `struct stat` layout; it is Emscripten's internal JS-FS
//! format, verified against `pyodide.asm.js` (Pyodide 0.26.4):
//!
//! ```text
//! offset  size  field
//!  0       4    st_dev (i32)
//!  4       4    st_mode (i32)          <- CPython reads this to detect file/dir
//!  8       4    st_nlink (u32)
//!  12      4    st_uid (i32)
//!  16      4    st_gid (i32)
//!  20      4    st_rdev (i32)
//!  24      8    st_size (i64)          <- CPython reads this for file size
//!  32      4    st_blksize (i32, 4096)
//!  36      4    st_blocks (i32)
//!  40      8    st_atim tv_sec (i64)
//!  48      4    st_atim tv_nsec (u32)
//!  52      4    padding
//!  56      8    st_mtim tv_sec (i64)
//!  64      4    st_mtim tv_nsec (u32)
//!  68      4    padding
//!  72      8    st_ctim tv_sec (i64)
//!  80      4    st_ctim tv_nsec (u32)
//!  84      4    padding
//!  88      8    st_ino (i64)           <- inode at end
//!  96      -    end
//! ```
//!
//! Source: `SYSCALLS.doStat` in `pyodide.asm.js` (Pyodide 0.26.4):
//! ```js
//! HEAP32[buf>>2]=stat.dev;          // +0
//! HEAP32[buf+4>>2]=stat.mode;       // +4
//! HEAPU32[buf+8>>2]=stat.nlink;     // +8
//! HEAP32[buf+12>>2]=stat.uid;       // +12
//! HEAP32[buf+16>>2]=stat.gid;       // +16
//! HEAP32[buf+20>>2]=stat.rdev;      // +20
//! HEAP64[buf+24>>3]=BigInt(stat.size); // +24
//! HEAP32[buf+32>>2]=4096;           // +32
//! HEAP32[buf+36>>2]=stat.blocks;    // +36
//! HEAP64[buf+40>>3]=...atime sec;   // +40
//! HEAPU32[buf+48>>2]=...atime nsec; // +48
//! HEAP64[buf+56>>3]=...mtime sec;   // +56
//! HEAPU32[buf+64>>2]=...mtime nsec; // +64
//! HEAP64[buf+72>>3]=...ctime sec;   // +72
//! HEAPU32[buf+80>>2]=...ctime nsec; // +80
//! HEAP64[buf+88>>3]=BigInt(stat.ino); // +88
//! ```
//!
//! ## getdents64 layout (musl `struct linux_dirent64`, wasm32)
//!
//! ```text
//! offset  size  field
//!  0       8    d_ino (u64)
//!  8       8    d_off (u64, next entry offset - used as opaque cookie)
//!  16      2    d_reclen (u16, total length of this entry incl. padding)
//!  18      1    d_type (u8: 4=DT_DIR, 8=DT_REG)
//!  19      1+   d_name (null-terminated, padded to align to 8 bytes)
//! ```

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::emscripten_syscall::EM_STAT_STRUCT_BYTES;
use crate::pyo_trace;

// ---- errno constants ---------------------------------------------------------

/// ENOENT: no such file or directory.
pub const ENOENT: i32 = -2;
/// EACCES: permission denied (write outside a rw-preopen).
pub const EACCES: i32 = -13;
/// EBADF: bad file descriptor.
pub const EBADF: i32 = -9;
/// ENOTDIR: not a directory.
pub const ENOTDIR: i32 = -20;
/// EISDIR: is a directory.
pub const EISDIR: i32 = -21;
/// EINVAL: invalid argument.
pub const EINVAL: i32 = -22;
/// ENOTTY: not a tty (ioctl on non-terminal fd).
pub const ENOTTY: i32 = -59;

// ---- O_FLAGS for openat -----------------------------------------------------

const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 64;
const O_TRUNC: i32 = 512;

// ---- stat mode bits ---------------------------------------------------------

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IRWXU: u32 = 0o000_755;

// ---- fs node ---------------------------------------------------------------

/// One node in the in-memory filesystem tree.
#[derive(Clone, Debug)]
pub enum FsNode {
    /// A regular file with its byte contents.
    File(Vec<u8>),
    /// A directory (children are tracked by path prefix in the parent map).
    Dir,
}

// ---- file-descriptor entry --------------------------------------------------

/// An open file-descriptor referencing a path and a read offset.
#[derive(Clone, Debug)]
pub struct FdEntry {
    pub path: String,
    /// Byte offset for file reads (unused for directory fds).
    pub offset: u64,
    /// For directory fds: how many entries (including "." and "..") have
    /// already been returned by `getdents64_into`. 0 on first call.
    pub dir_cursor: usize,
}

// ---- the filesystem --------------------------------------------------------

/// In-memory filesystem: a flat map from absolute canonical path to node, plus
/// a file-descriptor table.
///
/// Host passthrough: fds whose fd number appears in `host_fds` route I/O to
/// the real host filesystem via `std::fs::File`. All other fds stay in-memory.
/// The fd number is allocated by the normal `alloc_fd` path (the `fds` table
/// still holds the path + metadata); the host file is kept separately so the
/// single fd namespace is shared and `fd_path` / `stat` on a host-backed fd
/// still works via the path stored in `fds`.
pub struct InMemFs {
    /// Absolute path -> node. Keys are canonical: no trailing `/`, single slash.
    /// The root entry is `"/"` -> `Dir`.
    nodes: HashMap<String, FsNode>,
    /// File-descriptor table. Index 0/1/2 are permanently `None` (reserved for
    /// stdin/stdout/stderr so open() never issues them).
    fds: Vec<Option<FdEntry>>,
    /// Host-backed fds. When an fd appears here, reads and writes go to the
    /// real `std::fs::File` rather than the in-memory node. The fd still has
    /// an entry in `fds` for the path and metadata.
    host_fds: HashMap<i32, std::fs::File>,
    /// Next inode number (incrementing counter, non-zero, non-persistent).
    next_ino: u64,
}

impl Default for InMemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemFs {
    /// Create an empty filesystem with just the root directory.
    ///
    /// fd 0/1/2 are reserved (stdin/stdout/stderr). No preopened dirs.
    pub fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert("/".to_owned(), FsNode::Dir);
        Self {
            nodes,
            fds: vec![None, None, None], // reserve 0/1/2
            host_fds: HashMap::new(),
            next_ino: 1,
        }
    }

    /// Create a filesystem with `/` preopened at fd 3.
    ///
    /// WASI host implementations expose preopened directories so the guest can
    /// call `fd_prestat_get`/`path_open`. Preopening `/` at fd 3 means CPython
    /// can discover and open stdlib files via `path_open(base=3, path=...)`.
    /// After the preopen, the next file opened via `InMemFs::open` gets fd 4+.
    pub fn new_with_root_preopen() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert("/".to_owned(), FsNode::Dir);
        // fd 3 = preopened root "/".
        let fds = vec![
            None,
            None,
            None,
            Some(FdEntry {
                path: "/".to_owned(),
                offset: 0,
                dir_cursor: 0,
            }),
        ];
        Self {
            nodes,
            fds,
            host_fds: HashMap::new(),
            next_ino: 1,
        }
    }

    /// Return the path and name of the preopened directory at `fd`, or `None`
    /// if the fd is not a preopened directory (for `fd_prestat_get`).
    ///
    /// In our implementation fd 3 is always the preopened root `/`.
    pub fn preopen_name(&self, fd: i32) -> Option<&str> {
        if fd == 3 {
            // fd 3 is always the preopened root.
            if let Some(Some(entry)) = self.fds.get(3)
                && entry.path == "/"
            {
                return Some("/");
            }
        }
        None
    }

    /// Node metadata for WASI `path_filestat_get`.
    pub fn node_info(&mut self, abs_path: &str) -> Option<NodeInfo> {
        let node = self.nodes.get(abs_path)?;
        let (filetype, size) = match node {
            FsNode::Dir => (3u8, 0u64),
            FsNode::File(data) => (4u8, data.len() as u64),
        };
        let ino = self.alloc_ino();
        Some(NodeInfo {
            ino,
            filetype,
            size,
        })
    }

    // ---- internal helpers ---------------------------------------------------

    fn alloc_ino(&mut self) -> u64 {
        let v = self.next_ino;
        self.next_ino += 1;
        v
    }

    /// Resolve `path` relative to `dirfd_path` (a directory path for AT_FDCWD
    /// or an absolute path already set by the caller). Returns the canonical
    /// absolute path string.
    pub fn resolve(&self, base: &str, path: &str) -> String {
        if path.starts_with('/') {
            canonicalize(path)
        } else {
            canonicalize(&format!("{base}/{path}"))
        }
    }

    /// Ensure a directory at `abs_path` exists (creates all intermediate dirs).
    pub fn mkdir_p(&mut self, abs_path: &str) {
        // Walk each prefix segment.
        let path = canonicalize(abs_path);
        let mut cur = String::new();
        for part in path.split('/') {
            if part.is_empty() {
                cur.push('/');
                self.nodes.entry("/".to_owned()).or_insert(FsNode::Dir);
                continue;
            }
            if cur == "/" {
                cur.push_str(part);
            } else {
                cur.push('/');
                cur.push_str(part);
            }
            self.nodes.entry(cur.clone()).or_insert(FsNode::Dir);
        }
    }

    /// Insert a file at `abs_path` with `contents`. Creates parent dirs.
    pub fn insert_file(&mut self, abs_path: &str, contents: Vec<u8>) {
        let path = canonicalize(abs_path);
        // Ensure parent exists.
        if let Some(parent) = parent_of(&path) {
            self.mkdir_p(&parent);
        }
        self.nodes.insert(path, FsNode::File(contents));
    }

    /// Look up a node by its absolute canonical path.
    pub fn get(&self, abs_path: &str) -> Option<&FsNode> {
        self.nodes.get(abs_path)
    }

    /// Allocate a new fd for `path`.
    ///
    /// Supports `O_CREAT` (create if absent), `O_TRUNC` (truncate on open),
    /// and `O_WRONLY` / `O_RDWR`. Parent directories are created when
    /// `O_CREAT` is set.
    ///
    /// Returns the fd, or ENOENT/EISDIR as appropriate.
    pub fn open(&mut self, path: String, flags: i32) -> i32 {
        let want_write = flags & O_WRONLY != 0 || flags & O_RDWR != 0;
        let creat = flags & O_CREAT != 0;
        let trunc = flags & O_TRUNC != 0;

        match self.nodes.get(&path) {
            None if creat => {
                // Create a new empty file. Ensure parent directory exists.
                if let Some(parent) = parent_of(&path) {
                    self.mkdir_p(&parent);
                }
                self.nodes.insert(path.clone(), FsNode::File(Vec::new()));
                self.alloc_fd(path)
            }
            None => ENOENT,
            Some(FsNode::Dir) => {
                if want_write {
                    return EISDIR;
                }
                self.alloc_fd(path)
            }
            Some(FsNode::File(_)) => {
                if trunc && want_write {
                    self.nodes.insert(path.clone(), FsNode::File(Vec::new()));
                }
                self.alloc_fd(path)
            }
        }
    }

    fn alloc_fd(&mut self, path: String) -> i32 {
        let entry = FdEntry {
            path: path.clone(),
            offset: 0,
            dir_cursor: 0,
        };
        // Reuse a slot if one is free, starting from index 3 to preserve
        // the 0/1/2 reservation for stdin/stdout/stderr. Skip slots whose fd
        // number is still live in host_fds as a defensive guard.
        for (i, slot) in self.fds.iter_mut().enumerate().skip(3) {
            if slot.is_none() && !self.host_fds.contains_key(&(i as i32)) {
                *slot = Some(entry);
                return i as i32;
            }
        }
        let fd = self.fds.len() as i32;
        self.fds.push(Some(entry));
        fd
    }

    /// Read up to `len` bytes from the fd at its current offset into `dst`.
    /// Returns bytes read, or a negative errno.
    pub fn read(&mut self, fd: i32, dst: &mut [u8]) -> i32 {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            return EBADF;
        }
        let (path, offset) = match &self.fds[fd_usize] {
            None => return EBADF,
            Some(e) => (e.path.clone(), e.offset),
        };
        match self.nodes.get(&path) {
            None => ENOENT,
            Some(FsNode::Dir) => EISDIR,
            Some(FsNode::File(data)) => {
                let start = offset.min(data.len() as u64) as usize;
                let available = data.len() - start;
                let n = dst.len().min(available);
                dst[..n].copy_from_slice(&data[start..start + n]);
                self.fds[fd_usize].as_mut().unwrap().offset += n as u64;
                n as i32
            }
        }
    }

    /// Append `data` to the file referenced by `fd`, advancing the offset.
    /// Returns bytes written, or a negative errno.
    pub fn write(&mut self, fd: i32, data: &[u8]) -> i32 {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            return EBADF;
        }
        let path = match &self.fds[fd_usize] {
            None => return EBADF,
            Some(e) => e.path.clone(),
        };
        match self.nodes.get_mut(&path) {
            None => ENOENT,
            Some(FsNode::Dir) => EISDIR,
            Some(FsNode::File(buf)) => {
                buf.extend_from_slice(data);
                let n = data.len();
                self.fds[fd_usize].as_mut().unwrap().offset += n as u64;
                n as i32
            }
        }
    }

    /// Return the contents of the file at `abs_path`, or `None` if absent/dir.
    pub fn read_file(&self, abs_path: &str) -> Option<&[u8]> {
        match self.nodes.get(abs_path) {
            Some(FsNode::File(data)) => Some(data.as_slice()),
            _ => None,
        }
    }

    /// Seek the fd. whence: 0=SEEK_SET, 1=SEEK_CUR, 2=SEEK_END.
    /// Returns new offset (i64), or EBADF/EINVAL.
    pub fn lseek(&mut self, fd: i32, offset: i64, whence: i32) -> i64 {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            return EBADF as i64;
        }
        let (path, cur_offset) = match &self.fds[fd_usize] {
            None => return EBADF as i64,
            Some(e) => (e.path.clone(), e.offset),
        };
        let file_len = match self.nodes.get(&path) {
            None | Some(FsNode::Dir) => 0u64,
            Some(FsNode::File(data)) => data.len() as u64,
        };
        let new_offset = match whence {
            0 => offset, // SEEK_SET
            1 => (cur_offset as i64).saturating_add(offset),
            2 => (file_len as i64).saturating_add(offset),
            _ => return EINVAL as i64,
        };
        if new_offset < 0 {
            return EINVAL as i64;
        }
        self.fds[fd_usize].as_mut().unwrap().offset = new_offset as u64;
        new_offset
    }

    /// Close a file descriptor. Returns 0 or EBADF.
    pub fn close(&mut self, fd: i32) -> i32 {
        let fd_usize = fd as usize;
        // Never close the reserved fds 0/1/2.
        if fd_usize < 3 || fd_usize >= self.fds.len() {
            return EBADF;
        }
        if self.fds[fd_usize].is_none() {
            return EBADF;
        }
        self.fds[fd_usize] = None;
        // Drop the host File handle if this was a host-backed fd.
        self.host_fds.remove(&fd);
        0
    }

    /// WASI `fd_close` variant used by the WASI `fd_close` import.
    ///
    /// Python's threading / subprocess machinery issues a bulk `fd_close` sweep
    /// over all open fds when it starts a subprocess or resets the interpreter.
    /// Host-backed fds (SQLite database files, preopened directories) are opened
    /// via the Emscripten `env.__syscall_openat` path and closed via
    /// `env.__syscall_close`; the WASI close sweep must not destroy those live
    /// file handles mid-transaction.
    ///
    /// For host-backed fds that are SQLite journals (path ends with "-journal"):
    /// honour the close (SQLite explicitly closes the journal at commit). Keeping
    /// the journal fd alive would leak the fd slot and cause the next transaction's
    /// journal to land on a different fd number, confusing SQLite's internal state.
    ///
    /// For all other host-backed fds (the db file itself, preopened directories):
    /// this call is a no-op so Python's sweep cannot kill a live db connection.
    ///
    /// For MEMFS fds: the slot is released as usual.
    pub fn wasi_close(&mut self, fd: i32) -> i32 {
        let fd_usize = fd as usize;
        if fd_usize < 3 || fd_usize >= self.fds.len() {
            return EBADF;
        }
        if self.fds[fd_usize].is_none() {
            return EBADF;
        }
        if self.host_fds.contains_key(&fd) {
            // Journal fds (path ends with "-journal"): honour the close so the
            // fd slot is freed and the next write transaction can reuse it.
            let is_journal = self.fds[fd_usize]
                .as_ref()
                .is_some_and(|e| e.path.ends_with("-journal"));
            if is_journal {
                pyo_trace!("[wasi_close] fd={fd} journal - closing (freeing slot for next tx)");
                self.host_fds.remove(&fd);
                self.fds[fd_usize] = None;
                return 0;
            }
            // Database file or directory fd: no-op to survive Python's sweep.
            pyo_trace!("[wasi_close] fd={fd} host-backed db/dir - no-op (protected)");
            return 0;
        }
        // MEMFS-only fd: release the slot.
        self.fds[fd_usize] = None;
        0
    }

    /// Remove a MEMFS node. Returns 0 or a negative errno.
    pub fn unlink(&mut self, abs_path: &str) -> i32 {
        match self.nodes.remove(abs_path) {
            Some(_) => 0,
            None => ENOENT,
        }
    }

    /// Fill an Emscripten stat buffer (Emscripten doStat layout) for the node at
    /// `abs_path`. Returns 0 or ENOENT. The buffer is exactly the Emscripten
    /// wasm32 `struct stat` size (`EM_STAT_STRUCT_BYTES`).
    pub fn stat_into(&mut self, abs_path: &str, buf: &mut [u8; EM_STAT_STRUCT_BYTES]) -> i32 {
        match self.nodes.get(abs_path) {
            None => ENOENT,
            Some(node) => {
                let (mode, size) = match node {
                    FsNode::Dir => (S_IFDIR | S_IRWXU, 0u64),
                    FsNode::File(data) => (S_IFREG | S_IRWXU, data.len() as u64),
                };
                let ino = self.alloc_ino();
                write_stat_buf(buf, ino, mode, size);
                0
            }
        }
    }

    /// Return (mode, size) for the node at `abs_path`, or None if not found.
    /// Used by syscall handlers for debug logging after `stat_into`.
    pub fn stat_mode_size(&self, abs_path: &str) -> Option<(u32, u64)> {
        self.nodes.get(abs_path).map(|node| match node {
            FsNode::Dir => (S_IFDIR | S_IRWXU, 0u64),
            FsNode::File(data) => (S_IFREG | S_IRWXU, data.len() as u64),
        })
    }

    /// Fill a `struct stat` buffer for the node referenced by `fd`.
    pub fn fstat_into(&mut self, fd: i32, buf: &mut [u8; EM_STAT_STRUCT_BYTES]) -> i32 {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            return EBADF;
        }
        let path = match &self.fds[fd_usize] {
            None => return EBADF,
            Some(e) => e.path.clone(),
        };
        self.stat_into(&path, buf)
    }

    /// Enumerate direct children of the directory at `abs_path` for getdents64.
    /// Returns the list of (name, is_dir) pairs.
    pub fn list_dir(&self, abs_path: &str) -> Option<Vec<(String, bool)>> {
        match self.nodes.get(abs_path) {
            None | Some(FsNode::File(_)) => None,
            Some(FsNode::Dir) => {
                let prefix = if abs_path == "/" {
                    "/".to_owned()
                } else {
                    format!("{abs_path}/")
                };
                let mut entries: Vec<(String, bool)> = self
                    .nodes
                    .keys()
                    .filter_map(|p| {
                        if p == abs_path {
                            return None;
                        }
                        let rest = p.strip_prefix(&prefix)?;
                        // Only direct children (no `/` in remaining part).
                        if rest.contains('/') {
                            return None;
                        }
                        let is_dir = matches!(self.nodes.get(p), Some(FsNode::Dir));
                        Some((rest.to_owned(), is_dir))
                    })
                    .collect();
                entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                Some(entries)
            }
        }
    }

    /// Serialize `struct linux_dirent64` records for `fd` into `out`, starting
    /// at the fd's `dir_cursor`. Emits "." and ".." first, then children in
    /// sorted order. Advances `dir_cursor` by the number of entries consumed.
    ///
    /// Returns the number of bytes written, or 0 when the cursor is already at
    /// or past the end of the entry list (signals end-of-directory to the
    /// caller). Returns a negative errno on error.
    pub fn getdents64_into(&mut self, fd: i32, out: &mut [u8]) -> i32 {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            return EBADF;
        }
        let (dir_path, cursor) = match &self.fds[fd_usize] {
            None => return EBADF,
            Some(e) => (e.path.clone(), e.dir_cursor),
        };
        // Verify this fd references a directory.
        match self.nodes.get(&dir_path) {
            None => return EBADF,
            Some(FsNode::File(_)) => return ENOTDIR,
            Some(FsNode::Dir) => {}
        }

        // Build the full ordered entry list: ".", "..", then sorted children.
        let children = self.list_dir(&dir_path).unwrap_or_default();
        // Total logical entries: 2 dot entries + children.
        let total = 2 + children.len();

        // Already exhausted - return 0 to signal end-of-directory.
        if cursor >= total {
            return 0;
        }

        // Write as many entries as fit in `out` starting from `cursor`.
        // `i` is the relative position within this call (0-based); `idx` is
        // the absolute entry index in the full list.
        let mut pos = 0usize;
        let mut written_count = 0usize;
        for (i, idx) in (cursor..total).enumerate() {
            let ino = 100u64 + cursor as u64 + i as u64;
            let (name, is_dir): (&str, bool) = if idx == 0 {
                (".", true)
            } else if idx == 1 {
                ("..", true)
            } else {
                let (ref n, d) = children[idx - 2];
                (n.as_str(), d)
            };
            let off = (idx + 1) as u64; // opaque cookie: next entry index
            let n = write_dirent64(out, pos, ino, off, name, is_dir);
            if n == 0 {
                // Entry does not fit - stop here.
                break;
            }
            pos += n;
            written_count += 1;
        }

        // Advance the per-fd cursor.
        if let Some(Some(entry)) = self.fds.get_mut(fd_usize) {
            entry.dir_cursor = cursor + written_count;
        }

        pos as i32
    }

    /// Check whether `abs_path` exists (for faccessat / access).
    pub fn exists(&self, abs_path: &str) -> bool {
        self.nodes.contains_key(abs_path)
    }

    /// Get the path for fd, or None if invalid.
    pub fn fd_path(&self, fd: i32) -> Option<&str> {
        let fd_usize = fd as usize;
        self.fds
            .get(fd_usize)
            .and_then(|e| e.as_ref())
            .map(|e| e.path.as_str())
    }

    /// Read up to `len` bytes at `offset` from fd into `dst`, WITHOUT advancing
    /// the fd's current offset (positional read, like pread(2)).
    /// Returns bytes read, or a negative errno.
    pub fn pread(&mut self, fd: i32, dst: &mut [u8], offset: u64) -> i32 {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            return EBADF;
        }
        let path = match &self.fds[fd_usize] {
            None => return EBADF,
            Some(e) => e.path.clone(),
        };
        match self.nodes.get(&path) {
            None => ENOENT,
            Some(FsNode::Dir) => EISDIR,
            Some(FsNode::File(data)) => {
                let start = offset.min(data.len() as u64) as usize;
                let available = data.len() - start;
                let n = dst.len().min(available);
                dst[..n].copy_from_slice(&data[start..start + n]);
                n as i32
            }
        }
    }

    /// Write `src` at `offset` into the file referenced by `fd`, WITHOUT
    /// advancing the fd's offset (positional write, like pwrite(2)). Extends the
    /// file with zero fill if `offset` is past the current end. Returns bytes
    /// written, or a negative errno. Used by `msync` to flush a writable
    /// file-backed mapping back to its file.
    pub fn pwrite(&mut self, fd: i32, src: &[u8], offset: u64) -> i32 {
        let fd_usize = fd as usize;
        if fd_usize >= self.fds.len() {
            return EBADF;
        }
        let path = match &self.fds[fd_usize] {
            None => return EBADF,
            Some(e) => e.path.clone(),
        };
        match self.nodes.get_mut(&path) {
            None => ENOENT,
            Some(FsNode::Dir) => EISDIR,
            Some(FsNode::File(data)) => {
                let start = offset as usize;
                let end = start + src.len();
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[start..end].copy_from_slice(src);
                src.len() as i32
            }
        }
    }

    /// Return the `dir_cursor` for a directory fd (for getdents64 pagination).
    /// Returns 0 if the fd is invalid or not a directory fd.
    pub fn fd_dir_cursor(&self, fd: i32) -> usize {
        let fd_usize = fd as usize;
        self.fds
            .get(fd_usize)
            .and_then(|e| e.as_ref())
            .map(|e| e.dir_cursor)
            .unwrap_or(0)
    }

    /// Advance the `dir_cursor` for a directory fd by `count` entries.
    pub fn advance_fd_dir_cursor(&mut self, fd: i32, count: usize) {
        let fd_usize = fd as usize;
        if let Some(Some(entry)) = self.fds.get_mut(fd_usize) {
            entry.dir_cursor += count;
        }
    }

    /// Return true if `fd` is a valid open fd referencing a filesystem node
    /// (i.e. fd >= 3 and has an entry). Used by WASI shims to decide whether
    /// to delegate to the MEMFS or handle as stdin/stdout/stderr.
    pub fn is_fs_fd(&self, fd: i32) -> bool {
        let fd_usize = fd as usize;
        fd_usize >= 3 && fd_usize < self.fds.len() && self.fds[fd_usize].is_some()
    }

    /// Returns true if `fd` is a host-backed (rw-preopen) file descriptor.
    pub fn is_host_fd(&self, fd: i32) -> bool {
        self.host_fds.contains_key(&fd)
    }

    // ---- host passthrough -------------------------------------------------------
    //
    // A path under a declared rw-preopen is routed to the real host filesystem.
    // The fd is allocated from the same `fds` table (same namespace) so all
    // existing fd_path / stat callers still work; the host `File` lives in
    // `host_fds` and is checked first in read / write / close / lseek.

    /// Map a guest canonical absolute path to a host `PathBuf` if it falls under
    /// a declared rw-preopen, otherwise `None`. The preopens list is
    /// `(host_path, guest_path)` pairs exactly as in `WasiCommandOpts::preopens_rw`.
    pub fn resolve_to_host_path(
        abs_guest: &str,
        preopens: &[(PathBuf, String)],
    ) -> Option<PathBuf> {
        for (host_root, guest_root) in preopens {
            let guest_prefix = guest_root.trim_end_matches('/');
            if abs_guest == guest_prefix {
                return Some(host_root.clone());
            }
            // Use `if let` instead of `?` so a non-matching preopen continues
            // to the next rather than exiting the function.
            if let Some(rest) = abs_guest.strip_prefix(guest_prefix) {
                // rest must start with '/' (not a partial segment match like
                // "/dataextra" when the preopen is "/data").
                if let Some(child) = rest.strip_prefix('/') {
                    return Some(host_root.join(child));
                }
            }
        }
        None
    }

    /// Open a host-backed file or directory at `host_path` with the given
    /// Emscripten `flags` (O_RDONLY/O_WRONLY/O_RDWR, O_CREAT, O_TRUNC). Records
    /// the `guest_abs` path in the fd table so `fd_path` / stat work. Returns the
    /// allocated fd, or a negative errno.
    pub fn open_host(&mut self, guest_abs: String, host_path: PathBuf, flags: i32) -> i32 {
        let want_write = flags & O_WRONLY != 0 || flags & O_RDWR != 0;
        let creat = flags & O_CREAT != 0;
        let trunc = flags & O_TRUNC != 0;

        // Check if it is a directory first (directories can only be opened read-only).
        if host_path.is_dir() {
            if want_write {
                return EISDIR;
            }
            let fd = self.alloc_fd(guest_abs);
            // Directory fds have no host file handle; list_dir_host reads the dir.
            pyo_trace!("[host-open-dir] {:?} -> fd={fd}", host_path);
            return fd;
        }

        // Regular file: build the open options from Emscripten flags.
        let mut oo = std::fs::OpenOptions::new();
        oo.read(!want_write || flags & O_RDWR != 0);
        if want_write {
            oo.write(true);
        }
        if creat {
            oo.create(true);
        }
        if trunc {
            oo.truncate(true);
        }
        if !creat && !trunc {
            oo.create(false);
        }

        // For a write-only file that does not exist yet, `create` must be set.
        let file = match oo.open(&host_path) {
            Ok(f) => f,
            Err(e) => {
                pyo_trace!("[host-open-fail] {:?} flags={flags} err={e}", host_path);
                return io_err_to_errno(&e);
            }
        };

        let fd = self.alloc_fd(guest_abs.clone());
        {
            let meta_check = std::fs::metadata(&host_path);
            pyo_trace!(
                "[host-open] guest={guest_abs:?} host={host_path:?} flags={flags} -> fd={fd} meta_exists={}",
                meta_check.is_ok()
            );
        }
        self.host_fds.insert(fd, file);
        fd
    }

    /// Read from a host-backed fd. Returns bytes read, or a negative errno.
    /// Returns `None` if `fd` is not a host-backed fd.
    pub fn read_host(&mut self, fd: i32, dst: &mut [u8]) -> Option<i32> {
        let file = self.host_fds.get_mut(&fd)?;
        let n = match file.read(dst) {
            Ok(n) => n as i32,
            Err(e) => io_err_to_errno(&e),
        };
        Some(n)
    }

    /// Write to a host-backed fd. Returns bytes written, or a negative errno.
    /// Returns `None` if `fd` is not a host-backed fd.
    pub fn write_host(&mut self, fd: i32, src: &[u8]) -> Option<i32> {
        let file = self.host_fds.get_mut(&fd)?;
        let n = match file.write(src) {
            Ok(n) => n as i32,
            Err(e) => io_err_to_errno(&e),
        };
        Some(n)
    }

    /// Positional write (pwrite) to a host-backed fd at `offset` without changing
    /// the fd's current position. Returns bytes written, or a negative errno.
    /// Returns `None` if `fd` is not a host-backed fd.
    pub fn pwrite_host(&mut self, fd: i32, src: &[u8], offset: u64) -> Option<i32> {
        let file = self.host_fds.get_mut(&fd)?;
        let n = match file.write_at(src, offset) {
            Ok(n) => n as i32,
            Err(e) => io_err_to_errno(&e),
        };
        Some(n)
    }

    /// Positional read (pread) from a host-backed fd at `offset` without changing
    /// the fd's current position. Returns bytes read, or a negative errno.
    /// Returns `None` if `fd` is not a host-backed fd.
    pub fn pread_host(&mut self, fd: i32, dst: &mut [u8], offset: u64) -> Option<i32> {
        let file = self.host_fds.get_mut(&fd)?;
        let n = match file.read_at(dst, offset) {
            Ok(n) => n as i32,
            Err(e) => io_err_to_errno(&e),
        };
        Some(n)
    }

    /// Seek a host-backed fd. Returns the new offset, or a negative i64 errno.
    /// Returns `None` if `fd` is not a host-backed fd.
    pub fn lseek_host(&mut self, fd: i32, offset: i64, whence: i32) -> Option<i64> {
        let file = self.host_fds.get_mut(&fd)?;
        let pos = match whence {
            0 => SeekFrom::Start(offset.max(0) as u64),
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => return Some(EINVAL as i64),
        };
        let new_off = match file.seek(pos) {
            Ok(n) => n as i64,
            Err(e) => io_err_to_errno(&e) as i64,
        };
        Some(new_off)
    }

    /// Truncate a host-backed fd to `len` bytes. Returns `Some(0)` on success,
    /// `Some(negative_errno)` on error, `None` if not a host-backed fd.
    pub fn truncate_host(&mut self, fd: i32, len: u64) -> Option<i32> {
        let file = self.host_fds.get_mut(&fd)?;
        match file.set_len(len) {
            Ok(()) => Some(0),
            Err(e) => Some(io_err_to_errno(&e)),
        }
    }

    /// Close a host-backed fd. Returns `Some(0)` on success, `Some(errno)` on
    /// error. Returns `None` if `fd` is not a host-backed fd.
    pub fn close_host(&mut self, fd: i32) -> Option<i32> {
        let file = self.host_fds.remove(&fd)?;
        drop(file);
        // Also release the fds-table slot so the fd can be reused.
        let fd_usize = fd as usize;
        if fd_usize < self.fds.len() {
            self.fds[fd_usize] = None;
        }
        Some(0)
    }

    /// Fill an Emscripten stat buffer for a host path. Returns 0 or a negative errno.
    pub fn stat_host_path(
        &mut self,
        host_path: &Path,
        buf: &mut [u8; EM_STAT_STRUCT_BYTES],
    ) -> i32 {
        match std::fs::metadata(host_path) {
            Err(e) => {
                // Only trace for paths that look like the SQLite journal.
                if host_path.to_string_lossy().contains("accept_test") {
                    pyo_trace!("[stat_host_path] ENOENT for {:?} err={e}", host_path);
                    if let Some(parent) = host_path.parent() {
                        let parent_exists = parent.exists();
                        pyo_trace!("[stat_host_path] parent={parent:?} exists={parent_exists}");
                        if parent_exists && let Ok(rd) = std::fs::read_dir(parent) {
                            let names: Vec<_> = rd
                                .filter_map(|e| e.ok())
                                .map(|e| e.file_name().to_string_lossy().to_string())
                                .collect();
                            pyo_trace!("[stat_host_path] parent contents: {names:?}");
                        }
                    }
                }
                io_err_to_errno(&e)
            }
            Ok(meta) => {
                // Use the real host inode so SQLite's DBMOVED check (which
                // compares the inode recorded at open time against the inode
                // seen at pagerOpenJournal time) does not fire a false positive.
                let ino = meta.ino();
                let (mode, size) = if meta.is_dir() {
                    (S_IFDIR | S_IRWXU, 0u64)
                } else {
                    (S_IFREG | S_IRWXU, meta.len())
                };
                write_stat_buf(buf, ino, mode, size);
                0
            }
        }
    }

    /// Variant of `stat_host_path` used by `__syscall_lstat64`.
    ///
    /// For paths under a rw-preopen that do not yet exist on the host, if the
    /// parent directory exists we return a fake "empty regular file" stat (mode
    /// `S_IFREG|0644`, size 0) instead of ENOENT. This is required because musl's
    /// `realpath()` fails with ENOENT when the last path component does not exist,
    /// whereas glibc's realpath succeeds. sqlite3's `unixFullPathname` calls
    /// `realpath`; without this fix it returns `SQLITE_CANTOPEN` before ever
    /// issuing `openat`.
    pub fn stat_host_path_for_lstat(
        &mut self,
        host_path: &Path,
        buf: &mut [u8; EM_STAT_STRUCT_BYTES],
    ) -> i32 {
        match std::fs::metadata(host_path) {
            Ok(meta) => {
                // Use the real host inode for stable identity across stat calls.
                let ino = meta.ino();
                let (mode, size) = if meta.is_dir() {
                    (S_IFDIR | S_IRWXU, 0u64)
                } else {
                    (S_IFREG | S_IRWXU, meta.len())
                };
                write_stat_buf(buf, ino, mode, size);
                0
            }
            Err(e) if io_err_to_errno(&e) == ENOENT => {
                // File does not exist yet. If the parent directory is present (and
                // is the rw-preopen root or a subdir of it), report a zero-size
                // regular file so realpath continues instead of failing.
                let parent_exists = host_path.parent().is_some_and(|p| p.is_dir());
                if parent_exists {
                    let ino = self.alloc_ino();
                    write_stat_buf(buf, ino, S_IFREG | 0o644, 0);
                    0
                } else {
                    ENOENT
                }
            }
            Err(e) => io_err_to_errno(&e),
        }
    }

    /// Fill an Emscripten stat buffer for a host-backed fd. Returns 0 or a
    /// negative errno. Returns `None` if `fd` is not a host-backed fd.
    pub fn fstat_host(&mut self, fd: i32, buf: &mut [u8; EM_STAT_STRUCT_BYTES]) -> Option<i32> {
        // We need the host file metadata. For host dirs we have no File handle, so
        // fall back to the path stored in the fds table.
        if self.host_fds.contains_key(&fd) {
            let meta = match self.host_fds[&fd].metadata() {
                Ok(m) => m,
                Err(e) => return Some(io_err_to_errno(&e)),
            };
            // Use the real host inode so SQLite's DBMOVED check agrees with
            // the inode seen via stat64 on the same path.
            let ino = meta.ino();
            let (mode, size) = if meta.is_dir() {
                (S_IFDIR | S_IRWXU, 0u64)
            } else {
                (S_IFREG | S_IRWXU, meta.len())
            };
            write_stat_buf(buf, ino, mode, size);
            return Some(0);
        }
        // Host directory fds: no File in host_fds, but the path is in fds.
        None
    }

    /// List directory entries for a host-backed directory fd, for getdents64.
    /// Returns the (name, is_dir) list, or `None` if fd is not a host dir fd.
    ///
    /// A fd is a "host dir" if it has an entry in `fds` but NOT in `host_fds`
    /// AND the guest path has a corresponding host path. The caller supplies
    /// the host_path for the lookup.
    pub fn list_dir_host(host_path: &Path) -> Option<Vec<(String, bool)>> {
        if !host_path.is_dir() {
            return None;
        }
        let rd = std::fs::read_dir(host_path).ok()?;
        let mut entries: Vec<(String, bool)> = rd
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().to_string_lossy().into_owned();
                let is_dir = e.file_type().ok().map(|t| t.is_dir()).unwrap_or(false);
                Some((name, is_dir))
            })
            .collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Some(entries)
    }

    /// Check whether a host path exists (for faccessat under a rw-preopen).
    pub fn exists_host(host_path: &Path) -> bool {
        host_path.exists()
    }

    /// Create a directory (and parents) on the host. Returns 0 or a negative errno.
    pub fn mkdir_host(host_path: &Path) -> i32 {
        match std::fs::create_dir_all(host_path) {
            Ok(()) => 0,
            Err(e) => io_err_to_errno(&e),
        }
    }
}

// ---- host I/O error mapping ------------------------------------------------

/// Map a `std::io::Error` to the nearest Linux errno value (negated) that
/// Emscripten's musl layer expects. The mapping is intentionally minimal: only
/// the errors the host FS operations can plausibly return are covered.
pub(crate) fn io_err_to_errno(e: &std::io::Error) -> i32 {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => ENOENT,
        ErrorKind::PermissionDenied => EACCES,
        ErrorKind::AlreadyExists => -17, // EEXIST
        ErrorKind::InvalidInput | ErrorKind::InvalidData => EINVAL,
        ErrorKind::IsADirectory => EISDIR,
        ErrorKind::NotADirectory => ENOTDIR,
        // Treat everything else as EIO (-5) so the guest sees a real error.
        _ => -5,
    }
}

// ---- node info (WASI path_filestat_get) ------------------------------------

/// Metadata returned by [`InMemFs::node_info`] for WASI `path_filestat_get`.
pub struct NodeInfo {
    /// Inode number (monotonically increasing, non-persistent).
    pub ino: u64,
    /// WASI filetype: 3 = directory, 4 = regular file.
    pub filetype: u8,
    /// File size in bytes (0 for directories).
    pub size: u64,
}

// ---- path canonicalization -------------------------------------------------

/// Canonicalize an absolute path: collapse `//`, `..`, `.`; no trailing slash
/// (unless the result is just `/`).
fn canonicalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Return the parent of an absolute canonical path, or None for `/`.
fn parent_of(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }
    let slash = path.rfind('/')?;
    if slash == 0 {
        Some("/".to_owned())
    } else {
        Some(path[..slash].to_owned())
    }
}

// ---- stat buffer writer ----------------------------------------------------

/// Write an Emscripten stat buffer (Emscripten wasm32 `struct stat`,
/// `EM_STAT_STRUCT_BYTES` bytes, little-endian) into
/// `buf`.
///
/// Uses the Emscripten `struct stat` field layout (authoritative offsets from
/// Emscripten's `struct_info_generated.json`: st_ino is the last field, at
/// offset 88, so the struct is exactly 96 bytes), NOT the 112-byte musl C
/// `struct stat` whose timespec layout differs. The guest allocates exactly this
/// many bytes; the syscall shims must write exactly this many or they overrun
/// the guest's buffer.
///
/// Critical fields CPython reads:
/// - `st_mode` at offset 4 (i32): `S_IFREG` or `S_IFDIR` bits
/// - `st_size` at offset 24 (i64): byte length for regular files
fn write_stat_buf(buf: &mut [u8; EM_STAT_STRUCT_BYTES], ino: u64, mode: u32, size: u64) {
    buf.fill(0);
    // st_dev at offset 0 (i32 LE) - device 1
    buf[0..4].copy_from_slice(&1i32.to_le_bytes());
    // st_mode at offset 4 (i32 LE)
    buf[4..8].copy_from_slice(&(mode as i32).to_le_bytes());
    // st_nlink at offset 8 (u32 LE) - 1 link
    buf[8..12].copy_from_slice(&1u32.to_le_bytes());
    // st_uid at offset 12 (i32 LE) - 0
    // st_gid at offset 16 (i32 LE) - 0
    // st_rdev at offset 20 (i32 LE) - 0
    // st_size at offset 24 (i64 LE)
    buf[24..32].copy_from_slice(&(size as i64).to_le_bytes());
    // st_blksize at offset 32 (i32 LE) - 4096 (Emscripten hardcodes this)
    buf[32..36].copy_from_slice(&4096i32.to_le_bytes());
    // st_blocks at offset 36 (i32 LE) - size in 512-byte blocks
    let blocks = size.div_ceil(512) as i32;
    buf[36..40].copy_from_slice(&blocks.to_le_bytes());
    // timestamps at offsets 40, 48, 56, 64, 72, 80 - leave 0 (epoch)
    // st_ino at offset 88 (i64 LE)
    buf[88..96].copy_from_slice(&(ino as i64).to_le_bytes());
}

// ---- getdents64 layout helper ----------------------------------------------

/// Serialize a single `struct linux_dirent64` entry into `out[pos..]`.
/// Returns the number of bytes written, or 0 if the buffer is too small.
/// The entry is padded so `d_reclen` is a multiple of 8.
pub fn write_dirent64(
    out: &mut [u8],
    pos: usize,
    ino: u64,
    off: u64,
    name: &str,
    is_dir: bool,
) -> usize {
    let name_bytes = name.as_bytes();
    // d_name: null-terminated, then padded so total reclen % 8 == 0.
    let base_len = 19 + name_bytes.len() + 1; // header(19) + name + NUL
    let reclen = (base_len + 7) & !7; // round up to 8
    if pos + reclen > out.len() {
        return 0;
    }
    let buf = &mut out[pos..pos + reclen];
    buf.fill(0);
    buf[0..8].copy_from_slice(&ino.to_le_bytes());
    buf[8..16].copy_from_slice(&off.to_le_bytes());
    buf[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    buf[18] = if is_dir { 4 } else { 8 }; // DT_DIR=4, DT_REG=8
    buf[19..19 + name_bytes.len()].copy_from_slice(name_bytes);
    // NUL terminator at 19 + name_bytes.len() (already zeroed from fill)
    reclen
}

// ---- stdlib mount from zip ------------------------------------------------

/// Mount the contents of a ZIP archive (containing Python stdlib files) into
/// `fs` at `prefix` (e.g. `"/lib/python"`).
///
/// The ZIP is read from the bytes in `zip_data`. Each file in the archive
/// is extracted and placed under `<prefix>/<zip_entry_path>`. Directories
/// are created as needed.
///
/// This uses `flate2` (DEFLATE) for decompression and hand-parses the ZIP
/// local-file-header format to avoid pulling in a full zip crate.
///
/// vertexia: hand-rolled minimal zip parser; upgrade path is the `zip` crate
/// if additional compression methods or ZIP64 are needed.
pub fn mount_zip_into_fs(fs: &mut InMemFs, prefix: &str, zip_data: &[u8]) -> Result<usize, String> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut count = 0usize;
    let mut pos = 0usize;

    while pos + 30 <= zip_data.len() {
        // Local file header signature: 0x04034b50 (PK\x03\x04)
        let sig = u32::from_le_bytes(zip_data[pos..pos + 4].try_into().unwrap());
        if sig != 0x04034b50 {
            // Not a local file header - could be a data descriptor, central dir, etc.
            // Scan forward for the next local header.
            if sig == 0x02014b50 || sig == 0x06054b50 {
                // Central directory or EOCD - done.
                break;
            }
            // Try to skip past unknown data by scanning for the next PK signature.
            pos += 1;
            continue;
        }

        // Local file header layout:
        //   0   sig (4)
        //   4   version_needed (2)
        //   6   flags (2)
        //   8   compression (2)   0=stored, 8=deflate
        //   10  mod_time (2)
        //   12  mod_date (2)
        //   14  crc32 (4)
        //   18  compressed_size (4)
        //   22  uncompressed_size (4)
        //   26  fname_len (2)
        //   28  extra_len (2)
        //   30  fname (fname_len bytes)
        //   30+fname_len  extra (extra_len bytes)
        //   30+fname_len+extra_len  file data (compressed_size bytes)

        if pos + 30 > zip_data.len() {
            break;
        }
        let compression = u16::from_le_bytes(zip_data[pos + 8..pos + 10].try_into().unwrap());
        let compressed_size =
            u32::from_le_bytes(zip_data[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let uncompressed_size =
            u32::from_le_bytes(zip_data[pos + 22..pos + 26].try_into().unwrap()) as usize;
        let fname_len =
            u16::from_le_bytes(zip_data[pos + 26..pos + 28].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(zip_data[pos + 28..pos + 30].try_into().unwrap()) as usize;

        let fname_start = pos + 30;
        let fname_end = fname_start + fname_len;
        if fname_end > zip_data.len() {
            break;
        }
        let entry_name = match std::str::from_utf8(&zip_data[fname_start..fname_end]) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                // Skip non-UTF8 entry names.
                pos = fname_end + extra_len + compressed_size;
                continue;
            }
        };

        let data_start = fname_end + extra_len;
        let data_end = data_start + compressed_size;
        if data_end > zip_data.len() {
            break;
        }

        let abs_path = format!("{prefix}/{entry_name}");
        let abs_path = canonicalize(&abs_path);

        if entry_name.ends_with('/') || uncompressed_size == 0 && compressed_size == 0 {
            // Directory entry.
            fs.mkdir_p(&abs_path);
        } else {
            // File entry.
            let contents = match compression {
                0 => {
                    // Stored (no compression).
                    zip_data[data_start..data_end].to_vec()
                }
                8 => {
                    // DEFLATE - use flate2's raw DeflateDecoder.
                    let compressed = &zip_data[data_start..data_end];
                    let mut decoder = DeflateDecoder::new(compressed);
                    let mut out = Vec::with_capacity(uncompressed_size);
                    decoder
                        .read_to_end(&mut out)
                        .map_err(|e| format!("deflate error for {entry_name}: {e}"))?;
                    out
                }
                other => {
                    // Unsupported - skip silently (e.g. bzip2, lzma).
                    pyo_trace!(
                        "[emscripten_fs] skipping {entry_name}: unsupported compression {other}"
                    );
                    pos = data_end;
                    continue;
                }
            };
            fs.insert_file(&abs_path, contents);
            count += 1;
        }

        pos = data_end;
    }

    Ok(count)
}

// ---- unit tests ------------------------------------------------------------

#[cfg(test)]
mod tests;
