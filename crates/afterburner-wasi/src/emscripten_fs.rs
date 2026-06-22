// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

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

// ---- errno constants ---------------------------------------------------------

/// ENOENT: no such file or directory.
pub const ENOENT: i32 = -2;
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
    pub offset: u64,
}

// ---- the filesystem --------------------------------------------------------

/// In-memory filesystem: a flat map from absolute canonical path to node, plus
/// a file-descriptor table.
pub struct InMemFs {
    /// Absolute path -> node. Keys are canonical: no trailing `/`, single slash.
    /// The root entry is `"/"` -> `Dir`.
    nodes: HashMap<String, FsNode>,
    /// File-descriptor table. Index 0/1/2 are permanently `None` (reserved for
    /// stdin/stdout/stderr so open() never issues them).
    fds: Vec<Option<FdEntry>>,
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
            }),
        ];
        Self {
            nodes,
            fds,
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

    /// Allocate a new fd for `path` (must already exist as a File or Dir).
    /// Returns the fd, or ENOENT/EISDIR as appropriate (callers gate on flags).
    pub fn open(&mut self, path: String, flags: i32) -> i32 {
        match self.nodes.get(&path) {
            None => ENOENT,
            Some(FsNode::Dir) => {
                // Opening a directory is allowed for readdir; only reject if
                // write-only.
                if flags & O_WRONLY != 0 || flags & O_RDWR != 0 {
                    return EISDIR;
                }
                self.alloc_fd(path)
            }
            Some(FsNode::File(_)) => self.alloc_fd(path),
        }
    }

    fn alloc_fd(&mut self, path: String) -> i32 {
        let entry = FdEntry { path, offset: 0 };
        // Reuse a slot if one is free, starting from index 3 to preserve
        // the 0/1/2 reservation for stdin/stdout/stderr.
        for (i, slot) in self.fds.iter_mut().enumerate().skip(3) {
            if slot.is_none() {
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
        0
    }

    /// Fill an Emscripten stat buffer (96 bytes, Emscripten doStat layout) for
    /// the node at `abs_path`. Returns 0 or ENOENT.
    pub fn stat_into(&mut self, abs_path: &str, buf: &mut [u8; 112]) -> i32 {
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
    pub fn fstat_into(&mut self, fd: i32, buf: &mut [u8; 112]) -> i32 {
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

    /// Return true if `fd` is a valid open fd referencing a filesystem node
    /// (i.e. fd >= 3 and has an entry). Used by WASI shims to decide whether
    /// to delegate to the MEMFS or handle as stdin/stdout/stderr.
    pub fn is_fs_fd(&self, fd: i32) -> bool {
        let fd_usize = fd as usize;
        fd_usize >= 3 && fd_usize < self.fds.len() && self.fds[fd_usize].is_some()
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

/// Write an Emscripten stat buffer (96 bytes, little-endian) into `buf`.
///
/// Uses the Emscripten `doStat()` field layout from `pyodide.asm.js`, NOT the
/// musl C `struct stat` layout. The buffer passed by Emscripten is 96 bytes;
/// our `buf` is 112 bytes so the tail is always zeroed and safe to ignore.
///
/// Critical fields CPython reads:
/// - `st_mode` at offset 4 (i32): `S_IFREG` or `S_IFDIR` bits
/// - `st_size` at offset 24 (i64): byte length for regular files
fn write_stat_buf(buf: &mut [u8; 112], ino: u64, mode: u32, size: u64) {
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
                    eprintln!(
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
mod tests {
    use super::*;

    #[test]
    fn canonicalize_basic() {
        assert_eq!(canonicalize("/"), "/");
        assert_eq!(canonicalize("//a//b/"), "/a/b");
        assert_eq!(canonicalize("/a/../b"), "/b");
        assert_eq!(canonicalize("/a/./b"), "/a/b");
    }

    #[test]
    fn mkdir_p_creates_chain() {
        let mut fs = InMemFs::new();
        fs.mkdir_p("/a/b/c");
        assert!(matches!(fs.get("/a"), Some(FsNode::Dir)));
        assert!(matches!(fs.get("/a/b"), Some(FsNode::Dir)));
        assert!(matches!(fs.get("/a/b/c"), Some(FsNode::Dir)));
    }

    #[test]
    fn insert_and_read_file() {
        let mut fs = InMemFs::new();
        fs.insert_file("/foo.txt", b"hello".to_vec());
        let fd = fs.open("/foo.txt".to_owned(), 0);
        assert!(fd >= 3, "fd should be >= 3, got {fd}");
        let mut buf = [0u8; 5];
        let n = fs.read(fd, &mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
        // Second read at EOF returns 0.
        let n2 = fs.read(fd, &mut buf);
        assert_eq!(n2, 0);
        assert_eq!(fs.close(fd), 0);
    }

    #[test]
    fn lseek_seek_set() {
        let mut fs = InMemFs::new();
        fs.insert_file("/a.txt", b"abcde".to_vec());
        let fd = fs.open("/a.txt".to_owned(), 0);
        let _ = fs.read(fd, &mut [0u8; 3]);
        // SEEK_SET back to 1
        let new_off = fs.lseek(fd, 1, 0);
        assert_eq!(new_off, 1);
        let mut buf = [0u8; 2];
        fs.read(fd, &mut buf);
        assert_eq!(&buf, b"bc");
    }

    #[test]
    fn list_dir_returns_children() {
        let mut fs = InMemFs::new();
        fs.insert_file("/lib/a.py", b"".to_vec());
        fs.insert_file("/lib/b.py", b"".to_vec());
        fs.mkdir_p("/lib/pkg");
        let entries = fs.list_dir("/lib").unwrap();
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"a.py"));
        assert!(names.contains(&"b.py"));
        assert!(names.contains(&"pkg"));
    }

    #[test]
    fn reserved_fds_are_ebadf() {
        let mut fs = InMemFs::new();
        assert_eq!(fs.close(0), EBADF);
        assert_eq!(fs.close(1), EBADF);
        assert_eq!(fs.close(2), EBADF);
        assert_eq!(fs.read(0, &mut []), EBADF);
    }
}
