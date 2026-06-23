// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

use super::*;

// ---- path canonicalization --------------------------------------------------

#[test]
fn canonicalize_basic() {
    assert_eq!(canonicalize("/"), "/");
    assert_eq!(canonicalize("//a//b/"), "/a/b");
    assert_eq!(canonicalize("/a/../b"), "/b");
    assert_eq!(canonicalize("/a/./b"), "/a/b");
}

#[test]
fn canonicalize_dotdot_at_root() {
    // Going up from root must stay at root.
    assert_eq!(canonicalize("/../.."), "/");
    assert_eq!(canonicalize("/a/../.."), "/");
}

#[test]
fn canonicalize_trailing_slash_stripped() {
    assert_eq!(canonicalize("/a/b/"), "/a/b");
}

#[test]
fn canonicalize_dot_only_segments() {
    assert_eq!(canonicalize("/./././a"), "/a");
}

#[test]
fn canonicalize_mixed_dots() {
    assert_eq!(canonicalize("/a/b/../c/./d"), "/a/c/d");
}

// ---- resolve (relative path joining) ----------------------------------------

#[test]
fn resolve_absolute_path_ignores_base() {
    let fs = InMemFs::new();
    assert_eq!(fs.resolve("/base", "/abs/path"), "/abs/path");
}

#[test]
fn resolve_relative_joins_to_base() {
    let fs = InMemFs::new();
    assert_eq!(fs.resolve("/base", "rel/file"), "/base/rel/file");
}

#[test]
fn resolve_relative_dotdot() {
    let fs = InMemFs::new();
    assert_eq!(fs.resolve("/a/b", "../c"), "/a/c");
}

// ---- mkdir_p ----------------------------------------------------------------

#[test]
fn mkdir_p_creates_chain() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/a/b/c");
    assert!(matches!(fs.get("/a"), Some(FsNode::Dir)));
    assert!(matches!(fs.get("/a/b"), Some(FsNode::Dir)));
    assert!(matches!(fs.get("/a/b/c"), Some(FsNode::Dir)));
}

#[test]
fn mkdir_p_idempotent() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/x/y");
    fs.mkdir_p("/x/y"); // second call must not panic or overwrite
    assert!(matches!(fs.get("/x/y"), Some(FsNode::Dir)));
}

#[test]
fn mkdir_p_root_alone() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/");
    assert!(matches!(fs.get("/"), Some(FsNode::Dir)));
}

// ---- open / O_CREAT / O_TRUNC -----------------------------------------------

#[test]
fn open_nonexistent_no_creat_returns_enoent() {
    let mut fs = InMemFs::new();
    assert_eq!(fs.open("/missing.txt".to_owned(), 0), ENOENT);
}

#[test]
fn open_o_creat_creates_empty_file() {
    let mut fs = InMemFs::new();
    let flags = O_CREAT | O_WRONLY;
    let fd = fs.open("/new.txt".to_owned(), flags);
    assert!(fd >= 3, "expected valid fd, got {fd}");
    // Node exists and is empty.
    assert!(matches!(fs.get("/new.txt"), Some(FsNode::File(d)) if d.is_empty()));
}

#[test]
fn open_o_creat_creates_parent_dirs() {
    let mut fs = InMemFs::new();
    let flags = O_CREAT | O_WRONLY;
    let fd = fs.open("/deep/nested/file.txt".to_owned(), flags);
    assert!(fd >= 3);
    assert!(matches!(fs.get("/deep"), Some(FsNode::Dir)));
    assert!(matches!(fs.get("/deep/nested"), Some(FsNode::Dir)));
}

#[test]
fn open_o_trunc_empties_existing_file() {
    let mut fs = InMemFs::new();
    fs.insert_file("/f.txt", b"existing content".to_vec());
    let flags = O_CREAT | O_WRONLY | O_TRUNC;
    let fd = fs.open("/f.txt".to_owned(), flags);
    assert!(fd >= 3);
    // After O_TRUNC the file should be empty.
    assert!(matches!(fs.get("/f.txt"), Some(FsNode::File(d)) if d.is_empty()));
}

#[test]
fn open_directory_for_write_returns_eisdir() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/mydir");
    let fd = fs.open("/mydir".to_owned(), O_WRONLY);
    assert_eq!(fd, EISDIR);
}

#[test]
fn open_directory_for_read_succeeds() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/mydir");
    let fd = fs.open("/mydir".to_owned(), 0);
    assert!(fd >= 3);
}

// ---- write ------------------------------------------------------------------

#[test]
fn write_appends_and_grows_vec() {
    let mut fs = InMemFs::new();
    let fd = fs.open("/w.txt".to_owned(), O_CREAT | O_WRONLY);
    assert!(fd >= 3);

    let n1 = fs.write(fd, b"hello");
    assert_eq!(n1, 5);

    let n2 = fs.write(fd, b" world");
    assert_eq!(n2, 6);

    // Node now contains concatenated data.
    assert_eq!(fs.read_file("/w.txt"), Some(b"hello world".as_slice()));
}

#[test]
fn write_advances_fd_offset() {
    let mut fs = InMemFs::new();
    let fd = fs.open("/off.txt".to_owned(), O_CREAT | O_WRONLY);
    fs.write(fd, b"abc");
    // Offset should be 3 after writing 3 bytes.
    // Verify by reading from the beginning via a fresh fd.
    let fd2 = fs.open("/off.txt".to_owned(), 0);
    let mut buf = [0u8; 3];
    let n = fs.read(fd2, &mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf, b"abc");
}

#[test]
fn write_persists_to_fs_map() {
    // Writes through an fd must persist in the node so a different fd sees them.
    let mut fs = InMemFs::new();
    let fd_w = fs.open("/shared.txt".to_owned(), O_CREAT | O_WRONLY);
    fs.write(fd_w, b"persisted");
    fs.close(fd_w);

    let fd_r = fs.open("/shared.txt".to_owned(), 0);
    let mut buf = [0u8; 9];
    let n = fs.read(fd_r, &mut buf);
    assert_eq!(n, 9);
    assert_eq!(&buf, b"persisted");
}

#[test]
fn write_bad_fd_returns_ebadf() {
    let mut fs = InMemFs::new();
    assert_eq!(fs.write(99, b"x"), EBADF);
}

// ---- read -------------------------------------------------------------------

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
fn read_partial_advances_offset() {
    let mut fs = InMemFs::new();
    fs.insert_file("/p.txt", b"abcdef".to_vec());
    let fd = fs.open("/p.txt".to_owned(), 0);
    let mut buf = [0u8; 3];
    let n1 = fs.read(fd, &mut buf);
    assert_eq!(n1, 3);
    assert_eq!(&buf, b"abc");
    let n2 = fs.read(fd, &mut buf);
    assert_eq!(n2, 3);
    assert_eq!(&buf, b"def");
    let n3 = fs.read(fd, &mut buf);
    assert_eq!(n3, 0); // EOF
}

#[test]
fn read_bad_fd_returns_ebadf() {
    let mut fs = InMemFs::new();
    let mut buf = [0u8; 4];
    assert_eq!(fs.read(99, &mut buf), EBADF);
}

#[test]
fn read_dir_fd_returns_eisdir() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/d");
    let fd = fs.open("/d".to_owned(), 0);
    assert!(fd >= 3);
    let mut buf = [0u8; 4];
    assert_eq!(fs.read(fd, &mut buf), EISDIR);
}

// ---- close ------------------------------------------------------------------

#[test]
fn close_valid_fd_succeeds() {
    let mut fs = InMemFs::new();
    fs.insert_file("/c.txt", b"x".to_vec());
    let fd = fs.open("/c.txt".to_owned(), 0);
    assert!(fd >= 3);
    assert_eq!(fs.close(fd), 0);
    // Double-close returns EBADF.
    assert_eq!(fs.close(fd), EBADF);
}

#[test]
fn reserved_fds_are_ebadf() {
    let mut fs = InMemFs::new();
    assert_eq!(fs.close(0), EBADF);
    assert_eq!(fs.close(1), EBADF);
    assert_eq!(fs.close(2), EBADF);
    assert_eq!(fs.read(0, &mut []), EBADF);
}

// ---- lseek ------------------------------------------------------------------

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
fn lseek_seek_cur() {
    let mut fs = InMemFs::new();
    fs.insert_file("/b.txt", b"0123456789".to_vec());
    let fd = fs.open("/b.txt".to_owned(), 0);
    // SEEK_CUR +3
    let off = fs.lseek(fd, 3, 1);
    assert_eq!(off, 3);
    let mut buf = [0u8; 2];
    fs.read(fd, &mut buf);
    assert_eq!(&buf, b"34");
}

#[test]
fn lseek_seek_end() {
    let mut fs = InMemFs::new();
    fs.insert_file("/e.txt", b"hello".to_vec());
    let fd = fs.open("/e.txt".to_owned(), 0);
    // SEEK_END -2 -> offset 3
    let off = fs.lseek(fd, -2, 2);
    assert_eq!(off, 3);
    let mut buf = [0u8; 2];
    fs.read(fd, &mut buf);
    assert_eq!(&buf, b"lo");
}

#[test]
fn lseek_invalid_whence_returns_einval() {
    let mut fs = InMemFs::new();
    fs.insert_file("/q.txt", b"x".to_vec());
    let fd = fs.open("/q.txt".to_owned(), 0);
    assert_eq!(fs.lseek(fd, 0, 99), EINVAL as i64);
}

#[test]
fn lseek_negative_result_returns_einval() {
    let mut fs = InMemFs::new();
    fs.insert_file("/r.txt", b"abc".to_vec());
    let fd = fs.open("/r.txt".to_owned(), 0);
    // SEEK_SET to -1 -> invalid
    assert_eq!(fs.lseek(fd, -1, 0), EINVAL as i64);
}

// ---- pread ------------------------------------------------------------------

#[test]
fn pread_does_not_advance_offset() {
    let mut fs = InMemFs::new();
    fs.insert_file("/pr.txt", b"0123456789".to_vec());
    let fd = fs.open("/pr.txt".to_owned(), 0);
    let mut buf1 = [0u8; 3];
    let n1 = fs.pread(fd, &mut buf1, 2);
    assert_eq!(n1, 3);
    assert_eq!(&buf1, b"234");
    // Offset has not moved: sequential read still starts from 0.
    let mut buf2 = [0u8; 2];
    let n2 = fs.read(fd, &mut buf2);
    assert_eq!(n2, 2);
    assert_eq!(&buf2, b"01");
}

// ---- stat_into (struct layout) ---------------------------------------------

#[test]
fn stat_into_file_mode_and_size_at_correct_offsets() {
    let mut fs = InMemFs::new();
    fs.insert_file("/s.txt", b"hello world".to_vec());
    let mut buf = [0u8; 112];
    let rc = fs.stat_into("/s.txt", &mut buf);
    assert_eq!(rc, 0);

    // st_mode at offset 4 (i32 LE): must have S_IFREG bit (0o100000 = 0x8000).
    let mode = i32::from_le_bytes(buf[4..8].try_into().unwrap());
    assert!(
        mode & 0o100_000 != 0,
        "S_IFREG bit missing in st_mode: mode={mode:#o}"
    );

    // st_size at offset 24 (i64 LE): must equal 11 bytes.
    let size = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    assert_eq!(size, 11, "st_size mismatch");
}

#[test]
fn stat_into_dir_mode_and_zero_size() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/d");
    let mut buf = [0u8; 112];
    let rc = fs.stat_into("/d", &mut buf);
    assert_eq!(rc, 0);

    let mode = i32::from_le_bytes(buf[4..8].try_into().unwrap());
    assert!(
        mode & 0o040_000 != 0,
        "S_IFDIR bit missing in st_mode: mode={mode:#o}"
    );

    let size = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    assert_eq!(size, 0);
}

#[test]
fn stat_into_missing_path_returns_enoent() {
    let mut fs = InMemFs::new();
    let mut buf = [0u8; 112];
    assert_eq!(fs.stat_into("/no/such/file", &mut buf), ENOENT);
}

#[test]
fn stat_into_st_blksize_is_4096() {
    let mut fs = InMemFs::new();
    fs.insert_file("/blk.txt", b"data".to_vec());
    let mut buf = [0u8; 112];
    fs.stat_into("/blk.txt", &mut buf);
    let blksize = i32::from_le_bytes(buf[32..36].try_into().unwrap());
    assert_eq!(blksize, 4096);
}

// ---- fstat_into -------------------------------------------------------------

#[test]
fn fstat_into_matches_stat_into() {
    let mut fs = InMemFs::new();
    fs.insert_file("/fst.txt", b"abc".to_vec());
    let fd = fs.open("/fst.txt".to_owned(), 0);
    let mut buf_fstat = [0u8; 112];
    let rc = fs.fstat_into(fd, &mut buf_fstat);
    assert_eq!(rc, 0);

    let mode = i32::from_le_bytes(buf_fstat[4..8].try_into().unwrap());
    assert!(mode & 0o100_000 != 0, "S_IFREG expected from fstat");

    let size = i64::from_le_bytes(buf_fstat[24..32].try_into().unwrap());
    assert_eq!(size, 3);
}

// ---- list_dir ---------------------------------------------------------------

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
fn list_dir_is_sorted() {
    let mut fs = InMemFs::new();
    fs.insert_file("/s/z.txt", b"".to_vec());
    fs.insert_file("/s/a.txt", b"".to_vec());
    fs.insert_file("/s/m.txt", b"".to_vec());
    let entries = fs.list_dir("/s").unwrap();
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["a.txt", "m.txt", "z.txt"]);
}

#[test]
fn list_dir_excludes_deep_descendants() {
    let mut fs = InMemFs::new();
    fs.insert_file("/d/child/grandchild.txt", b"".to_vec());
    let entries = fs.list_dir("/d").unwrap();
    // Only "child" should appear - not "child/grandchild.txt".
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "child");
}

#[test]
fn list_dir_returns_none_for_file() {
    let mut fs = InMemFs::new();
    fs.insert_file("/f.txt", b"".to_vec());
    assert!(fs.list_dir("/f.txt").is_none());
}

// ---- getdents64_into --------------------------------------------------------

#[test]
fn getdents64_terminates_at_end_of_dir() {
    let mut fs = InMemFs::new();
    fs.insert_file("/lib/a.py", b"".to_vec());
    fs.insert_file("/lib/b.py", b"".to_vec());
    let fd = fs.open("/lib".to_owned(), 0);
    assert!(fd >= 3);

    let mut all_bytes = 0usize;
    let mut call_count = 0u32;
    loop {
        let mut buf = vec![0u8; 4096];
        let n = fs.getdents64_into(fd, &mut buf);
        assert!(n >= 0, "unexpected error from getdents64: {n}");
        if n == 0 {
            break;
        }
        all_bytes += n as usize;
        call_count += 1;
        assert!(call_count < 100, "getdents64 did not terminate");
    }
    assert!(all_bytes > 0, "no bytes from getdents64");
    // A second terminating call must still return 0, not restart.
    let mut buf2 = vec![0u8; 4096];
    let n2 = fs.getdents64_into(fd, &mut buf2);
    assert_eq!(n2, 0, "cursor did not stay at end after exhaustion");
}

#[test]
fn getdents64_empty_dir_emits_dots_then_zero() {
    let mut fs = InMemFs::new();
    fs.mkdir_p("/empty");
    let fd = fs.open("/empty".to_owned(), 0);
    assert!(fd >= 3);

    let mut buf = vec![0u8; 4096];
    let n1 = fs.getdents64_into(fd, &mut buf);
    assert!(n1 > 0, "expected dot entries, got {n1}");

    let n2 = fs.getdents64_into(fd, &mut buf);
    assert_eq!(n2, 0, "expected end-of-dir after dot entries");
}

/// getdents64 with a tiny buffer (just large enough for one entry at a time)
/// must paginate and eventually terminate. Each call returns at most one entry.
#[test]
fn getdents64_paginates_with_small_buffer() {
    let mut fs = InMemFs::new();
    // Three children: "a", "b", "c" - plus "." and ".." = 5 total.
    fs.insert_file("/pg/a", b"".to_vec());
    fs.insert_file("/pg/b", b"".to_vec());
    fs.insert_file("/pg/c", b"".to_vec());
    let fd = fs.open("/pg".to_owned(), 0);
    assert!(fd >= 3);

    // One entry at minimum is: 19 bytes header + 1 byte name ("." or ".") + NUL + padding = 24 bytes.
    // Use a buffer of exactly 32 bytes to fit one entry at a time.
    let mut calls = 0u32;
    let mut total_bytes = 0usize;
    loop {
        let mut buf = vec![0u8; 32];
        let n = fs.getdents64_into(fd, &mut buf);
        assert!(n >= 0, "getdents64 returned error: {n}");
        if n == 0 {
            break;
        }
        total_bytes += n as usize;
        calls += 1;
        assert!(calls < 20, "getdents64 did not terminate with small buffer");
    }
    // Must have produced exactly 5 separate calls (. .. a b c).
    assert_eq!(calls, 5, "expected 5 paginated calls, got {calls}");
    assert!(total_bytes > 0);
}

/// getdents64 on a non-directory fd returns ENOTDIR.
#[test]
fn getdents64_on_file_fd_returns_enotdir() {
    let mut fs = InMemFs::new();
    fs.insert_file("/f.txt", b"x".to_vec());
    let fd = fs.open("/f.txt".to_owned(), 0);
    assert!(fd >= 3);
    let mut buf = vec![0u8; 4096];
    assert_eq!(fs.getdents64_into(fd, &mut buf), ENOTDIR);
}

/// `write_dirent64` records encode the correct fields at the expected offsets.
#[test]
fn write_dirent64_field_layout() {
    let mut buf = vec![0u8; 256];
    let ino = 42u64;
    let off = 7u64;
    let name = "hello";
    let n = write_dirent64(&mut buf, 0, ino, off, name, false);

    // d_ino at offset 0 (u64 LE)
    let d_ino = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    assert_eq!(d_ino, ino);

    // d_off at offset 8 (u64 LE)
    let d_off = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    assert_eq!(d_off, off);

    // d_reclen at offset 16 (u16 LE): must match the returned n
    let reclen = u16::from_le_bytes(buf[16..18].try_into().unwrap()) as usize;
    assert_eq!(reclen, n);
    // Reclen must be a multiple of 8.
    assert_eq!(reclen % 8, 0);

    // d_type at offset 18: 8 = DT_REG
    assert_eq!(buf[18], 8);

    // d_name at offset 19: null-terminated "hello"
    assert_eq!(&buf[19..24], b"hello");
    assert_eq!(buf[24], 0); // NUL terminator
}

#[test]
fn write_dirent64_dir_type() {
    let mut buf = vec![0u8; 64];
    write_dirent64(&mut buf, 0, 1, 1, "dir", true);
    // d_type at offset 18: 4 = DT_DIR
    assert_eq!(buf[18], 4);
}

#[test]
fn write_dirent64_returns_zero_when_buffer_too_small() {
    let mut buf = vec![0u8; 10]; // too small for any entry
    let n = write_dirent64(&mut buf, 0, 1, 1, "x", false);
    assert_eq!(n, 0);
}

// ---- fd management ----------------------------------------------------------

#[test]
fn fd_starts_at_3() {
    let mut fs = InMemFs::new();
    fs.insert_file("/first.txt", b"".to_vec());
    let fd = fs.open("/first.txt".to_owned(), 0);
    assert_eq!(fd, 3, "first fd after reservation must be 3");
}

#[test]
fn closed_fd_slot_is_reused() {
    let mut fs = InMemFs::new();
    fs.insert_file("/r1.txt", b"".to_vec());
    fs.insert_file("/r2.txt", b"".to_vec());
    let fd1 = fs.open("/r1.txt".to_owned(), 0);
    let fd2 = fs.open("/r2.txt".to_owned(), 0);
    assert!(fd1 >= 3);
    assert!(fd2 > fd1);
    fs.close(fd1);
    // Next open should reuse fd1's slot.
    fs.insert_file("/r3.txt", b"".to_vec());
    let fd3 = fs.open("/r3.txt".to_owned(), 0);
    assert_eq!(fd3, fd1, "slot {fd1} should be reused after close");
    let _ = (fd2, fd3);
}

#[test]
fn is_fs_fd_correct() {
    let mut fs = InMemFs::new();
    assert!(!fs.is_fs_fd(0));
    assert!(!fs.is_fs_fd(1));
    assert!(!fs.is_fs_fd(2));
    fs.insert_file("/x.txt", b"".to_vec());
    let fd = fs.open("/x.txt".to_owned(), 0);
    assert!(fs.is_fs_fd(fd));
    fs.close(fd);
    assert!(!fs.is_fs_fd(fd));
}

// ---- preopen ----------------------------------------------------------------

#[test]
fn preopen_fd3_is_root() {
    let fs = InMemFs::new_with_root_preopen();
    assert_eq!(fs.preopen_name(3), Some("/"));
}

#[test]
fn preopen_non3_is_none() {
    let fs = InMemFs::new_with_root_preopen();
    assert!(fs.preopen_name(4).is_none());
}

// ---- property: write-then-read round-trip -----------------------------------

/// Writing an arbitrary byte sequence through an fd and reading it back must
/// produce the original bytes exactly.
#[test]
fn prop_write_read_roundtrip() {
    // Test vectors: empty, single byte, 1 KiB, max-u8 byte pattern.
    let cases: &[&[u8]] = &[
        b"",
        b"\x00",
        b"\xff",
        &[0u8; 1024],
        &(0u8..=255).collect::<Vec<_>>()[..],
        b"hello\x00world\xff",
    ];
    for &data in cases {
        let mut fs = InMemFs::new();
        let fd = fs.open("/rt.txt".to_owned(), O_CREAT | O_WRONLY);
        assert!(fd >= 3);
        let n = fs.write(fd, data);
        assert_eq!(
            n as usize,
            data.len(),
            "write count mismatch for len={}",
            data.len()
        );
        fs.close(fd);

        let fd_r = fs.open("/rt.txt".to_owned(), 0);
        let mut out = vec![0u8; data.len()];
        if data.is_empty() {
            let n_read = fs.read(fd_r, &mut out);
            assert_eq!(n_read, 0);
        } else {
            let n_read = fs.read(fd_r, &mut out);
            assert_eq!(n_read as usize, data.len());
            assert_eq!(out.as_slice(), data, "round-trip mismatch");
        }
        fs.close(fd_r);
    }
}

// ---- property: getdents visits each child exactly once then EOF -------------

/// For N children, getdents (with a large buffer) must emit exactly N + 2
/// entries (N children + "." + ".."), each once, then return 0.
#[test]
fn prop_getdents_visits_each_child_once() {
    for n_children in [0usize, 1, 3, 10, 50] {
        let mut fs = InMemFs::new();
        let base = "/prop_gd";
        fs.mkdir_p(base);
        for i in 0..n_children {
            fs.insert_file(&format!("{base}/f{i:03}"), b"".to_vec());
        }
        let fd = fs.open(base.to_owned(), 0);
        assert!(fd >= 3, "n_children={n_children}");

        let mut total_entries = 0usize;
        let mut calls = 0u32;
        loop {
            let mut buf = vec![0u8; 65536];
            let n = fs.getdents64_into(fd, &mut buf);
            assert!(n >= 0, "n_children={n_children}: getdents64 error {n}");
            if n == 0 {
                break;
            }
            // Count entries by walking d_reclen chain in the buffer.
            let mut pos = 0usize;
            while pos < n as usize {
                let reclen =
                    u16::from_le_bytes(buf[pos + 16..pos + 18].try_into().unwrap()) as usize;
                assert!(reclen > 0, "zero reclen at pos={pos}");
                total_entries += 1;
                pos += reclen;
            }
            calls += 1;
            assert!(
                calls < 200,
                "getdents64 did not terminate n_children={n_children}"
            );
        }
        assert_eq!(
            total_entries,
            n_children + 2,
            "n_children={n_children}: expected {} entries, got {total_entries}",
            n_children + 2
        );
        // One more call must return 0 (EOF stays stable).
        let mut buf2 = vec![0u8; 65536];
        assert_eq!(
            fs.getdents64_into(fd, &mut buf2),
            0,
            "n_children={n_children}: EOF not stable"
        );
    }
}
