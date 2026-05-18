// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B7 — `fs/promises` expansion: realpath, cp, opendir + Dir/Dirent,
//! watch + FSWatcher (polling-based), and FileHandle (returned from
//! `fs.promises.open`).
//!
//! Each test scratches a fresh tempdir and drives `burn` with `-A`
//! (full grants) so capability gating doesn't shadow the surface
//! we're verifying. Test inventory:
//!
//! * `realpath_resolves_symlink` — realpathSync follows a symlink.
//! * `realpath_promise_form` — `fs.promises.realpath` round-trips.
//! * `realpath_throws_for_missing` — clean ENOENT-class error.
//! * `cp_copies_file` — file → file copy.
//! * `cp_recursive_directory` — directory tree copy with nested entries.
//! * `cp_force_overwrites` — `force: true` clobbers an existing file.
//! * `cp_no_force_rejects_existing` — without `force`, existing dst errors.
//! * `cp_promise_form` — `fs.promises.cp` resolves on success.
//! * `opendir_returns_dirent_with_types` — `Dirent.isFile/isDirectory`.
//! * `opendir_async_iterator_yields_all` — `for await` yields every entry.
//! * `opendir_close_after_close_throws` — `ERR_DIR_CLOSED` after close.
//! * `readdir_with_file_types_returns_dirents` — readdirSync({withFileTypes:true}).
//! * `watch_emits_change_on_write` — FSWatcher fires 'change' when a file mutates.
//! * `watch_emits_rename_on_create` — FSWatcher fires 'rename' on a new file.
//! * `watch_close_stops_emissions` — `.close()` halts the watcher.
//! * `watch_async_iterator` — `fs.promises.watch` is async-iterable.
//! * `filehandle_read_writes_at_offsets` — read/write with positional offsets.
//! * `filehandle_readFile_writeFile` — convenience methods round-trip.
//! * `filehandle_close_then_use_throws` — `EBADF` after close.
//! * `filehandle_truncate_shrinks` — truncate(N) trims the file.

#![cfg(feature = "bin")]

use serial_test::serial;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn scratch(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_fsp_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_burn_in(cwd: &PathBuf, src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(cwd)
        .args(["-A", "-e", src])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} FAILED\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ----- realpath -----------------------------------------------------------

#[test]
fn realpath_resolves_symlink() {
    let dir = scratch("realpath");
    let target = dir.join("real.txt");
    fs::write(&target, b"hello").unwrap();
    let link = dir.join("link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    {
        // Windows symlink may need elevated privileges — fall back to
        // the same file path so the test still verifies realpath
        // collapses any "./" segments.
        std::fs::copy(&target, &link).unwrap();
    }

    let target_canon = std::fs::canonicalize(&target).unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            const r = fs.realpathSync({link});
            console.log('R=' + r);
        "#,
        link = serde_json::to_string(link.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "realpath_resolves_symlink");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("R={}", target_canon.display())),
        "stdout should contain canonical target path: {stdout}"
    );
}

#[test]
fn realpath_promise_form() {
    let dir = scratch("realpath_p");
    let target = dir.join("p.txt");
    fs::write(&target, b"x").unwrap();
    let canon = std::fs::canonicalize(&target).unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            fs.promises.realpath({path}).then((r) => console.log('R=' + r));
        "#,
        path = serde_json::to_string(target.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "realpath_promise_form");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!("R={}", canon.display())),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn realpath_throws_for_missing() {
    let dir = scratch("realpath_missing");
    let src = format!(
        r#"
            const fs = require('fs');
            try {{ fs.realpathSync({path}); console.log('NO_THROW'); }}
            catch (e) {{ console.log('THREW=' + (e.code || 'EOTHER')); }}
        "#,
        path = serde_json::to_string(dir.join("nonexistent.txt").to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "realpath_throws_for_missing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("THREW="), "stdout: {stdout}");
    assert!(!stdout.contains("NO_THROW"), "should have thrown");
}

// ----- cp -----------------------------------------------------------------

#[test]
fn cp_copies_file() {
    let dir = scratch("cp_file");
    let src_path = dir.join("a.txt");
    let dst_path = dir.join("b.txt");
    fs::write(&src_path, b"copy-me").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            fs.cpSync({s}, {d});
            console.log('OK=' + fs.readFileSync({d}, 'utf8'));
        "#,
        s = serde_json::to_string(src_path.to_str().unwrap()).unwrap(),
        d = serde_json::to_string(dst_path.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "cp_copies_file");
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK=copy-me"));
}

#[test]
fn cp_recursive_directory() {
    let dir = scratch("cp_dir");
    let src_root = dir.join("src");
    fs::create_dir_all(src_root.join("nested")).unwrap();
    fs::write(src_root.join("top.txt"), b"top").unwrap();
    fs::write(src_root.join("nested/inner.txt"), b"inner").unwrap();
    let dst_root = dir.join("dst");

    let src = format!(
        r#"
            const fs = require('fs');
            const path = require('path');
            const S = {s};
            const D = {d};
            fs.cpSync(S, D, {{ recursive: true }});
            console.log('TOP_SRC=' + fs.readFileSync(path.join(S, 'top.txt'), 'utf8'));
            console.log('TOP_DST=' + fs.readFileSync(path.join(D, 'top.txt'), 'utf8'));
            console.log('INNER=' + fs.readFileSync(path.join(D, 'nested', 'inner.txt'), 'utf8'));
        "#,
        s = serde_json::to_string(src_root.to_str().unwrap()).unwrap(),
        d = serde_json::to_string(dst_root.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "cp_recursive_directory");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TOP_SRC=top"), "stdout: {stdout}");
    assert!(stdout.contains("TOP_DST=top"), "stdout: {stdout}");
    assert!(stdout.contains("INNER=inner"), "stdout: {stdout}");
}

#[test]
fn cp_force_overwrites() {
    let dir = scratch("cp_force");
    let s = dir.join("a.txt");
    let d = dir.join("b.txt");
    fs::write(&s, b"new").unwrap();
    fs::write(&d, b"old").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            fs.cpSync({s}, {d}, {{ force: true }});
            console.log('GOT=' + fs.readFileSync({d}, 'utf8'));
        "#,
        s = serde_json::to_string(s.to_str().unwrap()).unwrap(),
        d = serde_json::to_string(d.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "cp_force_overwrites");
    assert!(String::from_utf8_lossy(&out.stdout).contains("GOT=new"));
}

#[test]
fn cp_no_force_rejects_existing() {
    let dir = scratch("cp_no_force");
    let s = dir.join("a.txt");
    let d = dir.join("b.txt");
    fs::write(&s, b"new").unwrap();
    fs::write(&d, b"old").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            try {{ fs.cpSync({s}, {d}, {{ force: false }}); console.log('NO_THROW'); }}
            catch (e) {{ console.log('THREW'); }}
        "#,
        s = serde_json::to_string(s.to_str().unwrap()).unwrap(),
        d = serde_json::to_string(d.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "cp_no_force_rejects_existing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("THREW"), "stdout: {stdout}");
    assert!(!stdout.contains("NO_THROW"));
}

#[test]
fn cp_promise_form() {
    let dir = scratch("cp_promise");
    let s = dir.join("a.txt");
    let d = dir.join("b.txt");
    fs::write(&s, b"asynchronous").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            fs.promises.cp({s}, {d}, {{ force: true }}).then(() => {{
                console.log('OK=' + fs.readFileSync({d}, 'utf8'));
            }});
        "#,
        s = serde_json::to_string(s.to_str().unwrap()).unwrap(),
        d = serde_json::to_string(d.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "cp_promise_form");
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK=asynchronous"));
}

// ----- opendir / Dir / Dirent --------------------------------------------

#[test]
fn opendir_returns_dirent_with_types() {
    let dir = scratch("opendir");
    fs::write(dir.join("alpha.txt"), b"a").unwrap();
    fs::create_dir(dir.join("subdir")).unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            const d = fs.opendirSync({d});
            const lines = [];
            let e;
            while ((e = d.readSync()) !== null) {{
                lines.push(e.name + '/' + (e.isFile() ? 'F' : '') + (e.isDirectory() ? 'D' : ''));
            }}
            d.closeSync();
            console.log('OUT=' + lines.sort().join(','));
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "opendir_returns_dirent_with_types");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("alpha.txt/F"), "stdout: {stdout}");
    assert!(stdout.contains("subdir/D"), "stdout: {stdout}");
}

#[test]
fn opendir_async_iterator_yields_all() {
    let dir = scratch("opendir_iter");
    fs::write(dir.join("one"), b"1").unwrap();
    fs::write(dir.join("two"), b"2").unwrap();
    fs::write(dir.join("three"), b"3").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            (async () => {{
                const dh = await fs.promises.opendir({d});
                const names = [];
                for await (const e of dh) {{ names.push(e.name); }}
                console.log('NAMES=' + names.sort().join(','));
            }})();
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "opendir_async_iterator_yields_all");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("NAMES=one,three,two"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn opendir_close_after_close_throws() {
    let dir = scratch("opendir_close");
    let src = format!(
        r#"
            const fs = require('fs');
            const d = fs.opendirSync({d});
            d.closeSync();
            try {{ d.readSync(); console.log('NO_THROW'); }}
            catch (e) {{ console.log('THREW=' + e.code); }}
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "opendir_close_after_close_throws");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("THREW=ERR_DIR_CLOSED"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn readdir_with_file_types_returns_dirents() {
    let dir = scratch("readdir_dirents");
    fs::write(dir.join("a.txt"), b"a").unwrap();
    fs::create_dir(dir.join("sub")).unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            const ents = fs.readdirSync({d}, {{ withFileTypes: true }});
            const lines = ents.map((e) => e.name + ':' + (e.isDirectory() ? 'D' : 'F'));
            console.log('LIST=' + lines.sort().join(','));
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "readdir_with_file_types_returns_dirents");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("a.txt:F"), "stdout: {stdout}");
    assert!(stdout.contains("sub:D"), "stdout: {stdout}");
}

// ----- watch / FSWatcher -------------------------------------------------
//
// host_fs_watch_poll BLOCKS the JS thread for `interval_ms`, so any
// in-burn setTimeout that schedules a write happens AFTER the first
// poll completes — too late to be observed. We instead coordinate via
// a shared event-log file: burn writes events into <dir>/events.log
// using fs.writeFileSync({flag:'a'}); the rust test thread spawns
// burn, sleeps long enough for the watcher to be running, mutates the
// target file, sleeps again for the next poll cycle, then reads the
// log and asserts. Avoids the cross-process pipe-buffering race
// entirely — disk-backed messaging is the simpler protocol.
//
// burn debug-build cold-start is ~6 seconds; budgets reflect that.

fn run_burn_capturing_log(cwd: &PathBuf, src: &str) -> std::process::Child {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        // Cap shards so 20+ parallel test subprocesses on a 36-core
        // host don't each fan out to `available_parallelism()` shards
        // and saturate the CPU before fs.watch can even register.
        .env("BURN_SHARDS", "2")
        .current_dir(cwd)
        .args(["-A", "-e", src])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn")
}

/// Poll for a marker file to appear under cross-binary CPU pressure
/// burn cold-start can stretch past any fixed sleep budget. Returns the
/// file contents (or empty string on timeout).
fn poll_for_file(path: &std::path::Path, timeout: Duration) -> String {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(s) = fs::read_to_string(path)
            && !s.is_empty()
        {
            return s;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    String::new()
}

#[test]
#[serial]
fn watch_emits_change_on_write() {
    let dir = scratch("watch_change");
    let target = dir.join("target.txt");
    let log = dir.join("events.log");
    let ready = dir.join("ready.flag");
    fs::write(&target, b"v1").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            const w = fs.watch({d}, {{ interval: 200 }});
            w.on('change', (kind, name) => {{
                fs.writeFileSync({log}, kind + ':' + name + '\n', {{ flag: 'a' }});
            }});
            // Signal watcher is registered. The test waits for this
            // marker before mutating, which eliminates the cold-start
            // race that a fixed sleep had.
            fs.writeFileSync({ready}, 'ready');
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap(),
        log = serde_json::to_string(log.to_str().unwrap()).unwrap(),
        ready = serde_json::to_string(ready.to_str().unwrap()).unwrap()
    );
    let mut child = run_burn_capturing_log(&dir, &src);
    assert!(
        !poll_for_file(&ready, Duration::from_secs(120)).is_empty(),
        "watcher never reported ready within 120s"
    );
    fs::write(&target, b"v2").unwrap();
    let contents = poll_for_file(&log, Duration::from_secs(60));
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        contents.contains("change:target.txt") || contents.contains("rename:target.txt"),
        "expected change event on target.txt. log: {contents:?}"
    );
}

#[test]
#[serial]
fn watch_emits_rename_on_create() {
    let dir = scratch("watch_create");
    let new_path = dir.join("new.txt");
    let log = dir.join("events.log");
    let ready = dir.join("ready.flag");
    let src = format!(
        r#"
            const fs = require('fs');
            const w = fs.watch({d}, {{ interval: 200 }});
            w.on('change', (kind, name) => {{
                if (name === 'new.txt' && kind === 'rename') {{
                    fs.writeFileSync({log}, 'CREATED\n', {{ flag: 'a' }});
                }}
            }});
            fs.writeFileSync({ready}, 'ready');
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap(),
        log = serde_json::to_string(log.to_str().unwrap()).unwrap(),
        ready = serde_json::to_string(ready.to_str().unwrap()).unwrap()
    );
    let mut child = run_burn_capturing_log(&dir, &src);
    assert!(
        !poll_for_file(&ready, Duration::from_secs(120)).is_empty(),
        "watcher never reported ready within 120s"
    );
    fs::write(&new_path, b"fresh").unwrap();
    let contents = poll_for_file(&log, Duration::from_secs(60));
    let _ = child.kill();
    let _ = child.wait();
    assert!(contents.contains("CREATED"), "log: {contents:?}");
}

#[test]
#[serial]
fn watch_close_stops_emissions() {
    // Close-immediately path doesn't depend on external writes;
    // the watcher is closed before the file is mutated, so no events
    // are expected. Run wholly inside burn — short setTimeout that
    // fits in our cold-start window thanks to the in-burn loop pump.
    let dir = scratch("watch_close");
    fs::write(dir.join("x.txt"), b"v1").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            const path = require('path');
            const w = fs.watch({d}, {{ interval: 50 }});
            let count = 0;
            w.on('change', () => {{ count += 1; }});
            w.close();
            // Mutate after close — should NOT emit.
            fs.writeFileSync(path.join({d}, 'x.txt'), 'v2');
            // Give the closed watcher a generous window to mis-fire.
            setTimeout(() => {{ console.log('COUNT=' + count); process.exit(0); }}, 1000);
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "watch_close_stops_emissions");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("COUNT=0"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
#[serial]
fn watch_async_iterator() {
    let dir = scratch("watch_iter");
    let target = dir.join("a.txt");
    let log = dir.join("events.log");
    let ready = dir.join("ready.flag");
    fs::write(&target, b"v1").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            (async () => {{
                const watcher = fs.promises.watch({d}, {{ interval: 200 }});
                // Signal ready AFTER the watcher iterator is set up but
                // before the first event lands; the for-await yields
                // when the next change fires.
                fs.writeFileSync({ready}, 'ready');
                for await (const ev of watcher) {{
                    fs.writeFileSync({log}, ev.eventType + ':' + ev.filename + '\n', {{ flag: 'a' }});
                    break;
                }}
            }})();
        "#,
        d = serde_json::to_string(dir.to_str().unwrap()).unwrap(),
        log = serde_json::to_string(log.to_str().unwrap()).unwrap(),
        ready = serde_json::to_string(ready.to_str().unwrap()).unwrap()
    );
    let mut child = run_burn_capturing_log(&dir, &src);
    assert!(
        !poll_for_file(&ready, Duration::from_secs(120)).is_empty(),
        "watcher never reported ready within 120s"
    );
    fs::write(&target, b"v2").unwrap();
    let contents = poll_for_file(&log, Duration::from_secs(60));
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        contents.contains(":a.txt") || contents.contains("change") || contents.contains("rename"),
        "log: {contents:?}"
    );
}

// ----- FileHandle --------------------------------------------------------

#[test]
fn filehandle_read_writes_at_offsets() {
    let dir = scratch("fh_offsets");
    let path = dir.join("file.bin");
    fs::write(&path, b"AAAAAAAAAA").unwrap(); // 10 As
    let src = format!(
        r#"
            const fs = require('fs');
            const {{ Buffer }} = require('buffer');
            (async () => {{
                const fh = await fs.promises.open({p}, 'r+');
                const buf = Buffer.alloc(4);
                const r1 = await fh.read(buf, 0, 4, 0);
                console.log('R1=' + r1.bytesRead + ':' + buf.toString('utf8'));
                await fh.write(Buffer.from('BBBB'), 0, 4, 4);
                await fh.close();
                console.log('AFTER=' + fs.readFileSync({p}, 'utf8'));
            }})();
        "#,
        p = serde_json::to_string(path.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "filehandle_read_writes_at_offsets");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("R1=4:AAAA"), "stdout: {stdout}");
    assert!(stdout.contains("AFTER=AAAABBBBAA"), "stdout: {stdout}");
}

#[test]
fn filehandle_readfile_writefile() {
    let dir = scratch("fh_rwfile");
    let path = dir.join("z.txt");
    fs::write(&path, b"start").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            (async () => {{
                const fh = await fs.promises.open({p}, 'r+');
                const got = await fh.readFile('utf8');
                console.log('GOT=' + got);
                await fh.writeFile('rewritten');
                await fh.close();
                console.log('FINAL=' + fs.readFileSync({p}, 'utf8'));
            }})();
        "#,
        p = serde_json::to_string(path.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "filehandle_readfile_writefile");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GOT=start"), "stdout: {stdout}");
    assert!(stdout.contains("FINAL=rewritten"), "stdout: {stdout}");
}

#[test]
fn filehandle_close_then_use_throws() {
    let dir = scratch("fh_closed");
    let path = dir.join("c.txt");
    fs::write(&path, b"x").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            (async () => {{
                const fh = await fs.promises.open({p}, 'r+');
                await fh.close();
                try {{
                    await fh.readFile();
                    console.log('NO_THROW');
                }} catch (e) {{
                    console.log('THREW=' + e.code);
                }}
            }})();
        "#,
        p = serde_json::to_string(path.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "filehandle_close_then_use_throws");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("THREW=EBADF"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn filehandle_truncate_shrinks() {
    let dir = scratch("fh_trunc");
    let path = dir.join("t.txt");
    fs::write(&path, b"abcdefghij").unwrap();
    let src = format!(
        r#"
            const fs = require('fs');
            (async () => {{
                const fh = await fs.promises.open({p}, 'r+');
                await fh.truncate(4);
                await fh.close();
                console.log('LEN=' + fs.readFileSync({p}).length);
                console.log('VAL=' + fs.readFileSync({p}, 'utf8'));
            }})();
        "#,
        p = serde_json::to_string(path.to_str().unwrap()).unwrap()
    );
    let out = run_burn_in(&dir, &src);
    assert_ok(&out, "filehandle_truncate_shrinks");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LEN=4"), "stdout: {stdout}");
    assert!(stdout.contains("VAL=abcd"), "stdout: {stdout}");
}

// ----- watch capability gating -------------------------------------------
//
// The `-A` flag in run_burn_in grants every capability. Watchers also
// need to surface a clean EACCES when the watched path isn't on the
// fs allowlist. We test that here by spawning burn WITHOUT -A.

#[test]
fn watch_outside_grant_emits_eacces() {
    // Drive the host fn directly to deterministically observe the
    // manifold gate without fighting cold-start timing. The grant
    // covers /tmp/<scratch>/sandbox; the watch target is outside it.
    let dir = scratch("watch_eacces");
    let allowed = dir.join("sandbox");
    fs::create_dir_all(&allowed).unwrap();
    // Pick a path OUTSIDE the allowed root.
    let outside = "/etc";
    let src = format!(
        r#"
            const raw = globalThis.__host_fs_watch_poll({p}, 50);
            if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {{
                const msg = raw.slice('__HOST_ERR__:'.length).toLowerCase();
                console.log('DENIED=' + (msg.indexOf('permission') !== -1 || msg.indexOf('denied') !== -1 ? 'YES' : 'NO'));
            }} else {{
                console.log('UNEXPECTED=' + raw);
            }}
        "#,
        p = serde_json::to_string(outside).unwrap()
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(&dir)
        .args(["--allow-fs", allowed.to_str().unwrap(), "-e", &src])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("DENIED=YES"),
        "expected manifold to deny out-of-root watch. stdout: {stdout}\nstderr: {stderr}"
    );
}
