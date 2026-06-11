// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Round 4 CLI parity flags (Node 22+): --watch · --env-file ·
//! --require · --import · --permission + --allow-fs-read /
//! --allow-fs-write / --allow-child-process / --allow-worker. Each
//! test runs the burn binary in a sub-process so the full clap →
//! manifold → daemon → polyfill chain is exercised.

#![cfg(feature = "bin")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn fresh_dir(name: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_cli_{name}_{pid}_{n}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

#[test]
fn env_file_loads_into_process_env() {
    let dir = fresh_dir("envfile");
    let env_path = dir.join(".env");
    fs::write(
        &env_path,
        b"# a comment\n\
          FOO=hello\n\
          BAR=\"quoted value\"\n\
          BAZ='single quoted'\n\
          EMPTY=\n",
    )
    .unwrap();
    let script = dir.join("entry.js");
    fs::write(
        &script,
        b"console.log('FOO=' + process.env.FOO);\
          console.log('BAR=' + process.env.BAR);\
          console.log('BAZ=' + process.env.BAZ);\
          console.log('EMPTY=[' + process.env.EMPTY + ']');\n",
    )
    .unwrap();
    let out = run(&[
        "--env-file",
        env_path.to_str().unwrap(),
        "--allow-env",
        "FOO,BAR,BAZ,EMPTY",
        script.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(stdout.contains("FOO=hello"), "FOO missing: {stdout}");
    assert!(
        stdout.contains("BAR=quoted value"),
        "BAR not unquoted: {stdout}"
    );
    assert!(
        stdout.contains("BAZ=single quoted"),
        "BAZ not unquoted: {stdout}"
    );
    assert!(stdout.contains("EMPTY=[]"), "EMPTY not blank: {stdout}");
}

#[test]
fn require_preloads_module_before_user_script() {
    let dir = fresh_dir("require");
    let preload = dir.join("preload.js");
    fs::write(
        &preload,
        b"globalThis.__preload_marker = 'loaded';\n\
          console.log('PRELOAD-RAN');\n",
    )
    .unwrap();
    let script = dir.join("entry.js");
    fs::write(
        &script,
        b"console.log('MARKER=' + globalThis.__preload_marker);\n",
    )
    .unwrap();
    let out = run(&[
        "--require",
        preload.to_str().unwrap(),
        script.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(
        stdout.contains("PRELOAD-RAN"),
        "preload didn't run: {stdout}"
    );
    assert!(stdout.contains("MARKER=loaded"), "marker missing: {stdout}");
}

#[test]
fn import_preloads_module_before_user_script() {
    // `--import` is the ESM-flavoured cousin of `--require`. burn's
    // resolver lowers ESM through TS-strip + ESM-rewrite at load
    // time, so a `.mjs` preload reaches the user script with the
    // same shape.
    let dir = fresh_dir("import");
    let preload = dir.join("preload.mjs");
    fs::write(
        &preload,
        b"export const x = 7;\n\
          globalThis.__import_marker = 'esm-loaded';\n",
    )
    .unwrap();
    let script = dir.join("entry.js");
    fs::write(
        &script,
        b"console.log('IMPORT-MARKER=' + globalThis.__import_marker);\n",
    )
    .unwrap();
    let out = run(&[
        "--import",
        preload.to_str().unwrap(),
        script.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(
        stdout.contains("IMPORT-MARKER=esm-loaded"),
        "esm marker missing: {stdout}"
    );
}

#[test]
fn permission_model_grants_only_allowed_scopes() {
    let dir = fresh_dir("permission");
    let script = dir.join("entry.js");
    fs::write(
        &script,
        b"const ok_tmp = process.permission.has('fs.read', '/tmp');\
          const no_etc = process.permission.has('fs.read', '/etc');\
          const no_cp  = process.permission.has('child_process');\
          const ok_w   = process.permission.has('worker');\
          console.log('TMP=' + ok_tmp);\
          console.log('ETC=' + no_etc);\
          console.log('CP=' + no_cp);\
          console.log('W=' + ok_w);\n",
    )
    .unwrap();
    let out = run(&[
        "--permission",
        "--allow-fs-read",
        "/tmp",
        "--allow-worker",
        script.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    assert!(stdout.contains("TMP=true"), "tmp not granted: {stdout}");
    assert!(stdout.contains("ETC=false"), "etc leaked: {stdout}");
    assert!(stdout.contains("CP=false"), "cp leaked: {stdout}");
    assert!(stdout.contains("W=true"), "worker not granted: {stdout}");
}

#[test]
fn permission_model_inactive_means_allow_all() {
    let dir = fresh_dir("perm_off");
    let script = dir.join("entry.js");
    fs::write(
        &script,
        b"console.log('FS=' + process.permission.has('fs.read', '/anything'));\
          console.log('NET=' + process.permission.has('net'));\n",
    )
    .unwrap();
    let out = run(&["-A", script.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "burn failed: {stdout}");
    // No --permission → allow-all; manifold layer is the real gate.
    assert!(stdout.contains("FS=true"), "fs not allow-all: {stdout}");
    assert!(stdout.contains("NET=true"), "net not allow-all: {stdout}");
}

#[test]
fn watch_re_runs_on_file_change() {
    // Spawn `burn --watch entry.js` as a child; mutate `entry.js`;
    // confirm we see two distinct outputs in the child's stdout.
    let dir = fresh_dir("watch");
    let script = dir.join("entry.js");
    fs::write(&script, b"console.log('VERSION-1');\n").unwrap();
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["--watch", "-A", script.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn watch child");

    // Wait for the first run to land in the child's stdout.
    use std::io::Read;
    let mut out_pipe = child.stdout.take().expect("stdout pipe");
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let buf_w = std::sync::Arc::clone(&buf);
    let reader = std::thread::spawn(move || {
        let mut tmp = [0u8; 4096];
        loop {
            match out_pipe.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let mut g = buf_w.lock().unwrap();
                    g.extend_from_slice(&tmp[..n]);
                }
                Err(_) => break,
            }
        }
    });

    // Poll until VERSION-1 lands. Generous window — burn cold-start
    // under cross-binary CPU pressure can stretch past any short budget.
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(100));
        let g = buf.lock().unwrap();
        if String::from_utf8_lossy(&g).contains("VERSION-1") {
            break;
        }
    }

    // Mutate the file and wait for re-run.
    std::thread::sleep(Duration::from_millis(400));
    fs::write(&script, b"console.log('VERSION-2');\n").unwrap();
    let start = std::time::Instant::now();
    let mut saw_v2 = false;
    while start.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(100));
        let g = buf.lock().unwrap();
        if String::from_utf8_lossy(&g).contains("VERSION-2") {
            saw_v2 = true;
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let final_buf = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    assert!(
        final_buf.contains("VERSION-1"),
        "first run didn't emit: {final_buf}"
    );
    assert!(saw_v2, "watch didn't re-run after change: {final_buf}");
}
