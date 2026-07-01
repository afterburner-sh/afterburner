// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Live Ruby probe for the WASI-command filesystem capture increment.
//!
//! Boots the real bundled CRuby (`~/.burn/ruby-<rel>` or `BURN_RUBY_RUNTIME`)
//! and runs a Ruby program that `File.binwrite`s a **binary** blob (NULs,
//! `0xFF`, the invalid-UTF-8 pair `0xC3 0x28`) then `File.binread`s it back and
//! echoes it to stdout, with a recording [`HostContext`] attached via the public
//! [`run_ruby_package_with_host`] path.
//!
//! Two things are proven honestly:
//!
//! 1. **Round-trip.** Real CRuby writes and reads the binary file byte-exact
//!    through afterburner's WASI host FS: `out.stdout == PAYLOAD`.
//!
//! 2. **Capture status (the honest deferred boundary).** The current public
//!    Ruby boot path ([`run_ruby_package_with_host`]) compiles with the sealed
//!    `wire_effect_wrapped_wasi` setup (clock + random shadows, **stock** fs), so
//!    Ruby file I/O is served by stock `wasmtime-wasi` host preopens and is NOT
//!    routed through the record/replay `FsSeam`. The fs shadows landed this
//!    increment are wired only for the standalone WAT command path
//!    (`wire_effect_wrapped_wasi_fs`, proven in `effect_wasi_fs_capture.rs`).
//!    So this run journals **zero** `Fs(...)` effects. The test asserts that
//!    honestly: it is the empirical marker of the deferred
//!    `run_ruby_pkg`-integration step, not a false green claiming Ruby fs
//!    capture that does not exist yet.
//!
//! `#[ignore]`d and runtime-guarded: it uses the real `~/.burn` Ruby runtime, so
//! it is opt-in (`cargo test -p afterburner-wasi --test effect_wasi_fs_ruby_live
//! -- --ignored`). When no runtime is resolvable it reports SKIP and returns,
//! never a false pass.

use std::sync::Mutex;

use afterburner_core::{EffectKind, HostContext, HostEffect, HostEffectRecord};
use afterburner_wasi::ruby_runner::{resolve_ruby_runtime, run_ruby_package_with_host};

/// The same 32-byte binary payload the WAT conformance proof uses: embedded NUL,
/// `0xFF`, and the invalid-UTF-8 pair `0xC3 0x28`.
const PAYLOAD: [u8; 32] = [
    0x00, 0xFF, 0xC3, 0x28, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0xFF,
    0x80, 0x7F, 0x00, 0xC3, 0x28, 0x41, 0x42, 0x43, 0x00, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
];

/// A Ruby program that reconstructs `PAYLOAD` from its byte values (no
/// source-encoding hazards), writes it to a file under the rw package mount,
/// reads it straight back, and writes the round-tripped bytes to stdout in
/// binary mode. `File.binwrite` / `File.binread` are the exact calls the WAT
/// conformance module models at the wasip1 level.
const RUBY_SRC: &str = r#"
bytes = [
  0x00,0xFF,0xC3,0x28,0xDE,0xAD,0xBE,0xEF,0x00,0x01,0x02,0x03,0xFC,0xFD,0xFE,0xFF,
  0x80,0x7F,0x00,0xC3,0x28,0x41,0x42,0x43,0x00,0xFF,0x10,0x20,0x30,0x40,0x50,0x60
].pack("C*")
path = "/pkg/fs_probe.bin"
File.binwrite(path, bytes)
back = File.binread(path)
STDOUT.binmode
STDOUT.write(back)
"#;

/// Records every effect handed to it (record mode: `on_host_call` -> `None`).
#[derive(Default)]
struct Recorder {
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for Recorder {
    fn on_host_call(&self, _effect: &HostEffect) -> Option<HostEffectRecord> {
        None
    }
    fn record_host_effect(&self, record: HostEffectRecord) {
        self.log.lock().unwrap().push(record);
    }
    fn get_effect_log(&self) -> Vec<HostEffectRecord> {
        self.log.lock().unwrap().clone()
    }
}

/// Process-unique temp dir (no wall clock / RNG): pid + a static counter.
fn unique_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

#[test]
#[ignore = "uses the real ~/.burn Ruby runtime; run explicitly with --ignored"]
fn ruby_binary_file_roundtrips_and_fs_capture_is_deferred() {
    // Runtime guard: no runtime -> honest SKIP, never a false pass.
    let rt = match resolve_ruby_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("SKIP ruby_binary_file_roundtrips_and_fs_capture_is_deferred: {e}");
            return;
        }
    };

    // Stage a one-file package.
    let pkg = unique_dir("burn-rb-fslive");
    std::fs::create_dir_all(&pkg).expect("mkdir pkg");
    std::fs::write(pkg.join("main.rb"), RUBY_SRC).expect("write main.rb");

    let host = std::sync::Arc::new(Recorder::default());
    let run = run_ruby_package_with_host(&rt, &pkg, "main.rb", Some(host.clone()));
    let _ = std::fs::remove_dir_all(&pkg);

    let out = run.expect("ruby run");
    assert_eq!(
        out.exit_code,
        0,
        "clean Ruby exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // (1) Round-trip: real CRuby wrote then read the binary file byte-exact.
    assert_eq!(
        out.stdout,
        PAYLOAD.to_vec(),
        "binary file round-tripped through real CRuby byte-exact"
    );

    // (2) Capture status: the current public Ruby path uses stock fs, so no
    // Fs effect is journalled. This is the empirical marker of the deferred
    // run_ruby_pkg fs-wiring step (see the module doc), reported not hidden.
    let log = host.get_effect_log();
    let fs_effects = log
        .iter()
        .filter(|r| matches!(r.effect.kind, EffectKind::Fs(_)))
        .count();
    eprintln!(
        "RUBY LIVE: total effects={} fs_effects={} stdout_len={} (fs capture into the Ruby \
         boot path is the honestly-deferred integration step)",
        log.len(),
        fs_effects,
        out.stdout.len()
    );
    assert_eq!(
        fs_effects, 0,
        "DEFERRED: the Ruby boot path does not yet route file I/O through FsSeam \
         (wire_effect_wrapped_wasi_fs is wired only for the standalone WAT path); \
         if this ever becomes non-zero the integration has landed and this probe \
         should be upgraded to assert Fs(Write)/Fs(Read) with BLAKE3 parity: {log:?}"
    );
}
