// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Live Ruby proof for the WASI-command **filesystem capture** increment
//! (increment 2: the host-backed real-boot fs seam).
//!
//! Boots the real bundled CRuby (`~/.burn/ruby-<rel>` or `BURN_RUBY_RUNTIME`)
//! and runs a Ruby program that `File.binwrite`s a **binary** blob (embedded
//! NUL, `0xFF`, the invalid-UTF-8 pair `0xC3 0x28`) to the rw scratch mount
//! `/work`, then `File.binread`s it back, with a recording / replaying
//! [`HostContext`] attached via the public [`run_ruby_package_with_host`] path.
//!
//! This is the empirical inversion of the increment-1 deferred marker: the
//! Ruby boot path now compiles with the fs-shadow variant
//! (`wire_effect_wrapped_wasi_fs`, host-backed over Ruby's real preopens), so
//! real File I/O is routed through the record/replay `FsSeam` and journalled as
//! `Fs(...)` effects. The proofs, all over a **real CRuby boot**:
//!
//! 1. **Round-trip.** Real CRuby writes and reads the binary file byte-exact
//!    through afterburner's host-backed WASI FS: `out.stdout == PAYLOAD`.
//! 2. **Capture with BLAKE3 parity.** The effect log carries an `Fs(Write)` and
//!    an `Fs(Read)` for `file::/work/x.bin` whose content-addresses agree:
//!    `write.input_hash == read.output_hash == content_hash(PAYLOAD)`, and each
//!    hash self-consistently addresses its own bytes.
//! 3. **Binary safety.** The recorded write bytes still hold the NUL and the
//!    invalid-UTF-8 pair: no lossy `String` decode on the capture path.
//! 4. **Internal-mount exclusion.** The guest's own `/.afb/output.frame` return
//!    write is afterburner's plumbing, not a guest effect, so no `Fs(...)`
//!    effect targets `/.afb/*` (the return frame still decodes: `out.output ==
//!    Bytes(PAYLOAD)`).
//! 5. **Serve/replay.** A second host that serves a distinctive substitute for
//!    the `/work/x.bin` `Fs(Read)` proves the served bytes reach Ruby, the real
//!    on-disk bytes are bypassed (no host read), and a served read journals no
//!    Read record: the increment-1 serve semantics carry through the real boot.
//!
//! `#[ignore]`d and runtime-guarded: it uses the real `~/.burn` Ruby runtime, so
//! it is opt-in (`cargo test -p afterburner-wasi --test effect_wasi_fs_ruby_live
//! -- --ignored`). When no runtime is resolvable it reports SKIP and returns,
//! never a false pass.

use std::sync::Mutex;

use afterburner_core::{
    EffectKind, EffectStatus, FileOp, HostContext, HostEffect, HostEffectRecord, OutputValue,
    content_hash, encode_output_value, fs_target,
};
use afterburner_wasi::ruby_runner::{resolve_ruby_runtime, run_ruby_package_with_host};

/// A 32-byte **binary** payload: embedded NUL (`0x00`), `0xFF`, and the pair
/// `0xC3 0x28` (an invalid UTF-8 sequence). If any capture step lossily decoded
/// to a `String` this blob would not survive byte-exact.
const PAYLOAD: [u8; 32] = [
    0x00, 0xFF, 0xC3, 0x28, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0xFF,
    0x80, 0x7F, 0x00, 0xC3, 0x28, 0x41, 0x42, 0x43, 0x00, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
];

/// The guest path the Ruby writes then reads: under the rw scratch mount
/// `/work`, so it never collides with the package or stdlib mounts.
const GUEST_PATH: &str = "/work/x.bin";

/// A comma-joined decimal byte list for a Ruby `[...].pack("C*")` literal, built
/// from the bytes in Rust so no source-encoding hazard can corrupt the blob.
fn ruby_byte_list(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

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

/// Serves a distinctive substitute for the `Fs(Read)` on `GUEST_PATH` and
/// records everything else (replay direction).
struct ReadReplayer {
    served: Vec<u8>,
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for ReadReplayer {
    fn on_host_call(&self, effect: &HostEffect) -> Option<HostEffectRecord> {
        if effect.kind == EffectKind::Fs(FileOp::Read) && effect.target == fs_target(GUEST_PATH) {
            Some(HostEffectRecord::new(
                effect.clone(),
                self.served.clone(),
                0,
                EffectStatus::Ok {
                    code: 0,
                    rows: None,
                },
            ))
        } else {
            None
        }
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
fn ruby_binary_file_capture_records_write_read_with_blake3_parity() {
    // Runtime guard: no runtime -> honest SKIP, never a false pass.
    let rt = match resolve_ruby_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("SKIP ruby_binary_file_capture_records_write_read_with_blake3_parity: {e}");
            return;
        }
    };

    // The guest also returns PAYLOAD via the /.afb frame; build it host-side.
    let frame = encode_output_value(&OutputValue::Bytes(PAYLOAD.to_vec())).expect("encode frame");
    let data_lit = ruby_byte_list(&PAYLOAD);
    let frame_lit = ruby_byte_list(&frame);
    let src = format!(
        "data = [{data_lit}].pack('C*')\n\
         path = '{GUEST_PATH}'\n\
         File.binwrite(path, data)\n\
         raise 'binary roundtrip mismatch' unless File.binread(path) == data\n\
         frame = [{frame_lit}].pack('C*')\n\
         File.binwrite('/.afb/output.frame', frame)\n\
         STDOUT.binmode\n\
         STDOUT.write(data)\n"
    );

    let pkg = unique_dir("burn-rb-fscap");
    std::fs::create_dir_all(&pkg).expect("mkdir pkg");
    std::fs::write(pkg.join("main.rb"), &src).expect("write main.rb");

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

    // (4a) The /.afb return frame still reconciles into a typed value.
    assert_eq!(
        out.output,
        OutputValue::Bytes(PAYLOAD.to_vec()),
        "typed return value decoded from the /.afb frame"
    );

    // The effect log: the real boot emits many stdlib Fs effects; we assert on
    // the /work/x.bin target specifically (a fixed total would be false
    // precision: the boot effect count is not fixed).
    let log = host.get_effect_log();
    let fs: Vec<&HostEffectRecord> = log
        .iter()
        .filter(|r| matches!(r.effect.kind, EffectKind::Fs(_)))
        .collect();
    let target = fs_target(GUEST_PATH);

    // The write leg: one Fs(Write) carrying the 32-byte payload as input.
    let write = fs
        .iter()
        .find(|r| {
            r.effect.kind == EffectKind::Fs(FileOp::Write)
                && r.effect.target == target
                && !r.effect.input.is_empty()
        })
        .unwrap_or_else(|| {
            panic!(
                "no content-bearing Fs(Write) captured for {target}; /work Fs effects seen: {:?}",
                fs.iter()
                    .filter(|r| r.effect.target == target)
                    .map(|r| (&r.effect.kind, r.effect.input.len(), r.output.len()))
                    .collect::<Vec<_>>()
            )
        });
    // The read leg: `File.binread` lowers to a read-open (journalled as an
    // empty-output "open marker" Fs(Read), deviation 3) plus the content-bearing
    // `fd_read`. Match the read whose *output* carries the file bytes.
    let read = fs
        .iter()
        .find(|r| {
            r.effect.kind == EffectKind::Fs(FileOp::Read)
                && r.effect.target == target
                && !r.output.is_empty()
        })
        .unwrap_or_else(|| {
            panic!(
                "no content-bearing Fs(Read) captured for {target}; /work Fs(Read) outputs: {:?}",
                fs.iter()
                    .filter(|r| {
                        r.effect.kind == EffectKind::Fs(FileOp::Read) && r.effect.target == target
                    })
                    .map(|r| r.output.len())
                    .collect::<Vec<_>>()
            )
        });

    let work_reads = fs
        .iter()
        .filter(|r| r.effect.kind == EffectKind::Fs(FileOp::Read) && r.effect.target == target)
        .count();
    eprintln!(
        "RUBY LIVE CAPTURE: total effects={} fs_effects={} /work Fs(Read) legs={} \
         write.input_len={} read.output_len={}",
        log.len(),
        fs.len(),
        work_reads,
        write.effect.input.len(),
        read.output.len(),
    );

    // (2) BLAKE3 parity over the real boot.
    let want = content_hash(&PAYLOAD);
    assert_eq!(
        write.effect.input,
        PAYLOAD.to_vec(),
        "captured write input == payload"
    );
    assert_eq!(
        read.output,
        PAYLOAD.to_vec(),
        "captured read output == payload"
    );
    assert_eq!(
        write.effect.input_hash, want,
        "write input hash == H(payload)"
    );
    assert_eq!(read.output_hash, want, "read output hash == H(payload)");
    assert_eq!(
        write.effect.input_hash, read.output_hash,
        "write in == read out (record/replay parity crux)"
    );
    // Self-consistency: each hash addresses its own bytes.
    assert_eq!(write.effect.input_hash, content_hash(&write.effect.input));
    assert_eq!(read.output_hash, content_hash(&read.output));

    // (3) Binary safety: NUL and the invalid-UTF-8 pair survived capture.
    assert!(write.effect.input.contains(&0x00), "NUL preserved");
    assert!(
        write.effect.input.windows(2).any(|w| w == [0xC3, 0x28]),
        "invalid-UTF-8 pair 0xC3 0x28 preserved"
    );

    // (4b) No Fs effect targets afterburner's internal /.afb plumbing.
    assert!(
        !fs.iter()
            .any(|r| r.effect.target.starts_with("file::/.afb")),
        "the /.afb return-frame write is internal plumbing, not a guest effect: {:?}",
        fs.iter()
            .filter(|r| r.effect.target.starts_with("file::/.afb"))
            .map(|r| &r.effect.target)
            .collect::<Vec<_>>()
    );
}

#[test]
#[ignore = "uses the real ~/.burn Ruby runtime; run explicitly with --ignored"]
fn ruby_replay_serves_substituted_read_without_touching_host_disk() {
    let rt = match resolve_ruby_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("SKIP ruby_replay_serves_substituted_read_without_touching_host_disk: {e}");
            return;
        }
    };

    // A read-back program with NO equality assertion: on serve the read returns
    // substituted bytes, so an equality check would (correctly) raise. Here we
    // echo whatever the read returns so the served bytes are observable.
    //
    // The read is length-bounded (`binread(path, 32)`) on purpose: an unbounded
    // `File.binread` reads to EOF, and a host that serves the substitute for
    // *every* `fd_read` never signals EOF to a to-EOF reader (it would loop).
    // A bounded read is satisfied by the single 32-byte serve. This is the
    // honest shape of the serve semantics for a real multi-read consumer.
    let data_lit = ruby_byte_list(&PAYLOAD);
    let src = format!(
        "data = [{data_lit}].pack('C*')\n\
         path = '{GUEST_PATH}'\n\
         File.binwrite(path, data)\n\
         back = File.binread(path, 32)\n\
         STDOUT.binmode\n\
         STDOUT.write(back)\n"
    );

    let pkg = unique_dir("burn-rb-fsserve");
    std::fs::create_dir_all(&pkg).expect("mkdir pkg");
    std::fs::write(pkg.join("main.rb"), &src).expect("write main.rb");

    // A distinctive fill the guest never wrote: 32 x 0xAB.
    let substitute = vec![0xABu8; 32];
    let host = std::sync::Arc::new(ReadReplayer {
        served: substitute.clone(),
        log: Mutex::new(Vec::new()),
    });

    let run = run_ruby_package_with_host(&rt, &pkg, "main.rb", Some(host.clone()));
    let _ = std::fs::remove_dir_all(&pkg);

    let out = run.expect("ruby run");
    assert_eq!(
        out.exit_code,
        0,
        "clean Ruby exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // (a) The served bytes reached Ruby: binread returned the substitute, not
    // the real on-disk PAYLOAD.
    assert_eq!(
        out.stdout, substitute,
        "served read bytes substituted into Ruby's binread result"
    );
    assert_ne!(
        out.stdout,
        PAYLOAD.to_vec(),
        "the real host-disk bytes were bypassed on replay"
    );

    // (c) A served read journals no Read record for that target: replay touches
    // no host disk for the read.
    let target = fs_target(GUEST_PATH);
    let log = host.get_effect_log();
    assert!(
        !log.iter()
            .any(|r| r.effect.kind == EffectKind::Fs(FileOp::Read) && r.effect.target == target),
        "a served read journals no Read record for {target}: {:?}",
        log.iter()
            .filter(|r| r.effect.kind == EffectKind::Fs(FileOp::Read))
            .map(|r| &r.effect.target)
            .collect::<Vec<_>>()
    );
    eprintln!(
        "RUBY LIVE SERVE: served {} bytes into binread; stdout_len={} (real disk bypassed)",
        substitute.len(),
        out.stdout.len()
    );
}
