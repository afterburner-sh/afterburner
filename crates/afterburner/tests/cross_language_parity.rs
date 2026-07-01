// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Cross-language + multimodal parity for the capture hooks, driven through the
//! *public* runner surface of every substrate that this build can reach:
//!
//! * JS / TS: `WasmCombustor::run_with_result` (QuickJS, in-process, always
//!   available) and `WasmSession`.
//! * Ruby: `run_ruby` / `WasiCommandSession` (the `~/.burn` CRuby runtime).
//! * Python: `run_python` / `run_python_with_preopens` / `PySession` (the
//!   `~/.burn` Pyodide runtime).
//! * Rust/Go/C: the WASI-command class. They compile to the *same*
//!   `wasm32-wasip1` command shape Ruby runs as, so their capture behaviour is
//!   fixed at the wasm layer by the shared frame codec and the shared
//!   `effect_seam` (proven generically here and by `tests/effect_wasi_capture.rs`).
//!
//! # What is genuinely uniform, and what is not (honest coverage map)
//!
//! Two things are byte-identical across *every* language **by construction**,
//! because there is exactly one implementation each:
//!
//! * the content address (`content_hash` = BLAKE3), used by both the frame
//!   carrier (`afterburner_core::frame`) and the effect seam
//!   (`afterburner_core::effect`); and
//! * the target string forms: the `fs_target` / `http_target` / ... builders
//!   every substrate calls.
//!
//! These are the parity *crux* and are asserted with no runtime at all.
//!
//! The per-syscall `HostEffect` *capture surface* is **not** uniform, and this
//! file asserts that honestly rather than faking a symmetry the substrates do
//! not have (see the module-level notes in `effect_wasi.rs` /
//! `emscripten_syscall.rs`):
//!
//! * JS seams fs/env/net/child_process -> real `HostEffect` records reachable
//!   through `run_with_result(host)`.
//! * The WASI-command substrate (Ruby/Rust/Go/C) seams only `clock_time_get` /
//!   `random_get`; fs flows through the preopen boundary, so it surfaces **no**
//!   `Fs`/`Net`/`Process` effects. `ruby_effect_log_is_clock_random_only`
//!   asserts that absence (N/A, never faked).
//! * Python's emscripten fs seam is instrumented but has **no public
//!   host-threading entry** (`run_pyodide_core` never sets `host_context`), so
//!   Python fs effects are not reachable from any public runner today. Python
//!   parity is therefore proven at the frame/output layer, not the effect layer.
//!
//! All runtime-touching tests are `#[ignore]` (QuickJS boot is seconds, CRuby
//! and Pyodide boots are minutes) and self-skip with a printed reason when their
//! runtime is absent, so a machine without `~/.burn` never reports a false
//! green. Run them with `--ignored`.

#![cfg(feature = "wasm")]

use std::sync::{Arc, Mutex};

use afterburner_core::effect::{
    EffectKind, EffectStatus, FileOp, HostEffect, HostEffectRecord, db_target, env_target,
    fs_target, http_target, process_target, socket_target,
};
use afterburner_core::frame::{
    HEADER_LEN, OutputTag, decode_frame, decode_output_value, encode_frame, encode_output_value,
};
use afterburner_core::host::HttpMethod;
use afterburner_core::{
    Combustor, FsAccess, FuelGauge, HostContext, Language, Manifold, NullHost, OutputValue,
    ScriptInvocation, Session, content_hash,
};

use afterburner_wasi::session::WasmSession;
use afterburner_wasi::wasm_engine::{WasmCombustor, WasmConfig};

// ---------------------------------------------------------------------------
// Multimodal fixtures: genuinely binary blobs (NUL, 0xFF, invalid UTF-8).
// ---------------------------------------------------------------------------

/// A real 16x16 RGBA PNG. PNG structurally carries NULs (IHDR), 0xFF bytes, and
/// byte sequences that are not valid UTF-8: the exact regression surface the
/// old text `/tmp/pyout.txt` path and the `from_utf8_lossy` calls would corrupt.
fn png_blob() -> Vec<u8> {
    use image::{DynamicImage, ImageBuffer, ImageFormat, Rgba};
    let buf: ImageBuffer<Rgba<u8>, _> = ImageBuffer::from_fn(16, 16, |x, y| {
        let a = if (x / 4 + y / 4) % 2 == 0 { 255 } else { 0 };
        Rgba([0, 128, 200, a])
    });
    let img = DynamicImage::ImageRgba8(buf);
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .expect("encode png");
    out
}

/// A tiny but structurally valid 8-bit mono PCM WAV, standing in for an audio
/// tool result. The sample bytes include `0x00` and `0xFF` so the blob is
/// unambiguously binary.
fn wav_blob() -> Vec<u8> {
    let samples: [u8; 8] = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE, 0x00, 0xFF];
    let data_len = samples.len() as u32;
    let mut w = Vec::new();
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data_len).to_le_bytes());
    w.extend_from_slice(b"WAVE");
    w.extend_from_slice(b"fmt ");
    w.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    w.extend_from_slice(&1u16.to_le_bytes()); // PCM
    w.extend_from_slice(&1u16.to_le_bytes()); // mono
    w.extend_from_slice(&8000u32.to_le_bytes()); // sample rate
    w.extend_from_slice(&8000u32.to_le_bytes()); // byte rate
    w.extend_from_slice(&1u16.to_le_bytes()); // block align
    w.extend_from_slice(&8u16.to_le_bytes()); // bits/sample
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data_len.to_le_bytes());
    w.extend_from_slice(&samples);
    w
}

/// Assert a blob is genuinely binary: it must embed a NUL, a `0xFF`, and at
/// least one byte sequence that is not valid UTF-8. Guards that the multimodal
/// round-trips below are real regression guards, not accidental ASCII.
fn assert_is_binary(bytes: &[u8], what: &str) {
    assert!(bytes.contains(&0x00), "{what}: expected an embedded NUL");
    assert!(bytes.contains(&0xFF), "{what}: expected a 0xFF byte");
    assert!(
        std::str::from_utf8(bytes).is_err(),
        "{what}: expected non-UTF-8 content"
    );
}

/// A recording host: journals every effect, replays none (original-run mode).
#[derive(Default)]
struct Recorder {
    log: Mutex<Vec<HostEffectRecord>>,
}

impl HostContext for Recorder {
    fn record_host_effect(&self, r: HostEffectRecord) {
        self.log.lock().expect("log lock").push(r);
    }
    fn get_effect_log(&self) -> Vec<HostEffectRecord> {
        self.log.lock().expect("log lock").clone()
    }
}

/// A replaying host: fed a journal, it substitutes the recorded output for any
/// effect whose identity (kind + target + input_hash) matches, and performs no
/// real effect. Any unrecorded effect falls through to a real run (`None`).
struct Replayer {
    journal: Vec<HostEffectRecord>,
    served: Mutex<usize>,
}

impl Replayer {
    fn new(journal: Vec<HostEffectRecord>) -> Self {
        Self {
            journal,
            served: Mutex::new(0),
        }
    }
    fn served(&self) -> usize {
        *self.served.lock().expect("served lock")
    }
}

impl HostContext for Replayer {
    fn on_host_call(&self, effect: &HostEffect) -> Option<HostEffectRecord> {
        let hit = self.journal.iter().find(|r| {
            r.effect.kind == effect.kind
                && r.effect.target == effect.target
                && r.effect.input_hash == effect.input_hash
        })?;
        *self.served.lock().expect("served lock") += 1;
        Some(hit.clone())
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn combustor() -> WasmCombustor {
    WasmCombustor::new(WasmConfig::default()).expect("build WasmCombustor")
}

// ===========================================================================
// GROUP A. The parity crux: one content address, one set of target strings.
// No runtime; always runs.
// ===========================================================================

/// R3: a blob's BLAKE3 is the SAME value at three independent observation
/// points: the frame header hash, an `Fs(Write)` effect's `input_hash`, and
/// the `Fs(Read)` record's `output_hash`. One content address, three seams.
#[test]
fn content_address_is_one_hash_at_every_observation_point() {
    let b = png_blob();
    assert_is_binary(&b, "png");
    let addr = content_hash(&b);

    // Observation point 1: the AFBF frame header hash.
    let frame = encode_output_value(&OutputValue::Bytes(b.clone())).expect("encode");
    assert_eq!(&frame[16..HEADER_LEN], &addr, "frame header hash == BLAKE3");

    // Observation point 2: an Fs(Write) effect built from the same bytes.
    let write = HostEffect::new(
        EffectKind::Fs(FileOp::Write),
        fs_target("/x"),
        b.clone(),
        afterburner_core::effect::EffectDetail::None,
        None,
    );
    assert_eq!(write.input_hash, addr, "Fs(Write).input_hash == BLAKE3");

    // Observation point 3: the Fs(Read) record that returns the same bytes.
    let read_effect = HostEffect::new(
        EffectKind::Fs(FileOp::Read),
        fs_target("/x"),
        Vec::new(),
        afterburner_core::effect::EffectDetail::None,
        None,
    );
    let read = HostEffectRecord::new(
        read_effect,
        b.clone(),
        0,
        EffectStatus::Ok {
            code: 0,
            rows: None,
        },
    );
    assert_eq!(read.output_hash, addr, "Fs(Read).output_hash == BLAKE3");
}

/// R2 target parity: the exact `"file::"` / `"shell::"` / `"api::host#method"` /
/// `"api::host:port"` / `"env::VAR"` / `"db::system"` spellings come from a
/// single set of builders that every substrate calls, so the same logical op
/// gets one identity everywhere, by construction. A divergent spelling would be
/// two content addresses for one effect and would break replay.
#[test]
fn target_string_forms_are_the_single_source_of_truth() {
    assert_eq!(fs_target("/x"), "file::/x");
    assert_eq!(process_target("ls"), "shell::ls");
    assert_eq!(
        http_target("api.example.com", "/v1/chat", HttpMethod::Post),
        "api::api.example.com/v1/chat#POST"
    );
    assert_eq!(socket_target("db.internal", 5432), "api::db.internal:5432");
    assert_eq!(env_target("OPENAI_API_KEY"), "env::OPENAI_API_KEY");
    assert_eq!(db_target("postgres"), "db::postgres");

    // Every HTTP method spells its token identically wherever it is rendered.
    for (m, tok) in [
        (HttpMethod::Get, "GET"),
        (HttpMethod::Post, "POST"),
        (HttpMethod::Put, "PUT"),
        (HttpMethod::Delete, "DELETE"),
        (HttpMethod::Patch, "PATCH"),
    ] {
        assert_eq!(http_target("h", "/p", m), format!("api::h/p#{tok}"));
    }
}

/// R7: the frame codec round-trips arbitrary bytes byte-exact, and fails
/// **loud** on truncation or a stale header hash, never a silent partial read.
/// A seeded xorshift stands in for a property test (no new dependency): it
/// covers empty, all-NUL, all-0xFF, and mixed non-UTF-8 payloads deterministically.
#[test]
fn frame_roundtrip_is_byte_exact_and_fails_loud() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for i in 0..2000usize {
        // A payload whose length and bytes vary, including the degenerate cases.
        let len = match i {
            0 => 0,
            1 => 1,
            2 => HEADER_LEN, // a payload exactly one header long
            _ => (next() % 512) as usize,
        };
        let payload: Vec<u8> = match i {
            3 => vec![0u8; len],    // all NUL
            4 => vec![0xFFu8; len], // all 0xFF
            _ => (0..len).map(|_| (next() & 0xFF) as u8).collect(),
        };

        // Exercise both kind bytes; `decode_frame` treats the payload as opaque
        // bytes under either tag, so an arbitrary payload round-trips regardless.
        let tag = if i % 2 == 0 {
            OutputTag::Bytes
        } else {
            OutputTag::Json
        };
        let frame = encode_frame(tag, &payload);
        let (dtag, out) = decode_frame(&frame).expect("round-trip decode");
        assert_eq!(dtag, tag);
        assert_eq!(out, payload, "byte-exact round-trip for len {len}");

        // Truncation is loud (drop the last byte when there is one to drop).
        if !frame.is_empty() {
            assert!(
                decode_frame(&frame[..frame.len() - 1]).is_err(),
                "truncated frame must be an Err"
            );
        }

        // A flipped payload byte with a now-stale header hash is loud.
        if !payload.is_empty() {
            let mut corrupt = frame.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 0xFF;
            assert!(
                decode_frame(&corrupt).is_err(),
                "payload corruption with a stale header hash must be an Err"
            );
        }
    }
}

/// R5 (pure part): an audio blob carried as a typed `OutputValue::Bytes`
/// round-trips through the frame codec byte-exact, and the frame's header hash
/// is `BLAKE3(blob)`, the same content address the tool's bytes would take as
/// an fs effect.
#[test]
fn audio_output_value_round_trips_through_the_frame() {
    let wav = wav_blob();
    assert_is_binary(&wav, "wav");
    let v = OutputValue::Bytes(wav.clone());
    let frame = encode_output_value(&v).expect("encode");
    assert_eq!(&frame[16..HEADER_LEN], &content_hash(&wav));
    assert_eq!(decode_output_value(&frame).expect("decode"), v);
}

// ===========================================================================
// GROUP B: JS / TS effect capture (QuickJS, in-process). #[ignore]: boot cost.
// ===========================================================================

/// The canonical program's effect sequence in JS: write blob B, read it back,
/// stat it. Asserts the `Fs(Write)` input is content-addressed to `BLAKE3(B)`,
/// the `Fs(Read)` output is content-addressed to `BLAKE3(B)`, and a `Fs(Stat)`
/// is present, all with `"file::"`-form targets.
#[test]
#[ignore = "boots QuickJS in-process; run with --ignored"]
fn js_canonical_fs_effect_sequence() {
    let b = png_blob();
    let addr = content_hash(&b);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x");
    let path_str = path.to_str().expect("utf8 path");

    let mut limits = FuelGauge::unlimited();
    limits.manifold = Manifold {
        fs: FsAccess::ReadWrite(vec![dir.path().to_path_buf()]),
        ..Manifold::sealed()
    };

    let src = format!(
        "const fs = require('fs');\n\
         const B = Buffer.from('{}', 'base64');\n\
         fs.writeFileSync({path_str:?}, B);\n\
         const back = fs.readFileSync({path_str:?});\n\
         fs.statSync({path_str:?});\n\
         process.stdout.write(String(back.length));\n",
        b64(&b),
    );

    let host = Recorder::default();
    let r = combustor()
        .run_with_result(src.as_bytes(), &ScriptInvocation::default(), &limits, &host)
        .expect("run");
    assert_eq!(
        r.exit_code,
        0,
        "clean exit; stderr={}",
        String::from_utf8_lossy(&r.stderr)
    );

    let log = host.get_effect_log();
    let want_target = fs_target(path_str);

    let write = log
        .iter()
        .find(|e| e.effect.kind == EffectKind::Fs(FileOp::Write))
        .expect("Fs(Write) recorded");
    assert_eq!(
        write.effect.target, want_target,
        "write target is file:: form"
    );
    assert_eq!(write.effect.input_hash, addr, "write input == BLAKE3(B)");

    let read = log
        .iter()
        .find(|e| e.effect.kind == EffectKind::Fs(FileOp::Read))
        .expect("Fs(Read) recorded");
    assert_eq!(
        read.effect.target, want_target,
        "read target is file:: form"
    );
    assert_eq!(read.output_hash, addr, "read output == BLAKE3(B)");
    assert_eq!(read.output, b, "read returned B byte-exact");

    assert!(
        log.iter()
            .any(|e| e.effect.kind == EffectKind::Fs(FileOp::Stat)),
        "Fs(Stat) recorded; kinds: {:?}",
        log.iter().map(|e| e.effect.kind).collect::<Vec<_>>()
    );
}

/// TS lowers to JS and runs on the *same* combustor and the *same* effect seam,
/// so an identical logical program in TS produces the identical content
/// addresses as JS. Proves the TS path is JS-at-the-seam, not a second capture
/// surface that could drift.
#[test]
#[cfg(feature = "ts")]
#[ignore = "boots QuickJS in-process; needs --features ts; run with --ignored"]
fn ts_effect_capture_matches_js() {
    let b = wav_blob();
    let addr = content_hash(&b);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x");
    let path_str = path.to_str().expect("utf8 path");

    let mut limits = FuelGauge::unlimited();
    limits.manifold = Manifold {
        fs: FsAccess::ReadWrite(vec![dir.path().to_path_buf()]),
        ..Manifold::sealed()
    };

    // A TypeScript source with real type annotations that must be stripped.
    let ts_src = format!(
        "const fs = require('fs');\n\
         const B: Buffer = Buffer.from('{}', 'base64');\n\
         const p: string = {path_str:?};\n\
         fs.writeFileSync(p, B);\n\
         const back: Buffer = fs.readFileSync(p);\n\
         process.stdout.write(String(back.length));\n",
        b64(&b),
    );
    let js = afterburner::ts::transpile(&ts_src, std::path::Path::new("<parity>.ts"))
        .expect("transpile TS");

    let host = Recorder::default();
    let r = combustor()
        .run_with_result(js.as_bytes(), &ScriptInvocation::default(), &limits, &host)
        .expect("run");
    assert_eq!(
        r.exit_code,
        0,
        "clean exit; stderr={}",
        String::from_utf8_lossy(&r.stderr)
    );

    let log = host.get_effect_log();
    let write = log
        .iter()
        .find(|e| e.effect.kind == EffectKind::Fs(FileOp::Write))
        .expect("Fs(Write) recorded");
    assert_eq!(write.effect.input_hash, addr, "TS write input == BLAKE3(B)");
    let read = log
        .iter()
        .find(|e| e.effect.kind == EffectKind::Fs(FileOp::Read))
        .expect("Fs(Read) recorded");
    assert_eq!(read.output_hash, addr, "TS read output == BLAKE3(B)");
}

/// R5 in JS: a script whose typed return is a PNG's bytes yields
/// `OutputValue::Bytes(exact)` via the `host_raw_output` channel; the bytes
/// content-address to `BLAKE3(png)`, and re-framing them reproduces the frame.
#[test]
#[ignore = "boots QuickJS in-process; run with --ignored"]
fn js_binary_output_is_bytes_exact() {
    let png = png_blob();
    let src = format!(
        "const B = Buffer.from('{}', 'base64');\n\
         __AB_RAW_OUTPUT__(new Uint8Array(B));\n",
        b64(&png),
    );
    let r = combustor()
        .run_with_result(
            src.as_bytes(),
            &ScriptInvocation::default(),
            &FuelGauge::unlimited(),
            &NullHost,
        )
        .expect("run");
    assert_eq!(
        r.exit_code,
        0,
        "clean exit; stderr={}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        r.output,
        OutputValue::Bytes(png.clone()),
        "output is exact PNG"
    );
    // The output content-addresses identically to a frame of the same bytes.
    let frame = encode_output_value(&r.output).expect("encode");
    assert_eq!(&frame[16..HEADER_LEN], &content_hash(&png));
}

/// R9 in JS (record/serve duality): phase 1 records a real `Fs(Read)`; phase 2
/// replays that journal after the real file has been **deleted**. The replay
/// still yields the recorded bytes with a clean exit, proving the seam
/// substituted the record and performed **zero** real fs access (a real read of
/// the now-missing file would have failed).
#[test]
#[ignore = "boots QuickJS in-process; run with --ignored"]
fn js_two_phase_replay_performs_no_real_fs() {
    let b = png_blob();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sentinel.bin");
    std::fs::write(&path, &b).expect("seed file");
    let path_str = path.to_str().expect("utf8 path").to_owned();

    let mut limits = FuelGauge::unlimited();
    limits.manifold = Manifold {
        fs: FsAccess::ReadWrite(vec![dir.path().to_path_buf()]),
        ..Manifold::sealed()
    };

    // The read program is identical in both phases.
    let src = format!(
        "const fs = require('fs');\n\
         const back = fs.readFileSync({path_str:?});\n\
         __AB_RAW_OUTPUT__(new Uint8Array(back));\n"
    );

    // Phase 1: real read, capture the journal.
    let rec = Recorder::default();
    let r1 = combustor()
        .run_with_result(src.as_bytes(), &ScriptInvocation::default(), &limits, &rec)
        .expect("phase 1 run");
    assert_eq!(r1.exit_code, 0, "phase 1 clean");
    assert_eq!(r1.output, OutputValue::Bytes(b.clone()));
    let journal = rec.get_effect_log();
    assert!(
        journal
            .iter()
            .any(|e| e.effect.kind == EffectKind::Fs(FileOp::Read)),
        "phase 1 recorded a read"
    );

    // Sentinel: delete the real file. A real read in phase 2 would now fail.
    std::fs::remove_file(&path).expect("delete sentinel");
    assert!(!path.exists(), "sentinel is gone");

    // Phase 2: replay. The seam must serve the recorded bytes, not touch the FS.
    let replay = Replayer::new(journal);
    let r2 = combustor()
        .run_with_result(
            src.as_bytes(),
            &ScriptInvocation::default(),
            &limits,
            &replay,
        )
        .expect("phase 2 run");
    assert_eq!(
        r2.exit_code,
        0,
        "phase 2 clean despite the deleted file; stderr={}",
        String::from_utf8_lossy(&r2.stderr)
    );
    assert_eq!(
        r2.output,
        OutputValue::Bytes(b),
        "replay substituted the recorded bytes"
    );
    assert!(replay.served() >= 1, "the read was served from the journal");
    assert!(!path.exists(), "replay did not recreate the file");
}

/// R4 in JS: a `WasmSession` persists a binary artifact across runs. Run 1
/// writes a PNG under `process.cwd()`; run 2 reads it back and its length is the
/// PNG length; the host-side `fs_read` returns the PNG byte-exact.
#[test]
#[ignore = "boots QuickJS in-process; run with --ignored"]
fn js_session_persists_binary_across_runs() {
    let png = png_blob();
    let mut s = WasmSession::new(FuelGauge::unlimited()).expect("session");

    let write_src = format!(
        "const fs = require('fs');\n\
         const path = require('path');\n\
         const B = Buffer.from('{}', 'base64');\n\
         fs.writeFileSync(path.join(process.cwd(), 'img.png'), B);\n",
        b64(&png),
    );
    let r1 = s.run(write_src.as_bytes(), Language::Js).expect("run 1");
    assert_eq!(
        r1.exit_code,
        0,
        "run 1 clean; stderr={}",
        String::from_utf8_lossy(&r1.stderr)
    );

    // Host sees the guest write, byte-exact.
    assert_eq!(s.fs_read("img.png").expect("host read"), png);

    // Run 2 reads the persisted binary.
    let read_src = "const fs = require('fs');\n\
         const path = require('path');\n\
         const B = fs.readFileSync(path.join(process.cwd(), 'img.png'));\n\
         process.stdout.write(String(B.length));\n";
    let r2 = s.run(read_src.as_bytes(), Language::Js).expect("run 2");
    assert_eq!(r2.exit_code, 0, "run 2 clean");
    assert_eq!(
        String::from_utf8_lossy(&r2.stdout).trim_end(),
        png.len().to_string(),
        "run 2 saw the persisted PNG length"
    );
}

// ===========================================================================
// GROUP C: Ruby (WASI-command). #[ignore]: uses the ~/.burn CRuby runtime.
// ===========================================================================

fn ruby_available() -> bool {
    afterburner_wasi::ruby_runner::resolve_ruby_runtime().is_ok()
}

/// R5 in Ruby: the typed return is a PNG's bytes, delivered through the
/// `/.afb/output.frame` file-frame and decoded to `OutputValue::Bytes(exact)`.
/// Ruby has no stdlib BLAKE3, so (as the runner's own end-to-end test does) the
/// self-verifying frame is precomputed host-side and the guest writes it: the
/// guest->host binary return channel and the host decode are what is exercised.
#[test]
#[ignore = "uses the ~/.burn CRuby runtime; run with --ignored"]
fn ruby_binary_output_via_frame() {
    if !ruby_available() {
        eprintln!("[cross_language_parity] SKIP ruby_binary_output_via_frame: no ~/.burn Ruby");
        return;
    }
    let png = png_blob();
    let frame = encode_output_value(&OutputValue::Bytes(png.clone())).expect("frame");
    let frame_lit = frame
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "frame = [{frame_lit}].pack('C*')\n\
         File.binwrite('/.afb/output.frame', frame)\n\
         puts 'ok'\n"
    );
    let out = afterburner_wasi::ruby_runner::run_ruby(&script).expect("run_ruby");
    assert_eq!(
        out.exit_code,
        0,
        "clean exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.output,
        OutputValue::Bytes(png),
        "PNG returned byte-exact via the /.afb frame"
    );
}

/// Honest N/A assertion (R2 "asserted absent, never faked"): the WASI-command
/// substrate seams only `clock_time_get` / `random_get`. A recording Ruby
/// session therefore journals `Clock` / `Random` effects and **no** `Fs` / `Net`
/// / `Process` / `Env` / `Db` effect. Fs flows through the preopen boundary,
/// not the `HostEffect` seam. This documents the coverage asymmetry rather than
/// fabricating fs effects the substrate does not produce.
#[test]
#[ignore = "uses the ~/.burn CRuby runtime; run with --ignored"]
fn ruby_effect_log_is_clock_random_only() {
    use afterburner_wasi::wasi_session::WasiCommandSession;
    if !ruby_available() {
        eprintln!(
            "[cross_language_parity] SKIP ruby_effect_log_is_clock_random_only: no ~/.burn Ruby"
        );
        return;
    }

    let host: Arc<Recorder> = Arc::new(Recorder::default());
    let dir = tempfile::tempdir().expect("tempdir");
    let mut s = WasiCommandSession::new(dir.path(), host.clone()).expect("session");

    // A run that touches the filesystem inside the guest.
    let script = "File.binwrite('/pkg/probe.bin', [0,255,10].pack('C*'))\nputs 'ok'\n";
    let r = s.run(script.as_bytes(), Language::Ruby).expect("run");
    assert_eq!(
        r.exit_code,
        0,
        "clean exit; stderr={}",
        String::from_utf8_lossy(&r.stderr)
    );

    let log = host.get_effect_log();
    for rec in &log {
        assert!(
            matches!(rec.effect.kind, EffectKind::Clock | EffectKind::Random),
            "WASI-command substrate must only surface Clock/Random effects; \
             saw {:?} (target {:?})",
            rec.effect.kind,
            rec.effect.target
        );
    }
    // The fs write happened (host sees it) yet produced no Fs effect record.
    assert!(
        s.fs_exists("probe.bin"),
        "guest fs write landed on the host"
    );
    assert!(
        !log.iter()
            .any(|r| matches!(r.effect.kind, EffectKind::Fs(_))),
        "fs is N/A at the HostEffect layer for WASI-command (surfaced via preopen)"
    );
}

/// R4 in Ruby: a `WasiCommandSession` persists a binary artifact across runs.
/// Run 1 writes a PNG under the session mount; run 2 reads it back inside the
/// guest and returns its length via the frame; the host-side `fs_read` returns
/// the PNG byte-exact.
#[test]
#[ignore = "uses the ~/.burn CRuby runtime; run with --ignored"]
fn ruby_session_persists_binary_across_runs() {
    use afterburner_wasi::wasi_session::WasiCommandSession;
    if !ruby_available() {
        eprintln!(
            "[cross_language_parity] SKIP ruby_session_persists_binary_across_runs: no ~/.burn Ruby"
        );
        return;
    }
    let png = png_blob();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut s = WasiCommandSession::sealed(dir.path()).expect("session");

    let png_lit = png
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let write_src = format!(
        "data = [{png_lit}].pack('C*')\n\
         File.binwrite('/pkg/img.png', data)\n\
         puts 'wrote'\n"
    );
    let r1 = s.run(write_src.as_bytes(), Language::Ruby).expect("run 1");
    assert_eq!(
        r1.exit_code,
        0,
        "run 1 clean; stderr={}",
        String::from_utf8_lossy(&r1.stderr)
    );
    // Host sees the guest write, byte-exact.
    assert_eq!(s.fs_read("img.png").expect("host read"), png);

    let read_src = "data = File.binread('/pkg/img.png')\nputs data.bytesize\n";
    let r2 = s.run(read_src.as_bytes(), Language::Ruby).expect("run 2");
    assert_eq!(r2.exit_code, 0, "run 2 clean");
    assert_eq!(
        String::from_utf8_lossy(&r2.stdout).trim_end(),
        png.len().to_string(),
        "run 2 saw the persisted PNG length"
    );
}

// ===========================================================================
// GROUP D: Python (Pyodide). #[ignore]: uses the ~/.burn Pyodide runtime.
// ===========================================================================

fn python_available() -> bool {
    afterburner_wasi::pyodide_runner::resolve_runtime().is_ok()
}

/// R6: raw binary written to `sys.stdout.buffer` (all 256 byte values, including
/// `0x00`, `0xFF`, and an invalid-UTF-8 sequence) reaches `Outcome.stdout`
/// byte-identical, proving the binary sink replaced the old text redirect.
#[test]
#[ignore = "uses the ~/.burn Pyodide runtime; run with --ignored"]
fn python_binary_stdout_is_bit_identical() {
    if !python_available() {
        eprintln!(
            "[cross_language_parity] SKIP python_binary_stdout_is_bit_identical: no ~/.burn Pyodide"
        );
        return;
    }
    // All 256 byte values plus an explicit invalid-UTF-8 pair.
    let mut expected: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    expected.extend_from_slice(&[0xC3, 0x28]);
    let payload_lit = expected
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let src = format!("import sys\nsys.stdout.buffer.write(bytes([{payload_lit}]))\n");
    let out = afterburner_wasi::pyodide_runner::run_python(&src).expect("run_python");
    assert_eq!(
        out.exit_code,
        0,
        "clean exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, expected, "binary stdout is bit-identical");
}

/// R5 in Python: `__afb_emit__(png_bytes)` returns the PNG through the
/// `/.afb/output.frame` file-frame as `OutputValue::Bytes(exact)`.
#[test]
#[ignore = "uses the ~/.burn Pyodide runtime; run with --ignored"]
fn python_binary_output_via_frame() {
    if !python_available() {
        eprintln!(
            "[cross_language_parity] SKIP python_binary_output_via_frame: no ~/.burn Pyodide"
        );
        return;
    }
    let png = png_blob();
    let src = format!(
        "import base64\n__afb_emit__(base64.b64decode('{}'))\n",
        b64(&png),
    );
    let out = afterburner_wasi::pyodide_runner::run_python(&src).expect("run_python");
    assert_eq!(
        out.exit_code,
        0,
        "clean exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.output,
        OutputValue::Bytes(png),
        "PNG returned byte-exact via the /.afb frame"
    );
}

/// R4 in Python: a `PySession` persists a binary artifact across runs. Run 1
/// writes a PNG under the session mount; run 2 reads it and emits it; both the
/// emitted output and the host-side `fs_read` are byte-identical to the PNG.
#[test]
#[ignore = "uses the ~/.burn Pyodide runtime; run with --ignored"]
fn python_session_persists_binary_across_runs() {
    use afterburner_wasi::pyodide_runner::PySession;
    if !python_available() {
        eprintln!(
            "[cross_language_parity] SKIP python_session_persists_binary_across_runs: no ~/.burn Pyodide"
        );
        return;
    }
    let png = png_blob();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut s = PySession::open(dir.path()).expect("session");

    let write_src = format!(
        "import base64\n\
         data = base64.b64decode('{}')\n\
         open('/session/img.png','wb').write(data)\n",
        b64(&png),
    );
    let r1 = s
        .run(write_src.as_bytes(), Language::Python)
        .expect("run 1");
    assert_eq!(
        r1.exit_code,
        0,
        "run 1 clean; stderr={}",
        String::from_utf8_lossy(&r1.stderr)
    );
    // Host sees the guest write, byte-exact.
    assert_eq!(s.fs_read("img.png").expect("host read"), png);

    let read_src = "data = open('/session/img.png','rb').read()\n__afb_emit__(data)\n";
    let r2 = s.run(read_src.as_bytes(), Language::Python).expect("run 2");
    assert_eq!(r2.exit_code, 0, "run 2 clean");
    assert_eq!(
        r2.output,
        OutputValue::Bytes(png),
        "run 2 read the persisted PNG byte-exact"
    );
}

// ===========================================================================
// GROUP E: the facade binary Outcome (R8). #[ignore]: boots QuickJS.
// ===========================================================================

/// R8: a non-UTF-8 stdout survives `Afterburner::run_source` into
/// `Outcome.stdout: Vec<u8>` byte-exact: the guard for the deleted
/// `from_utf8_lossy` calls on the facade run path.
///
/// This is exercised through **Python**, not JS, on purpose: it is the
/// substrate that actually *delivers* non-UTF-8 bytes to the facade (its
/// `sys.stdout.buffer` binary sink is byte-transparent). JS is deliberately not
/// used here because this runtime's `process.stdout` is a UTF-8 text channel
/// with no byte-exact primitive (`fs.writeSync(1, buf)` is unsupported and a
/// `latin1` string is re-encoded), so a high byte comes back as the U+FFFD
/// replacement sequence *before* the facade ever sees it. The JS binary channel
/// is the typed output (`js_binary_output_is_bytes_exact`), not stdout. This
/// test therefore proves the facade's own `Vec<u8>` passthrough is lossless on a
/// genuinely-binary stdout, which is the deletion guard the case asks for.
#[test]
#[ignore = "uses the ~/.burn Pyodide runtime; run with --ignored"]
fn facade_carries_non_utf8_stdout_byte_exact() {
    if !python_available() {
        eprintln!(
            "[cross_language_parity] SKIP facade_carries_non_utf8_stdout_byte_exact: no ~/.burn Pyodide"
        );
        return;
    }
    // Every byte value 0..256 plus an invalid-UTF-8 pair; a lossy conversion
    // anywhere on the path would mangle the high bytes.
    let mut expected: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    expected.extend_from_slice(&[0xC3, 0x28]);
    let payload_lit = expected
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let src = format!("import sys\nsys.stdout.buffer.write(bytes([{payload_lit}]))\n");
    let ab = afterburner::Afterburner::new().expect("build Afterburner");
    let outcome = ab.run_source(Language::Python, &src).expect("run_source");
    assert!(outcome.ok, "clean run; stderr={:?}", outcome.stderr);
    assert_eq!(
        outcome.stdout, expected,
        "facade carries non-UTF-8 stdout byte-exact"
    );
}
