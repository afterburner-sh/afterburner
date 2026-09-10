// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Colocated tests for [`run_afb_bytes`][super::run_afb_bytes], one pair per
//! language family (a compiled language via a real wasi-sdk `clang`, JS via a
//! real `javy`, and Ruby-source via the bundled CRuby interpreter): a normal
//! run asserting captured stdout and a non-zero exit code, and a bound-firing
//! run.
//!
//! Every test here boots a real toolchain or a real WASM/interpreter runtime,
//! so all of them are `#[ignore]`d (run with `cargo test --ignored`),
//! matching this crate's existing convention for runtime-touching tests (see
//! `tests/cross_language_parity.rs`). Each also self-skips with a printed
//! reason, rather than failing, on a machine that lacks the toolchain a
//! fixture needs - never a silent green from a test that did not run.

use super::*;
use afterburner_afb::manifest::{Format, Manifest, Package, Runtime};
use afterburner_afb::pack::Builder;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The smallest valid [`Manifest`] for a fixture package, mirroring
/// `afterburner_afb::resolve::minimal_manifest`'s exact field values (the
/// smallest manifest this crate's own unpacker already accepts).
fn minimal_manifest(language: &str, entry: &str, runtime_target: Option<&str>) -> Manifest {
    Manifest {
        format: Format {
            version: "1.0".into(),
            min_reader: None,
        },
        package: Package {
            name: "fixture".into(),
            namespace: "test".into(),
            version: "0.1.0".into(),
            language: language.into(),
            entry: entry.into(),
            description: None,
            homepage: None,
            license: None,
            keywords: vec![],
        },
        runtime: Runtime {
            min: "0.1.0".into(),
            target: runtime_target.map(str::to_owned),
        },
        dependencies: Default::default(),
        npm: Default::default(),
        pip: Default::default(),
        gem: Default::default(),
        signature: None,
        metadata: toml::Table::new(),
        extra: toml::Table::new(),
    }
}

/// Build a compiled-WASM fixture `.afb`: one precompiled
/// `precompiled/wasm32-wasip1/main.wasm` member, no source.
fn build_compiled_afb(language: &str, wasm_bytes: Vec<u8>) -> Vec<u8> {
    let manifest = minimal_manifest(language, "source/main", Some("wasm32-wasip1"));
    let (bytes, _digest) = Builder::new(manifest, Manifold::sealed())
        .precompiled(PRECOMPILED_WASM_MEMBER, wasm_bytes)
        .build()
        .expect("build compiled fixture .afb");
    bytes
}

/// Build a source-shipped fixture `.afb` (the Ruby/Python interpreted shape):
/// one `source/<entry>` member, no precompiled artifact.
fn build_source_afb(language: &str, entry: &str, source: &str) -> Vec<u8> {
    let manifest = minimal_manifest(language, entry, None);
    let (bytes, _digest) = Builder::new(manifest, Manifold::sealed())
        .source(entry, source.as_bytes().to_vec())
        .build()
        .expect("build source fixture .afb");
    bytes
}

// ---- compiled-language family (C via wasi-sdk clang) -----------------------

/// Locate the wasi-sdk's `wasm32-wasip1-clang` wrapper: `WASI_SDK_PATH/bin/…`
/// first (the canonical wasi-sdk convention), else the first
/// `~/.burn/wasi-sdk-*/bin/…` cache directory (the `burn compile` lazy-fetch
/// location). `None` when neither is present - the caller skips instead of
/// failing.
fn find_wasi_sdk_clang() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("WASI_SDK_PATH") {
        let p = PathBuf::from(dir).join("bin/wasm32-wasip1-clang");
        if p.is_file() {
            return Some(p);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let entries = std::fs::read_dir(PathBuf::from(home).join(".burn")).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("wasi-sdk-") {
            let p = entry.path().join("bin/wasm32-wasip1-clang");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// Compile `source` (a full C translation unit) to a `wasm32-wasip1` WASI
/// command module via the located `clang`.
fn compile_c(clang: &Path, source: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!(
        "afb-run-test-c-{}-{}",
        std::process::id(),
        NEXT_SCRATCH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src = dir.join("fixture.c");
    let wasm = dir.join("fixture.wasm");
    std::fs::write(&src, source).expect("write fixture.c");
    let status = std::process::Command::new(clang)
        .arg("-o")
        .arg(&wasm)
        .arg(&src)
        .status()
        .expect("spawn clang");
    assert!(
        status.success(),
        "clang exited non-zero compiling the fixture"
    );
    let bytes = std::fs::read(&wasm).expect("read fixture.wasm");
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

#[test]
#[ignore = "compiles a real C fixture via wasi-sdk clang and runs it through wasmtime; cargo test --ignored"]
fn compiled_family_normal_run_captures_stdout_and_exit_code() {
    let Some(clang) = find_wasi_sdk_clang() else {
        eprintln!(
            "skipping compiled_family_normal_run_captures_stdout_and_exit_code: \
             no wasi-sdk found (set WASI_SDK_PATH or install one under ~/.burn)"
        );
        return;
    };
    let wasm = compile_c(
        &clang,
        r#"#include <stdio.h>
int main(void) { printf("hello from c\n"); return 7; }
"#,
    );
    let afb = build_compiled_afb("c", wasm);

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(7));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from c"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
#[ignore = "compiles a real C fixture via wasi-sdk clang and runs it through wasmtime; cargo test --ignored"]
fn compiled_family_fuel_bound_fires() {
    let Some(clang) = find_wasi_sdk_clang() else {
        eprintln!(
            "skipping compiled_family_fuel_bound_fires: no wasi-sdk found (set WASI_SDK_PATH or install one under ~/.burn)"
        );
        return;
    };
    let wasm = compile_c(&clang, "int main(void) { while (1) {} return 0; }\n");
    let afb = build_compiled_afb("c", wasm);

    let request = AfbRunRequest {
        fuel: Some(50_000),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::OutOfFuel);
    assert_eq!(out.fuel_used, 50_000);
}

/// Number of threads in the current process, via `/proc/self/task` (one
/// entry per thread). `None` on a non-Linux host - callers treat that as
/// "cannot check here", not as zero.
fn thread_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/task")
        .ok()
        .map(Iterator::count)
}

#[test]
#[ignore = "compiles a real C fixture via wasi-sdk clang and runs it through wasmtime; cargo test --ignored"]
fn compiled_family_timeout_actually_stops_the_guest_and_leaks_no_thread() {
    let Some(clang) = find_wasi_sdk_clang() else {
        eprintln!(
            "skipping compiled_family_timeout_actually_stops_the_guest_and_leaks_no_thread: \
             no wasi-sdk found (set WASI_SDK_PATH or install one under ~/.burn)"
        );
        return;
    };
    let wasm = compile_c(&clang, "int main(void) { while (1) {} return 0; }\n");
    let afb = build_compiled_afb("c", wasm);

    // Warm the shared epoch VM (and its one-time ticker thread) before
    // measuring, so the thread-count check below reflects THIS call, not
    // the one-time lazy-init cost of the shared VM.
    let warm = AfbRunRequest {
        fuel: Some(1),
        ..Default::default()
    };
    let _ = run_afb_bytes(&afb, warm);

    let before = thread_count();
    let start = std::time::Instant::now();
    // A huge fuel budget: the timeout, not fuel exhaustion, must be what
    // stops this run. Without real preemption a `while (1) {}` at
    // `fuel: u64::MAX` does not return on its own inside this test's
    // lifetime, let alone within a few seconds.
    let request = AfbRunRequest {
        fuel: Some(u64::MAX),
        timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");
    let elapsed = start.elapsed();
    let after = thread_count();

    assert_eq!(out.outcome, AfbRunOutcome::Timeout);
    // Generous margin over the 300ms deadline (compile + instantiate
    // overhead, a loaded CI box), but nowhere near "ran until fuel
    // exhaustion" territory - proves the guest was actually interrupted,
    // not merely that the call returned while something kept running.
    assert!(
        elapsed < Duration::from_secs(5),
        "run_afb_bytes took {elapsed:?} to return from a 300ms timeout; \
         the guest was not actually stopped"
    );
    if let (Some(before), Some(after)) = (before, after) {
        assert_eq!(
            before, after,
            "thread count changed across the timed-out call (before={before}, after={after}); \
             a thread was spawned and left behind"
        );
    } else {
        eprintln!(
            "note: /proc/self/task unavailable (non-Linux host) - skipping the \
             no-leaked-thread assertion; timeout + elapsed-time checks above still ran"
        );
    }
}

// ---- JS family (javy) -------------------------------------------------------

/// Whether a `javy` binary is on `PATH` and runnable. `None` (not `Err`) on
/// any failure to spawn it - the caller skips instead of failing.
fn javy_available() -> bool {
    std::process::Command::new("javy")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Compile `source` (already Javy.IO-shaped: no bare `console.log`, no
/// Node-isms) to a self-contained `wasm32-wasip1` WASI command module, using
/// the same sealed-build flags `cli::compile::mod::run_javy_sealed` invokes.
fn compile_js(source: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!(
        "afb-run-test-js-{}-{}",
        std::process::id(),
        NEXT_SCRATCH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let src = dir.join("fixture.js");
    let wasm = dir.join("fixture.wasm");
    std::fs::write(&src, source).expect("write fixture.js");
    let status = std::process::Command::new("javy")
        .args([
            "build",
            "-J",
            "event-loop=y",
            "-J",
            "javy-stream-io=y",
            "-C",
            "deterministic=y",
        ])
        .arg(&src)
        .arg("-o")
        .arg(&wasm)
        .status()
        .expect("spawn javy");
    assert!(
        status.success(),
        "javy build exited non-zero compiling the fixture"
    );
    let bytes = std::fs::read(&wasm).expect("read fixture.wasm");
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

#[test]
#[ignore = "compiles a real JS fixture via javy and runs it through wasmtime; cargo test --ignored"]
fn js_family_normal_run_captures_stdout() {
    if !javy_available() {
        eprintln!("skipping js_family_normal_run_captures_stdout: no `javy` on PATH");
        return;
    }
    let wasm = compile_js(
        r#"
const enc = new TextEncoder();
Javy.IO.writeSync(1, enc.encode("hello from js\n"));
"#,
    );
    let afb = build_compiled_afb("js", wasm);

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from js"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Javy's runtime has no `process.exit` / POSIX-exit-code mechanism at all
/// (confirmed against `javy build -J help` / `-C help`: no such option
/// exists) - an uncaught JS exception is the only way a script signals
/// abnormal termination, and it traps (a WASM `unreachable`), not a process
/// exit code. So the JS family's "the guest failed and we said so honestly"
/// case is `Trapped`, not a fabricated `Exited(n)` - exactly the case
/// `AfbRunOutcome::Trapped` exists for. C and Ruby demonstrate a genuine
/// non-zero `Exited` elsewhere in this file; JS cannot produce one.
#[test]
#[ignore = "compiles a real JS fixture via javy and runs it through wasmtime; cargo test --ignored"]
fn js_family_uncaught_exception_traps_honestly() {
    if !javy_available() {
        eprintln!("skipping js_family_uncaught_exception_traps_honestly: no `javy` on PATH");
        return;
    }
    let wasm = compile_js(
        r#"
const enc = new TextEncoder();
Javy.IO.writeSync(1, enc.encode("about to throw\n"));
throw new Error("boom");
"#,
    );
    let afb = build_compiled_afb("js", wasm);

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert!(
        matches!(out.outcome, AfbRunOutcome::Trapped(_)),
        "expected Trapped, got {:?}",
        out.outcome
    );
}

#[test]
#[ignore = "compiles a real JS fixture via javy and runs it through wasmtime; cargo test --ignored"]
fn js_family_fuel_bound_fires() {
    if !javy_available() {
        eprintln!("skipping js_family_fuel_bound_fires: no `javy` on PATH");
        return;
    }
    let wasm = compile_js("while (true) {}\n");
    let afb = build_compiled_afb("js", wasm);

    let request = AfbRunRequest {
        fuel: Some(50_000),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::OutOfFuel);
    assert_eq!(out.fuel_used, 50_000);
}

// ---- interpreted-language family (Ruby source) ------------------------------

#[test]
#[ignore = "boots the bundled CRuby WASI interpreter (real runtime, seconds); cargo test --ignored"]
fn ruby_family_normal_run_captures_stdout_and_exit_code() {
    if afterburner_wasi::ruby_runner::resolve_ruby_runtime().is_err() {
        eprintln!(
            "skipping ruby_family_normal_run_captures_stdout_and_exit_code: \
             no Ruby runtime available (neither the bundled ~/.burn cache nor BURN_RUBY_RUNTIME)"
        );
        return;
    }
    let afb = build_source_afb("ruby", "source/main.rb", "puts 'hello from ruby'\nexit 5\n");

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(5));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from ruby"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Ruby-source was never wired with bounds this round (see the module doc's
/// "known gaps"): every axis is refused outright rather than silently
/// ignored. This does not need the Ruby runtime at all - the refusal fires
/// before `resolve_ruby_runtime` is ever called - so, unlike its siblings,
/// this test is not `#[ignore]`d.
#[test]
fn ruby_source_refuses_a_requested_timeout() {
    let afb = build_source_afb("ruby", "source/main.rb", "puts 'unreachable'\n");
    let request = AfbRunRequest {
        timeout: Some(Duration::from_secs(1)),
        ..Default::default()
    };

    let err = run_afb_bytes(&afb, request).expect_err("expected a refusal, not a run");
    let msg = err.to_string();

    assert!(msg.contains("Ruby (source)"), "message was {msg:?}");
    assert!(msg.contains("timeout"), "message was {msg:?}");
}

#[test]
fn ruby_source_refuses_a_requested_fuel_override() {
    let afb = build_source_afb("ruby", "source/main.rb", "puts 'unreachable'\n");
    let request = AfbRunRequest {
        fuel: Some(1_000),
        ..Default::default()
    };

    let err = run_afb_bytes(&afb, request).expect_err("expected a refusal, not a run");
    let msg = err.to_string();

    assert!(msg.contains("Ruby (source)"), "message was {msg:?}");
    assert!(msg.contains("fuel"), "message was {msg:?}");
}

/// One request naming several unsupported bounds at once: the refusal names
/// all of them, not just the first.
#[test]
fn ruby_source_refuses_and_names_every_missing_bound_at_once() {
    let afb = build_source_afb("ruby", "source/main.rb", "puts 'unreachable'\n");
    let request = AfbRunRequest {
        stdin: b"hello".to_vec(),
        memory_bytes: Some(1 << 20),
        ..Default::default()
    };

    let err = run_afb_bytes(&afb, request).expect_err("expected a refusal, not a run");
    let msg = err.to_string();

    assert!(msg.contains("Ruby (source)"), "message was {msg:?}");
    assert!(msg.contains("stdin"), "message was {msg:?}");
    assert!(msg.contains("memory_bytes"), "message was {msg:?}");
}

// ---- Python (source) family: fully bounded, unlike Ruby-source -------------
//
// Python-source and Python-compiled share `python_bounds` / `finish_pyodide`
// (see afb_run.rs), so these tests exercise that shared logic. The
// compiled-bundle shape (`run_python_wasm`) is covered too, by
// `python_compiled_bundle_runs_and_its_bounds_fire` below: it compiles a
// real package through the same `dispatch_compile` a customer runs and then
// puts the bundle through `run_afb_bytes`. Sharing `python_bounds` with the
// source path is an argument, not evidence, and the compiled bundle is the
// shape a published Python plugin actually takes, so it gets its own test.

/// Compiles a real Python package to an `emscripten-pyodide` bundle through
/// the same path `burn compile` takes, and returns the bytes.
///
/// Deliberately the real compiler rather than a hand-built fixture: the
/// bundle a customer publishes is whatever `dispatch_compile` emits, so a
/// fixture that merely resembles one would prove nothing about the shape
/// that actually ships.
#[cfg(feature = "bin")]
fn compile_python_bundle(source: &str) -> Option<Vec<u8>> {
    use crate::cli::compile::dispatch_compile;
    use afterburner_cloud::pkg;

    if !python_runtime_available() {
        return None;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("source")).expect("mkdir");
    std::fs::write(root.join("source/main.py"), source).expect("write source");
    std::fs::write(
        root.join("afb.toml"),
        format!(
            "[format]\nversion = \"1.0\"\n\n[package]\nname = \"pyplug\"\n\
             namespace = \"acme\"\nversion = \"0.1.0\"\nlanguage = \"python\"\n\
             entry = \"source/main.py\"\n\n[runtime]\nmin = \"{}\"\n",
            afterburner_core::VERSION
        ),
    )
    .expect("write afb.toml");
    std::fs::write(
        root.join("manifold.json"),
        serde_json::to_vec(&Manifold::sealed()).expect("encode manifold"),
    )
    .expect("write manifold.json");

    let local = pkg::LocalPackage::load(root).expect("load the package");
    let out = root.join("pyplug.afb");
    dispatch_compile(root, local, &out, false).expect("compile the python package");
    Some(std::fs::read(&out).expect("read the compiled bundle"))
}

/// The compiled bundle runs, and a bound it is given actually fires.
///
/// This is the shape a published Python plugin takes, so it is tested as
/// itself rather than inferred from the source path it shares code with.
#[test]
#[ignore = "compiles a real Pyodide bundle; needs the cached Python runtime"]
#[cfg(feature = "bin")]
fn python_compiled_bundle_runs_and_its_bounds_fire() {
    let Some(afb) = compile_python_bundle("print(\"hello from a compiled plugin\")\n") else {
        eprintln!("skipping: no Python runtime available");
        return;
    };

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run the compiled bundle");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello from a compiled plugin"),
        "the bundle should have printed: outcome {:?}, stdout {stdout:?}, stderr {:?}",
        out.outcome,
        String::from_utf8_lossy(&out.stderr)
    );

    // And a bound it cannot honour is refused by name rather than dropped,
    // which is the property that makes running one as a plugin safe at all.
    // A read-only fs grant is the one axis this path still cannot offer.
    let refused = run_afb_bytes(
        &afb,
        AfbRunRequest {
            manifold: Manifold {
                fs: FsAccess::ReadOnly(vec![std::path::PathBuf::from("/tmp")]),
                ..Manifold::sealed()
            },
            ..Default::default()
        },
    );
    match refused {
        Err(error) => {
            let message = format!("{error:#}");
            assert!(
                message.to_lowercase().contains("read-only"),
                "a bound that cannot be honoured must be refused by name: {message}"
            );
        }
        Ok(output) => panic!(
            "a read-only grant this path cannot honour must be refused, not silently \
             widened to read-write: {:?}",
            output.outcome
        ),
    }
}

/// The wall clock preempts a compiled bundle that would otherwise run
/// forever, and reports itself as `Timeout` rather than as a crash.
///
/// This is the bound the Pyodide path used to refuse outright. It is
/// enforced by wasmtime epoch interruption on the shared epoch engine and
/// covers booting CPython as well as the guest's own code, so the budget
/// here is generous enough to boot and still far short of forever.
#[test]
#[ignore = "compiles a real Pyodide bundle; needs the cached Python runtime"]
#[cfg(feature = "bin")]
fn python_compiled_bundle_wall_clock_preempts() {
    let Some(afb) = compile_python_bundle("while True:\n pass\n") else {
        eprintln!("skipping: no Python runtime available");
        return;
    };

    let started = std::time::Instant::now();
    let out = run_afb_bytes(
        &afb,
        AfbRunRequest {
            timeout: Some(std::time::Duration::from_secs(20)),
            ..Default::default()
        },
    )
    .expect("run the compiled bundle");

    assert_eq!(
        out.outcome,
        AfbRunOutcome::Timeout,
        "an infinite loop under a wall clock must report the wall clock, not a crash"
    );
    // The default fuel budget is 500 billion instructions: an infinite loop
    // would sit there for many minutes before spending it, so finishing
    // anywhere near the deadline is what proves the wall clock, not fuel,
    // is what stopped it.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(90),
        "the deadline should have preempted the guest, took {:?}",
        started.elapsed()
    );
}

/// The infinite loop stops, so a fuel budget is real for a compiled bundle
/// and not merely accepted.
#[test]
#[ignore = "compiles a real Pyodide bundle; needs the cached Python runtime"]
#[cfg(feature = "bin")]
fn python_compiled_bundle_fuel_bound_fires() {
    let Some(afb) = compile_python_bundle("while True:\n pass\n") else {
        eprintln!("skipping: no Python runtime available");
        return;
    };
    let out = run_afb_bytes(
        &afb,
        AfbRunRequest {
            fuel: Some(2_000_000),
            ..Default::default()
        },
    )
    .expect("run the compiled bundle");
    assert_eq!(
        out.outcome,
        AfbRunOutcome::OutOfFuel,
        "an infinite loop under a small fuel budget must report the fuel bound"
    );
}

fn python_runtime_available() -> bool {
    afterburner_wasi::pyodide_runner::resolve_runtime().is_ok()
}

#[test]
#[ignore = "boots the bundled Pyodide/CPython WASI interpreter (real runtime); cargo test --ignored"]
fn python_source_normal_run_captures_stdout() {
    if !python_runtime_available() {
        eprintln!(
            "skipping python_source_normal_run_captures_stdout: \
             no Python runtime available (neither the bundled ~/.burn cache nor BURN_PYTHON_RUNTIME)"
        );
        return;
    }
    let afb = build_source_afb("python", "source/main.py", "print('hello from python')\n");

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from python"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// An uncaught exception is the way a cold-boot Python run signals abnormal
/// termination (unlike the warm-interpreter path, which catches it and
/// reports exit code 0 - see `pyodide_runner::WarmPyInterpreter`'s own doc).
/// `sys.exit(N)` was tried first and traps instead of returning a clean
/// `Exited(N)` in this harness; an uncaught exception is the reliable way to
/// get a real non-zero `Exited` out of the cold path.
#[test]
#[ignore = "boots the bundled Pyodide/CPython WASI interpreter (real runtime); cargo test --ignored"]
fn python_source_uncaught_exception_exits_nonzero() {
    if !python_runtime_available() {
        eprintln!(
            "skipping python_source_uncaught_exception_exits_nonzero: no Python runtime available"
        );
        return;
    }
    let afb = build_source_afb(
        "python",
        "source/main.py",
        "print('about to raise')\nraise ValueError('boom')\n",
    );

    let out = run_afb_bytes(&afb, AfbRunRequest::default()).expect("run_afb_bytes");

    assert!(
        matches!(out.outcome, AfbRunOutcome::Exited(code) if code != 0),
        "expected a non-zero exit, got {:?}",
        out.outcome
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("about to raise"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
#[ignore = "boots the bundled Pyodide/CPython WASI interpreter (real runtime); cargo test --ignored"]
fn python_source_fuel_bound_fires() {
    if !python_runtime_available() {
        eprintln!("skipping python_source_fuel_bound_fires: no Python runtime available");
        return;
    }
    let afb = build_source_afb("python", "source/main.py", "while True:\n pass\n");

    let request = AfbRunRequest {
        fuel: Some(2_000_000),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    // The outcome names the bound that fired rather than reporting a
    // generic trap: `pyodide_runner::guest_trap` classifies the
    // `Trap::OutOfFuel` the guest call carries, so a caller can tell "spent
    // its instruction budget" apart from a crash. An infinite loop given a
    // 2,000,000-fuel budget stops
    // (`python_source_normal_run_captures_stdout` shows the same runtime
    // completes cleanly under the much larger default budget), so fuel
    // exhaustion - not a coincidental unrelated trap - is what stopped it.
    assert_eq!(
        out.outcome,
        AfbRunOutcome::OutOfFuel,
        "an infinite loop under a small fuel budget must report the fuel bound"
    );
    assert_eq!(
        out.fuel_used, 2_000_000,
        "an exhausted budget was spent in full, so that is what is reported"
    );
}

#[test]
#[ignore = "boots the bundled Pyodide/CPython WASI interpreter (real runtime); cargo test --ignored"]
fn python_source_memory_bound_fires() {
    if !python_runtime_available() {
        eprintln!("skipping python_source_memory_bound_fires: no Python runtime available");
        return;
    }
    let afb = build_source_afb(
        "python",
        "source/main.py",
        // Grow a bytearray in a loop past the cap below; the fuel budget
        // (engine default) is generous enough that the memory cap, not
        // fuel, is what stops this.
        "buf = bytearray()\nwhile True:\n buf += bytes(1 << 20)\n",
    );

    // The Pyodide/CPython wasm module itself declares a minimum linear
    // memory around 67 MiB (1047 pages) - a cap below that fails at
    // instantiation, before any guest code runs, which is a different
    // (and differently classified) failure than a runtime `memory.grow`
    // denial. 200 MiB clears that floor with headroom for interpreter
    // bringup, while the runaway loop above still grows well past it.
    let request = AfbRunRequest {
        memory_bytes: Some(200 << 20),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::OutOfMemory);
}

#[test]
#[ignore = "boots the bundled Pyodide/CPython WASI interpreter (real runtime); cargo test --ignored"]
fn python_source_stdin_is_delivered() {
    if !python_runtime_available() {
        eprintln!("skipping python_source_stdin_is_delivered: no Python runtime available");
        return;
    }
    let afb = build_source_afb(
        "python",
        "source/main.py",
        "import sys\nprint('got: ' + sys.stdin.read())\n",
    );

    let request = AfbRunRequest {
        stdin: b"hello from the caller".to_vec(),
        ..Default::default()
    };
    let out = run_afb_bytes(&afb, request).expect("run_afb_bytes");

    assert_eq!(out.outcome, AfbRunOutcome::Exited(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("got: hello from the caller"),
        "stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn python_source_refuses_a_readonly_fs_grant() {
    let afb = build_source_afb("python", "source/main.py", "print('unreachable')\n");
    let request = AfbRunRequest {
        manifold: Manifold {
            fs: FsAccess::ReadOnly(vec![std::env::temp_dir()]),
            ..Manifold::sealed()
        },
        ..Default::default()
    };

    let err = run_afb_bytes(&afb, request).expect_err("expected a refusal, not a run");
    let msg = err.to_string();

    assert!(msg.contains("Python (source)"), "message was {msg:?}");
    assert!(msg.contains("read-only"), "message was {msg:?}");
}

#[test]
fn python_source_refuses_a_requested_timeout() {
    let afb = build_source_afb("python", "source/main.py", "print('unreachable')\n");
    let request = AfbRunRequest {
        timeout: Some(Duration::from_secs(1)),
        ..Default::default()
    };

    let err = run_afb_bytes(&afb, request).expect_err("expected a refusal, not a run");
    let msg = err.to_string();

    assert!(msg.contains("Python (source)"), "message was {msg:?}");
    assert!(msg.contains("timeout"), "message was {msg:?}");
}
