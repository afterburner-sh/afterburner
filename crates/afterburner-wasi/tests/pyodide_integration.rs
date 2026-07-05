// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Integration tests against the real Pyodide 0.28 wasm binary.
//!
//! All tests are `#[ignore]` for two reasons:
//! 1. CPython static init takes ~200M Wasm instructions (minutes on first run).
//! 2. The binary at /tmp/pyodide-exnref.wasm is not committed to the repo;
//!    CI machines do not have it. Run these manually after translating the
//!    binary with wasm-opt as described in examples/pyodide028_probe.rs.
//!
//! To run on demand:
//!   cargo test -p afterburner-wasi --test pyodide_integration -- --ignored

use afterburner_wasi::pyodide_runner::boot_pyodide;

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";

fn pyodide_available() -> bool {
    std::path::Path::new(PYODIDE_WASM_PATH).exists()
}

/// Whether `run_python_with_net` can resolve its runtime: the
/// `BURN_PYTHON_RUNTIME` override dir, or the self-contained `~/.burn/pyodide-*/`
/// bundle. This differs from [`pyodide_available`] (the `/tmp` `boot_pyodide`
/// convention) because `run_python_with_net` discovers the runtime through the
/// bundle resolver, not a hardcoded `/tmp` path.
#[cfg(feature = "daemon")]
fn python_net_runtime_available() -> bool {
    if let Ok(dir) = std::env::var("BURN_PYTHON_RUNTIME")
        && std::path::Path::new(&dir)
            .join("pyodide-exnref.wasm")
            .exists()
    {
        return true;
    }
    if let Some(home) = std::env::var_os("HOME")
        && let Ok(entries) = std::fs::read_dir(std::path::Path::new(&home).join(".burn"))
    {
        return entries
            .flatten()
            .any(|e| e.path().join("pyodide-exnref.wasm").exists());
    }
    false
}

// ---- boot ------------------------------------------------------------------

/// Pyodide 0.28 Wasm binary compiles and boots CPython through
/// `__wasm_call_ctors` without trapping.
#[test]
#[ignore]
fn pyodide_boots_without_trap() {
    if !pyodide_available() {
        eprintln!(
            "[pyodide_integration] SKIP: {} not found",
            PYODIDE_WASM_PATH
        );
        return;
    }
    let out = boot_pyodide(PYODIDE_WASM_PATH, PYTHON_STDLIB_ZIP_PATH)
        .expect("Pyodide should boot through __wasm_call_ctors without trap");
    // Not asserting specific stdout content - just that the boot did not trap.
    let _ = out;
}

// ---- determinism -----------------------------------------------------------

/// Two back-to-back boots of the same binary produce byte-identical stdout.
#[test]
#[ignore]
fn pyodide_boot_is_deterministic() {
    if !pyodide_available() {
        eprintln!(
            "[pyodide_integration] SKIP: {} not found",
            PYODIDE_WASM_PATH
        );
        return;
    }
    let out1 = boot_pyodide(PYODIDE_WASM_PATH, PYTHON_STDLIB_ZIP_PATH).expect("first boot");
    let out2 = boot_pyodide(PYODIDE_WASM_PATH, PYTHON_STDLIB_ZIP_PATH).expect("second boot");
    assert_eq!(
        out1.stdout, out2.stdout,
        "two identical boots must produce byte-identical stdout"
    );
}

// ---- compile only ----------------------------------------------------------

/// The translated binary compiles with the deterministic engine without
/// needing to boot CPython. This is a fast sanity check (no fuel consumed).
#[test]
#[ignore]
fn pyodide_binary_compiles() {
    if !pyodide_available() {
        eprintln!(
            "[pyodide_integration] SKIP: {} not found",
            PYODIDE_WASM_PATH
        );
        return;
    }
    let wasm_bytes = std::fs::read(PYODIDE_WASM_PATH).expect("read wasm");
    let engine =
        afterburner_wasi::embedder_vm::deterministic_engine().expect("deterministic engine");
    wasmtime::Module::new(&engine, &wasm_bytes)
        .expect("Pyodide binary must compile with the deterministic engine");
}

// ---- live HTTPS (RealOs entropy) -------------------------------------------

/// Probe whether the host machine has outbound HTTPS reachability to example.com.
/// Returns false when offline or when the connect times out (a short 2 s budget).
#[cfg(feature = "daemon")]
fn https_reachable() -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    // Resolve example.com by name rather than a hardcoded IP: the classic
    // 93.184.216.34 (EdgeCast) was retired when example.com moved to Cloudflare,
    // so a fixed IP gives a false "offline". Resolve, then connect to the first
    // address with a timeout.
    "example.com:443"
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok())
        .is_some()
}

/// Live HTTPS GET via `run_python_with_net`: proves that real OS entropy (the
/// RealOs shim mode) enables a working TLS handshake inside Pyodide.
///
/// Skipped when:
///   - the Pyodide runtime is not available at /tmp/pyodide-exnref.wasm, or
///   - the host is offline (no HTTPS reachability to example.com:443).
///
/// The test fetches https://example.com via Python's stdlib `urllib.request`
/// (which calls into CPython's ssl module and triggers the `getentropy`/
/// `random_get` shims), reads the HTTP status from the response, and asserts it
/// is 200. A TLS handshake failure (the pre-fix symptom) would surface as a
/// Python exception, which would propagate as a non-zero exit code.
///
/// To run on demand:
///   cargo test -p afterburner-wasi --test pyodide_integration --features daemon -- --ignored live_https_get_returns_200
#[test]
#[ignore]
#[cfg(feature = "daemon")]
fn live_https_get_returns_200() {
    if !python_net_runtime_available() {
        eprintln!(
            "[pyodide_integration] SKIP live_https: no run_python_with_net runtime \
             (set BURN_PYTHON_RUNTIME or populate ~/.burn/pyodide-*/)"
        );
        return;
    }
    if !https_reachable() {
        eprintln!("[pyodide_integration] SKIP live_https: host appears to be offline");
        return;
    }

    use afterburner_core::Manifold;
    use afterburner_wasi::pyodide_runner::{PythonNetOpts, run_python_with_net};

    // Build a tokio runtime; the socket bridge needs async I/O.
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for live_https test");

    let opts = PythonNetOpts {
        tokio_handle: tokio_rt.handle().clone(),
        manifold: Manifold::open(),
        rw_preopens: Vec::new(),
        host_context: None,
    };

    // urllib.request is stdlib; it uses Python's ssl module which calls getentropy
    // and random_get during the TLS handshake. A non-zero exit code means Python
    // raised an exception (e.g. ssl.SSLError or urllib.error.URLError).
    // Use a blocking socket (no timeout) so CPython's PySSL_select short-circuits
    // the SOCKET_IS_BLOCKING path and never calls select/poll. Our socket bridge
    // handles read/write on blocking fds but does not implement select/newselect,
    // so a non-None timeout would cause the TLS handshake to stall on a spurious
    // "nothing ready" return from __syscall__newselect.
    let source = concat!(
        "import urllib.request as _u\n",
        "resp = _u.urlopen('https://example.com')\n",
        "print(resp.status)\n",
    );

    let out = run_python_with_net(source, opts).expect("run_python_with_net failed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.exit_code, 0,
        "Python must exit cleanly (TLS handshake + HTTP GET succeeded); stdout={text:?}"
    );
    assert!(
        text.trim() == "200",
        "expected HTTP status 200 from example.com, got: {text:?}"
    );
}

// ---- warm-interpreter reuse (#53) ------------------------------------------

/// Whether `run_python_batch` can resolve its runtime (the `BURN_PYTHON_RUNTIME`
/// override, or the `~/.burn/pyodide-*` bundle).
fn batch_runtime_available() -> bool {
    if let Ok(dir) = std::env::var("BURN_PYTHON_RUNTIME")
        && std::path::Path::new(&dir)
            .join("pyodide-exnref.wasm")
            .exists()
    {
        return true;
    }
    if let Some(home) = std::env::var_os("HOME")
        && let Ok(entries) = std::fs::read_dir(std::path::Path::new(&home).join(".burn"))
    {
        return entries
            .flatten()
            .any(|e| e.path().join("pyodide-exnref.wasm").exists());
    }
    false
}

/// A batch of programs runs on ONE warmed interpreter: stdout is captured per
/// program, each program runs in a FRESH namespace (a name defined by one does
/// not leak into the next), and a typed return via `__afb_emit__` round-trips.
#[test]
#[ignore]
fn pyodide_warm_batch_reuse_isolated_and_correct() {
    if !batch_runtime_available() {
        eprintln!("[pyodide_integration] SKIP: no ~/.burn pyodide runtime");
        return;
    }
    use afterburner_core::OutputValue;
    use afterburner_wasi::pyodide_runner::run_python_batch;

    let sources = [
        "leaked = 111\nprint('one', leaked)",
        "print('two', 'leaked' in globals())",
        "__afb_emit__({'sum': 7 + 35})",
    ];
    let outs = run_python_batch(&sources).expect("warm batch should run");
    assert_eq!(outs.len(), 3, "one output per source");
    assert_eq!(
        String::from_utf8_lossy(&outs[0].stdout).trim(),
        "one 111",
        "program 1 stdout captured"
    );
    assert_eq!(
        String::from_utf8_lossy(&outs[1].stdout).trim(),
        "two False",
        "fresh namespace: program 1's global must not leak into program 2"
    );
    match &outs[2].output {
        OutputValue::Json(v) => assert_eq!(v, &serde_json::json!({ "sum": 42 })),
        other => panic!("expected Json({{sum:42}}) from __afb_emit__, got {other:?}"),
    }
}

/// Benchmark: N cold runs (a boot + CPython bringup each) vs one warm batch (one
/// boot, then N `PyRun_SimpleString` runs). Prints per-run times + speedup.
#[test]
#[ignore]
fn bench_warm_reuse_vs_cold() {
    if !batch_runtime_available() {
        eprintln!("[pyodide_integration] SKIP: no ~/.burn pyodide runtime");
        return;
    }
    use afterburner_wasi::pyodide_runner::{run_python, run_python_batch};

    let script = "print(sum(range(1000)))";
    let n = 12usize;

    let t = std::time::Instant::now();
    for _ in 0..n {
        run_python(script).expect("cold run");
    }
    let cold = t.elapsed();

    let sources = vec![script; n];
    let t = std::time::Instant::now();
    let outs = run_python_batch(&sources).expect("warm batch");
    let warm = t.elapsed();

    assert_eq!(outs.len(), n);
    for o in &outs {
        assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "499500");
    }
    eprintln!(
        "[bench] N={n}: cold {cold:?} ({}ms/run) | warm {warm:?} ({}ms/run) | speedup {:.1}x",
        cold.as_millis() / n as u128,
        warm.as_millis() / n as u128,
        cold.as_secs_f64() / warm.as_secs_f64().max(1e-9)
    );
}
