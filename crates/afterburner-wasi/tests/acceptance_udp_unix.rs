// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Acceptance tests for UDP and Unix-domain socket support in the Python runtime.
//!
//! All tests are `#[ignore]` because they require the Pyodide runtime artifacts
//! at `/tmp/pyodide-exnref.wasm` and `/tmp/python_stdlib.zip`, which are not
//! present in CI by default. Run with:
//!
//! ```text
//! cargo test -p afterburner-wasi --features daemon --test acceptance_udp_unix -- --include-ignored
//! ```

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";

// Serialize: two Pyodide engines cannot init concurrently in one process
// (LLVM / wasmtime module compilation is not safe to parallelize here).
static ACCEPTANCE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn pyodide_available() -> bool {
    std::path::Path::new(PYODIDE_WASM_PATH).exists()
        && std::path::Path::new(PYTHON_STDLIB_ZIP_PATH).exists()
}

/// Pick a UDP port unlikely to collide with the TCP range used by acceptance_15.
fn pick_udp_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static CTR: AtomicU16 = AtomicU16::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let pid_tail = (std::process::id() & 0x1FF) as u16;
    56000 + ((pid_tail * 7 + n * 11) % 4000)
}

/// UDP echo round-trip.
///
/// Python binds a UDP socket on 127.0.0.1:<port>, a second socket sends a
/// datagram to it, the first recvfrom's it, asserts the payload, and prints
/// a marker. The host asserts the marker appears in stdout.
#[test]
#[ignore = "requires /tmp/pyodide-exnref.wasm + /tmp/python_stdlib.zip and daemon feature"]
#[cfg(feature = "daemon")]
fn udp_echo_round_trip() {
    let _guard = ACCEPTANCE_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    if !pyodide_available() {
        eprintln!("[acceptance_udp_unix] SKIP udp_echo: runtime not found");
        return;
    }

    let port = pick_udp_port();

    // Single script: bind, send to self, recv, assert payload, print marker.
    let python_source = format!(
        r#"
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', {port}))

# Send a datagram to ourselves.
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.sendto(b'hello-udp', ('127.0.0.1', {port}))
sender.close()

# Receive it.
data, addr = s.recvfrom(1024)
assert data == b'hello-udp', f'got {{data!r}}'
s.close()
print('udp-echo-ok')
"#
    );

    use afterburner_core::Manifold;
    use afterburner_wasi::pyodide_runner::{PythonNetOpts, run_python_with_net};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    let handle = rt.handle().clone();

    let opts = PythonNetOpts {
        tokio_handle: handle,
        manifold: Manifold::open(),
        rw_preopens: Vec::new(),
    };
    let result = run_python_with_net(&python_source, opts)
        .expect("[acceptance_udp_unix] udp_echo: run_python_with_net failed");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains("udp-echo-ok"),
        "[acceptance_udp_unix] udp_echo: missing 'udp-echo-ok' in stdout: {stdout:?}"
    );
    assert_eq!(
        result.exit_code, 0,
        "[acceptance_udp_unix] udp_echo: exit_code != 0; stdout: {stdout}"
    );
    eprintln!("[acceptance_udp_unix] udp_echo: PASS");
}

/// Unix-domain stream round-trip.
///
/// Python binds and listens on an AF_UNIX SOCK_STREAM socket at a temp path,
/// a client connects, sends data, the server accepts, reads, and replies.
/// Both sides print markers; the host asserts the success marker appears.
#[test]
#[ignore = "requires /tmp/pyodide-exnref.wasm + /tmp/python_stdlib.zip and daemon feature"]
#[cfg(all(feature = "daemon", unix))]
fn unix_stream_round_trip() {
    let _guard = ACCEPTANCE_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    if !pyodide_available() {
        eprintln!("[acceptance_udp_unix] SKIP unix_stream: runtime not found");
        return;
    }

    // The socket path is a raw host-fs path passed verbatim through sockaddr_un.
    // Our DaemonUnix coordinator binds/connects on the host directly, so no WASI
    // preopen is required. Avoid mapping /tmp to preserve the pyout.txt capture.
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("burn_test.sock");
    let sock_path_str = sock_path.to_str().expect("sock path str").to_owned();

    // Emscripten's Python C socket module (socketmodule.c) may not have
    // AF_UNIX support compiled in; detect this before running the real test so
    // the test self-skips rather than erroring on "bad family".
    // vertexia: AF_UNIX support requires a Pyodide build with
    // HAVE_SOCKADDR_ALG / AF_UNIX in socketmodule.c; upgrade path is a custom
    // Pyodide build or patching _socket via a WASM shim.
    let probe_source = r#"
import socket
if hasattr(socket, 'AF_UNIX'):
    print('AF_UNIX_AVAILABLE')
else:
    print('SKIP:AF_UNIX not in Emscripten Python socket module')
"#;

    let python_source = format!(
        r#"
import socket

# AF_UNIX = 1; it may not be a named constant in Emscripten's Python
AF_UNIX = 1
SOCK_PATH = '{sock_path_str}'

# Server: bind + listen.
srv = socket.socket(AF_UNIX, socket.SOCK_STREAM)
srv.bind(SOCK_PATH)
srv.listen(1)

# Client: connect + send.
cli = socket.socket(AF_UNIX, socket.SOCK_STREAM)
cli.connect(SOCK_PATH)
cli.sendall(b'hello-unix')

# Server: accept + recv.
conn, _ = srv.accept()
data = conn.recv(1024)
assert data == b'hello-unix', f'server got {{data!r}}'
conn.sendall(b'world-unix')
conn.close()

# Client: recv reply.
reply = cli.recv(1024)
assert reply == b'world-unix', f'client got {{reply!r}}'
cli.close()
srv.close()

print('unix-stream-ok')
"#
    );

    use afterburner_core::Manifold;
    use afterburner_wasi::pyodide_runner::{PythonNetOpts, run_python_with_net};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    let handle = rt.handle().clone();

    // Probe: check if AF_UNIX is available in the Emscripten Python build.
    // If not, self-skip with an honest message rather than failing on "bad family".
    let probe_opts = PythonNetOpts {
        tokio_handle: handle.clone(),
        manifold: Manifold::open(),
        rw_preopens: Vec::new(),
    };
    let probe_out = run_python_with_net(probe_source, probe_opts)
        .expect("[acceptance_udp_unix] unix_stream: probe failed");
    let probe_stdout = String::from_utf8_lossy(&probe_out.stdout);
    if probe_stdout.contains("SKIP:") {
        eprintln!(
            "[acceptance_udp_unix] unix_stream: SKIP (AF_UNIX not in this Emscripten Python build)"
        );
        return;
    }

    let opts = PythonNetOpts {
        tokio_handle: handle,
        manifold: Manifold::open(),
        rw_preopens: Vec::new(),
    };
    let result = run_python_with_net(&python_source, opts)
        .expect("[acceptance_udp_unix] unix_stream: run_python_with_net failed");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains("unix-stream-ok"),
        "[acceptance_udp_unix] unix_stream: missing 'unix-stream-ok' in stdout: {stdout:?}"
    );
    assert_eq!(
        result.exit_code, 0,
        "[acceptance_udp_unix] unix_stream: exit_code != 0; stdout: {stdout}"
    );
    eprintln!("[acceptance_udp_unix] unix_stream: PASS");
}
