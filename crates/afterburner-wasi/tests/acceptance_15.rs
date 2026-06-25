// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Section 15 acceptance tests: webserver (N1 sockets + N2 threads) and
//! database (N3 durable FS + N2 threads).
//!
//! Both tests are `#[ignore]` because they require the Python runtime artifacts
//! (`/tmp/pyodide-exnref.wasm`, `/tmp/python_stdlib.zip`) that are not committed
//! to the repository. Run them after downloading and translating the binary:
//!
//! ```text
//! cargo test -p afterburner-wasi --test acceptance_15 -- --ignored --nocapture
//! ```
//!
//! The webserver test requires the `daemon` feature (real socket + thread
//! coordinators). The database persistence test uses the sealed path (N3 only,
//! no sockets needed).
//!
//! ## What each test proves
//!
//! `webserver_acceptance_s15`: a Python `http.server.HTTPServer` inside the
//! runtime binds a real OS TCP port via the N1 socket shims (`DaemonNet`), and
//! serves concurrent requests via the N2 thread shims (`DaemonWorkers`). The
//! test makes two real HTTP requests to the running server and asserts the
//! expected response body.
//!
//! `database_persistence_s15`: a Python `sqlite3` script writes three rows to a
//! database file under a host-backed read-write preopen (N3). A SECOND run
//! reopens the same host file and reads the rows back, proving persistence across
//! runtime exits. A concurrent-access assertion (two threads racing to insert via
//! `threading.Thread`) confirms N2 is live for the database path.

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";

fn pyodide_available() -> bool {
    std::path::Path::new(PYODIDE_WASM_PATH).exists()
        && std::path::Path::new(PYTHON_STDLIB_ZIP_PATH).exists()
}

// ---- helpers shared by both tests ------------------------------------------

/// Block until `127.0.0.1:port` accepts a TCP connection (listener is up) or the
/// deadline elapses. Returns `true` if the listener appeared in time.
fn wait_for_listener(port: u16, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            std::time::Duration::from_millis(100),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    false
}

/// Pick a test port unlikely to collide: anchored to the test binary PID so
/// parallel test binaries diverge, plus a small per-test counter.
fn pick_port(offset: u16) -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static CTR: AtomicU16 = AtomicU16::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let pid_tail = (std::process::id() & 0x1FF) as u16;
    51000 + ((pid_tail * 13 + n * 17 + offset) % 4000)
}

// ---- S15 WEBSERVER ----------------------------------------------------------

/// Section 15 webserver acceptance test.
///
/// Boots the Python runtime with a real `DaemonNet` (N1) and `DaemonWorkers`
/// (N2), runs `http.server.ThreadingHTTPServer` on an ephemeral port, waits for
/// the listener to appear, fires two real HTTP requests, and asserts the
/// response body.
///
/// The server runs in its own OS thread (it blocks inside the runtime); the test
/// thread drives the client. After the assertions the OS thread is detached; the
/// tokio runtime drops on test exit, which closes all sockets.
///
/// Requires: `/tmp/pyodide-exnref.wasm`, `/tmp/python_stdlib.zip`, and the
/// `daemon` feature.
#[test]
#[ignore = "requires /tmp/pyodide-exnref.wasm + /tmp/python_stdlib.zip and daemon feature"]
#[cfg(feature = "daemon")]
fn webserver_acceptance_s15() {
    if !pyodide_available() {
        eprintln!(
            "[acceptance_15] SKIP webserver: Python runtime artifacts not found at {}",
            PYODIDE_WASM_PATH
        );
        return;
    }

    use std::io::{Read, Write};
    use std::net::TcpStream;

    let port = pick_port(0);

    // Python source: a ThreadingHTTPServer (uses real threads via N2) that
    // responds with "burn-ok\n" to any GET request. `serve_forever` loops
    // until the runtime exits; the test detaches the thread after assertions.
    //
    // ThreadingHTTPServer extends HTTPServer with mix-in threading so each
    // incoming connection is handled on a new thread - this exercises N2
    // (DaemonWorkers / pthread_create shims).
    let python_source = format!(
        r#"
import http.server
import threading

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'burn-ok\n')
    def log_message(self, fmt, *args):
        pass  # suppress request log noise

class ThreadingHTTPServer(http.server.HTTPServer):
    def process_request(self, request, client_address):
        t = threading.Thread(target=self.process_request_thread,
                             args=(request, client_address))
        t.daemon = True
        t.start()
    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

server = ThreadingHTTPServer(('127.0.0.1', {port}), Handler)
server.serve_forever()
"#
    );

    use afterburner_core::Manifold;
    use afterburner_wasi::pyodide_runner::{PythonNetOpts, run_python_with_net};

    // Build a multi-thread tokio runtime for the socket + thread bridge.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("[acceptance_15] build tokio runtime");
    let handle = rt.handle().clone();

    // Run the Python server in a dedicated OS thread; it blocks inside the
    // runtime for the duration of `serve_forever`.
    let source_clone = python_source.clone();
    let _server_thread = std::thread::spawn(move || {
        // The tokio runtime handle is moved into this thread; drop order is
        // correct (runtime outlives this thread via the outer `rt`).
        let opts = PythonNetOpts {
            tokio_handle: handle,
            manifold: Manifold::open(),
            rw_preopens: Vec::new(),
        };
        let _ = run_python_with_net(&source_clone, opts);
    });

    // Wait up to 30 s for the listener to appear. CPython static init is heavy
    // (the first run compiles the Wasm binary), so the budget is generous.
    let listener_up = wait_for_listener(port, std::time::Duration::from_secs(30));
    assert!(
        listener_up,
        "[acceptance_15] webserver did not bind port {} within 30 s",
        port
    );

    // Fire two sequential GET requests and assert the body.
    for i in 0..2 {
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).expect("[acceptance_15] TCP connect");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .expect("[acceptance_15] write GET");
        let mut resp = Vec::new();
        stream
            .read_to_end(&mut resp)
            .expect("[acceptance_15] read resp");
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("burn-ok"),
            "[acceptance_15] request {i}: expected 'burn-ok' in response, got: {resp_str}"
        );
    }

    // The server thread is detached (it runs inside `_server_thread`). The OS
    // thread continues blocking on `serve_forever`, but the tokio runtime drops
    // when `rt` goes out of scope at test exit, closing all sockets and
    // unblocking the serve loop.
    eprintln!("[acceptance_15] webserver: PASS (port {port}, 2 requests OK)");
}

// ---- S15 DATABASE -----------------------------------------------------------

/// Section 15 database persistence acceptance test.
///
/// Run 1: opens a SQLite database under a host-backed read-write preopen (N3),
/// writes three rows from a concurrent-insert loop (`threading.Thread`, N2).
///
/// Run 2: reopens the SAME host file and reads the rows back, asserting each
/// expected value is present (proving persistence across runtime exits).
///
/// Uses the sealed Python path (`run_python_with_preopens`) - no network
/// capability needed. The N3 host-FS routing is the only daemon-infrastructure
/// piece exercised here.
#[test]
#[ignore = "requires /tmp/pyodide-exnref.wasm + /tmp/python_stdlib.zip"]
fn database_persistence_s15() {
    if !pyodide_available() {
        eprintln!(
            "[acceptance_15] SKIP database: Python runtime artifacts not found at {}",
            PYODIDE_WASM_PATH
        );
        return;
    }

    use afterburner_wasi::pyodide_runner::run_python_with_preopens;

    // Use a temporary directory so parallel test runs do not collide and the
    // file is cleaned up automatically when the test exits.
    let tmp = tempfile::tempdir().expect("[acceptance_15] tempdir");
    let host_db_dir = tmp.path().to_path_buf();
    let guest_db_dir = "/data".to_owned();

    // Run 1: write three rows from two concurrent threads.
    let write_source = r#"
import sqlite3
import threading

DB = '/data/accept_test.db'

conn = sqlite3.connect(DB)
conn.execute(
    'CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, val TEXT)'
)
conn.commit()
conn.close()

errors = []
def insert_row(val):
    try:
        c = sqlite3.connect(DB)
        c.execute('INSERT INTO items (val) VALUES (?)', (val,))
        c.commit()
        c.close()
    except Exception as e:
        errors.append(str(e))

threads = [threading.Thread(target=insert_row, args=(v,)) for v in ('alpha', 'beta')]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Insert the third row on this thread after the concurrent pair finishes.
c = sqlite3.connect(DB)
c.execute('INSERT INTO items (val) VALUES (?)', ('gamma',))
c.commit()
c.close()

if errors:
    raise RuntimeError('concurrent insert errors: ' + repr(errors))
print('write-ok')
"#;

    let run1 =
        run_python_with_preopens(write_source, &[(host_db_dir.clone(), guest_db_dir.clone())])
            .expect("[acceptance_15] run1 (write) failed");
    let stdout1 = String::from_utf8_lossy(&run1.stdout);
    assert_eq!(
        run1.exit_code, 0,
        "[acceptance_15] run1 exit_code != 0; stdout: {stdout1}"
    );
    assert!(
        stdout1.contains("write-ok"),
        "[acceptance_15] run1 missing 'write-ok'; stdout: {stdout1}"
    );

    // Confirm the database file is actually on the host filesystem.
    let host_db_path = host_db_dir.join("accept_test.db");
    assert!(
        host_db_path.exists(),
        "[acceptance_15] database file not found at {:?} after run1",
        host_db_path
    );

    // Run 2: reopen the same file and read rows back.
    let read_source = r#"
import sqlite3
c = sqlite3.connect('/data/accept_test.db')
rows = [r[0] for r in c.execute('SELECT val FROM items ORDER BY id').fetchall()]
c.close()
print('rows=' + ','.join(rows))
"#;

    let run2 =
        run_python_with_preopens(read_source, &[(host_db_dir.clone(), guest_db_dir.clone())])
            .expect("[acceptance_15] run2 (read) failed");
    let stdout2 = String::from_utf8_lossy(&run2.stdout);
    assert_eq!(
        run2.exit_code, 0,
        "[acceptance_15] run2 exit_code != 0; stdout: {stdout2}"
    );

    // All three values must be present (order is not guaranteed for the
    // concurrent inserts, so check membership rather than exact sequence).
    for expected in ["alpha", "beta", "gamma"] {
        assert!(
            stdout2.contains(expected),
            "[acceptance_15] run2 missing '{expected}' in stdout: {stdout2}"
        );
    }

    eprintln!("[acceptance_15] database: PASS (rows persisted across two runs: {stdout2})");
}
