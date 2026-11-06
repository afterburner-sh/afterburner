// SPDX-License-Identifier: Apache-2.0
//! A tiny mock HTTP/1.1 server for the afterburner test suites.
//!
//! One std thread accepts on `127.0.0.1:0` and one std thread serves each
//! connection (keep-alive, `Content-Length` and chunked request bodies).
//! Mocks match in the order they were made, the first match wins, and an
//! unmatched request gets a 404. Dropping the [`MockServer`] wakes the
//! accept loop with a self-connect, shuts every open connection down and
//! joins every thread, so nothing outlives the server. No async runtime.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use serde::Serialize;
use serde_json::Value;

const MAX_LINE: u64 = 64 * 1024;
const MAX_HEADERS: usize = 256;
const MAX_BODY: usize = 256 * 1024 * 1024;

macro_rules! methods {
    ($($variant:ident => $konst:ident),* $(,)?) => {
        /// An HTTP request method.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Method { $($variant),* }

        impl Method {
            /// The method as it appears on the request line.
            pub fn as_str(self) -> &'static str {
                match self { $(Method::$variant => stringify!($konst)),* }
            }
        }

        $(
            #[doc = concat!("The `", stringify!($konst), "` method.")]
            pub const $konst: Method = Method::$variant;
        )*
    };
}

methods!(
    Get => GET,
    Post => POST,
    Put => PUT,
    Delete => DELETE,
    Patch => PATCH,
    Head => HEAD,
    Options => OPTIONS,
);

/// `use afterburner_mock_http::prelude::*;` brings in everything a test needs.
pub mod prelude {
    pub use crate::{DELETE, GET, HEAD, Method, MockServer, OPTIONS, PATCH, POST, PUT};
}

/// What a request must look like for a mock to answer it. Unset fields match anything.
#[derive(Default)]
pub struct When {
    method: Option<Method>,
    path: Option<String>,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    json: Option<Value>,
}

impl When {
    /// Match this request method.
    pub fn method(&mut self, method: Method) -> &mut Self {
        self.method = Some(method);
        self
    }

    /// Match this exact path (the query string is not part of it).
    pub fn path(&mut self, path: impl Into<String>) -> &mut Self {
        self.path = Some(path.into());
        self
    }

    /// Require a request header (name case-insensitive, value exact).
    pub fn header(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Require a decoded query parameter.
    pub fn query_param(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.query.push((name.into(), value.into()));
        self
    }

    /// Require a JSON request body structurally equal to `body`.
    pub fn json_body(&mut self, body: impl Serialize) -> &mut Self {
        self.json = Some(serde_json::to_value(body).expect("json_body must serialize"));
        self
    }
}

/// The response a mock sends.
pub struct Then {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Then {
    fn new() -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Set the status code (default 200).
    pub fn status(&mut self, status: u16) -> &mut Self {
        self.status = status;
        self
    }

    /// Set the raw response body.
    pub fn body(&mut self, body: impl AsRef<[u8]>) -> &mut Self {
        self.body = body.as_ref().to_vec();
        self
    }

    /// Set a JSON response body and its content type.
    pub fn json_body(&mut self, body: impl Serialize) -> &mut Self {
        self.body = serde_json::to_vec(&body).expect("json_body must serialize");
        self.header("Content-Type", "application/json")
    }

    /// Add a response header.
    pub fn header(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

struct MockState {
    when: When,
    then: Then,
    hits: AtomicUsize,
}

impl MockState {
    fn matches(&self, req: &Request) -> bool {
        let w = &self.when;
        w.method.is_none_or(|m| m.as_str() == req.method)
            && w.path
                .as_deref()
                .is_none_or(|p| p == req.path || p == req.decoded_path)
            && w.headers.iter().all(|(k, v)| {
                req.headers
                    .iter()
                    .any(|(rk, rv)| rk.eq_ignore_ascii_case(k) && rv == v)
            })
            && w.query.iter().all(|kv| req.query.contains(kv))
            && w.json
                .as_ref()
                .is_none_or(|j| serde_json::from_slice::<Value>(&req.body).is_ok_and(|b| &b == j))
    }

    fn describe(&self) -> String {
        format!(
            "{} {}",
            self.when.method.map_or("ANY", Method::as_str),
            self.when.path.as_deref().unwrap_or("*")
        )
    }
}

/// A handle to a registered mock.
pub struct Mock {
    state: Arc<MockState>,
}

impl Mock {
    /// Panic unless exactly one request has matched this mock.
    pub fn assert(&self) {
        let hits = self.state.hits.load(Ordering::Acquire);
        assert_eq!(
            hits,
            1,
            "expected exactly 1 request matching {}, got {hits}",
            self.state.describe()
        );
    }
}

struct Shared {
    mocks: Mutex<Vec<Arc<MockState>>>,
    stop: AtomicBool,
}

impl Shared {
    // vertexia: a plain mutex, the mock list is touched once per request in tests only
    fn mocks(&self) -> MutexGuard<'_, Vec<Arc<MockState>>> {
        self.mocks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn find(&self, req: &Request) -> Option<Arc<MockState>> {
        let found = self.mocks().iter().find(|m| m.matches(req)).cloned();
        if let Some(m) = &found {
            m.hits.fetch_add(1, Ordering::AcqRel);
        }
        found
    }
}

/// A mock HTTP server on a random loopback port; stops when dropped.
pub struct MockServer {
    addr: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl MockServer {
    /// Bind `127.0.0.1:0` and start serving. Panics if the socket cannot be bound.
    pub fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the mock server socket");
        let addr = listener.local_addr().expect("mock server local address");
        let shared = Arc::new(Shared {
            mocks: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
        });
        let serving = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("mock-http".into())
            .spawn(move || serve(&listener, &serving))
            .expect("spawn the mock server thread");
        Self {
            addr,
            shared,
            thread: Some(thread),
        }
    }

    /// Register a mock; `f` fills in what it matches and what it answers.
    pub fn mock(&self, f: impl FnOnce(&mut When, &mut Then)) -> Mock {
        let (mut when, mut then) = (When::default(), Then::new());
        f(&mut when, &mut then);
        let state = Arc::new(MockState {
            when,
            then,
            hits: AtomicUsize::new(0),
        });
        self.shared.mocks().push(Arc::clone(&state));
        Mock { state }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The full URL of `path` on this server.
    pub fn url(&self, path: impl AsRef<str>) -> String {
        format!("http://{}{}", self.addr, path.as_ref())
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        // Wake the blocking accept; a refused connect means the thread already ended.
        drop(TcpStream::connect(self.addr));
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

fn serve(listener: &TcpListener, shared: &Arc<Shared>) {
    // vertexia: one entry per accepted connection kept until the server drops, fine for test lifetimes
    let mut conns: Vec<(TcpStream, JoinHandle<()>)> = Vec::new();
    for stream in listener.incoming() {
        if shared.stop.load(Ordering::Acquire) {
            break;
        }
        let Ok(stream) = stream else { break };
        let Ok(control) = stream.try_clone() else {
            continue;
        };
        let conn_shared = Arc::clone(shared);
        conns.push((
            control,
            std::thread::spawn(move || handle(stream, &conn_shared)),
        ));
    }
    for (control, handler) in conns {
        // A connection the peer already closed refuses the shutdown; nothing to do then.
        drop(control.shutdown(Shutdown::Both));
        drop(handler.join());
    }
}

fn handle(stream: TcpStream, shared: &Shared) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    while let Ok(Some((req, keep_alive))) = read_request(&mut reader) {
        let hit = shared.find(&req);
        let fallback;
        let then = match &hit {
            Some(m) => &m.then,
            None => {
                fallback = Then {
                    status: 404,
                    headers: Vec::new(),
                    body: b"no mock matches this request".to_vec(),
                };
                &fallback
            }
        };
        if write_response(&mut writer, req.method == "HEAD", then).is_err() || !keep_alive {
            break;
        }
    }
}

struct Request {
    method: String,
    path: String,
    decoded_path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

fn eof() -> io::Error {
    io::Error::from(io::ErrorKind::UnexpectedEof)
}

/// One CRLF- or LF-terminated line without its terminator; `None` on a clean EOF.
fn read_line<R: BufRead>(r: &mut R) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r.by_ref().take(MAX_LINE).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.pop() != Some(b'\n') {
        return Err(invalid("header line too long or truncated"));
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| invalid("non-UTF-8 header line"))
}

fn read_request<R: BufRead>(r: &mut R) -> io::Result<Option<(Request, bool)>> {
    let Some(line) = read_line(r)? else {
        return Ok(None);
    };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("malformed request line"));
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let line = read_line(r)?.ok_or_else(eof)?;
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(invalid("too many headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed header"))?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let keep_alive = version != "HTTP/1.0"
        && !header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let chunked =
        header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        read_chunked(r)?
    } else if let Some(len) = header("content-length") {
        let len: usize = len.parse().map_err(|_| invalid("bad Content-Length"))?;
        if len > MAX_BODY {
            return Err(invalid("request body too large"));
        }
        let mut body = Vec::new();
        r.by_ref().take(len as u64).read_to_end(&mut body)?;
        if body.len() != len {
            return Err(eof());
        }
        body
    } else {
        Vec::new()
    };
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let query = raw_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k, true), percent_decode(v, true))
        })
        .collect();
    let request = Request {
        method: method.to_owned(),
        path: path.to_owned(),
        decoded_path: percent_decode(path, false),
        query,
        headers,
        body,
    };
    Ok(Some((request, keep_alive)))
}

fn read_chunked<R: BufRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line(r)?.ok_or_else(eof)?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| invalid("bad chunk size"))?;
        if size == 0 {
            while !read_line(r)?.ok_or_else(eof)?.is_empty() {}
            return Ok(body);
        }
        if body.len().saturating_add(size) > MAX_BODY {
            return Err(invalid("request body too large"));
        }
        let before = body.len();
        r.by_ref().take(size as u64).read_to_end(&mut body)?;
        if body.len() - before != size {
            return Err(eof());
        }
        if !read_line(r)?.ok_or_else(eof)?.is_empty() {
            return Err(invalid("missing chunk terminator"));
        }
    }
}

fn percent_decode(s: &str, plus_is_space: bool) -> String {
    let b = s.as_bytes();
    let hex = |i: usize| b.get(i).and_then(|c| char::from(*c).to_digit(16));
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%'
            && let (Some(h), Some(l)) = (hex(i + 1), hex(i + 2))
        {
            out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
            i += 3;
            continue;
        }
        out.push(if plus_is_space && c == b'+' { b' ' } else { c });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn write_response(w: &mut TcpStream, head_only: bool, then: &Then) -> io::Result<()> {
    let mut out = Vec::with_capacity(then.body.len() + 256);
    write!(
        out,
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
        then.status,
        reason(then.status),
        then.body.len()
    )?;
    for (k, v) in then
        .headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("content-length"))
    {
        write!(out, "{k}: {v}\r\n")?;
    }
    out.extend_from_slice(b"\r\n");
    if !head_only {
        out.extend_from_slice(&then.body);
    }
    w.write_all(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(server: &MockServer) -> BufReader<TcpStream> {
        BufReader::new(TcpStream::connect(server.addr).unwrap())
    }

    fn exchange(r: &mut BufReader<TcpStream>, raw: &str) -> (u16, String) {
        r.get_mut().write_all(raw.as_bytes()).unwrap();
        let mut status_line = String::new();
        r.read_line(&mut status_line).unwrap();
        let status = status_line.split(' ').nth(1).unwrap().parse().unwrap();
        let mut len = 0usize;
        loop {
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let lower = line.trim_end().to_ascii_lowercase();
            if lower.is_empty() {
                break;
            }
            if let Some(v) = lower.strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; len];
        r.read_exact(&mut body).unwrap();
        (status, String::from_utf8(body).unwrap())
    }

    #[test]
    fn first_match_wins_and_unmatched_is_404() {
        let server = MockServer::start();
        let first = server.mock(|when, then| {
            when.method(GET).path("/a");
            then.status(200).body("first");
        });
        let second = server.mock(|when, then| {
            when.method(GET).path("/a");
            then.status(200).body("second");
        });
        let mut c = connect(&server);
        assert_eq!(
            exchange(&mut c, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"),
            (200, "first".into())
        );
        assert_eq!(exchange(&mut c, "POST /a HTTP/1.1\r\n\r\n").0, 404);
        first.assert();
        assert_eq!(second.state.hits.load(Ordering::Acquire), 0);
    }

    #[test]
    #[should_panic(expected = "GET /never")]
    fn assert_fails_naming_method_and_path() {
        let server = MockServer::start();
        server
            .mock(|when, _then| {
                when.method(GET).path("/never");
            })
            .assert();
    }

    #[test]
    fn matches_header_query_and_json_body_structurally() {
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(POST)
                .path("/p")
                .header("authorization", "Bearer t")
                .query_param("q", "a b")
                .json_body(serde_json::json!({"x": 1, "y": [true]}));
            then.status(201)
                .header("X-Seen", "1")
                .json_body(serde_json::json!({"ok": true}));
        });
        let body = r#"{ "y": [true], "x": 1 }"#;
        let raw = format!(
            "POST /p?q=a+b HTTP/1.1\r\nAUTHORIZATION: Bearer t\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut c = connect(&server);
        assert_eq!(exchange(&mut c, &raw), (201, r#"{"ok":true}"#.into()));
        m.assert();
    }

    #[test]
    fn chunked_request_body_is_decoded_and_connection_is_reused() {
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(POST)
                .path("/c")
                .json_body(serde_json::json!({"k": "v"}));
            then.status(200).body("ok");
        });
        let mut c = connect(&server);
        let raw = "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"k\":\r\n4\r\n\"v\"}\r\n0\r\n\r\n";
        assert_eq!(exchange(&mut c, raw), (200, "ok".into()));
        // Same connection, second request: keep-alive.
        assert_eq!(exchange(&mut c, "GET /other HTTP/1.1\r\n\r\n").0, 404);
        m.assert();
    }

    #[test]
    fn drop_ends_all_threads_with_a_live_keep_alive_connection() {
        let server = MockServer::start();
        let mut c = connect(&server);
        assert_eq!(exchange(&mut c, "GET /x HTTP/1.1\r\n\r\n").0, 404);
        drop(server);
        let mut rest = String::new();
        assert_eq!(c.read_line(&mut rest).unwrap_or(0), 0);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2fb%zz+c", false), "a/b%zz+c");
        assert_eq!(percent_decode("a+b%20c", true), "a b c");
    }
}
