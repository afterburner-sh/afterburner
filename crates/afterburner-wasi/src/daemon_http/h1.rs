// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! HTTP/1.1 server primitives over any nuclei byte stream: request head
//! parsing (`httparse`), content-length and chunked bodies, `Expect:
//! 100-continue`, keep-alive and a single-write response. The daemon's listener
//! and the inspector's discovery server both loop over these.
//!
//! Invariants: a request head is at most [`MAX_HEAD`] bytes with at most
//! [`MAX_HEADERS`] headers, a body at most the caller's cap; a request that
//! carries both `content-length` and `transfer-encoding` is rejected (request
//! smuggling), and every rejection names the status to answer before closing.

use http::{Response, StatusCode};
use nuclei::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;
use std::time::SystemTime;

/// Largest accepted request head (request line plus headers).
pub(crate) const MAX_HEAD: usize = 64 * 1024;
/// Most headers accepted on one request.
pub(crate) const MAX_HEADERS: usize = 128;
/// Largest accepted request body.
pub(crate) const MAX_BODY: usize = 16 * 1024 * 1024;

const READ_CHUNK: usize = 16 * 1024;
const MAX_CHUNK_LINE: usize = 1024;
const MAX_TRAILERS: usize = 8 * 1024;

/// The HTTP/2 connection preface a prior-knowledge client opens with.
pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A parsed request: head plus the whole (capped) body.
#[derive(Debug)]
pub(crate) struct Request {
    pub method: String,
    /// Path and query, `/` when the target carries none (as `OPTIONS *`).
    pub url: String,
    /// `0` for HTTP/1.0, `1` for HTTP/1.1.
    pub minor: u8,
    /// Header names lowercased; a value that is not visible ASCII is empty.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first value of header `name` (lowercase).
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Whether the connection stays open after this request's response.
    pub(crate) fn keep_alive(&self) -> bool {
        let tokens = self.header("connection").unwrap_or("");
        let has = |t: &str| tokens.split(',').any(|x| x.trim().eq_ignore_ascii_case(t));
        if self.minor == 0 {
            has("keep-alive")
        } else {
            !has("close")
        }
    }
}

/// Why a request could not be read.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// The transport failed or ended mid-request: the connection ends.
    Io,
    /// The request is refused with this status and one-line reason.
    Reject(u16, &'static str),
}

impl From<io::Error> for ReadError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

/// One HTTP/1.1 connection: the transport plus the bytes read ahead.
pub(crate) struct Conn<IO> {
    io: IO,
    buf: Vec<u8>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Conn<IO> {
    pub(crate) fn new(io: IO) -> Self {
        Self {
            io,
            buf: Vec::new(),
        }
    }

    /// The transport and the bytes read ahead and not yet consumed.
    pub(crate) fn into_parts(self) -> (IO, Vec<u8>) {
        (self.io, self.buf)
    }

    /// Reads more bytes into the lookahead; `0` is the end of the stream.
    async fn fill(&mut self) -> io::Result<usize> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        match self.io.read(&mut self.buf[start..]).await {
            Ok(n) => {
                self.buf.truncate(start + n);
                Ok(n)
            }
            Err(e) => {
                self.buf.truncate(start);
                Err(e)
            }
        }
    }

    /// Reads until the lookahead holds at least `n` bytes.
    async fn need(&mut self, n: usize) -> Result<(), ReadError> {
        while self.buf.len() < n {
            if self.fill().await? == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        }
        Ok(())
    }

    /// Whether the peer opens with the HTTP/2 prior-knowledge preface. Reads
    /// just enough to decide; the bytes stay in the lookahead.
    pub(crate) async fn sniff_h2(&mut self) -> io::Result<bool> {
        loop {
            if self.buf.len() >= H2_PREFACE.len() {
                return Ok(self.buf.starts_with(H2_PREFACE));
            }
            if !self.buf.is_empty() && !H2_PREFACE.starts_with(&self.buf) {
                return Ok(false);
            }
            if self.fill().await? == 0 {
                return Ok(false);
            }
        }
    }

    /// Reads one line (without its CRLF) of at most `limit` bytes.
    async fn read_line(&mut self, limit: usize, over: (u16, &'static str)) -> Result<Vec<u8>, ReadError> {
        let mut from = 0;
        loop {
            if let Some(i) = self.buf[from..].windows(2).position(|w| w == b"\r\n") {
                let end = from + i;
                let line = self.buf[..end].to_vec();
                self.buf.drain(..end + 2);
                return Ok(line);
            }
            if self.buf.len() > limit {
                return Err(ReadError::Reject(over.0, over.1));
            }
            from = self.buf.len().saturating_sub(1);
            if self.fill().await? == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        }
    }

    /// Reads the next request, or `None` when the peer closed between requests.
    /// `max_body` caps the body; a larger one is rejected with 413 before it is read.
    pub(crate) async fn read_request(&mut self, max_body: usize) -> Result<Option<Request>, ReadError> {
        let mut head = loop {
            let mut raw = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut parsed = httparse::Request::new(&mut raw);
            match parsed.parse(&self.buf) {
                Ok(httparse::Status::Complete(n)) => {
                    let head = Request {
                        method: parsed.method.unwrap_or("GET").to_owned(),
                        url: target_url(parsed.path.unwrap_or("/"))?,
                        minor: parsed.version.unwrap_or(1) as u8,
                        headers: parsed
                            .headers
                            .iter()
                            .map(|h| (h.name.to_ascii_lowercase(), header_text(h.value)))
                            .collect(),
                        body: Vec::new(),
                    };
                    self.buf.drain(..n);
                    break head;
                }
                Ok(httparse::Status::Partial) => {
                    if self.buf.len() >= MAX_HEAD {
                        return Err(ReadError::Reject(431, "burn: request header too large"));
                    }
                }
                Err(httparse::Error::TooManyHeaders) => {
                    return Err(ReadError::Reject(431, "burn: too many request headers"));
                }
                Err(_) => return Err(ReadError::Reject(400, "burn: malformed request")),
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
                };
            }
        };

        let transfer = head.header("transfer-encoding").map(str::to_owned);
        let lengths: Vec<&str> = head
            .headers
            .iter()
            .filter(|(k, _)| k == "content-length")
            .map(|(_, v)| v.as_str())
            .collect();
        if transfer.is_some() && !lengths.is_empty() {
            return Err(ReadError::Reject(400, "burn: conflicting message framing"));
        }
        let expects_continue = head
            .header("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
            && head.minor == 1;

        if let Some(te) = transfer {
            if !te.eq_ignore_ascii_case("chunked") {
                return Err(ReadError::Reject(501, "burn: unsupported transfer encoding"));
            }
            if expects_continue {
                self.io.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            }
            head.body = self.read_chunked(max_body).await?;
        } else if let Some(first) = lengths.first() {
            let len = parse_length(first)?;
            if lengths.iter().any(|v| parse_length(v).ok() != Some(len)) {
                return Err(ReadError::Reject(400, "burn: conflicting content-length"));
            }
            if len > max_body {
                return Err(ReadError::Reject(413, "burn: request body too large"));
            }
            if len > 0 {
                if expects_continue && self.buf.len() < len {
                    self.io.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                }
                self.need(len).await?;
                head.body = self.buf.drain(..len).collect();
            }
        }
        Ok(Some(head))
    }

    async fn read_chunked(&mut self, max_body: usize) -> Result<Vec<u8>, ReadError> {
        let mut body = Vec::new();
        loop {
            let line = self
                .read_line(MAX_CHUNK_LINE, (400, "burn: malformed chunk"))
                .await?;
            let size_text = line.split(|b| *b == b';').next().unwrap_or(&[]);
            if size_text.is_empty() || !size_text.iter().all(u8::is_ascii_hexdigit) {
                return Err(ReadError::Reject(400, "burn: malformed chunk size"));
            }
            let size = std::str::from_utf8(size_text)
                .ok()
                .and_then(|s| usize::from_str_radix(s, 16).ok())
                .ok_or(ReadError::Reject(400, "burn: malformed chunk size"))?;
            if size == 0 {
                loop {
                    let trailer = self
                        .read_line(MAX_TRAILERS, (431, "burn: request trailers too large"))
                        .await?;
                    if trailer.is_empty() {
                        return Ok(body);
                    }
                }
            }
            match body.len().checked_add(size) {
                Some(total) if total <= max_body => {}
                _ => return Err(ReadError::Reject(413, "burn: request body too large")),
            }
            self.need(size + 2).await?;
            if &self.buf[size..size + 2] != b"\r\n" {
                return Err(ReadError::Reject(400, "burn: malformed chunk"));
            }
            body.extend_from_slice(&self.buf[..size]);
            self.buf.drain(..size + 2);
        }
    }

    /// Writes `resp` in one write. The body is sent with an exact
    /// `content-length` (never for `head_only`, 1xx, 204 and 304 responses);
    /// `connection` and `transfer-encoding` headers of the handler are dropped
    /// because this layer owns the framing.
    pub(crate) async fn write_response(
        &mut self,
        resp: &Response<Vec<u8>>,
        minor: u8,
        head_only: bool,
        keep_alive: bool,
    ) -> io::Result<()> {
        let status = resp.status();
        let bodyless = status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED;
        let mut out = Vec::with_capacity(256 + resp.body().len());
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(status.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
        out.extend_from_slice(b"\r\n");
        let mut has_date = false;
        for (name, value) in resp.headers() {
            match name.as_str() {
                "content-length" | "transfer-encoding" | "connection" => continue,
                "date" => has_date = true,
                _ => {}
            }
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if !has_date {
            out.extend_from_slice(b"date: ");
            out.extend_from_slice(httpdate::fmt_http_date(SystemTime::now()).as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if !bodyless {
            out.extend_from_slice(b"content-length: ");
            out.extend_from_slice(resp.body().len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if !keep_alive {
            out.extend_from_slice(b"connection: close\r\n");
        } else if minor == 0 {
            out.extend_from_slice(b"connection: keep-alive\r\n");
        }
        out.extend_from_slice(b"\r\n");
        if !bodyless && !head_only {
            out.extend_from_slice(resp.body());
        }
        self.io.write_all(&out).await?;
        self.io.flush().await
    }

    /// Writes pre-framed bytes (an upgrade's `101` response) and flushes.
    pub(crate) async fn write_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.io.write_all(bytes).await?;
        self.io.flush().await
    }

    /// Answers a rejected request and leaves the connection to be closed.
    pub(crate) async fn write_reject(&mut self, status: u16, reason: &str) -> io::Result<()> {
        let resp = text_response(status, reason);
        self.write_response(&resp, 1, false, false).await
    }
}

/// A plain-text response with the given status (500 when `status` is invalid).
pub(crate) fn text_response(status: u16, body: &str) -> Response<Vec<u8>> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = Response::new(body.as_bytes().to_vec());
    *resp.status_mut() = status;
    resp
}

/// The path and query of a request target, or a 400 for a target that is no URI.
fn target_url(target: &str) -> Result<String, ReadError> {
    let uri: http::Uri = target
        .parse()
        .map_err(|_| ReadError::Reject(400, "burn: malformed request target"))?;
    Ok(uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".into()))
}

/// A header value as text; empty when it is not visible ASCII.
fn header_text(value: &[u8]) -> String {
    http::HeaderValue::from_bytes(value)
        .ok()
        .and_then(|v| v.to_str().ok().map(str::to_owned))
        .unwrap_or_default()
}

/// A `content-length` value: ASCII digits only.
fn parse_length(text: &str) -> Result<usize, ReadError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ReadError::Reject(400, "burn: malformed content-length"));
    }
    text.parse()
        .map_err(|_| ReadError::Reject(413, "burn: request body too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nuclei::io::duplex;

    async fn read_one(raw: &[u8], max_body: usize) -> Result<Option<Request>, ReadError> {
        let (mut client, server) = duplex(1 << 20);
        client.write_all(raw).await.expect("write request");
        drop(client);
        Conn::new(server).read_request(max_body).await
    }

    #[nuclei::test]
    async fn parses_a_get_with_headers() {
        let req = read_one(b"GET /a/b?x=1 HTTP/1.1\r\nHost: h\r\nX-Y: z\r\n\r\n", 1024)
            .await
            .expect("parse")
            .expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "/a/b?x=1");
        assert_eq!(req.header("x-y"), Some("z"));
        assert!(req.body.is_empty());
        assert!(req.keep_alive());
    }

    #[nuclei::test]
    async fn reads_a_content_length_body() {
        let req = read_one(
            b"POST /p HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello",
            1024,
        )
        .await
        .expect("parse")
        .expect("request");
        assert_eq!(req.body, b"hello");
    }

    #[nuclei::test]
    async fn decodes_a_chunked_body() {
        let req = read_one(
            b"POST /p HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\nx: y\r\n\r\n",
            1024,
        )
        .await
        .expect("parse")
        .expect("request");
        assert_eq!(req.body, b"abcde");
    }

    #[nuclei::test]
    async fn rejects_an_oversized_body_before_reading_it() {
        let err = read_one(b"POST /p HTTP/1.1\r\ncontent-length: 2000\r\n\r\n", 1000)
            .await
            .expect_err("too large");
        assert!(matches!(err, ReadError::Reject(413, _)));
    }

    #[nuclei::test]
    async fn rejects_an_oversized_chunked_body() {
        let err = read_one(
            b"POST /p HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n",
            8,
        )
        .await
        .expect_err("too large");
        assert!(matches!(err, ReadError::Reject(413, _)));
    }

    #[nuclei::test]
    async fn rejects_conflicting_framing() {
        let err = read_one(
            b"POST /p HTTP/1.1\r\ncontent-length: 3\r\ntransfer-encoding: chunked\r\n\r\n",
            1024,
        )
        .await
        .expect_err("smuggling");
        assert!(matches!(err, ReadError::Reject(400, _)));
    }

    #[nuclei::test]
    async fn rejects_a_malformed_chunk_size_and_content_length() {
        let err = read_one(
            b"POST /p HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n",
            1024,
        )
        .await
        .expect_err("bad size");
        assert!(matches!(err, ReadError::Reject(400, _)));
        let err = read_one(b"POST /p HTTP/1.1\r\ncontent-length: +4\r\n\r\n", 1024)
            .await
            .expect_err("bad length");
        assert!(matches!(err, ReadError::Reject(400, _)));
    }

    #[nuclei::test]
    async fn rejects_a_head_larger_than_the_cap() {
        let mut raw = b"GET / HTTP/1.1\r\nx: ".to_vec();
        raw.extend(vec![b'a'; MAX_HEAD + 1]);
        let err = read_one(&raw, 1024).await.expect_err("head too large");
        assert!(matches!(err, ReadError::Reject(431, _)));
    }

    #[nuclei::test]
    async fn serves_pipelined_requests_and_a_clean_close() {
        let (mut client, server) = duplex(1 << 20);
        client
            .write_all(b"GET /1 HTTP/1.1\r\n\r\nGET /2 HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        drop(client);
        let mut conn = Conn::new(server);
        let first = conn.read_request(1024).await.expect("first").expect("some");
        let second = conn.read_request(1024).await.expect("second").expect("some");
        assert_eq!((first.url.as_str(), second.url.as_str()), ("/1", "/2"));
        assert!(first.keep_alive());
        assert!(!second.keep_alive());
        assert!(conn.read_request(1024).await.expect("eof").is_none());
    }

    #[nuclei::test]
    async fn sniffs_the_http2_preface_only() {
        let (mut client, server) = duplex(4096);
        client.write_all(H2_PREFACE).await.expect("write");
        assert!(Conn::new(server).sniff_h2().await.expect("sniff"));
        let (mut client, server) = duplex(4096);
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.expect("write");
        assert!(!Conn::new(server).sniff_h2().await.expect("sniff"));
    }

    #[nuclei::test]
    async fn writes_exact_framing() {
        let (client, server) = duplex(4096);
        let mut conn = Conn::new(server);
        let mut resp = text_response(200, "hello");
        resp.headers_mut().insert("content-length", "99".parse().expect("value"));
        resp.headers_mut().insert("x-k", "v".parse().expect("value"));
        conn.write_response(&resp, 1, false, false).await.expect("write");
        drop(conn);
        let mut text = String::new();
        let mut client = client;
        client.read_to_string(&mut text).await.expect("read");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("x-k: v\r\n"));
        assert!(text.contains("content-length: 5\r\n"));
        assert!(!text.contains("99"));
        assert!(text.contains("connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[nuclei::test]
    async fn head_responses_carry_no_body() {
        let (client, server) = duplex(4096);
        let mut conn = Conn::new(server);
        conn.write_response(&text_response(200, "hello"), 1, true, true)
            .await
            .expect("write");
        drop(conn);
        let mut text = String::new();
        let mut client = client;
        client.read_to_string(&mut text).await.expect("read");
        assert!(text.contains("content-length: 5\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }
}
