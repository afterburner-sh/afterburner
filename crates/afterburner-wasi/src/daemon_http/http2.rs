// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! HTTP/2 prior-knowledge serving on a nuclei stream, through the `h2` crate's
//! protocol engine over the stream's own `AsyncRead` / `AsyncWrite`.
//! [`Replay`] hands the engine the bytes the protocol sniff already read before
//! the stream's.
//!
//! Invariants: at most [`MAX_STREAMS`] concurrent streams per connection, a
//! header list of at most `h1::MAX_HEAD` bytes, a body of at most
//! `h1::MAX_BODY`; the connection is polled by the accept loop for as long as
//! it is open, which is what drives every stream's IO.

use super::h1::{MAX_BODY, MAX_HEAD};
use super::{ServerState, dispatch};
use bytes::Bytes;
use http::{Response, StatusCode};
use nuclei::io::{AsyncRead, AsyncWrite};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Most concurrent streams one connection may open.
const MAX_STREAMS: u32 = 200;

/// A nuclei stream that reads the already-read-ahead bytes first.
struct Replay<IO> {
    io: IO,
    ahead: Vec<u8>,
    pos: usize,
}

impl<IO: AsyncRead + Unpin> AsyncRead for Replay<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pos < this.ahead.len() {
            let n = buf.len().min(this.ahead.len() - this.pos);
            buf[..n].copy_from_slice(&this.ahead[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(n));
        }
        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Replay<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_close(cx)
    }
}

/// Serves one HTTP/2 connection whose first `ahead` bytes were already read.
pub(super) async fn serve<IO>(io: IO, ahead: Vec<u8>, state: Arc<ServerState>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = Replay { io, ahead, pos: 0 };
    let mut conn = match h2::server::Builder::new()
        .max_concurrent_streams(MAX_STREAMS)
        .max_header_list_size(MAX_HEAD as u32)
        .handshake::<_, Bytes>(io)
        .await
    {
        Ok(c) => c,
        Err(_) => return,
    };
    while let Some(next) = conn.accept().await {
        let Ok((request, respond)) = next else {
            break;
        };
        let state = Arc::clone(&state);
        nuclei::spawn(serve_stream(request, respond, state)).detach();
    }
}

async fn serve_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: Arc<ServerState>,
) {
    let (parts, mut body) = request.into_parts();
    let method = parts.method.to_string();
    let url = parts
        .uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".into());
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        if payload.len() + chunk.len() > MAX_BODY {
            send(
                &mut respond,
                super::h1::text_response(413, "burn: request body too large"),
            );
            return;
        }
        payload.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(chunk.len());
    }

    let response = dispatch(&state, method, url, headers, payload).await;
    send(&mut respond, response);
}

/// Sends `response` on the stream: headers, then the whole body with the stream's end.
fn send(respond: &mut h2::server::SendResponse<Bytes>, response: Response<Vec<u8>>) {
    let (mut head, body) = response.into_parts();
    // Connection-specific headers are malformed in HTTP/2.
    for name in [
        "connection",
        "transfer-encoding",
        "keep-alive",
        "proxy-connection",
        "upgrade",
        "content-length",
    ] {
        head.headers.remove(name);
    }
    let bodyless = head.status.is_informational()
        || head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED;
    if !bodyless {
        head.headers
            .insert("content-length", http::HeaderValue::from(body.len()));
    }
    let end = body.is_empty() || bodyless;
    let Ok(mut stream) = respond.send_response(Response::from_parts(head, ()), end) else {
        return;
    };
    if !end {
        let _ = stream.send_data(Bytes::from(body), true);
    }
}
