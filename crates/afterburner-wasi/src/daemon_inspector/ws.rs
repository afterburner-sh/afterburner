// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! RFC 6455 server side of the inspector's WebSocket: the opening
//! handshake's accept key, and a framed message stream over a nuclei byte
//! stream (text, binary, ping, pong, close, fragmentation, client masking).
//!
//! Invariants: every client frame is masked and carries no reserved bits; a
//! message is at most [`MAX_MESSAGE`] bytes; all state between reads lives in
//! the struct, so a read future may be dropped (a `select!` arm losing) and
//! restarted without losing a byte.

use base64::Engine as _;
use nuclei::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use sha1::{Digest, Sha1};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;

/// Largest accepted client message (after reassembling fragments).
pub(super) const MAX_MESSAGE: usize = 16 * 1024 * 1024;
const READ_CHUNK: usize = 16 * 1024;
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The `Sec-WebSocket-Accept` value answering the client's `key`.
pub(super) fn accept_key(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sha.finalize())
}

/// One reassembled message or control frame from the client.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    /// The client's close frame payload (status code and reason, possibly empty).
    Close(Vec<u8>),
}

/// One complete frame with its payload unmasked, and the bytes it took.
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    used: usize,
}

/// A WebSocket over `IO`, after the HTTP upgrade completed.
pub(super) struct Ws<IO> {
    io: IO,
    buf: Vec<u8>,
    /// A fragmented message in progress: its first opcode and the bytes so far.
    partial: Option<(u8, Vec<u8>)>,
}

fn bad(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Ws<IO> {
    /// Wraps the stream; `ahead` holds bytes already read past the HTTP request.
    pub(super) fn new(io: IO, ahead: Vec<u8>) -> Self {
        Self {
            io,
            buf: ahead,
            partial: None,
        }
    }

    /// Reads once into the lookahead; `0` is the end of the stream. Cancel-safe:
    /// the buffer is back to its length before every suspension.
    async fn fill(&mut self) -> io::Result<usize> {
        let start = self.buf.len();
        poll_fn(|cx| {
            self.buf.resize(start + READ_CHUNK, 0);
            let polled = Pin::new(&mut self.io).poll_read(cx, &mut self.buf[start..]);
            let got = match &polled {
                Poll::Ready(Ok(n)) => *n,
                _ => 0,
            };
            self.buf.truncate(start + got);
            polled
        })
        .await
    }

    /// The next message, or `Close` when the stream ends. Cancel-safe.
    pub(super) async fn next(&mut self) -> io::Result<Message> {
        loop {
            if let Some(message) = self.parse()? {
                return Ok(message);
            }
            if self.fill().await? == 0 {
                return Ok(Message::Close(Vec::new()));
            }
        }
    }

    /// Consumes buffered frames until one completes a message.
    fn parse(&mut self) -> io::Result<Option<Message>> {
        loop {
            let Some(Frame {
                fin,
                opcode,
                payload,
                used,
            }) = self.frame()?
            else {
                return Ok(None);
            };
            self.buf.drain(..used);
            match opcode {
                0x0 => {
                    let Some((first, mut data)) = self.partial.take() else {
                        return Err(bad("unexpected continuation frame"));
                    };
                    if data.len() + payload.len() > MAX_MESSAGE {
                        return Err(bad("message too large"));
                    }
                    data.extend_from_slice(&payload);
                    if fin {
                        return finish(first, data).map(Some);
                    }
                    self.partial = Some((first, data));
                }
                0x1 | 0x2 => {
                    if self.partial.is_some() {
                        return Err(bad("data frame inside a fragmented message"));
                    }
                    if fin {
                        return finish(opcode, payload).map(Some);
                    }
                    self.partial = Some((opcode, payload));
                }
                0x8 => return Ok(Some(Message::Close(payload))),
                0x9 => return Ok(Some(Message::Ping(payload))),
                0xA => return Ok(Some(Message::Pong)),
                _ => return Err(bad("unknown opcode")),
            }
        }
    }

    /// The first complete frame in the lookahead.
    fn frame(&self) -> io::Result<Option<Frame>> {
        let b = &self.buf;
        if b.len() < 2 {
            return Ok(None);
        }
        if b[0] & 0x70 != 0 {
            return Err(bad("reserved bits set"));
        }
        if b[1] & 0x80 == 0 {
            return Err(bad("unmasked client frame"));
        }
        let (fin, opcode) = (b[0] & 0x80 != 0, b[0] & 0x0f);
        let (len, mut at) = match b[1] & 0x7f {
            126 if b.len() >= 4 => (usize::from(u16::from_be_bytes([b[2], b[3]])), 4),
            127 if b.len() >= 10 => {
                let mut eight = [0u8; 8];
                eight.copy_from_slice(&b[2..10]);
                (
                    usize::try_from(u64::from_be_bytes(eight))
                        .map_err(|_| bad("frame too large"))?,
                    10,
                )
            }
            126 | 127 => return Ok(None),
            n => (usize::from(n), 2),
        };
        if len > MAX_MESSAGE {
            return Err(bad("frame too large"));
        }
        if opcode >= 0x8 && (!fin || len > 125) {
            return Err(bad("malformed control frame"));
        }
        if b.len() < at + 4 + len {
            return Ok(None);
        }
        let mask = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        at += 4;
        let payload = b[at..at + len]
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ mask[i % 4])
            .collect();
        Ok(Some(Frame {
            fin,
            opcode,
            payload,
            used: at + len,
        }))
    }

    /// Sends a text message.
    pub(super) async fn send_text(&mut self, text: &str) -> io::Result<()> {
        self.send(0x1, text.as_bytes()).await
    }

    /// Answers a ping with a pong carrying the same payload.
    pub(super) async fn send_pong(&mut self, payload: &[u8]) -> io::Result<()> {
        self.send(0xA, payload).await
    }

    /// Sends a close frame with `payload` (a status code, possibly empty) and flushes.
    pub(super) async fn send_close(&mut self, payload: &[u8]) -> io::Result<()> {
        self.send(0x8, &payload[..payload.len().min(125)]).await
    }

    async fn send(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(10 + payload.len());
        out.push(0x80 | opcode);
        match payload.len() {
            n if n < 126 => out.push(n as u8),
            n if n <= usize::from(u16::MAX) => {
                out.push(126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        self.io.write_all(&out).await?;
        self.io.flush().await
    }
}

/// A completed data message of the given first opcode.
fn finish(opcode: u8, data: Vec<u8>) -> io::Result<Message> {
    if opcode == 0x1 {
        String::from_utf8(data)
            .map(Message::Text)
            .map_err(|_| bad("invalid utf-8 in text message"))
    } else {
        Ok(Message::Binary(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nuclei::io::duplex;

    /// A masked client frame.
    fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        let mut out = vec![first];
        match payload.len() {
            n if n < 126 => out.push(0x80 | n as u8),
            n => {
                out.push(0x80 | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        out
    }

    async fn ws_with(bytes: &[u8]) -> Ws<nuclei::io::DuplexStream> {
        let (mut client, server) = duplex(1 << 20);
        client.write_all(bytes).await.expect("write");
        drop(client);
        Ws::new(server, Vec::new())
    }

    #[test]
    fn accept_key_matches_the_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[nuclei::test]
    async fn reads_text_ping_and_close() {
        let mut bytes = client_frame(0x81, b"{\"id\":1}");
        bytes.extend(client_frame(0x89, b"hi"));
        bytes.extend(client_frame(0x88, &[3, 232]));
        let mut ws = ws_with(&bytes).await;
        assert_eq!(
            ws.next().await.expect("text"),
            Message::Text("{\"id\":1}".into())
        );
        assert_eq!(
            ws.next().await.expect("ping"),
            Message::Ping(b"hi".to_vec())
        );
        assert_eq!(
            ws.next().await.expect("close"),
            Message::Close(vec![3, 232])
        );
    }

    #[nuclei::test]
    async fn reassembles_fragments_and_long_frames() {
        let long = vec![b'a'; 300];
        let mut bytes = client_frame(0x01, b"ab");
        bytes.extend(client_frame(0x00, b"cd"));
        bytes.extend(client_frame(0x80, b"ef"));
        bytes.extend(client_frame(0x81, &long));
        let mut ws = ws_with(&bytes).await;
        assert_eq!(
            ws.next().await.expect("joined"),
            Message::Text("abcdef".into())
        );
        assert_eq!(
            ws.next().await.expect("long"),
            Message::Text(String::from_utf8(long).expect("ascii"))
        );
        assert_eq!(ws.next().await.expect("eof"), Message::Close(Vec::new()));
    }

    #[nuclei::test]
    async fn rejects_unmasked_and_malformed_frames() {
        let mut ws = ws_with(&[0x81, 0x02, b'h', b'i']).await;
        assert!(ws.next().await.is_err());
        let mut ws = ws_with(&client_frame(0xC1, b"x")).await;
        assert!(ws.next().await.is_err());
        let mut ws = ws_with(&client_frame(0x00, b"x")).await;
        assert!(ws.next().await.is_err());
        let mut ws = ws_with(&client_frame(0x81, &[0xff, 0xfe])).await;
        assert!(ws.next().await.is_err());
    }

    #[nuclei::test]
    async fn writes_unmasked_frames_with_extended_lengths() {
        let (mut client, server) = duplex(1 << 20);
        let mut ws = Ws::new(server, Vec::new());
        ws.send_text("hi").await.expect("short");
        let long = "x".repeat(200);
        ws.send_text(&long).await.expect("long");
        ws.send_close(&[3, 232]).await.expect("close");
        drop(ws);
        let mut all = Vec::new();
        nuclei::io::AsyncReadExt::read_to_end(&mut client, &mut all)
            .await
            .expect("read");
        assert_eq!(&all[..4], &[0x81, 2, b'h', b'i']);
        assert_eq!(&all[4..8], &[0x81, 126, 0, 200]);
        assert_eq!(&all[8 + 200..], &[0x88, 2, 3, 232]);
    }
}
