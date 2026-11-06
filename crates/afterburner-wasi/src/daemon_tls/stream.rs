// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! rustls over a nuclei stream: the client and server handshakes and an
//! `AsyncRead` / `AsyncWrite` TLS stream, driven by polling the sans-IO
//! `rustls::ConnectionCommon` against any `futures-io` transport.
//!
//! Invariants: a transport read or write that is not ready surfaces as
//! `WouldBlock` to rustls and as `Poll::Pending` to the caller (the transport
//! has registered the waker); alerts rustls queues on a protocol error are
//! flushed best-effort before the error is returned.

use rustls::pki_types::ServerName;
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, ServerConfig, ServerConnection, SideData,
};
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use nuclei::io::{AsyncRead, AsyncWrite};

/// A TLS client stream over `IO`.
pub type ClientTlsStream<IO> = TlsStream<IO, ClientConnection>;
/// A TLS server stream over `IO`.
pub type ServerTlsStream<IO> = TlsStream<IO, ServerConnection>;

/// A TLS session `C` (client or server connection) running over the transport `IO`.
pub struct TlsStream<IO, C> {
    io: IO,
    conn: C,
    sent_close: bool,
}

/// The sync `Read` / `Write` view rustls drives, bound to one poll context.
struct SyncIo<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}

impl<IO: AsyncRead + Unpin> Read for SyncIo<'_, '_, IO> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_read(self.cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<IO: AsyncWrite + Unpin> Write for SyncIo<'_, '_, IO> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.io).poll_flush(self.cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<IO, C> TlsStream<IO, C> {
    fn new(io: IO, conn: C) -> Self {
        Self {
            io,
            conn,
            sent_close: false,
        }
    }

    /// The transport and the rustls connection behind the stream.
    pub fn get_ref(&self) -> (&IO, &C) {
        (&self.io, &self.conn)
    }
}

impl<IO, C, SD> TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    /// Moves every byte rustls has queued to the transport.
    fn poll_write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.wants_write() {
            let mut sync = SyncIo {
                io: &mut self.io,
                cx,
            };
            match self.conn.write_tls(&mut sync) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Reads once from the transport into rustls; `Ok(0)` is the transport's end.
    fn poll_read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut sync = SyncIo {
            io: &mut self.io,
            cx,
        };
        match self.conn.read_tls(&mut sync) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Runs rustls over the bytes read; on a protocol error the queued alert is
    /// sent best-effort and the error returned as `InvalidData`.
    fn process(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.conn.process_new_packets() {
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = self.poll_write_tls(cx);
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            ready!(self.poll_write_tls(cx))?;
            if !self.conn.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.poll_read_tls(cx))? {
                0 => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls handshake eof",
                    )));
                }
                _ => self.process(cx)?,
            }
        }
    }
}

impl<IO, C, SD> AsyncRead for TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut transport_eof = false;
        loop {
            match this.conn.reader().read(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            if transport_eof {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            // Key updates and alerts rustls queued go out before waiting for more input.
            if let Poll::Ready(Err(e)) = this.poll_write_tls(cx) {
                return Poll::Ready(Err(e));
            }
            match ready!(this.poll_read_tls(cx))? {
                0 => transport_eof = true,
                _ => this.process(cx)?,
            }
        }
    }
}

impl<IO, C, SD> AsyncWrite for TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut written = 0;
        loop {
            if written == 0 {
                written = this.conn.writer().write(buf)?;
            }
            match this.poll_write_tls(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) if written > 0 => return Poll::Ready(Ok(written)),
                Poll::Ready(Ok(())) => {}
                Poll::Pending if written > 0 => return Poll::Ready(Ok(written)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.writer().flush()?;
        ready!(this.poll_write_tls(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.sent_close {
            this.conn.send_close_notify();
            this.sent_close = true;
        }
        ready!(this.poll_write_tls(cx))?;
        Pin::new(&mut this.io).poll_close(cx)
    }
}

/// Starts TLS client handshakes with one shared `ClientConfig`.
#[derive(Clone)]
pub struct TlsConnector {
    config: Arc<ClientConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl TlsConnector {
    /// Runs the client handshake for `name` over `io`.
    pub async fn connect<IO>(
        &self,
        name: ServerName<'static>,
        io: IO,
    ) -> io::Result<ClientTlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let conn = ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut stream = TlsStream::new(io, conn);
        poll_fn(|cx| stream.poll_handshake(cx)).await?;
        Ok(stream)
    }
}

/// Accepts TLS server handshakes with one shared `ServerConfig`.
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

impl TlsAcceptor {
    /// Runs the server handshake over `io`.
    pub async fn accept<IO>(&self, io: IO) -> io::Result<ServerTlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let conn = ServerConnection::new(Arc::clone(&self.config))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut stream = TlsStream::new(io, conn);
        poll_fn(|cx| stream.poll_handshake(cx)).await?;
        Ok(stream)
    }
}
