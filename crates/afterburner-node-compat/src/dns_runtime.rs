// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! hickory's `RuntimeProvider` on nuclei: UDP and TCP sockets, timers and
//! background tasks all run on the nuclei runtime, so the resolver needs
//! no other async runtime.

use async_trait::async_trait;
use hickory_resolver::net::runtime::{DnsTcpStream, DnsUdpSocket, RuntimeProvider, Spawn, Time};
use nuclei::io::{AsyncRead, AsyncWrite, ReadBuf};
use nuclei::net::{TcpSocket, TcpStream, UdpSocket};
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Connect timeout when the resolver passes none (hickory's own default).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The nuclei runtime as hickory's provider of sockets, timers and tasks.
#[derive(Clone, Copy, Default)]
pub struct NucleiRuntimeProvider;

/// Spawns resolver background tasks on the nuclei runtime.
#[derive(Clone, Copy, Default)]
pub struct NucleiHandle;

impl Spawn for NucleiHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        nuclei::spawn(future).detach();
    }
}

/// Timers on nuclei's timer wheel.
#[derive(Clone, Copy, Debug)]
pub struct NucleiTime;

#[async_trait]
impl Time for NucleiTime {
    async fn delay_for(duration: Duration) {
        nuclei::sleep(duration).await
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> Result<F::Output, io::Error> {
        nuclei::timeout(duration, future)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "future timed out"))
    }
}

/// A nuclei UDP socket as a DNS socket.
pub struct NucleiUdp(UdpSocket);

#[async_trait]
impl DnsUdpSocket for NucleiUdp {
    type Time = NucleiTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut read = ReadBuf::new(buf);
        let from = std::task::ready!(self.0.poll_recv_from(cx, &mut read))?;
        Poll::Ready(Ok((read.filled().len(), from)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.0.poll_send_to(cx, buf, target)
    }
}

/// A nuclei TCP stream as a DNS stream.
pub struct NucleiTcp(TcpStream);

impl DnsTcpStream for NucleiTcp {
    type Time = NucleiTime;
}

impl AsyncRead for NucleiTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NucleiTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl RuntimeProvider for NucleiRuntimeProvider {
    type Handle = NucleiHandle;
    type Timer = NucleiTime;
    type Udp = NucleiUdp;
    type Tcp = NucleiTcp;

    fn create_handle(&self) -> Self::Handle {
        NucleiHandle
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;
            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }
            socket.set_nodelay(true)?;
            let wait_for = wait_for.unwrap_or(CONNECT_TIMEOUT);
            match nuclei::timeout(wait_for, socket.connect(server_addr)).await {
                Ok(stream) => stream.map(NucleiTcp),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP connect timed out",
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        Box::pin(async move { UdpSocket::bind(local_addr).await.map(NucleiUdp) })
    }
}
