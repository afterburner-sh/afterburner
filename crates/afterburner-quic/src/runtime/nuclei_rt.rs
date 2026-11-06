//! The [`Runtime`] on nuclei: timers on the shard wheel, background tasks on the runtime
//! handle, and UDP sockets driven through `quinn-udp` by the socket's own readiness.
//!
//! Invariant: every task, timer and socket quinn creates lives on the one runtime handle
//! given to [`NucleiRuntime::new`].

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use nuclei::io::Interest;
use nuclei::net::UdpSocket;
use nuclei::runtime::RuntimeHandle;
use nuclei::time::Sleep;
use udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller};
use crate::Instant;

/// The QUIC runtime backed by one nuclei runtime.
#[derive(Debug)]
pub struct NucleiRuntime {
    handle: RuntimeHandle,
}

impl NucleiRuntime {
    /// A runtime that places every task, timer and socket on `handle`
    pub fn new(handle: RuntimeHandle) -> Arc<Self> {
        Arc::new(Self { handle })
    }
}

impl Runtime for NucleiRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(Timer(nuclei::time::sleep_until(t)))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.handle.spawn(future).detach();
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = UdpSocketState::new(UdpSockRef::from(&sock))?;
        let _enter = self.handle.enter();
        let io = UdpSocket::new(sock)?;
        Ok(Arc::new(Socket { io, inner }))
    }
}

struct Timer(Sleep);

impl fmt::Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl AsyncTimer for Timer {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Pin::new(&mut self.get_mut().0).reset(t);
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

struct Socket {
    io: UdpSocket,
    inner: UdpSocketState,
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller(self))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send(UdpSockRef::from(&self.io), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(n) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv(UdpSockRef::from(&self.io), bufs, meta)
            }) {
                return Poll::Ready(Ok(n));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

/// Write-readiness for one task. The socket's write side keeps one waker, so a
/// stalled sender that loses it to another recovers on its next timer or packet.
// vertexia: single write waker per socket, a Notify fan-out if senders stall under load
#[derive(Debug)]
struct Poller(Arc<Socket>);

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}
