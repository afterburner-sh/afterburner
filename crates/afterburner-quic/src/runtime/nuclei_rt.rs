//! The [`Runtime`] on nuclei: timers on the shard wheel, background tasks on the runtime
//! handle, and UDP sockets.
//!
//! On unix a socket is an [`AsyncFd`]: nuclei only says when it may be ready, and every
//! datagram moves through `quinn-udp`'s own calls (GSO, GRO, ECN, the destination address).
//! A nuclei socket would not do: its driver reads ahead into its own buffers, so a call of
//! the caller's own finds the kernel queue empty while the driver holds the datagram. On
//! Windows, where nuclei completes every operation itself, the socket is nuclei's and moves
//! one datagram per call.
//!
//! Invariant: every task, timer and socket quinn creates lives on the one runtime handle
//! given to [`NucleiRuntime::new`].

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

#[cfg(unix)]
use nuclei::io::unix::AsyncFd;
#[cfg(unix)]
use nuclei::io::Interest;
use nuclei::runtime::RuntimeHandle;
use nuclei::time::Sleep;
use udp::{RecvMeta, Transmit};
#[cfg(unix)]
use udp::{UdpSockRef, UdpSocketState};

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
        let _enter = self.handle.enter();
        Ok(Arc::new(Socket::new(sock)?))
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

#[cfg(unix)]
struct Socket {
    io: AsyncFd<std::net::UdpSocket>,
    inner: UdpSocketState,
}

#[cfg(unix)]
impl Socket {
    fn new(sock: std::net::UdpSocket) -> io::Result<Self> {
        // `UdpSocketState::new` makes the socket non-blocking, as `AsyncFd` needs it.
        let inner = UdpSocketState::new(UdpSockRef::from(&sock))?;
        Ok(Self {
            io: AsyncFd::new(sock)?,
            inner,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, |sock| {
            self.inner.send(UdpSockRef::from(sock), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.io.poll_read_ready(cx))?;
            if let Ok(result) =
                guard.try_io(|fd| self.inner.recv(UdpSockRef::from(fd.get_ref()), bufs, meta))
            {
                return Poll::Ready(result);
            }
        }
    }

    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.io.poll_write_ready(cx).map(|ready| ready.map(drop))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
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

// vertexia: Windows moves one datagram per call with no ECN; GSO, GRO and ECN need nuclei to
// expose the socket's readiness to its caller on Windows as `AsyncFd` does on unix.
#[cfg(windows)]
struct Socket {
    io: nuclei::net::UdpSocket,
}

#[cfg(windows)]
impl Socket {
    fn new(sock: std::net::UdpSocket) -> io::Result<Self> {
        Ok(Self {
            io: nuclei::net::UdpSocket::new(sock)?,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // `max_transmit_segments` is one, so a transmit is one datagram.
        self.io
            .try_send_to(transmit.contents, transmit.destination)
            .map(drop)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut buf = nuclei::io::ReadBuf::new(&mut bufs[0]);
        let addr = ready!(self.io.poll_recv_from(cx, &mut buf))?;
        let len = buf.filled().len();
        meta[0] = RecvMeta {
            addr,
            len,
            stride: len,
            ..RecvMeta::default()
        };
        Poll::Ready(Ok(1))
    }

    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
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
        Self::try_send(self, transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        Self::poll_recv(self, cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    fn may_fragment(&self) -> bool {
        Self::may_fragment(self)
    }

    fn max_transmit_segments(&self) -> usize {
        Self::max_transmit_segments(self)
    }

    fn max_receive_segments(&self) -> usize {
        Self::max_receive_segments(self)
    }
}

/// Write-readiness for one task.
#[derive(Debug)]
struct Poller(Arc<Socket>);

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.poll_writable(cx)
    }
}
