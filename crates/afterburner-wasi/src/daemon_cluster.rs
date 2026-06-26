// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Cluster-mode bind helpers - SO_REUSEPORT (Linux/macOS/BSD) /
//! SO_REUSEADDR (Windows) for multi-process accept-balance.
//!
//! Activated by setting `BURN_CLUSTER_REUSEPORT=1` in the subprocess
//! environment. The Node `cluster` polyfill propagates this via
//! `__host_worker_spawn_env` so each forked worker's daemon binds
//! the listening socket with `SO_REUSEPORT`. The kernel then
//! 4-tuple-hashes incoming connections across all listeners on the
//! same `(addr, port)` - that's how Node 20 cluster's default
//! `SCHED_RR` is implemented at the OS level.
//!
//! Behaviour matrix:
//!
//! | Platform | TCP option        | UDP option       |
//! |----------|-------------------|------------------|
//! | Linux    | `SO_REUSEPORT`    | `SO_REUSEPORT`   |
//! | macOS    | `SO_REUSEPORT`    | `SO_REUSEPORT`   |
//! | BSD      | `SO_REUSEPORT`    | `SO_REUSEPORT`   |
//! | Windows  | `SO_REUSEADDR`    | `SO_REUSEADDR`   |
//!
//! On Windows, `SO_REUSEADDR` allows a socket to bind to an
//! already-bound port; on Server 2016+ the kernel does load-balanced
//! delivery for `SO_REUSEADDR` sockets that share a 5-tuple. Older
//! Windows versions allow the bind but only the most-recent listener
//! receives connections - accept-balance falls back to "no balance,
//! just no EADDRINUSE."

use std::net::{SocketAddr, TcpListener, UdpSocket};

pub const ENV_FLAG: &str = "BURN_CLUSTER_REUSEPORT";

/// Returns `true` if the calling process should bind every listening
/// socket with reuse-port semantics. Set by the cluster primary on
/// every spawned worker via `__host_worker_spawn_env`.
pub fn cluster_mode_enabled() -> bool {
    std::env::var(ENV_FLAG)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[derive(Debug)]
pub enum ClusterBindError {
    AddrInUse,
    Io(std::io::Error),
}

impl From<std::io::Error> for ClusterBindError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            ClusterBindError::AddrInUse
        } else {
            ClusterBindError::Io(e)
        }
    }
}

/// Build a TCP listener honouring [`cluster_mode_enabled`]. When the
/// flag is off this is a plain `TcpListener::bind` so the non-cluster
/// hot path keeps zero-overhead behaviour.
pub fn build_tcp_listener(addr: SocketAddr) -> Result<TcpListener, ClusterBindError> {
    if !cluster_mode_enabled() {
        return TcpListener::bind(addr).map_err(Into::into);
    }
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        sock.set_reuse_port(true)?;
    }
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}

/// UDP variant for the HTTP/3 endpoint. Same gating as the TCP path.
pub fn build_udp_socket(addr: SocketAddr) -> Result<UdpSocket, ClusterBindError> {
    if !cluster_mode_enabled() {
        return UdpSocket::bind(addr).map_err(Into::into);
    }
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        sock.set_reuse_port(true)?;
    }
    sock.bind(&addr.into())?;
    Ok(sock.into())
}
