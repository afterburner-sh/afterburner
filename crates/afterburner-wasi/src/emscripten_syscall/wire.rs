// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Daemon-feature socket registration helpers.
//!
//! `wire_socket_syscalls` and `wire_sendto_recvfrom` register the real
//! socket syscall implementations against `DaemonNet`. Only compiled when
//! the `daemon` feature is active.
//!
//! ## Emscripten socket syscall ABI
//!
//! Every socket import in the Pyodide wasm binary (0.28.3 and 3.14) is typed
//! as `(func (param i32 i32 i32 i32 i32 i32) (result i32))` - exactly 6 i32
//! params regardless of the underlying POSIX syscall's actual argument count.
//! Emscripten pads shorter calls with trailing zeros, e.g. `__syscall_socket`
//! is called as `socket(domain, type, proto, 0, 0, 0)`.  All `func_wrap`
//! signatures here must match this 6-arg shape or instantiation will fail with
//! "incompatible import type".

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Linker};

use crate::embedder_vm::EmbedderState;

use super::socket;

/// Wire the real socket syscalls (socket/connect/bind/listen/accept4/sendmsg/recvmsg)
/// to `DaemonNet`. Only compiled when the `daemon` feature is active.
///
/// Every function is registered with 6 i32 params to match the Emscripten
/// legacy-syscall ABI (type 10 = `(i32 i32 i32 i32 i32 i32) -> i32`).
pub(super) fn wire_socket_syscalls(linker: &mut Linker<EmbedderState>) -> Result<()> {
    // __syscall_socket(domain, type, protocol, 0, 0, 0) -> fd
    linker
        .func_wrap(
            "env",
            "__syscall_socket",
            |mut caller: Caller<'_, EmbedderState>,
             domain: i32,
             sock_type: i32,
             _protocol: i32,
             _p3: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let has_net = caller.data().daemon_net.is_some();
                if !has_net {
                    return socket::EPERM;
                }
                let actual_type = sock_type & socket::SOCK_TYPE_MASK;
                let supported = (domain == socket::AF_UNIX || domain == socket::AF_INET)
                    && (actual_type == socket::SOCK_STREAM || actual_type == socket::SOCK_DGRAM);
                if !supported {
                    return socket::ENOTSUP;
                }
                let state = caller
                    .data_mut()
                    .socket_state
                    .get_or_insert_with(socket::SocketState::new);
                let fd = state.alloc_fd();
                let kind = match (domain, actual_type) {
                    (d, t) if d == socket::AF_INET && t == socket::SOCK_STREAM => {
                        socket::SockKind::TcpStream
                    }
                    (d, t) if d == socket::AF_INET && t == socket::SOCK_DGRAM => {
                        socket::SockKind::UdpDgram
                    }
                    (d, t) if d == socket::AF_UNIX && t == socket::SOCK_STREAM => {
                        socket::SockKind::UnixStream
                    }
                    _ => socket::SockKind::UnixDgram,
                };
                state.fd_kinds.insert(fd, kind);
                fd
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_socket: {e}")))?;

    // __syscall_connect(sockfd, addr_ptr, addrlen, 0, 0, 0) -> 0 | err
    linker
        .func_wrap(
            "env",
            "__syscall_connect",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             addr_ptr: i32,
             _addrlen: i32,
             _p3: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let mem_snap: Vec<u8> = mem_handle.data(&caller).to_vec();

                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                match kind {
                    Some(socket::SockKind::TcpStream) | None => {
                        // Default: TCP connect (None = kind not yet recorded; treat as TCP).
                        let net = match caller.data().daemon_net.clone() {
                            Some(n) => n,
                            None => return socket::EPERM,
                        };
                        let manifold = match caller.data().manifold.clone() {
                            Some(m) => m,
                            None => return socket::EPERM,
                        };
                        let Some((host, port)) =
                            socket::parse_sockaddr_in(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        if !crate::daemon_net_gate::net_outbound_allowed(&manifold, &host, port) {
                            return socket::EPERM;
                        }
                        let mut err_str = String::new();
                        let conn_id = net.connect(&host, port, &mut err_str);
                        if conn_id < 0 {
                            return socket::ECONNREFUSED;
                        }
                        {
                            let state = caller
                                .data_mut()
                                .socket_state
                                .get_or_insert_with(socket::SocketState::new);
                            state.conn_fds.insert(sockfd, conn_id);
                        }
                        let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                        socket::blocking::wait_connect(&net, conn_id, state)
                    }
                    Some(socket::SockKind::UdpDgram) => {
                        // UDP "connect": just record the default remote address.
                        let Some((host, port)) =
                            socket::parse_sockaddr_in(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        let state = caller
                            .data_mut()
                            .socket_state
                            .get_or_insert_with(socket::SocketState::new);
                        state.udp_connected.insert(sockfd, (host, port));
                        0
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixStream) => {
                        let unix = match caller.data().daemon_unix.clone() {
                            Some(u) => u,
                            None => return socket::EPERM,
                        };
                        let Some(path) =
                            socket::parse_sockaddr_un(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        let conn_id = unix.connect_stream(&path);
                        if conn_id < 0 {
                            return socket::ECONNREFUSED;
                        }
                        {
                            let state = caller
                                .data_mut()
                                .socket_state
                                .get_or_insert_with(socket::SocketState::new);
                            state.conn_fds.insert(sockfd, conn_id);
                        }
                        let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                        socket::blocking::wait_unix_connect(&unix, conn_id, state)
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixDgram) => {
                        // Unix dgram "connect": record the default remote path.
                        let Some(path) =
                            socket::parse_sockaddr_un(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        let state = caller
                            .data_mut()
                            .socket_state
                            .get_or_insert_with(socket::SocketState::new);
                        state.unix_dgram_connected.insert(sockfd, path);
                        0
                    }
                    #[cfg(not(unix))]
                    Some(socket::SockKind::UnixStream | socket::SockKind::UnixDgram) => {
                        socket::ENOTSUP
                    }
                }
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_connect: {e}")))?;

    // __syscall_bind(sockfd, addr_ptr, addrlen, 0, 0, 0) -> 0 | err
    linker
        .func_wrap(
            "env",
            "__syscall_bind",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             addr_ptr: i32,
             _addrlen: i32,
             _p3: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let mem_snap: Vec<u8> = mem_handle.data(&caller).to_vec();

                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                match kind {
                    Some(socket::SockKind::TcpStream) | None => {
                        let manifold = match caller.data().manifold.clone() {
                            Some(m) => m,
                            None => return socket::EPERM,
                        };
                        let Some((_host, port)) =
                            socket::parse_sockaddr_in(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        if !manifold.listen.allows(port) {
                            return socket::EPERM;
                        }
                        let state = caller
                            .data_mut()
                            .socket_state
                            .get_or_insert_with(socket::SocketState::new);
                        state.server_fds.insert(sockfd, -(port as i32));
                        0
                    }
                    Some(socket::SockKind::UdpDgram) => {
                        let dgram = match caller.data().daemon_dgram_py.clone() {
                            Some(d) => d,
                            None => return socket::EPERM,
                        };
                        let Some((host, port)) =
                            socket::parse_sockaddr_in(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        let mut err_s = String::new();
                        let socket_id = dgram.bind(&host, port, &mut err_s);
                        if socket_id < 0 {
                            return socket::EINVAL;
                        }
                        let state = caller
                            .data_mut()
                            .socket_state
                            .get_or_insert_with(socket::SocketState::new);
                        state.udp_fds.insert(sockfd, socket_id);
                        0
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixStream) => {
                        let Some(path) =
                            socket::parse_sockaddr_un(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        let state = caller
                            .data_mut()
                            .socket_state
                            .get_or_insert_with(socket::SocketState::new);
                        state.unix_stream_bind_paths.insert(sockfd, path);
                        0
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixDgram) => {
                        let unix = match caller.data().daemon_unix.clone() {
                            Some(u) => u,
                            None => return socket::EPERM,
                        };
                        let Some(path) =
                            socket::parse_sockaddr_un(&mem_snap, addr_ptr as u32 as usize)
                        else {
                            return socket::EINVAL;
                        };
                        let mut err_s = String::new();
                        let socket_id = unix.bind_dgram(&path, &mut err_s);
                        if socket_id < 0 {
                            return socket::EINVAL;
                        }
                        let state = caller
                            .data_mut()
                            .socket_state
                            .get_or_insert_with(socket::SocketState::new);
                        state.unix_dgram_fds.insert(sockfd, socket_id);
                        0
                    }
                    #[cfg(not(unix))]
                    Some(socket::SockKind::UnixStream | socket::SockKind::UnixDgram) => {
                        socket::ENOTSUP
                    }
                }
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_bind: {e}")))?;

    // __syscall_listen(sockfd, backlog, 0, 0, 0, 0) -> 0 | err
    linker
        .func_wrap(
            "env",
            "__syscall_listen",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             _backlog: i32,
             _p2: i32,
             _p3: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                #[cfg(unix)]
                if kind == Some(socket::SockKind::UnixStream) {
                    let unix = match caller.data().daemon_unix.clone() {
                        Some(u) => u,
                        None => return socket::EPERM,
                    };
                    let path = caller
                        .data()
                        .socket_state
                        .as_deref()
                        .and_then(|s| s.unix_stream_bind_paths.get(&sockfd).cloned())
                        .unwrap_or_default();
                    if path.is_empty() {
                        return socket::EINVAL;
                    }
                    let mut err_str = String::new();
                    let server_id = unix.listen(&path, &mut err_str);
                    if server_id < 0 {
                        return socket::EINVAL;
                    }
                    let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                    state.server_fds.insert(sockfd, server_id);
                    return 0;
                }

                // TCP path (TcpStream or None).
                let _ = kind; // suppress unused warning on non-unix
                let net = match caller.data().daemon_net.clone() {
                    Some(n) => n,
                    None => return socket::EPERM,
                };
                let manifold = match caller.data().manifold.clone() {
                    Some(m) => m,
                    None => return socket::EPERM,
                };
                let placeholder = {
                    let state = caller
                        .data_mut()
                        .socket_state
                        .get_or_insert_with(socket::SocketState::new);
                    state
                        .server_fds
                        .get(&sockfd)
                        .copied()
                        .unwrap_or(socket::EBADF)
                };
                if placeholder == socket::EBADF {
                    return socket::EBADF;
                }
                if placeholder >= 0 {
                    return 0; // already listening
                }
                let port = (-placeholder) as u16;
                if !manifold.listen.allows(port) {
                    return socket::EPERM;
                }
                let mut err_str = String::new();
                let server_id = net.listen("0.0.0.0", port, &mut err_str);
                if server_id < 0 {
                    return socket::EINVAL;
                }
                let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                state.server_fds.insert(sockfd, server_id);
                0
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_listen: {e}")))?;

    // __syscall_accept4(sockfd, addr_ptr, addrlen_ptr, flags, 0, 0) -> new_fd | err
    linker
        .func_wrap(
            "env",
            "__syscall_accept4",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             addr_ptr: i32,
             addrlen_ptr: i32,
             _flags: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                #[cfg(unix)]
                if kind == Some(socket::SockKind::UnixStream) {
                    let unix = match caller.data().daemon_unix.clone() {
                        Some(u) => u,
                        None => return socket::EPERM,
                    };
                    let server_id = {
                        let state = caller
                            .data_mut()
                            .socket_state
                            .get_or_insert_with(socket::SocketState::new);
                        state
                            .server_fds
                            .get(&sockfd)
                            .copied()
                            .unwrap_or(socket::EBADF)
                    };
                    if server_id < 0 {
                        return socket::EBADF;
                    }
                    let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                    let conn_id = match socket::blocking::wait_unix_accept(&unix, server_id, state)
                    {
                        Ok(cid) => cid,
                        Err(e) => return e,
                    };
                    let new_fd = state.alloc_fd();
                    state.conn_fds.insert(new_fd, conn_id);
                    // Record kind for the new fd.
                    state.fd_kinds.insert(new_fd, socket::SockKind::UnixStream);
                    if addr_ptr != 0 {
                        let mem_handle = match caller.data().pyodide_memory {
                            Some(m) => m,
                            None => return new_fd,
                        };
                        let mem = mem_handle.data_mut(&mut caller);
                        socket::write_sockaddr_un_empty(mem, addr_ptr as u32 as usize);
                        if addrlen_ptr != 0 {
                            let ap = addrlen_ptr as u32 as usize;
                            if ap + 4 <= mem.len() {
                                mem[ap..ap + 4].copy_from_slice(&3u32.to_le_bytes()); // sizeof family + NUL
                            }
                        }
                    }
                    return new_fd;
                }

                // TCP accept path.
                let _ = kind;
                let net = match caller.data().daemon_net.clone() {
                    Some(n) => n,
                    None => return socket::EPERM,
                };
                let server_id = {
                    let state = caller
                        .data_mut()
                        .socket_state
                        .get_or_insert_with(socket::SocketState::new);
                    state
                        .server_fds
                        .get(&sockfd)
                        .copied()
                        .unwrap_or(socket::EBADF)
                };
                if server_id < 0 {
                    return socket::EBADF;
                }
                let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                let conn_id = match socket::blocking::wait_accept(&net, server_id, state) {
                    Ok(cid) => cid,
                    Err(e) => return e,
                };
                let new_fd = state.alloc_fd();
                state.conn_fds.insert(new_fd, conn_id);
                state.fd_kinds.insert(new_fd, socket::SockKind::TcpStream);
                // Write peer sockaddr if requested.
                if addr_ptr != 0 {
                    let mem_handle = match caller.data().pyodide_memory {
                        Some(m) => m,
                        None => return new_fd,
                    };
                    let mem = mem_handle.data_mut(&mut caller);
                    socket::write_sockaddr_in(mem, addr_ptr as u32 as usize, "0.0.0.0", 0);
                    if addrlen_ptr != 0 {
                        let ap = addrlen_ptr as u32 as usize;
                        if ap + 4 <= mem.len() {
                            mem[ap..ap + 4].copy_from_slice(&16u32.to_le_bytes());
                        }
                    }
                }
                new_fd
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_accept4: {e}")))?;

    // __syscall_sendmsg(sockfd, msg_ptr, flags, 0, 0, 0) -> bytes_sent | err
    linker
        .func_wrap(
            "env",
            "__syscall_sendmsg",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             msg_ptr: i32,
             _flags: i32,
             _p3: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let mem = mem_handle.data(&caller).to_vec();
                // msghdr layout (wasm32): [msg_name:i32, msg_namelen:i32, msg_iov:i32, msg_iovlen:i32, ...]
                let iov_off = msg_ptr as u32 as usize + 8;
                let data = match socket::gather_iov(&mem, iov_off) {
                    Err(e) => return e,
                    Ok(d) => d,
                };
                let n = data.len() as i32;

                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                #[cfg(unix)]
                if kind == Some(socket::SockKind::UnixStream) {
                    let unix = match caller.data().daemon_unix.clone() {
                        Some(u) => u,
                        None => return socket::EPERM,
                    };
                    let conn_id = caller
                        .data()
                        .socket_state
                        .as_deref()
                        .and_then(|s| s.conn_fds.get(&sockfd).copied())
                        .unwrap_or(socket::EBADF);
                    if conn_id == socket::EBADF {
                        return socket::EBADF;
                    }
                    let mut err_s = String::new();
                    unix.write(conn_id, data, &mut err_s);
                    return n;
                }

                // TCP path.
                let net = match caller.data().daemon_net.clone() {
                    Some(n) => n,
                    None => return socket::EPERM,
                };
                let conn_id = {
                    let state = caller
                        .data_mut()
                        .socket_state
                        .get_or_insert_with(socket::SocketState::new);
                    state
                        .conn_fds
                        .get(&sockfd)
                        .copied()
                        .unwrap_or(socket::EBADF)
                };
                if conn_id == socket::EBADF {
                    return socket::EBADF;
                }
                let mut err_s = String::new();
                net.write(conn_id, data, &mut err_s);
                n
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_sendmsg: {e}")))?;

    // __syscall_recvmsg(sockfd, msg_ptr, flags, 0, 0, 0) -> bytes_recv | err
    linker
        .func_wrap(
            "env",
            "__syscall_recvmsg",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             msg_ptr: i32,
             _flags: i32,
             _p3: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let iov_off = msg_ptr as u32 as usize + 8;
                let mem_snap: Vec<u8> = mem_handle.data(&caller).to_vec();
                let max = socket::iov_capacity(&mem_snap, iov_off);

                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                #[cfg(unix)]
                if kind == Some(socket::SockKind::UnixStream) {
                    let unix = match caller.data().daemon_unix.clone() {
                        Some(u) => u,
                        None => return socket::EPERM,
                    };
                    let conn_id = caller
                        .data()
                        .socket_state
                        .as_deref()
                        .and_then(|s| s.conn_fds.get(&sockfd).copied())
                        .unwrap_or(socket::EBADF);
                    if conn_id == socket::EBADF {
                        return socket::EBADF;
                    }
                    let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                    let bytes = match socket::blocking::wait_unix_data(&unix, conn_id, state, max) {
                        Err(e) => return e,
                        Ok(b) => b,
                    };
                    if bytes.is_empty() {
                        return 0;
                    }
                    let mem = mem_handle.data_mut(&mut caller);
                    return socket::scatter_iov(mem, iov_off, &bytes);
                }

                // TCP path.
                let net = match caller.data().daemon_net.clone() {
                    Some(n) => n,
                    None => return socket::EPERM,
                };
                let conn_id = {
                    let state = caller
                        .data_mut()
                        .socket_state
                        .get_or_insert_with(socket::SocketState::new);
                    state
                        .conn_fds
                        .get(&sockfd)
                        .copied()
                        .unwrap_or(socket::EBADF)
                };
                if conn_id == socket::EBADF {
                    return socket::EBADF;
                }
                let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                let bytes = match socket::blocking::wait_data(&net, conn_id, state, max) {
                    Err(e) => return e,
                    Ok(b) => b,
                };
                if bytes.is_empty() {
                    return 0;
                }
                let mem = mem_handle.data_mut(&mut caller);
                socket::scatter_iov(mem, iov_off, &bytes)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_recvmsg: {e}")))?;

    // __syscall_shutdown(sockfd, how, 0, 0, 0, 0) -> 0 | err
    // Close the connection on the coordinator side; Python's socket.shutdown()
    // calls this before close() on graceful teardown.
    linker
        .func_wrap(
            "env",
            "__syscall_shutdown",
            |caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             _how: i32,
             _p2: i32,
             _p3: i32,
             _p4: i32,
             _p5: i32|
             -> i32 {
                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                #[cfg(unix)]
                if kind == Some(socket::SockKind::UnixStream) {
                    let unix = match caller.data().daemon_unix.clone() {
                        Some(u) => u,
                        None => return socket::EPERM,
                    };
                    let conn_id = caller
                        .data()
                        .socket_state
                        .as_deref()
                        .and_then(|s| s.conn_fds.get(&sockfd).copied());
                    return match conn_id {
                        Some(cid) => {
                            unix.destroy(cid);
                            0
                        }
                        None => socket::EBADF,
                    };
                }

                // TCP path.
                let net = match caller.data().daemon_net.clone() {
                    Some(n) => n,
                    None => return socket::EPERM,
                };
                let conn_id = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.conn_fds.get(&sockfd).copied());
                match conn_id {
                    Some(cid) => {
                        net.destroy(cid);
                        0
                    }
                    None => socket::EBADF,
                }
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_shutdown: {e}")))?;

    Ok(())
}

/// Wire `__syscall_sendto` and `__syscall_recvfrom` to `DaemonNet`.
/// Only compiled when the `daemon` feature is active.
///
/// Both are already typed as `(i32 i32 i32 i32 i32 i32) -> i32` in the wasm
/// module (type 10) and their POSIX signatures happen to use all 6 params:
/// `sendto(fd, buf, len, flags, addr, addrlen)` and
/// `recvfrom(fd, buf, len, flags, addr, addrlen)`.
pub(super) fn wire_sendto_recvfrom(linker: &mut Linker<EmbedderState>) -> Result<()> {
    linker
        .func_wrap(
            "env",
            "__syscall_sendto",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             buf_ptr: i32,
             len: i32,
             _flags: i32,
             addr: i32,
             _addrlen: i32|
             -> i32 {
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let bp = buf_ptr as u32 as usize;
                let n = len as u32 as usize;
                {
                    let mem = mem_handle.data(&caller);
                    if bp.checked_add(n).map(|e| e > mem.len()).unwrap_or(true) {
                        return socket::EINVAL;
                    }
                }
                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                match kind {
                    Some(socket::SockKind::UdpDgram) => {
                        let dgram = match caller.data().daemon_dgram_py.clone() {
                            Some(d) => d,
                            None => return socket::EPERM,
                        };
                        // Auto-bind to 0.0.0.0:0 if the socket has not been
                        // explicitly bound yet (Linux semantics: first sendto
                        // on an unbound SOCK_DGRAM socket auto-assigns an
                        // ephemeral port).
                        let socket_id = {
                            let existing = caller
                                .data()
                                .socket_state
                                .as_deref()
                                .and_then(|s| s.udp_fds.get(&sockfd).copied());
                            match existing {
                                Some(sid) => sid,
                                None => {
                                    let mut err_s = String::new();
                                    let sid = dgram.bind("0.0.0.0", 0, &mut err_s);
                                    if sid < 0 {
                                        return socket::EINVAL;
                                    }
                                    caller
                                        .data_mut()
                                        .socket_state
                                        .get_or_insert_with(socket::SocketState::new)
                                        .udp_fds
                                        .insert(sockfd, sid);
                                    sid
                                }
                            }
                        };
                        // Parse destination from addr param, or fall back to udp_connected.
                        let (host, port) = if addr != 0 {
                            let mem_snap = mem_handle.data(&caller).to_vec();
                            match socket::parse_sockaddr_in(&mem_snap, addr as u32 as usize) {
                                Some(hp) => hp,
                                None => return socket::EINVAL,
                            }
                        } else {
                            match caller
                                .data()
                                .socket_state
                                .as_deref()
                                .and_then(|s| s.udp_connected.get(&sockfd).cloned())
                            {
                                Some(hp) => hp,
                                None => return socket::EINVAL,
                            }
                        };
                        let payload = mem_handle.data(&caller)[bp..bp + n].to_vec();
                        let mut err_s = String::new();
                        dgram.send(socket_id, &host, port, &payload, &mut err_s)
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixDgram) => {
                        let unix = match caller.data().daemon_unix.clone() {
                            Some(u) => u,
                            None => return socket::EPERM,
                        };
                        let socket_id = caller
                            .data()
                            .socket_state
                            .as_deref()
                            .and_then(|s| s.unix_dgram_fds.get(&sockfd).copied())
                            .unwrap_or(socket::EBADF);
                        if socket_id == socket::EBADF {
                            return socket::EBADF;
                        }
                        let dest = if addr != 0 {
                            let mem_snap = mem_handle.data(&caller).to_vec();
                            match socket::parse_sockaddr_un(&mem_snap, addr as u32 as usize) {
                                Some(p) => p,
                                None => return socket::EINVAL,
                            }
                        } else {
                            match caller
                                .data()
                                .socket_state
                                .as_deref()
                                .and_then(|s| s.unix_dgram_connected.get(&sockfd).cloned())
                            {
                                Some(p) => p,
                                None => return socket::EINVAL,
                            }
                        };
                        let payload = mem_handle.data(&caller)[bp..bp + n].to_vec();
                        let mut err_s = String::new();
                        unix.send_dgram(socket_id, &dest, &payload, &mut err_s)
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixStream) => {
                        let unix = match caller.data().daemon_unix.clone() {
                            Some(u) => u,
                            None => return socket::EPERM,
                        };
                        let conn_id = caller
                            .data()
                            .socket_state
                            .as_deref()
                            .and_then(|s| s.conn_fds.get(&sockfd).copied())
                            .unwrap_or(socket::EBADF);
                        if conn_id == socket::EBADF {
                            return socket::EBADF;
                        }
                        let data = mem_handle.data(&caller)[bp..bp + n].to_vec();
                        let written = data.len() as i32;
                        let mut err_s = String::new();
                        unix.write(conn_id, data, &mut err_s);
                        written
                    }
                    // TCP stream or unknown.
                    _ => {
                        let net = match caller.data().daemon_net.clone() {
                            Some(n) => n,
                            None => return socket::EPERM,
                        };
                        let conn_id = {
                            let state = caller
                                .data_mut()
                                .socket_state
                                .get_or_insert_with(socket::SocketState::new);
                            state
                                .conn_fds
                                .get(&sockfd)
                                .copied()
                                .unwrap_or(socket::EBADF)
                        };
                        if conn_id == socket::EBADF {
                            return socket::EBADF;
                        }
                        let data = mem_handle.data(&caller)[bp..bp + n].to_vec();
                        let written = data.len() as i32;
                        let mut err_s = String::new();
                        net.write(conn_id, data, &mut err_s);
                        written
                    }
                }
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_sendto: {e}")))?;

    linker
        .func_wrap(
            "env",
            "__syscall_recvfrom",
            |mut caller: Caller<'_, EmbedderState>,
             sockfd: i32,
             buf_ptr: i32,
             len: i32,
             _flags: i32,
             _addr: i32,
             _addrlen: i32|
             -> i32 {
                let bp = buf_ptr as u32 as usize;
                let max = len as u32 as usize;

                let kind = caller
                    .data()
                    .socket_state
                    .as_deref()
                    .and_then(|s| s.fd_kind(sockfd));

                match kind {
                    Some(socket::SockKind::UdpDgram) => {
                        let dgram = match caller.data().daemon_dgram_py.clone() {
                            Some(d) => d,
                            None => return socket::EPERM,
                        };
                        let socket_id = caller
                            .data()
                            .socket_state
                            .as_deref()
                            .and_then(|s| s.udp_fds.get(&sockfd).copied())
                            .unwrap_or(socket::EBADF);
                        if socket_id == socket::EBADF {
                            return socket::EBADF;
                        }
                        let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                        match socket::blocking::wait_dgram(&dgram, socket_id, state, max) {
                            Err(e) => e,
                            Ok(bytes) if bytes.is_empty() => 0,
                            Ok(bytes) => {
                                let n = bytes.len().min(max);
                                let mem_handle = match caller.data().pyodide_memory {
                                    Some(m) => m,
                                    None => return socket::EINVAL,
                                };
                                let mem = mem_handle.data_mut(&mut caller);
                                if bp.checked_add(n).map(|e| e <= mem.len()).unwrap_or(false) {
                                    mem[bp..bp + n].copy_from_slice(&bytes[..n]);
                                }
                                n as i32
                            }
                        }
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixDgram) => {
                        let unix = match caller.data().daemon_unix.clone() {
                            Some(u) => u,
                            None => return socket::EPERM,
                        };
                        let socket_id = caller
                            .data()
                            .socket_state
                            .as_deref()
                            .and_then(|s| s.unix_dgram_fds.get(&sockfd).copied())
                            .unwrap_or(socket::EBADF);
                        if socket_id == socket::EBADF {
                            return socket::EBADF;
                        }
                        let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                        match socket::blocking::wait_unix_dgram(&unix, socket_id, state, max) {
                            Err(e) => e,
                            Ok(bytes) if bytes.is_empty() => 0,
                            Ok(bytes) => {
                                let n = bytes.len().min(max);
                                let mem_handle = match caller.data().pyodide_memory {
                                    Some(m) => m,
                                    None => return socket::EINVAL,
                                };
                                let mem = mem_handle.data_mut(&mut caller);
                                if bp.checked_add(n).map(|e| e <= mem.len()).unwrap_or(false) {
                                    mem[bp..bp + n].copy_from_slice(&bytes[..n]);
                                }
                                n as i32
                            }
                        }
                    }
                    #[cfg(unix)]
                    Some(socket::SockKind::UnixStream) => {
                        let unix = match caller.data().daemon_unix.clone() {
                            Some(u) => u,
                            None => return socket::EPERM,
                        };
                        let conn_id = caller
                            .data()
                            .socket_state
                            .as_deref()
                            .and_then(|s| s.conn_fds.get(&sockfd).copied())
                            .unwrap_or(socket::EBADF);
                        if conn_id == socket::EBADF {
                            return socket::EBADF;
                        }
                        let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                        match socket::blocking::wait_unix_data(&unix, conn_id, state, max) {
                            Err(e) => e,
                            Ok(bytes) if bytes.is_empty() => 0,
                            Ok(bytes) => {
                                let n = bytes.len().min(max);
                                let mem_handle = match caller.data().pyodide_memory {
                                    Some(m) => m,
                                    None => return socket::EINVAL,
                                };
                                let mem = mem_handle.data_mut(&mut caller);
                                if bp.checked_add(n).map(|e| e <= mem.len()).unwrap_or(false) {
                                    mem[bp..bp + n].copy_from_slice(&bytes[..n]);
                                }
                                n as i32
                            }
                        }
                    }
                    // TCP stream or unknown.
                    _ => {
                        let net = match caller.data().daemon_net.clone() {
                            Some(n) => n,
                            None => return socket::EPERM,
                        };
                        let conn_id = {
                            let state = caller
                                .data_mut()
                                .socket_state
                                .get_or_insert_with(socket::SocketState::new);
                            state
                                .conn_fds
                                .get(&sockfd)
                                .copied()
                                .unwrap_or(socket::EBADF)
                        };
                        if conn_id == socket::EBADF {
                            return socket::EBADF;
                        }
                        let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                        match socket::blocking::wait_data(&net, conn_id, state, max) {
                            Err(e) => e,
                            Ok(bytes) if bytes.is_empty() => 0,
                            Ok(bytes) => {
                                let n = bytes.len().min(max);
                                let mem_handle = match caller.data().pyodide_memory {
                                    Some(m) => m,
                                    None => return socket::EINVAL,
                                };
                                let mem = mem_handle.data_mut(&mut caller);
                                if bp.checked_add(n).map(|e| e <= mem.len()).unwrap_or(false) {
                                    mem[bp..bp + n].copy_from_slice(&bytes[..n]);
                                }
                                n as i32
                            }
                        }
                    }
                }
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_recvfrom: {e}")))?;

    Ok(())
}
