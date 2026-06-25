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
                if domain != socket::AF_INET || actual_type != socket::SOCK_STREAM {
                    return socket::ENOTSUP;
                }
                let state = caller
                    .data_mut()
                    .socket_state
                    .get_or_insert_with(socket::SocketState::new);
                state.alloc_fd()
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
                let net = match caller.data().daemon_net.clone() {
                    Some(n) => n,
                    None => return socket::EPERM,
                };
                let manifold = match caller.data().manifold.clone() {
                    Some(m) => m,
                    None => return socket::EPERM,
                };
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let mem_snap: Vec<u8> = mem_handle.data(&caller).to_vec();
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
                let manifold = match caller.data().manifold.clone() {
                    Some(m) => m,
                    None => return socket::EPERM,
                };
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let mem_snap: Vec<u8> = mem_handle.data(&caller).to_vec();
                let Some((_host, port)) =
                    socket::parse_sockaddr_in(&mem_snap, addr_ptr as u32 as usize)
                else {
                    return socket::EINVAL;
                };
                if !manifold.listen.allows(port) {
                    return socket::EPERM;
                }
                // Store a placeholder (negative port) so listen() knows which port.
                let state = caller
                    .data_mut()
                    .socket_state
                    .get_or_insert_with(socket::SocketState::new);
                state.server_fds.insert(sockfd, -(port as i32));
                0
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
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let mem = mem_handle.data(&caller).to_vec();
                // msghdr layout (wasm32): [msg_name:i32, msg_namelen:i32, msg_iov:i32, msg_iovlen:i32, ...]
                let iov_off = msg_ptr as u32 as usize + 8;
                match socket::gather_iov(&mem, iov_off) {
                    Err(e) => e,
                    Ok(data) => {
                        let n = data.len() as i32;
                        let mut err_s = String::new();
                        net.write(conn_id, data, &mut err_s);
                        n
                    }
                }
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
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let mem_snap: Vec<u8> = mem_handle.data(&caller).to_vec();
                let iov_off = msg_ptr as u32 as usize + 8;
                let max = socket::iov_capacity(&mem_snap, iov_off);
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
    // Close the connection on the DaemonNet side; Python's socket.shutdown()
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
             _addr: i32,
             _addrlen: i32|
             -> i32 {
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
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return socket::EINVAL,
                };
                let bp = buf_ptr as u32 as usize;
                let n = len as u32 as usize;
                let mem = mem_handle.data(&caller);
                if bp.checked_add(n).map(|e| e > mem.len()).unwrap_or(true) {
                    return socket::EINVAL;
                }
                let data = mem[bp..bp + n].to_vec();
                let written = data.len() as i32;
                let mut err_s = String::new();
                net.write(conn_id, data, &mut err_s);
                written
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
                let bp = buf_ptr as u32 as usize;
                let max = len as u32 as usize;
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
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_recvfrom: {e}")))?;

    Ok(())
}
