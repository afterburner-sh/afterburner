// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! WASI stdio for the plugin. Minimal preview1 bindings — avoids
//! pulling the full `wasi` crate (which would bloat the plugin).
//! Only `fd_read` / `fd_write` are needed.

use alloc::vec::Vec;

pub fn write_stdout(bytes: &[u8]) {
    let iov = wasi::Ciovec {
        buf: bytes.as_ptr(),
        buf_len: bytes.len(),
    };
    let iov_arr = [iov];
    let mut nwritten: usize = 0;
    let _ = unsafe { wasi::fd_write_raw(1, iov_arr.as_ptr(), 1, &mut nwritten) };
}

pub fn write_stderr(bytes: &[u8]) {
    let iov = wasi::Ciovec {
        buf: bytes.as_ptr(),
        buf_len: bytes.len(),
    };
    let iov_arr = [iov];
    let mut nwritten: usize = 0;
    let _ = unsafe { wasi::fd_write_raw(2, iov_arr.as_ptr(), 1, &mut nwritten) };
}

pub fn read_stdin() -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(4096);
    let chunk = [0u8; 4096];
    loop {
        let iov = wasi::Ciovec {
            buf: chunk.as_ptr(),
            buf_len: chunk.len(),
        };
        let iov_arr = [iov];
        let mut nread: usize = 0;
        let res =
            unsafe { wasi::fd_read_raw(0, iov_arr.as_ptr() as *const wasi::Iovec, 1, &mut nread) };
        if res != 0 {
            return Err(());
        }
        if nread == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..nread]);
    }
}

mod wasi {
    #[repr(C)]
    pub struct Ciovec {
        pub buf: *const u8,
        pub buf_len: usize,
    }
    pub type Iovec = Ciovec;

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        #[link_name = "fd_read"]
        pub fn fd_read_raw(fd: u32, iovs: *const Iovec, iovs_len: u32, nread: *mut usize) -> u32;
        #[link_name = "fd_write"]
        pub fn fd_write_raw(
            fd: u32,
            iovs: *const Ciovec,
            iovs_len: u32,
            nwritten: *mut usize,
        ) -> u32;
    }
}
