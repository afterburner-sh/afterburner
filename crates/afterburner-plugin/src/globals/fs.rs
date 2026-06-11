// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `__host_fs_*` globals - file-system bridges (sync + chunked).

use alloc::format;
use alloc::string::String;
use javy_plugin_api::javy::quickjs::{Object, prelude::Func};

use super::{call_read, read_last_error};
use crate::host_api::*;

pub fn install<'js>(globals: &Object<'js>) {
    let _ = globals.set(
        "__host_fs_exists_sync",
        Func::from(|path: String| -> bool {
            let bytes = path.as_bytes();
            unsafe { host_fs_exists_sync(bytes.as_ptr(), bytes.len() as u32) == 1 }
        }),
    );

    let _ = globals.set(
        "__host_fs_read_file_sync",
        Func::from(|path: String, _enc: Option<String>| -> String {
            let pb = path.as_bytes();
            match call_read(|out, cap| unsafe {
                host_fs_read_file_sync(pb.as_ptr(), pb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_write_file_sync",
        Func::from(
            |path: String, data: String, _enc: Option<String>| -> String {
                let pb = path.as_bytes();
                let db = data.as_bytes();
                let code = unsafe {
                    host_fs_write_file_sync(
                        pb.as_ptr(),
                        pb.len() as u32,
                        db.as_ptr(),
                        db.len() as u32,
                    )
                };
                if code >= 0 {
                    String::new()
                } else {
                    format!("__HOST_ERR__:{}", read_last_error(code))
                }
            },
        ),
    );

    let _ = globals.set(
        "__host_fs_unlink_sync",
        Func::from(|path: String| -> String {
            let pb = path.as_bytes();
            let code = unsafe { host_fs_unlink_sync(pb.as_ptr(), pb.len() as u32) };
            if code >= 0 {
                String::new()
            } else {
                format!("__HOST_ERR__:{}", read_last_error(code))
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_rename_sync",
        Func::from(|from: String, to: String| -> String {
            let fb = from.as_bytes();
            let tb = to.as_bytes();
            let code = unsafe {
                host_fs_rename_sync(fb.as_ptr(), fb.len() as u32, tb.as_ptr(), tb.len() as u32)
            };
            if code >= 0 {
                String::new()
            } else {
                format!("__HOST_ERR__:{}", read_last_error(code))
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_mkdir_sync",
        Func::from(|path: String, recursive: Option<bool>| -> String {
            let pb = path.as_bytes();
            let flag = if recursive.unwrap_or(false) { 1 } else { 0 };
            let code = unsafe { host_fs_mkdir_sync(pb.as_ptr(), pb.len() as u32, flag) };
            if code >= 0 {
                String::new()
            } else {
                format!("__HOST_ERR__:{}", read_last_error(code))
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_readdir_sync",
        Func::from(|path: String| -> String {
            let pb = path.as_bytes();
            match call_read(|out, cap| unsafe {
                host_fs_readdir_sync(pb.as_ptr(), pb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_realpath_sync",
        Func::from(|path: String| -> String {
            let pb = path.as_bytes();
            match call_read(|out, cap| unsafe {
                host_fs_realpath_sync(pb.as_ptr(), pb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_readlink_sync",
        Func::from(|path: String| -> String {
            let pb = path.as_bytes();
            match call_read(|out, cap| unsafe {
                host_fs_readlink_sync(pb.as_ptr(), pb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_cp",
        Func::from(|src: String, dst: String, force: Option<bool>| -> String {
            let sb = src.as_bytes();
            let db = dst.as_bytes();
            let f = if force.unwrap_or(false) { 1 } else { 0 };
            let code = unsafe {
                host_fs_cp(
                    sb.as_ptr(),
                    sb.len() as u32,
                    db.as_ptr(),
                    db.len() as u32,
                    f,
                )
            };
            if code >= 0 {
                String::new()
            } else {
                format!("__HOST_ERR__:{}", read_last_error(code))
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_opendir_sync",
        Func::from(|path: String| -> String {
            let pb = path.as_bytes();
            match call_read(|out, cap| unsafe {
                host_fs_opendir_sync(pb.as_ptr(), pb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_watch_poll",
        Func::from(|path: String, interval_ms: f64| -> String {
            let pb = path.as_bytes();
            let interval = interval_ms.max(0.0) as i32;
            match call_read(|out, cap| unsafe {
                host_fs_watch_poll(pb.as_ptr(), pb.len() as u32, interval, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_stat_sync",
        Func::from(|path: String| -> String {
            let pb = path.as_bytes();
            match call_read(|out, cap| unsafe {
                host_fs_stat_sync(pb.as_ptr(), pb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    // Chunked fs (createReadStream / createWriteStream backing).
    let _ = globals.set(
        "__host_fs_read_chunk",
        Func::from(|path: String, offset: f64, len: u32| -> String {
            let pb = path.as_bytes();
            let off = offset as u64;
            let lo = (off & 0xFFFF_FFFF) as u32;
            let hi = (off >> 32) as u32;
            match call_read(|out, cap| unsafe {
                host_fs_read_chunk(pb.as_ptr(), pb.len() as u32, lo, hi, len, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_write_chunk",
        Func::from(|path: String, offset: f64, data_b64: String| -> String {
            let pb = path.as_bytes();
            let db = data_b64.as_bytes();
            let off = offset as u64;
            let lo = (off & 0xFFFF_FFFF) as u32;
            let hi = (off >> 32) as u32;
            let code = unsafe {
                host_fs_write_chunk(
                    pb.as_ptr(),
                    pb.len() as u32,
                    lo,
                    hi,
                    db.as_ptr(),
                    db.len() as u32,
                )
            };
            if code >= 0 {
                String::new()
            } else {
                format!("__HOST_ERR__:{}", read_last_error(code))
            }
        }),
    );

    let _ = globals.set(
        "__host_fs_size",
        Func::from(|path: String| -> String {
            let pb = path.as_bytes();
            match call_read(|out, cap| unsafe {
                host_fs_size(pb.as_ptr(), pb.len() as u32, out, cap)
            }) {
                Ok(s) => s,
                Err(e) => format!("__HOST_ERR__:{e}"),
            }
        }),
    );
}
