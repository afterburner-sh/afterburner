// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Raw result bridge for the invoke path — the output-side mirror of
//! `globals::input`.
//!
//! `__AB_RAW_OUTPUT__(uint8arr)` reads the bytes from the module's
//! result `Uint8Array` and forwards them through the
//! [`host_raw_output`] import. The invoke wrapper
//! (`envelope::wrap_user_source_with_input_global`) calls it when the
//! module returned a `Uint8Array` / `ArrayBuffer`; every other return
//! value keeps the JSON-over-stdout contract. The host stashes the
//! bytes in `HostState::pending_raw_output` and surfaces
//! `OutputValue::Bytes` after `_start` returns — no `JSON.stringify`,
//! no string materialization, no base64 anywhere on the path.

use alloc::format;
use javy_plugin_api::javy::quickjs::{
    Ctx, Exception, Object, Result as JsResult, TypedArray, prelude::Func,
};

use crate::host_api::host_raw_output;

/// Reply sink — same shape as the columnar `__AB_COLUMNAR_REPLY__`
/// bridge: read the TypedArray's backing bytes in linmem, hand
/// `(ptr, len)` to the host import, throw a JS exception (which fails
/// the invocation) on a negative return so errors never pass silently.
fn ab_raw_output<'js>(ctx: Ctx<'js>, arr: TypedArray<'js, u8>) -> JsResult<()> {
    let Some(bytes) = arr.as_bytes() else {
        return Err(Exception::throw_message(
            &ctx,
            "__AB_RAW_OUTPUT__: detached ArrayBuffer",
        ));
    };
    let rc = unsafe { host_raw_output(bytes.as_ptr(), bytes.len() as u32) };
    if rc < 0 {
        let detail = super::read_last_error(rc);
        return Err(Exception::throw_message(
            &ctx,
            &format!("__AB_RAW_OUTPUT__: {detail}"),
        ));
    }
    Ok(())
}

pub fn install<'js>(globals: &Object<'js>) {
    let _ = globals.set("__AB_RAW_OUTPUT__", Func::from(ab_raw_output));
}
