// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Per-thrust input bridges for the bytecode-cache invoke path.
//!
//! The host stashes the per-call input in `HostState::pending_input`;
//! the wrapped script materializes it through one of these globals at
//! the top of every invocation. Both bridges size their destination
//! buffer exactly via `host_get_input_len` - on multi-MiB inputs the
//! older retry-doubling protocol cost O(n) metered instructions per
//! doubling step (zeroing each resize) plus repeated host-side clones,
//! all pure overhead.
//!
//! * `__AB_GET_INPUT_VALUE__()` - format-aware getter the invoke
//!   wrapper calls. Consults the `host_input_format` import: JSON
//!   framing returns one JS string (the wrapper hands it to QuickJS's
//!   native `JSON.parse`); raw framing returns a `Uint8Array` backed
//!   by a QuickJS-heap allocation (≥8-byte aligned via
//!   [`ArrayBuffer::new_copy`], so callers can construct any typed
//!   view over `.buffer` - same rationale as the codec + columnar
//!   bridges). Raw framing skips string materialization and
//!   `JSON.parse` entirely - the O(n) byte movement happens on the
//!   host side of the boundary, outside fuel metering.
//! * `__AB_GET_INPUT__()` - string-shaped getter, kept for user code
//!   and diagnostics that read the input text directly.

use alloc::format;
use alloc::string::String;
use javy_plugin_api::javy::quickjs::{
    ArrayBuffer, Ctx, Exception, IntoJs, Object, Result as JsResult, String as JsString,
    TypedArray, Value, prelude::Func,
};

use super::read_pending_input;
use crate::host_api::host_input_format;

/// Raw-bytes input framing (`host_input_format() == 1`). `0` is JSON
/// text. Mirrors `InputFormat` in `afterburner-wasi/src/host.rs`.
const FORMAT_RAW: i32 = 1;

/// Decode the pending input as UTF-8, lossy only on invalid sequences.
/// The JSON framing always carries valid UTF-8 (host-side
/// `serde_json::to_vec`), so the common path moves the buffer without
/// copying; the lossy fallback exists for misuse (e.g. user code
/// calling `__AB_GET_INPUT__()` under raw framing).
fn input_to_string(buf: alloc::vec::Vec<u8>) -> String {
    String::from_utf8(buf).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// `__AB_GET_INPUT_VALUE__()` - JS string (JSON framing) or
/// `Uint8Array` (raw framing). Free function (not a closure) for the
/// same reason as the codec / columnar bridges: rquickjs's HRTB-based
/// `Fn` impls reject closures whose return types are `'js`-bound.
fn ab_get_input_value<'js>(ctx: Ctx<'js>) -> JsResult<Value<'js>> {
    let buf = read_pending_input()
        .map_err(|e| Exception::throw_message(&ctx, &format!("__AB_GET_INPUT_VALUE__: {e}")))?;
    if unsafe { host_input_format() } == FORMAT_RAW {
        let ab = ArrayBuffer::new_copy(ctx.clone(), &buf)?;
        return TypedArray::<u8>::from_arraybuffer(ab)?.into_js(&ctx);
    }
    JsString::from_str(ctx.clone(), &input_to_string(buf))?.into_js(&ctx)
}

pub fn install<'js>(globals: &Object<'js>) {
    let _ = globals.set("__AB_GET_INPUT_VALUE__", Func::from(ab_get_input_value));

    // String-shaped getter. Any host error returns an empty string so
    // the caller's `JSON.parse` surfaces the failure clearly - the
    // pre-existing contract for this global.
    let _ = globals.set(
        "__AB_GET_INPUT__",
        Func::from(|| -> String {
            match read_pending_input() {
                Ok(buf) => input_to_string(buf),
                Err(_) => String::new(),
            }
        }),
    );
}
