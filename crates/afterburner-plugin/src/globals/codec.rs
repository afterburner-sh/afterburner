// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Base64 fast-path bridges.
//!
//! Base64 is the universal binary framing across the JS boundary
//! (request/response bodies, file payloads, codec wire formats), and
//! the interpreter-side encoder/decoder in the `buffer` polyfill costs
//! O(n) interpreted bytecode per byte - tens of seconds and >1e9
//! metered instructions on multi-MiB payloads. These bridges hoist the
//! bit-twiddling to the host.
//!
//! ## Framing
//!
//! Unlike the zlib bridges (whose JS-visible API is string-shaped, so
//! base64-framing the wire is free), framing *base64 itself* as base64
//! would be self-defeating. These bridges move raw bytes instead:
//!
//! * `__host_b64_encode(Uint8Array) -> string` - the typed array's
//!   backing bytes are passed to the host by pointer (zero-copy on the
//!   guest side; QuickJS's heap lives in linear memory), and the ASCII
//!   result crosses back through an exact-fit out buffer.
//! * `__host_b64_decode(string) -> Uint8Array` - the ASCII input
//!   crosses as a Rust `String` (one native UTF-8 copy), and the raw
//!   decoded bytes come back through an exact-fit out buffer, returned
//!   to JS as a `Uint8Array` backed by a QuickJS-heap allocation
//!   (`ArrayBuffer::new_copy`, ≥8-byte aligned so callers can construct
//!   any typed view over `.buffer` - same rationale as the columnar
//!   input bridge).
//!
//! Output sizes are exactly computable from input sizes, so neither
//! direction uses the `-4` retry-doubling protocol. On any host error
//! the bridges throw; the `buffer` polyfill catches and falls back to
//! its interpreter-side implementation, preserving its lenient-input
//! semantics.

use alloc::string::String;
use alloc::vec;
use javy_plugin_api::javy::quickjs::{
    ArrayBuffer, Ctx, Exception, Object, Result as JsResult, TypedArray, prelude::Func,
};

use super::read_last_error;
use crate::host_api::{host_b64_decode, host_b64_encode};

/// Defensive input ceiling. Keeps the `u32` ABI casts and the
/// exact-fit output-size arithmetic trivially overflow-free; inputs
/// beyond this fall back to the polyfill path (which will be slow, but
/// payloads this large already exceed engine output caps elsewhere).
const MAX_INPUT_BYTES: usize = 1 << 30;

/// `__host_b64_encode(bytes)` - raw bytes to base64 string.
///
/// Free function (not a closure) for the same reason as the columnar
/// bridges: rquickjs's HRTB-based `Fn` impls reject closures whose
/// parameter/return types are `'js`-bound.
fn b64_encode<'js>(ctx: Ctx<'js>, data: TypedArray<'js, u8>) -> JsResult<String> {
    let Some(bytes) = data.as_bytes() else {
        return Err(Exception::throw_message(
            &ctx,
            "__host_b64_encode: detached buffer",
        ));
    };
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Exception::throw_message(
            &ctx,
            "__host_b64_encode: input too large",
        ));
    }
    // Exact output size: 4 chars per 3-byte group, final group padded.
    let cap = bytes.len().div_ceil(3) * 4;
    let mut out = vec![0u8; cap];
    let n = unsafe {
        host_b64_encode(
            bytes.as_ptr(),
            bytes.len() as u32,
            out.as_mut_ptr(),
            cap as u32,
        )
    };
    if n < 0 {
        return Err(Exception::throw_message(&ctx, &read_last_error(n)));
    }
    out.truncate(n as usize);
    // The host writes standard-alphabet ASCII only; from_utf8 cannot
    // fail on it, but map the error rather than assume.
    String::from_utf8(out)
        .map_err(|_| Exception::throw_message(&ctx, "__host_b64_encode: non-ASCII host reply"))
}

/// `__host_b64_decode(str)` - base64 string to raw bytes.
fn b64_decode<'js>(ctx: Ctx<'js>, input: String) -> JsResult<TypedArray<'js, u8>> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(Exception::throw_message(
            &ctx,
            "__host_b64_decode: input too large",
        ));
    }
    let ib = input.as_bytes();
    // Upper bound: 3 bytes per 4-char group; unpadded tails round up.
    let cap = ib.len() / 4 * 3 + 3;
    let mut out = vec![0u8; cap];
    let n = unsafe { host_b64_decode(ib.as_ptr(), ib.len() as u32, out.as_mut_ptr(), cap as u32) };
    if n < 0 {
        return Err(Exception::throw_message(&ctx, &read_last_error(n)));
    }
    out.truncate(n as usize);
    let ab = ArrayBuffer::new_copy(ctx, &out)?;
    TypedArray::<u8>::from_arraybuffer(ab)
}

pub fn install<'js>(globals: &Object<'js>) {
    let _ = globals.set("__host_b64_encode", Func::from(b64_encode));
    let _ = globals.set("__host_b64_decode", Func::from(b64_decode));
}
