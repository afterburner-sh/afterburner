// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! JS-side globals the plugin installs at `modify_runtime` time.
//!
//! Wizer preinit captures these — every thrust starts with all
//! `__host_*` bridges, `__AB_GET_INPUT__`, and the plenum polyfill
//! bundle already visible to user scripts. The installers are split by
//! capability group so no single file goes over the workspace line
//! ceiling.
//!
//! Call order matters:
//!
//! 1. `fs::install` / `crypto::install` / `misc::install` register the
//!    `__host_*` bridges (and `__AB_GET_INPUT__`).
//! 2. `ctx.eval(PLENUM_BUNDLE)` evaluates the Tier-1 polyfill bundle,
//!    which builds `require()` and the Node-stdlib modules on top of
//!    the bridges — so the bridges MUST exist first.

mod codec;
mod columnar;
mod crypto;
mod fs;
mod input;
mod misc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use javy_plugin_api::javy::quickjs::Ctx;

use crate::host_api::{host_get_input, host_get_input_len, host_last_error};

/// Default buffer size for variable-length host responses. The retry
/// loop in [`call_read`] doubles until the host confirms it fits.
pub(super) const DEFAULT_BUF: usize = 64 * 1024;

/// The plenum.js bundle, baked into the plugin. Evaluated once during
/// [`install`] so Wizer captures it into the preinit snapshot.
const PLENUM_BUNDLE: &str =
    include_str!("../../../afterburner-node-compat/generated/plenum_bundle.js");

/// Patch QuickJS's V8-style `CallSite` prototype with the seven Node-
/// shaped methods QuickJS doesn't ship natively: `isEval`,
/// `getEvalOrigin`, `isToplevel`, `isConstructor`, `getThis`,
/// `getTypeName`, `getMethodName`. Real npm packages probe these at
/// module-load time — `depd` (transitively required by `body-parser`,
/// `serve-static`, `morgan`, `finalhandler`) calls `callSite.isEval()`
/// inside `callSiteLocation`; without this patch the call traps with
/// `TypeError: not a function` and Express init aborts.
///
/// Strategy: capture a sample stack with a temporary
/// `Error.prepareStackTrace` that returns the raw frames array, walk
/// to the first frame's prototype, install the missing methods. The
/// previous `Error.prepareStackTrace` value is restored before user
/// code runs — preserving the invariant that `e.stack` is a string
/// for unmodified scripts (no engine-side change). Stub return values
/// match Node conventions (`false` / `null` / `undefined`).
///
/// Wizer preinit re-evaluates this once per snapshot capture; every
/// Store the plugin instantiates inherits the patched prototype from
/// the snapshot.
const CALLSITE_PROTO_PATCH: &str = r#"
(function patchCallSiteProto() {
    var sample = {};
    var prev = Error.prepareStackTrace;
    Error.prepareStackTrace = function(_e, frames) { return frames; };
    Error.captureStackTrace(sample);
    var frames = sample.stack;
    Error.prepareStackTrace = prev;
    if (!Array.isArray(frames) || frames.length === 0) return;
    var proto = Object.getPrototypeOf(frames[0]);
    var stubs = {
        isEval:        function() { return false; },
        getEvalOrigin: function() { return undefined; },
        isToplevel:    function() { return false; },
        isConstructor: function() { return false; },
        getThis:       function() { return undefined; },
        getTypeName:   function() { return null; },
        getMethodName: function() { return null; }
    };
    for (var name in stubs) {
        if (typeof proto[name] !== 'function') {
            proto[name] = stubs[name];
        }
    }
})();
"#;

/// Install every `__host_*` + `__AB_GET_INPUT__` global and then eval
/// the plenum polyfill bundle. Called from `modify_runtime`.
pub fn install(ctx: Ctx<'_>) {
    let globals = ctx.globals();
    fs::install(&globals);
    crypto::install(&globals);
    misc::install(&globals);
    input::install(&globals);
    codec::install(&globals);
    columnar::install(&globals);

    // Eval the plenum bundle so Wizer preinit captures `require()` and
    // every Tier-1 polyfill into the snapshot.
    let _ = ctx.eval::<(), _>(PLENUM_BUNDLE);

    // Columnar UDF dispatcher — JS-side helper that reads the input
    // blob via `__AB_GET_COLUMNAR_INPUT__`, builds typed views over
    // linmem, dispatches the user UDF, and posts the reply. Installed
    // after the plenum bundle so it can rely on `TextEncoder` /
    // `TextDecoder` (from the encoding polyfill).
    columnar::install_dispatcher_js(ctx.clone());

    // Patch the V8-style CallSite prototype after the plenum bundle so
    // the snapshot also captures the Node-shaped CallSite methods. The
    // patch is independent of any plenum module — it only touches
    // `Error.prepareStackTrace` / `Error.captureStackTrace`.
    let _ = ctx.eval::<(), _>(CALLSITE_PROTO_PATCH);
}

/// Retry-doubling helper for variable-length host responses. Returns
/// the UTF-8 decoded string on success, or a human-readable error
/// message on failure — callers typically surface the latter to JS as
/// a `__HOST_ERR__:...` sentinel that a polyfill then detects.
pub(super) fn call_read<F>(mut call: F) -> Result<String, String>
where
    F: FnMut(*mut u8, u32) -> i32,
{
    let mut buf = vec![0u8; DEFAULT_BUF];
    let mut cap = buf.len();
    loop {
        let n = call(buf.as_mut_ptr(), cap as u32);
        if n >= 0 {
            buf.truncate(n as usize);
            return String::from_utf8(buf).map_err(|e| format!("utf8: {e}"));
        }
        if n == -4 {
            cap *= 2;
            if cap > 16 * 1024 * 1024 {
                return Err("output exceeded 16 MiB cap".to_string());
            }
            buf.resize(cap, 0);
            continue;
        }
        return Err(read_last_error(n));
    }
}

/// Exact-fit read of `HostState::pending_input`. Sizes the destination
/// once via `host_get_input_len` — no retry-doubling: each doubling
/// step zeroes the resized region (O(n) metered instructions) and
/// triggers another host-side clone of the full input, so on multi-MiB
/// inputs the old guess-and-retry protocol cost several full passes
/// over the payload before the real copy even happened. The buffer is
/// deliberately *not* pre-zeroed either — the host overwrites every
/// byte it reports, and the memset would be one more wasted metered
/// pass over a multi-MiB payload.
pub(super) fn read_pending_input() -> Result<Vec<u8>, String> {
    let len = unsafe { host_get_input_len() };
    let Ok(cap) = usize::try_from(len) else {
        return Err(format!("host_get_input_len returned {len}"));
    };
    let mut buf: Vec<u8> = Vec::with_capacity(cap);
    let n = unsafe { host_get_input(buf.as_mut_ptr(), cap as u32) };
    let Ok(filled) = usize::try_from(n) else {
        return Err(format!("host_get_input returned {n}"));
    };
    if filled > cap {
        return Err(format!(
            "host_get_input overran its buffer ({filled} > {cap})"
        ));
    }
    // SAFETY: `host_get_input` wrote exactly `filled` bytes into the
    // buffer (host-side `write_out` copies `filled <= cap` bytes or
    // returns a negative code, and the overrun guard above re-checks);
    // every element below `filled` is initialized, and `filled` does
    // not exceed the capacity allocated above.
    unsafe { buf.set_len(filled) };
    Ok(buf)
}

pub(super) fn read_last_error(code: i32) -> String {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { host_last_error(buf.as_mut_ptr(), buf.len() as u32) };
    if n >= 0 {
        buf.truncate(n as usize);
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        format!("host error (code {code})")
    }
}
