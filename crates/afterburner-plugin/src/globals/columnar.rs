// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Globals for the Phase 1 columnar UDF path.
//!
//! Two Rust-implemented bridges + one JS-implemented dispatcher
//! (installed via `ctx.eval(...)`):
//!
//! * `__AB_GET_COLUMNAR_INPUT__()` - reads `HostState::pending_input`
//!   into a wasm-side buffer and hands it back to JS as a
//!   `Uint8Array`. Zero-copy on the JS side: the `Vec<u8>` we fill
//!   via `host_get_input` is moved (not copied) into the
//!   `ArrayBuffer`'s backing store via [`ArrayBuffer::new`], which
//!   uses QuickJS's free-function callback to take ownership of the
//!   Rust allocation. The user UDF later constructs typed views
//!   (`Int32Array`, `Float64Array`, …) directly into the same
//!   backing store - also zero-copy.
//! * `__AB_COLUMNAR_REPLY__(uint8arr)` - reads the bytes the JS-side
//!   dispatcher wrote into a `Uint8Array` and forwards them through
//!   `host_columnar_reply`. The host then performs the symmetric
//!   boundary `memcpy` from linmem into `pending_columnar_reply` and
//!   `WasmCombustor::thrust_columnar` decodes after `_start` returns.
//! * `__ab_columnar_dispatch(userFn)` - pure-JS dispatcher (no
//!   capability gates of its own). Reads the `BatchHeader` +
//!   `ColumnHeader[]` block at the start of the input blob, builds
//!   the `{ row_count, columns: { name: TypedArrayView, ... } }`
//!   batch the user UDF receives, calls the user function, then
//!   serialises the result back into a reply blob and ships it via
//!   `__AB_COLUMNAR_REPLY__`.
//!
//! ## Sandbox properties
//!
//! TypedArray views are bounded to the wasm guest's own linear
//! memory - Wasmtime guarantees the guest cannot read host memory
//! through these views. Per-call lifecycle stays identical to the
//! JSON-shaped invoke path: a fresh Store is allocated from the
//! pool, the input blob is copied into linmem, the UDF runs, the
//! reply is copied out, the Store drops (linmem with it). No
//! TypedArray view can outlive the call's Store.

use alloc::format;
use javy_plugin_api::javy::quickjs::{
    ArrayBuffer, Ctx, Exception, Object, Result as JsResult, TypedArray, prelude::Func,
};

use crate::host_api::host_columnar_reply;

/// Pure-JS dispatcher installed via `ctx.eval(...)` at modify_runtime
/// time. Reads the columnar input blob, builds the typed-view batch,
/// dispatches the user UDF, and posts back the reply blob.
///
/// Kept short so it compresses well into the Wizer-preinit snapshot.
/// The wire-format constants here (`HEADER`, `COL_HDR`, dtype size +
/// view tables) MUST stay in sync with `crates/afterburner-wasi/src/
/// columnar.rs`'s `BATCH_HEADER_BYTES` / `COLUMN_HEADER_BYTES` /
/// `ColumnDtype` enum / `dtype.size_bytes()`. The host's manifest
/// drift gate is `abi_parity` for host imports; the columnar
/// dispatcher's drift is caught by the integration tests in
/// `crates/afterburner/tests/b_columnar_udf.rs` (Phase 1.5).
const COLUMNAR_DISPATCHER: &str = r#"
(function() {
    const HEADER = 16;
    // ColumnHeader: 1+3+4+4+4+4+4+4+4 = 32 bytes (Phase 1.5 added
    // heap_offset + heap_len at +20 / +24; the constant-column ABI tag
    // added is_constant at +28).
    const COL_HDR = 32;
    const INLINE_SLOT = 16;
    const INLINE_MAX = 12;
    // dtype tags: 12=Utf8, 18=Bytea, 19=Jsonb (Phase 1.5).
    const DT_UTF8 = 12, DT_BYTEA = 18, DT_JSONB = 19;
    function isVarWidth(t) { return t === DT_UTF8 || t === DT_BYTEA || t === DT_JSONB; }
    // Shared by every var-width decode/encode below - constructed once
    // (module scope) rather than per call.
    const dec = new TextDecoder("utf-8");
    const enc = new TextEncoder();
    // Indexed by ColumnDtype tag (1..19). 0 = unused / variable-width
    // (the slot array's element size is 16 - INLINE_SLOT - but
    // var-width has a separate code path).
    const DTYPE_SIZE = [0, 1, 1, 2, 4, 8, 1, 2, 4, 8, 4, 8, 0, 4, 8, 16, 16, 16, 0, 0];
    const DTYPE_VIEW = [
        null,
        Uint8Array,    // 1  Bool - same bytewidth as Uint8
        Int8Array,     // 2  Int8
        Int16Array,    // 3  Int16
        Int32Array,    // 4  Int32
        BigInt64Array, // 5  Int64
        Uint8Array,    // 6  UInt8
        Uint16Array,   // 7  UInt16
        Uint32Array,   // 8  UInt32
        BigUint64Array,// 9  UInt64
        Float32Array,  // 10 Float32
        Float64Array,  // 11 Float64
        null,          // 12 Utf8     - var-width (own path)
        Int32Array,    // 13 Date32
        BigInt64Array, // 14 Timestamp
        null,          // 15 Decimal128 - Phase 2
        null,          // 16 Interval   - Phase 2
        null,          // 17 Uuid       - Phase 2
        null,          // 18 Bytea     - var-width (own path)
        null,          // 19 Jsonb     - var-width (own path)
    ];
    function fixedTypedToTag(v) {
        // JS has no native boolean TypedArray, so `Uint8ClampedArray`
        // is the dedicated signal for a Bool OUTPUT column - the only
        // ABI dtype tag that shares Uint8's 1-byte width with no
        // native typed-array counterpart of its own. `Uint8Array`
        // keeps meaning UInt8 exactly as before (byte-identical
        // default): this is a pure addition, not a behaviour change.
        if (v instanceof Uint8ClampedArray) return 1;
        if (v instanceof Int8Array) return 2;
        if (v instanceof Int16Array) return 3;
        if (v instanceof Int32Array) return 4;
        if (v instanceof BigInt64Array) return 5;
        if (v instanceof Uint8Array) return 6;
        if (v instanceof Uint16Array) return 7;
        if (v instanceof Uint32Array) return 8;
        if (v instanceof BigUint64Array) return 9;
        if (v instanceof Float32Array) return 10;
        if (v instanceof Float64Array) return 11;
        return 0;
    }
    // Bit `i` of a packed validity bitmap, LSB-first, bit set = valid
    // (DuckDB/Arrow convention - see afterburner-wasi/src/columnar.rs's
    // module doc). Shared by every validity read on the input side.
    function isValidBit(bytes, i) {
        return (bytes[i >> 3] >> (i & 7)) & 1;
    }
    // A dtype tag this file's fixed-width/var-width WRITERS below can
    // serialise byte-exactly from a marker alone (see `__abDtype` below):
    // Int64 (bigint, setBigInt64), Float64 (number, setFloat64), and the
    // three var-width tags (raw bytes, no width assumption). Any other
    // original tag (Int32, UInt16, Date32, ...) is NOT in this set - a
    // marker naming one of those is deliberately ignored below and the
    // column falls back to content sampling, because the fixed-width
    // writer only knows how to emit these two shapes; trusting a wider
    // marker there would write the wrong byte width.
    function isSafeMarkerTag(t) {
        return t === 5 || t === 11 || t === DT_UTF8 || t === DT_BYTEA || t === DT_JSONB;
    }
    // Encode a plain output Array (never a real TypedArray - a TypedArray
    // has no way to represent a missing element) that may hold `null`
    // entries. When `v` is the EXACT array object an input column handed
    // the UDF (see `__abDtype` at every nullable-column build site below),
    // its original dtype is trusted directly - this is what lets a UDF
    // that echoes a nullable argument back out (`columns: { x: batch.
    // columns.x }`) round-trip its exact type, not just its nulls.
    // Otherwise the dtype is inferred from the first non-null sample: a
    // string -> Utf8, a Uint8Array -> Bytea, a bigint -> Int64, a number
    // -> Float64. A column with no non-null sample at all (every row
    // null, or zero rows, and no usable marker) carries no type evidence
    // in JS - it defaults to Float64, a structurally valid "no data"
    // reply whose bytes are never read because every row is invalid.
    function encodeNullableColumn(name, v, out_row_count) {
        const n = v.length;
        if (n !== out_row_count) {
            throw new Error("columnar UDF: column '" + name + "' length " + n + " ≠ row_count " + out_row_count);
        }
        let tag = (typeof v.__abDtype === 'number' && isSafeMarkerTag(v.__abDtype)) ? v.__abDtype : 0;
        if (tag === 0) {
            for (let j = 0; j < n; j++) {
                const e = v[j];
                if (e === null || e === undefined) continue;
                if (typeof e === 'string') { tag = DT_UTF8; break; }
                if (e instanceof Uint8Array) { tag = DT_BYTEA; break; }
                if (typeof e === 'bigint') { tag = 5; break; } // Int64: the canonical 64-bit default
                if (typeof e === 'number') { tag = 11; break; } // Float64: the canonical numeric default
                throw new Error("columnar UDF: column '" + name + "' row " + j + " has unsupported value type " + typeof e);
            }
        }
        if (tag === 0) tag = 11; // no evidence anywhere: a Float64 column of nulls

        const nullBytes = new Uint8Array((n + 7) >> 3);
        let anyNull = false;
        if (isVarWidth(tag)) {
            const encoded = new Array(n);
            let heap_size = 0;
            for (let j = 0; j < n; j++) {
                const e = v[j];
                if (e === null || e === undefined) {
                    anyNull = true;
                    encoded[j] = null;
                    continue;
                }
                nullBytes[j >> 3] |= (1 << (j & 7));
                let bytes;
                if (tag === DT_UTF8) {
                    if (typeof e !== 'string') {
                        throw new Error("columnar UDF: col '" + name + "' row " + j + " is not a string");
                    }
                    bytes = enc.encode(e);
                } else {
                    if (!(e instanceof Uint8Array)) {
                        throw new Error("columnar UDF: col '" + name + "' row " + j + " is not a Uint8Array");
                    }
                    bytes = e;
                }
                encoded[j] = bytes;
                if (bytes.byteLength > INLINE_MAX) heap_size += bytes.byteLength;
            }
            const slots = new Uint8Array(n * INLINE_SLOT);
            const slotsDV = new DataView(slots.buffer, slots.byteOffset, slots.byteLength);
            const heap = new Uint8Array(heap_size);
            let heap_cursor = 0;
            for (let j = 0; j < n; j++) {
                const b = encoded[j];
                if (b === null) continue; // slot stays zero: len=0, inline, never read.
                const sb = j * INLINE_SLOT;
                slotsDV.setUint32(sb, b.byteLength, true);
                if (b.byteLength <= INLINE_MAX) {
                    slots.set(b, sb + 4);
                } else {
                    slots.set(b.subarray(0, 4), sb + 4);
                    slotsDV.setUint32(sb + 12, heap_cursor, true);
                    heap.set(b, heap_cursor);
                    heap_cursor += b.byteLength;
                }
            }
            return { tag: tag, slots: slots, heap: heap, data: null, validity: anyNull ? nullBytes : null };
        }

        const size = DTYPE_SIZE[tag];
        const buf = new Uint8Array(n * size);
        const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        for (let j = 0; j < n; j++) {
            const e = v[j];
            if (e === null || e === undefined) {
                anyNull = true;
                continue; // element stays zero bytes, never read.
            }
            nullBytes[j >> 3] |= (1 << (j & 7));
            const off = j * size;
            if (tag === 5) {
                if (typeof e !== 'bigint') {
                    throw new Error("columnar UDF: col '" + name + "' row " + j + " is not a bigint");
                }
                dv.setBigInt64(off, e, true);
            } else {
                if (typeof e !== 'number') {
                    throw new Error("columnar UDF: col '" + name + "' row " + j + " is not a number");
                }
                dv.setFloat64(off, e, true);
            }
        }
        return { tag: tag, slots: null, heap: null, data: buf, validity: anyNull ? nullBytes : null };
    }
    globalThis.__ab_columnar_dispatch = function(userFn) {
        if (typeof userFn !== "function") {
            throw new Error("columnar UDF: module.exports must be a function (got " + typeof userFn + ")");
        }
        const buf = __AB_GET_COLUMNAR_INPUT__();
        const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        const row_count = dv.getUint32(0, true);
        const column_count = dv.getUint32(4, true);
        const columns_offset = dv.getUint32(8, true);

        const columns = {};
        for (let i = 0; i < column_count; i++) {
            const off = columns_offset + i * COL_HDR;
            const dtype = dv.getUint8(off);
            const data_off = dv.getUint32(off + 4, true);
            const validity_off = dv.getUint32(off + 8, true);
            const name_off = dv.getUint32(off + 12, true);
            const name_len = dv.getUint32(off + 16, true);
            const heap_off = dv.getUint32(off + 20, true);
            const heap_len = dv.getUint32(off + 24, true);
            const is_constant = dv.getUint32(off + 28, true);
            const name = dec.decode(buf.subarray(name_off, name_off + name_len));

            if (is_constant) {
                // O(1) broadcast column (constant-column ABI tag):
                // `data_off` holds exactly ONE element's bytes
                // (fixed-width dtypes only - the host-side encoder
                // rejects var-width constants). Read it once, then
                // hand back a Proxy that answers every index
                // `0..row_count` with that same value - no
                // row_count-sized materialization on the guest side
                // either, matching the O(1) transfer cost. A non-zero
                // `validity_off` points at exactly ONE byte, bit 0 =
                // whether the constant is valid for every row (see
                // `ConstantColumnRef`'s doc) - never a per-row bitmap.
                const ViewCtor = DTYPE_VIEW[dtype];
                if (!ViewCtor) {
                    throw new Error("columnar UDF: unsupported constant dtype tag " + dtype + " for column '" + name + "'");
                }
                const constValid = validity_off === 0 || (dv.getUint8(validity_off) & 1) !== 0;
                const constValue = constValid ? new ViewCtor(buf.buffer, buf.byteOffset + data_off, 1)[0] : null;
                columns[name] = new Proxy([], {
                    get(target, prop, receiver) {
                        if (prop === "length") return row_count;
                        if (typeof prop === "string") {
                            const idx = Number(prop);
                            if (Number.isInteger(idx) && idx >= 0 && idx < row_count) return constValue;
                        }
                        return Reflect.get(target, prop, receiver);
                    },
                    has(target, prop) {
                        if (typeof prop === "string") {
                            const idx = Number(prop);
                            if (Number.isInteger(idx) && idx >= 0 && idx < row_count) return true;
                        }
                        return Reflect.has(target, prop);
                    },
                });
                continue;
            }

            if (isVarWidth(dtype)) {
                // Parse the slot array + heap into a JS array of
                // strings (Utf8) or Uint8Array (Bytea/Jsonb). One
                // pass over slots + heap; long slots dereference into
                // the heap buffer. The dispatcher allocates
                // `row_count` JS values up front; user UDFs index
                // through them like `b.columns.email[i]`. An invalid
                // row (validity bit clear) is exposed as `null` - its
                // slot bytes are never decoded.
                const heap = (heap_len > 0)
                    ? buf.subarray(heap_off, heap_off + heap_len)
                    : new Uint8Array(0);
                const validity = (validity_off !== 0)
                    ? buf.subarray(validity_off, validity_off + ((row_count + 7) >> 3))
                    : null;
                const slotsDV = new DataView(buf.buffer, buf.byteOffset + data_off, row_count * INLINE_SLOT);
                const arr = new Array(row_count);
                for (let r = 0; r < row_count; r++) {
                    if (validity && !isValidBit(validity, r)) {
                        arr[r] = null;
                        continue;
                    }
                    const sb = r * INLINE_SLOT;
                    const len = slotsDV.getUint32(sb, true);
                    let bytes;
                    if (len <= INLINE_MAX) {
                        // Inline: bytes live in the slot itself at
                        // offset +4 (after the length).
                        const base = data_off + sb + 4;
                        bytes = buf.subarray(base, base + len);
                    } else {
                        const ho = slotsDV.getUint32(sb + 12, true);
                        bytes = heap.subarray(ho, ho + len);
                    }
                    arr[r] = (dtype === DT_UTF8) ? dec.decode(bytes) : new Uint8Array(bytes);
                }
                // Tag with the wire dtype so a UDF that echoes this exact
                // array back out (`columns: { x: batch.columns.x }`)
                // round-trips its precise type - see `encodeNullableColumn`.
                arr.__abDtype = dtype;
                columns[name] = arr;
                continue;
            }

            const ViewCtor = DTYPE_VIEW[dtype];
            if (!ViewCtor) {
                throw new Error("columnar UDF: unsupported dtype tag " + dtype + " for column '" + name + "'");
            }
            if (validity_off !== 0) {
                // At least one row may be invalid: expose a plain
                // Array with `null` at each invalid row instead of the
                // zero-copy TypedArray view - a TypedArray has no way
                // to represent a missing element.
                const validity = buf.subarray(validity_off, validity_off + ((row_count + 7) >> 3));
                const view = new ViewCtor(buf.buffer, buf.byteOffset + data_off, row_count);
                const arr = new Array(row_count);
                for (let r = 0; r < row_count; r++) {
                    arr[r] = isValidBit(validity, r) ? view[r] : null;
                }
                // Tag with the wire dtype so a UDF that echoes this exact
                // array back out (`columns: { x: batch.columns.x }`)
                // round-trips its precise type - see `encodeNullableColumn`.
                arr.__abDtype = dtype;
                columns[name] = arr;
                continue;
            }
            // TypedArray view directly into linmem at the blob offset.
            // Reading through `columns[name][i]` is a single linmem load.
            columns[name] = new ViewCtor(buf.buffer, buf.byteOffset + data_off, row_count);
        }

        const out = userFn({row_count: row_count, columns: columns});
        if (!out || typeof out !== "object") {
            throw new Error("columnar UDF: result must be {row_count, columns: {name: TypedArray|Array}}");
        }
        const out_row_count = (out.row_count >>> 0);
        const out_columns = out.columns || {};
        const out_names = Object.keys(out_columns);

        // Per-column metadata + pre-encoded var-width slot arrays.
        const dtype_tags = new Array(out_names.length);
        const var_slots = new Array(out_names.length); // Uint8Array of length n*16, populated for var-width
        const var_heaps = new Array(out_names.length); // Uint8Array of heap bytes, populated for var-width
        const fixed_bufs = new Array(out_names.length); // Uint8Array of pre-encoded bytes, populated for a nullable fixed-width Array output
        const null_masks = new Array(out_names.length); // Uint8Array validity bitmap, or null when the column has no nulls

        for (let i = 0; i < out_names.length; i++) {
            const v = out_columns[out_names[i]];
            const fixed_tag = fixedTypedToTag(v);
            if (fixed_tag !== 0) {
                dtype_tags[i] = fixed_tag;
                var_slots[i] = null;
                var_heaps[i] = null;
                fixed_bufs[i] = null;
                null_masks[i] = null;
                continue;
            }
            if (!Array.isArray(v)) {
                const tname = (v && v.constructor && v.constructor.name) || typeof v;
                throw new Error("columnar UDF: column '" + out_names[i] + "' must be a fixed-width TypedArray or an Array (string[] / Uint8Array[] / number[] / bigint[], nulls allowed); got " + tname);
            }
            const encoded = encodeNullableColumn(out_names[i], v, out_row_count);
            dtype_tags[i] = encoded.tag;
            null_masks[i] = encoded.validity;
            var_slots[i] = encoded.slots;
            var_heaps[i] = encoded.heap;
            fixed_bufs[i] = encoded.data;
        }

        // Layout pass - same shape as before, plus a validity bitmap
        // for a nullable column and heap regions for var-width columns,
        // appended after data + name.
        let cursor = HEADER + out_names.length * COL_HDR;
        cursor = (cursor + 7) & ~7;
        const data_offsets = new Array(out_names.length);
        const validity_offsets = new Array(out_names.length);
        const heap_offsets = new Array(out_names.length);
        const heap_lens = new Array(out_names.length);
        const name_bytes = new Array(out_names.length);
        const name_offsets = new Array(out_names.length);
        for (let i = 0; i < out_names.length; i++) {
            const tag = dtype_tags[i];
            // Align cursor to 8 BEFORE writing this column's data.
            cursor = (cursor + 7) & ~7;
            data_offsets[i] = cursor;
            if (var_slots[i]) {
                cursor += var_slots[i].byteLength; // n * 16
            } else {
                const size = DTYPE_SIZE[tag];
                cursor += out_row_count * size;
            }
        }
        for (let i = 0; i < out_names.length; i++) {
            if (null_masks[i]) {
                validity_offsets[i] = cursor;
                cursor += null_masks[i].byteLength;
            } else {
                validity_offsets[i] = 0;
            }
        }
        for (let i = 0; i < out_names.length; i++) {
            name_bytes[i] = enc.encode(out_names[i]);
            name_offsets[i] = cursor;
            cursor += name_bytes[i].byteLength;
        }
        for (let i = 0; i < out_names.length; i++) {
            if (var_heaps[i]) {
                heap_offsets[i] = cursor;
                heap_lens[i] = var_heaps[i].byteLength;
                cursor += var_heaps[i].byteLength;
            } else {
                heap_offsets[i] = 0;
                heap_lens[i] = 0;
            }
        }

        const reply = new Uint8Array(cursor);
        const dvR = new DataView(reply.buffer, reply.byteOffset, reply.byteLength);
        dvR.setUint32(0, out_row_count, true);
        dvR.setUint32(4, out_names.length, true);
        dvR.setUint32(8, HEADER, true);
        dvR.setUint32(12, 0, true);
        for (let i = 0; i < out_names.length; i++) {
            const hOff = HEADER + i * COL_HDR;
            dvR.setUint8(hOff, dtype_tags[i]);
            dvR.setUint32(hOff + 4, data_offsets[i], true);
            dvR.setUint32(hOff + 8, validity_offsets[i], true);
            dvR.setUint32(hOff + 12, name_offsets[i], true);
            dvR.setUint32(hOff + 16, name_bytes[i].byteLength, true);
            dvR.setUint32(hOff + 20, heap_offsets[i], true);
            dvR.setUint32(hOff + 24, heap_lens[i], true);
        }
        for (let i = 0; i < out_names.length; i++) {
            let src;
            if (var_slots[i]) {
                src = var_slots[i];
            } else if (fixed_bufs[i]) {
                src = fixed_bufs[i];
            } else {
                const v = out_columns[out_names[i]];
                src = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
            }
            const dst = new Uint8Array(reply.buffer, reply.byteOffset + data_offsets[i], src.byteLength);
            dst.set(src);
        }
        for (let i = 0; i < out_names.length; i++) {
            if (null_masks[i]) {
                reply.set(null_masks[i], validity_offsets[i]);
            }
        }
        for (let i = 0; i < out_names.length; i++) {
            reply.set(name_bytes[i], name_offsets[i]);
        }
        for (let i = 0; i < out_names.length; i++) {
            if (var_heaps[i]) {
                reply.set(var_heaps[i], heap_offsets[i]);
            }
        }
        __AB_COLUMNAR_REPLY__(reply);
    };
})();
"#;

/// Input getter. Host writes the encoded batch blob into a Rust-side
/// Vec<u8>; we then copy into a QuickJS-allocated `ArrayBuffer` via
/// [`ArrayBuffer::new_copy`].
///
/// **Why `new_copy` and not `new` (zero-copy ownership transfer)?**
/// `ArrayBuffer::new` wraps the Vec's existing allocation, which has
/// only `align_of::<u8>() == 1` byte alignment from the Rust default
/// allocator. JS-side `new Float64Array(buf, off, len)` validates
/// that the *absolute* backing pointer + offset is a multiple of
/// 8 - so a u8-aligned Vec base trips a `RangeError: invalid offset`
/// even when our column data offsets are themselves 8-aligned within
/// the blob. `new_copy` allocates inside QuickJS's heap, which
/// guarantees ≥ 8-byte alignment, so the typed-view construction
/// works for every Phase-1 dtype (Float64 / BigInt64 / Int32 / etc).
/// Cost: one extra in-process `memcpy` of the blob (~100 KB to
/// 1 MB) per call - ~10–100 µs, well under the JSON-decode work it
/// replaces. Removing this copy is a Phase-2 optimisation (allocate
/// the Vec via a high-alignment newtype + transfer ownership).
///
/// Written as a free function (not a closure) so the
/// `for<'js> fn(Ctx<'js>) -> JsResult<TypedArray<'js, u8>>`
/// higher-rank trait bound holds - closures capture a single
/// inferred lifetime and trip the rquickjs Fn trait when the
/// returned type is `'js`-bound.
fn ab_get_columnar_input<'js>(ctx: Ctx<'js>) -> JsResult<TypedArray<'js, u8>> {
    let buf = super::read_pending_input()
        .map_err(|e| Exception::throw_message(&ctx, &format!("__AB_GET_COLUMNAR_INPUT__: {e}")))?;
    let ab = ArrayBuffer::new_copy(ctx, &buf)?;
    TypedArray::<u8>::from_arraybuffer(ab)
}

/// Reply sink. Reads raw bytes from the user's reply `Uint8Array`
/// and forwards them through [`host_columnar_reply`]. The host
/// handler does the symmetric boundary `memcpy`
/// (linmem → `HostState::pending_columnar_reply`).
fn ab_columnar_reply<'js>(arr: TypedArray<'js, u8>) -> i32 {
    // `as_bytes()` returns the slice over the TypedArray's own
    // backing store. Detached returns None - surface as a negative
    // code the JS dispatcher converts to a thrown error.
    let Some(bytes) = arr.as_bytes() else {
        return -3;
    };
    unsafe { host_columnar_reply(bytes.as_ptr(), bytes.len() as u32) }
}

pub fn install<'js>(globals: &Object<'js>) {
    let _ = globals.set(
        "__AB_GET_COLUMNAR_INPUT__",
        Func::from(ab_get_columnar_input),
    );
    let _ = globals.set("__AB_COLUMNAR_REPLY__", Func::from(ab_columnar_reply));
}

/// Eval the JS-side dispatcher. Called from `globals::install` AFTER
/// `__AB_GET_COLUMNAR_INPUT__` / `__AB_COLUMNAR_REPLY__` are
/// installed - the dispatcher uses both at runtime so they must
/// exist first. Wizer preinit captures the resulting
/// `__ab_columnar_dispatch` closure into the snapshot, so every
/// columnar-invoke call boots with it already resident.
pub fn install_dispatcher_js(ctx: Ctx<'_>) {
    let _ = ctx.eval::<(), _>(COLUMNAR_DISPATCHER);
}
