// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Vendor-neutral columnar batch ABI for the wasm host↔guest UDF path.
//!
//! ## Why this exists
//!
//! The JSON-shaped UDF path (`thrust(id, &Value, ...)`) round-trips
//! every per-call payload through `serde_json::to_vec` on the host,
//! `JSON.parse` inside QuickJS, then the symmetric stringify+parse on
//! the way out. ~70% of the per-row cost is encoding/decoding,
//! ~7% is the actual JS UDF body. For billion-row analytical workloads
//! the encode is the dominant cycle eater, not the language.
//!
//! This module defines a typed columnar wire format that lets the host
//! hand wasm linear memory **already-laid-out** column buffers + a
//! validity bitmap; the JS-side polyfill exposes them as
//! `Int32Array`/`Float64Array`/etc. *views into linmem* - no
//! `JSON.parse`, no per-element allocation. The user's UDF reads
//! `batch.columns.c0[i]`, writes `out[i] = ...`, and the host reads
//! the result column back through the symmetric exit boundary.
//!
//! ## Two boundary copies, no other data movement
//!
//! Per call:
//!
//! 1. One `wasmtime::Memory::write` per input column - `memcpy` from
//!    host slice into wasm linmem. Unavoidable: wasm guests have a
//!    separate address space; there is no Wasmtime mechanism to make
//!    a guest read host pointers.
//! 2. JS-side TypedArray views are constructed with
//!    `new Int32Array(memory.buffer, offset, len)` - *views* into
//!    linmem, not copies.
//! 3. User UDF reads/writes through the views - direct linmem
//!    loads/stores; no allocation, no conversion.
//! 4. One `wasmtime::Memory::data()` slice per output column - symmetric
//!    `memcpy` back into host-owned [`OwnedColumn`] vectors.
//!
//! Total data movement per call: **one host→guest `memcpy` per input
//! column + one guest→host `memcpy` per output column.** No JSON, no
//! base64, no varint, no Arrow framing, no protobuf - just typed
//! contiguous bytes plus a packed validity bitmap.
//!
//! ## Vendor-neutral type set
//!
//! Numeric primitives (`Int8`–`Int64`, `UInt8`–`UInt64`, `Float32/64`,
//! `Bool`), `Date32` (days since epoch), and `Timestamp` (i64 micros
//! since epoch) ship in Phase 1. Variable-width (`Utf8`/`Bytea`/`Jsonb`)
//! and 16-byte fixed (`Decimal128`/`Uuid`/`Interval`) tags are reserved
//! in the enum so on-the-wire byte tags stay stable when Phase 1.5/2
//! adds support; the Phase 1 host path returns
//! [`AfterburnerError::Engine`] if a caller passes a not-yet-implemented
//! dtype.
//!
//! The validity convention follows DuckDB's published vector format:
//! one bit per row, packed into u64 chunks LSB-first, **bit set = valid**
//! (the inverse of Arrow's null-bitmap convention - Arrow also uses
//! "1 = valid", so the conventions coincide). `validity: None` on the
//! host side means "all rows valid" - zero-cost; the guest skips the
//! validity slice read entirely.
//!
//! ## What's NOT in this module
//!
//! Anything embedder-specific. This crate is
//! open source and the public surface stays vendor-neutral. Embedders
//! that already store data in a layout-compatible columnar format
//! (DuckDB-style 2048-row vectors + bit-set-valid validity + 16-byte
//! inline-string slots) write a thin private adapter
//! `&theirs::DataChunk -> ColumnarBatch<'_>` outside this repo; the
//! adapter typically borrows column buffers directly with zero copies
//! before the boundary `memcpy` fires.

use afterburner_core::AfterburnerError;

/// Physical type tag for a column crossing the host↔guest boundary.
///
/// Wire-stable: every variant's `u8` discriminant is fixed forever.
/// Adding new dtypes appends to the end; existing tags never move.
/// The plugin's columnar-invoke mode and the JS polyfill match on
/// these tags, so a guest built against an older Afterburner
/// version that doesn't know a new tag returns
/// [`AfterburnerError::Engine`] cleanly instead of mis-decoding.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDtype {
    Bool = 1,
    Int8 = 2,
    Int16 = 3,
    Int32 = 4,
    Int64 = 5,
    UInt8 = 6,
    UInt16 = 7,
    UInt32 = 8,
    UInt64 = 9,
    Float32 = 10,
    Float64 = 11,
    /// UTF-8 bytes via 16-byte inline-or-pointer slots + heap. Phase 1.5.
    Utf8 = 12,
    /// Days since 1970-01-01 (signed, i32). Same shape as Int32 but
    /// the guest-side polyfill exposes it as a JS `Date` accessor.
    Date32 = 13,
    /// Microseconds since 1970-01-01T00:00:00Z (signed, i64).
    Timestamp = 14,
    /// 16-byte fixed binary: i128 mantissa + scale stored in
    /// per-column metadata. Phase 2.
    Decimal128 = 15,
    /// Months + days + microseconds packed into 16 bytes. Phase 2.
    Interval = 16,
    /// 16-byte unsigned binary. Phase 2.
    Uuid = 17,
    /// Opaque bytes via 16-byte inline-or-pointer slots + heap. Phase 1.5.
    Bytea = 18,
    /// Pre-parsed JSON body as opaque bytes (caller's encoding). Phase 1.5.
    Jsonb = 19,
}

impl ColumnDtype {
    /// Per-row byte count of the column's *primary* data buffer.
    ///
    /// * Fixed-width dtypes: the size of one element.
    /// * Variable-width (Utf8 / Bytea / Jsonb): always 16 bytes - the
    ///   inline-or-pointer slot. Long-slot bytes live in a separate
    ///   heap buffer; `size_bytes` covers the slot array only.
    ///
    /// The encoder uses this to validate `data.len() == row_count *
    /// dtype.size_bytes()` for every column type.
    pub fn size_bytes(self) -> Result<usize, AfterburnerError> {
        Ok(match self {
            ColumnDtype::Bool | ColumnDtype::Int8 | ColumnDtype::UInt8 => 1,
            ColumnDtype::Int16 | ColumnDtype::UInt16 => 2,
            ColumnDtype::Int32
            | ColumnDtype::UInt32
            | ColumnDtype::Float32
            | ColumnDtype::Date32 => 4,
            ColumnDtype::Int64
            | ColumnDtype::UInt64
            | ColumnDtype::Float64
            | ColumnDtype::Timestamp => 8,
            ColumnDtype::Decimal128 | ColumnDtype::Interval | ColumnDtype::Uuid => 16,
            // Variable-width dtypes use a 16-byte inline-or-pointer
            // slot per row (DuckDB-style `string_t`). The actual
            // bytes for >12-byte slots live in the heap buffer
            // pointed at by `heap_offset` in the column header.
            ColumnDtype::Utf8 | ColumnDtype::Bytea | ColumnDtype::Jsonb => INLINE_SLOT_BYTES,
        })
    }

    /// True if the dtype's storage is a single constant-stride buffer
    /// (no separate heap region). Numerics + 16-byte fixed dtypes.
    /// Variable-width returns `false`; that path needs the column's
    /// `heap` slice in addition to its slot data.
    pub fn is_fixed_width(self) -> bool {
        !matches!(
            self,
            ColumnDtype::Utf8 | ColumnDtype::Bytea | ColumnDtype::Jsonb
        )
    }

    /// True if the dtype is implemented in the current Afterburner
    /// version. Decimal128 / Uuid / Interval (16-byte fixed) are
    /// reserved for a later phase; everything else (numerics +
    /// temporal + Utf8 / Bytea / Jsonb) ships from Phase 1.5 onward.
    pub fn is_phase1_supported(self) -> bool {
        !matches!(
            self,
            ColumnDtype::Decimal128 | ColumnDtype::Interval | ColumnDtype::Uuid
        )
    }

    /// Decode a `u8` byte tag back to the enum. Used by the host when
    /// reading the result columns the guest writes back. Returns `Err`
    /// for unknown tags so a future-Afterburner-built guest writing
    /// a tag the current host doesn't recognise surfaces a clean
    /// error rather than silently mis-decoding.
    pub fn from_u8(tag: u8) -> Result<Self, AfterburnerError> {
        Ok(match tag {
            1 => ColumnDtype::Bool,
            2 => ColumnDtype::Int8,
            3 => ColumnDtype::Int16,
            4 => ColumnDtype::Int32,
            5 => ColumnDtype::Int64,
            6 => ColumnDtype::UInt8,
            7 => ColumnDtype::UInt16,
            8 => ColumnDtype::UInt32,
            9 => ColumnDtype::UInt64,
            10 => ColumnDtype::Float32,
            11 => ColumnDtype::Float64,
            12 => ColumnDtype::Utf8,
            13 => ColumnDtype::Date32,
            14 => ColumnDtype::Timestamp,
            15 => ColumnDtype::Decimal128,
            16 => ColumnDtype::Interval,
            17 => ColumnDtype::Uuid,
            18 => ColumnDtype::Bytea,
            19 => ColumnDtype::Jsonb,
            _ => {
                return Err(AfterburnerError::Engine(format!(
                    "unknown ColumnDtype tag {tag}",
                )));
            }
        })
    }
}

/// Inline-or-pointer slot size for variable-width dtypes (Utf8 /
/// Bytea / Jsonb). 16 bytes per row, DuckDB-style `string_t` layout:
///
/// * `len ≤ 12`: `[len: u32 LE][bytes: [u8; 12]]` - inline; first
///   `len` bytes of the data field carry the value, remainder is
///   padding.
/// * `len > 12`:  `[len: u32 LE][prefix: [u8; 4]][heap_off: u32 LE]`
///   where the 4-byte prefix is the first four bytes of the value (used
///   for fast comparisons / hash bucketing); `heap_off` is the
///   absolute byte offset into the column's heap buffer where the
///   full `len` bytes live.
pub const INLINE_SLOT_BYTES: usize = 16;
/// Inline cap - slot values up to this size embed in the slot
/// itself, longer values point at the heap buffer.
pub const INLINE_SLOT_INLINE_MAX: usize = 12;

/// Borrowed reference to a single column in a [`ColumnarBatch`].
///
/// The host owns the buffers; this struct just borrows them for the
/// duration of one columnar call. After the call the borrows are
/// released.
///
/// # Validity convention
///
/// `validity: None` means "every row is valid" (zero-cost - the
/// guest never reads a validity slice in this case). `Some(slice)`
/// must hold `ceil(row_count / 8)` bytes packed LSB-first; bit
/// `i` corresponds to row `i`; **bit set = valid** (matches Arrow
/// + DuckDB).
pub struct ColumnRef<'a> {
    pub name: &'a str,
    pub dtype: ColumnDtype,
    /// Primary column data buffer.
    ///
    /// * Fixed-width dtypes: exactly `row_count × dtype.size_bytes()`
    ///   bytes of contiguous element values.
    /// * Variable-width (Utf8 / Bytea / Jsonb): exactly
    ///   `row_count × INLINE_SLOT_BYTES = row_count × 16` bytes of
    ///   inline-or-pointer slots. Each slot's first 4 bytes are the
    ///   value's length (u32 LE); slots with `len ≤ 12` carry the
    ///   value inline in the next 12 bytes; slots with `len > 12`
    ///   carry a 4-byte prefix + a 4-byte `heap_offset` (u32 LE)
    ///   into the column's [`Self::heap`] buffer.
    pub data: &'a [u8],
    /// Heap-bytes buffer for variable-width dtypes. `Some(slice)`
    /// only when `dtype.is_fixed_width() == false`. Long-slot
    /// `heap_offset` indexes into this buffer; the slot's `len`
    /// gives how many bytes to read.
    pub heap: Option<&'a [u8]>,
    /// `None` ⇒ every row valid. `Some(bitmap)` ⇒ packed
    /// LSB-first u64 bitmap, `ceil(row_count / 8)` bytes.
    pub validity: Option<&'a [u8]>,
}

/// Host-side input batch - caller owns every byte; this struct borrows
/// for the duration of [`crate::wasm_engine::WasmCombustor::thrust_columnar`].
pub struct ColumnarBatch<'a> {
    pub row_count: u32,
    pub columns: Vec<ColumnRef<'a>>,
}

impl<'a> ColumnarBatch<'a> {
    pub fn new(row_count: u32) -> Self {
        Self {
            row_count,
            columns: Vec::new(),
        }
    }

    pub fn push(&mut self, col: ColumnRef<'a>) -> &mut Self {
        self.columns.push(col);
        self
    }
}

/// A column whose single value is broadcast across every row of the
/// batch, carried in [`encode_batch_with_constants`] - the O(1)
/// counterpart to a fully-materialized [`ColumnRef`] for a scalar
/// argument (e.g. a SQL literal passed alongside per-row columns).
/// The embedder builds `value` once instead of `row_count` copies, and
/// the wire transfer itself is O(1) bytes rather than O(row_count).
///
/// Scoped to fixed-width dtypes for now: [`ColumnDtype::is_fixed_width`]
/// must be `true`. A variable-width constant (Utf8 / Bytea / Jsonb) is
/// not yet supported - `encode_batch_with_constants` errors loudly
/// naming the column; encode it as a length-1 [`ColumnRef`] with its
/// own one-value heap in the meantime.
pub struct ConstantColumnRef<'a> {
    pub name: &'a str,
    pub dtype: ColumnDtype,
    /// Exactly `dtype.size_bytes()` bytes - the one value.
    pub value: &'a [u8],
    /// `false` ⇒ the constant is NULL for every row. `true` (the
    /// common case) ⇒ valid for every row - identical cost to
    /// `validity: None` on an ordinary [`ColumnRef`].
    pub valid: bool,
}

/// Long-slot pointer variant of [`ColumnRef`] for the E6 zero-copy
/// var-width ingest path (see [`encode_batch_ptr_slots`]).
///
/// Slot shape matches [`ColumnRef::data`] exactly for `len ≤ 12`
/// (inline). For `len > 12`, bytes `8..16` of the slot carry an
/// 8-byte little-endian host pointer (`usize`) - valid to dereference
/// for `len` bytes - instead of a heap offset; there is no separate
/// `heap` buffer because the caller never materializes one. This is
/// the natural wire-compatible shape of an embedder's own long-string
/// representation (e.g. a German-string vector: `[len:u32][prefix:4]
/// [ptr:8]`), so a caller whose native layout already matches can pass
/// its column buffer through with zero pre-processing.
pub struct PtrSlotColumnRef<'a> {
    pub name: &'a str,
    /// Must be a variable-width dtype (Utf8 / Bytea / Jsonb).
    pub dtype: ColumnDtype,
    /// `row_count × INLINE_SLOT_BYTES` bytes, ptr-slot form (see above).
    pub data: &'a [u8],
    /// Same convention as [`ColumnRef::validity`].
    pub validity: Option<&'a [u8]>,
}

/// One column of a [`PtrSlotBatch`] - either an ordinary borrowed
/// column (fixed-width, or variable-width with a caller-built heap;
/// identical semantics to [`ColumnRef`]) or a [`PtrSlotColumnRef`].
/// Mixing both kinds in one batch is the common case: numeric columns
/// stay zero-copy as they already were, and only the var-width columns
/// need the ptr-slot form.
pub enum PtrSlotColumn<'a> {
    Ref(ColumnRef<'a>),
    PtrSlot(PtrSlotColumnRef<'a>),
}

/// Host-side input batch for [`encode_batch_ptr_slots`]. The additive,
/// zero-copy-var-width sibling of [`ColumnarBatch`]; existing callers
/// of [`ColumnarBatch`] / [`encode_batch`] are completely unaffected.
pub struct PtrSlotBatch<'a> {
    pub row_count: u32,
    pub columns: Vec<PtrSlotColumn<'a>>,
}

impl<'a> PtrSlotBatch<'a> {
    pub fn new(row_count: u32) -> Self {
        Self {
            row_count,
            columns: Vec::new(),
        }
    }

    pub fn push(&mut self, col: PtrSlotColumn<'a>) -> &mut Self {
        self.columns.push(col);
        self
    }
}

/// Owned result of a columnar call. The guest's UDF allocated each
/// `data` / `validity` `Vec<u8>` in linmem; the host did one symmetric
/// `memcpy` per output column to land them in heap-owned `Vec`s before
/// the Store dropped (which would have freed the linmem). The caller
/// downstream may do a second `memcpy` into its own allocator (e.g. a
/// columnar engine's aligned-buffer arena) - that copy is post-boundary
/// and outside this crate's scope.
#[derive(Debug)]
pub struct ColumnarOutput {
    pub row_count: u32,
    pub columns: Vec<OwnedColumn>,
}

#[derive(Debug)]
pub struct OwnedColumn {
    pub name: String,
    pub dtype: ColumnDtype,
    /// Same shape as [`ColumnRef::data`].
    pub data: Vec<u8>,
    /// Heap-bytes buffer; `Some` only for variable-width dtypes.
    pub heap: Option<Vec<u8>>,
    /// `None` ⇒ every row valid. Same convention as [`ColumnRef::validity`].
    pub validity: Option<Vec<u8>>,
}

impl OwnedColumn {
    /// Materialise the value at row `i` as a `&[u8]`. Variable-width
    /// columns: handles inline + heap slots transparently. Fixed-
    /// width columns: returns the element's `dtype.size_bytes()` bytes.
    /// Caller is responsible for honouring the validity bitmap; this
    /// helper does not consult `validity`.
    pub fn row_bytes(&self, i: usize) -> Result<&[u8], AfterburnerError> {
        if self.dtype.is_fixed_width() {
            let stride = self.dtype.size_bytes()?;
            let off = i.checked_mul(stride).ok_or_else(|| {
                AfterburnerError::Engine(format!(
                    "row_bytes: row {i} × stride {stride} overflows usize",
                ))
            })?;
            return self.data.get(off..off + stride).ok_or_else(|| {
                AfterburnerError::Engine(format!("row_bytes: row {i} out of range"))
            });
        }
        // Variable-width: parse the inline-or-pointer slot.
        let slot_off = i
            .checked_mul(INLINE_SLOT_BYTES)
            .ok_or_else(|| AfterburnerError::Engine("row_bytes: slot index overflow".into()))?;
        let slot = self
            .data
            .get(slot_off..slot_off + INLINE_SLOT_BYTES)
            .ok_or_else(|| AfterburnerError::Engine(format!("row_bytes: row {i} out of range")))?;
        let len = u32::from_le_bytes(slot[0..4].try_into().unwrap()) as usize;
        if len <= INLINE_SLOT_INLINE_MAX {
            Ok(&slot[4..4 + len])
        } else {
            let heap_off = u32::from_le_bytes(slot[12..16].try_into().unwrap()) as usize;
            let heap = self.heap.as_ref().ok_or_else(|| {
                AfterburnerError::Engine(format!(
                    "row_bytes: var-width column '{}' has long slot at row {i} but no heap buffer",
                    self.name,
                ))
            })?;
            heap.get(heap_off..heap_off + len).ok_or_else(|| {
                AfterburnerError::Engine(format!(
                    "row_bytes: heap slice out of bounds: heap_off={heap_off}, len={len}, heap_len={}",
                    heap.len(),
                ))
            })
        }
    }

    /// Convenience for [`Self::row_bytes`] returning a UTF-8 `&str`
    /// for [`ColumnDtype::Utf8`] columns.
    pub fn row_str(&self, i: usize) -> Result<&str, AfterburnerError> {
        if self.dtype != ColumnDtype::Utf8 {
            return Err(AfterburnerError::Engine(format!(
                "row_str called on non-Utf8 column '{}' (dtype {:?})",
                self.name, self.dtype,
            )));
        }
        let bytes = self.row_bytes(i)?;
        std::str::from_utf8(bytes).map_err(|e| {
            AfterburnerError::Engine(format!(
                "row_str: column '{}' row {i} not UTF-8: {e}",
                self.name,
            ))
        })
    }
}

// ---- wire-level header layout ------------------------------------------
//
// The host serialises a `ColumnarBatch` into a single contiguous blob
// the guest reads via the `__host_get_columnar_input` import. The blob
// layout is: BatchHeader || ColumnHeader[column_count] || (column data
// + validity + name bytes, in any order, addressed by absolute offsets
// relative to the blob start). This lets the guest construct
// TypedArray views with `new Int32Array(memory.buffer, base + offset,
// len)`-style calls directly into wasm linear memory.

/// Top-of-blob header, byte 0..16. All offsets are relative to the
/// start of the blob (i.e. the same address the
/// `__host_get_columnar_input` polyfill receives in the guest).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchHeader {
    pub row_count: u32,
    pub column_count: u32,
    /// Byte offset of the `[ColumnHeader; column_count]` array.
    /// Always equals `size_of::<BatchHeader>()` in the current layout
    /// but stored explicitly so a future revision could move the
    /// column-header table without an ABI break.
    pub columns_offset: u32,
    /// Reserved - must be 0. Lets the guest detect a forward-compatible
    /// blob written by a newer host with the same `BatchHeader` size
    /// but different downstream tail.
    pub _reserved: u32,
}

pub const BATCH_HEADER_BYTES: usize = std::mem::size_of::<BatchHeader>();
pub const COLUMN_HEADER_BYTES: usize = std::mem::size_of::<ColumnHeader>();

/// Per-column header, byte-packed `#[repr(C)]`. The guest reads these
/// sequentially out of the `[ColumnHeader; column_count]` array.
///
/// Field order matters for ABI stability - never reorder. Adding new
/// fields is allowed (it grows the header size; the
/// [`COLUMN_HEADER_BYTES`] constant is the SSOT for both sides) but
/// reordering existing fields is not.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnHeader {
    /// [`ColumnDtype`] tag.
    pub dtype: u8,
    pub _pad: [u8; 3],
    /// Byte offset of the column data buffer relative to the blob.
    /// For fixed-width dtypes the buffer holds
    /// `row_count × dtype.size_bytes()` bytes.
    pub data_offset: u32,
    /// Byte offset of the validity bitmap relative to the blob.
    /// `0` means "no validity bitmap - every row valid".
    pub validity_offset: u32,
    /// Byte offset of the column name (UTF-8, no terminator).
    pub name_offset: u32,
    /// Length of the column name in bytes.
    pub name_len: u32,
    /// **Variable-width dtypes only:** byte offset of the heap-bytes
    /// buffer relative to the blob. `0` for fixed-width dtypes (no
    /// heap region present); for var-width dtypes with no >12-byte
    /// slots the heap is still emitted (possibly empty) and this
    /// points at it. Phase 1.5+.
    pub heap_offset: u32,
    /// **Variable-width dtypes only:** length of the heap-bytes buffer
    /// in bytes. `0` for fixed-width dtypes. The guest validates
    /// every long-slot's `heap_offset + len` falls within
    /// `heap_offset..heap_offset+heap_len`. Phase 1.5+.
    pub heap_len: u32,
    /// `1` ⇒ this column is CONSTANT: the data buffer holds exactly
    /// one element's bytes (`dtype.size_bytes()`), logically broadcast
    /// across every row `0..row_count`. `0` ⇒ the ordinary per-row
    /// layout (`row_count × dtype.size_bytes()` bytes). See
    /// [`encode_batch_with_constants`]; produced only on the host→guest
    /// direction today - a reply blob with `is_constant != 0` is a
    /// decode error (constant OUTPUT columns are not yet supported).
    pub is_constant: u32,
}

/// Offsets used to lay a [`ColumnarBatch`] into a contiguous host-side
/// buffer (which the host then copies into the guest's linmem).
///
/// Computed in two passes: first the headers (fixed size), then each
/// column's data/validity/name (variable, computed in declaration
/// order). The result is a `Vec<u8>` the guest can index by absolute
/// offset to reach any byte.
#[derive(Debug)]
pub struct EncodedBatch {
    pub bytes: Vec<u8>,
    /// Per-column data offsets - handy for tests and the bench
    /// extrapolation that wants to assert "the i-th column's first
    /// byte is at offset N". Same order as
    /// [`ColumnarBatch::columns`].
    pub column_data_offsets: Vec<u32>,
}

// ---- shared encoder core -----------------------------------------------
//
// `encode_batch`, `encode_batch_with_constants`, and
// `encode_batch_ptr_slots` all funnel through `encode_columns` so the
// three entry points can never drift on alignment, header field order,
// or validation - the wire format is defined ONCE.

/// Internal: how one column's bytes are sourced during the shared
/// layout-and-write pass. Not public; each entry point builds
/// [`ColumnSpec`]s from its own input type.
enum ColumnSource<'a> {
    /// Ordinary per-row buffer - [`encode_batch`]'s existing contract,
    /// unchanged: `row_count × dtype.size_bytes()` bytes (fixed-width)
    /// or `row_count × INLINE_SLOT_BYTES` slots plus a caller-built
    /// `heap` (variable-width).
    Rows {
        data: &'a [u8],
        heap: Option<&'a [u8]>,
    },
    /// One value broadcast across every row (`is_constant = 1` on the
    /// wire). Fixed-width dtypes only; `value` is exactly
    /// `dtype.size_bytes()` bytes.
    Constant { value: &'a [u8] },
    /// Variable-width rows whose long slots (`len > 12`) carry a raw
    /// host pointer at byte offset 8 (little-endian `usize`, valid to
    /// dereference for `len` bytes) instead of a heap offset. See
    /// [`encode_batch_ptr_slots`]'s safety contract.
    PtrSlotRows { data: &'a [u8] },
}

/// Internal: one column's full encode instructions.
struct ColumnSpec<'a> {
    name: &'a str,
    dtype: ColumnDtype,
    source: ColumnSource<'a>,
    /// `Rows` / `PtrSlotRows`: `None` = all valid, `Some(bitmap)` = a
    /// `ceil(row_count/8)`-byte packed bitmap (today's convention).
    /// `Constant`: `None` = valid, `Some(&[0])` = NULL for every row -
    /// the natural one-byte specialization of the same bit-set-valid
    /// convention.
    validity: Option<&'a [u8]>,
}

/// Sentinel one-byte "invalid" bitmap for a NULL constant column - bit
/// 0 clear, matching the bit-set-valid convention at 1-byte scale.
const CONSTANT_NULL_VALIDITY: [u8; 1] = [0];

/// Per-column byte counts computed during validation, reused by the
/// layout and write passes so slot-heap scanning (for `PtrSlotRows`)
/// and dtype/size lookups happen exactly once.
struct ColumnSizes {
    data_len: usize,
    heap_present: bool,
    heap_len: usize,
    is_constant: bool,
}

fn size_overflow_err(idx: usize, name: &str, row_count: u32, stride: usize) -> AfterburnerError {
    AfterburnerError::Engine(format!(
        "column[{idx}] '{name}' size overflow: {row_count} × {stride}",
    ))
}

/// Cross-validate slot heap_offsets for a caller-built heap: every
/// long slot must point at a valid sub-range of `heap`. Catches
/// malformed inputs at encode time so the guest never sees a bad
/// pointer. Shared by [`encode_batch`] and [`encode_batch_with_constants`]
/// (via `ColumnSource::Rows`).
fn validate_slot_heap_offsets(
    idx: usize,
    name: &str,
    data: &[u8],
    heap: &[u8],
    row_count: u32,
) -> Result<(), AfterburnerError> {
    for r in 0..row_count as usize {
        let slot_off = r * INLINE_SLOT_BYTES;
        let slot = &data[slot_off..slot_off + INLINE_SLOT_BYTES];
        let len = u32::from_le_bytes(slot[0..4].try_into().unwrap()) as usize;
        if len > INLINE_SLOT_INLINE_MAX {
            let heap_off = u32::from_le_bytes(slot[12..16].try_into().unwrap()) as usize;
            if heap_off.checked_add(len).is_none_or(|end| end > heap.len()) {
                return Err(AfterburnerError::Engine(format!(
                    "column[{idx}] '{name}' row {r}: slot len={len}, heap_off={heap_off}, heap_len={} - out of bounds",
                    heap.len(),
                )));
            }
        }
    }
    Ok(())
}

/// Sum the value lengths of every long slot (`len > 12`) in a ptr-slot
/// column - the total heap bytes [`encode_batch_ptr_slots`] will need
/// to reserve for it. Reads only the `len` field of each slot (never
/// the pointer bytes), so this half of the scan needs no `unsafe`.
fn ptr_slot_heap_len(data: &[u8], row_count: u32) -> Result<usize, AfterburnerError> {
    let mut total = 0usize;
    for r in 0..row_count as usize {
        let slot_off = r * INLINE_SLOT_BYTES;
        let slot = &data[slot_off..slot_off + INLINE_SLOT_BYTES];
        let len = u32::from_le_bytes(slot[0..4].try_into().unwrap()) as usize;
        if len > INLINE_SLOT_INLINE_MAX {
            total = total
                .checked_add(len)
                .ok_or_else(|| AfterburnerError::Engine("ptr-slot heap length overflow".into()))?;
        }
    }
    Ok(total)
}

/// Write a ptr-slot column's rewritten slot array + dereferenced heap
/// bytes directly into the output blob - the E6 elimination of the
/// intermediate heap-buffer materialization `encode_batch` requires:
/// every long slot's value bytes are copied exactly ONCE, straight
/// from the caller's pointer into their final blob position.
///
/// # Safety
/// Every long slot (`len > 12`) in `data` must carry, at byte offset
/// `8..16` (little-endian), a `usize` pointer valid for reads of `len`
/// bytes, for the duration of this call. Upheld transitively by
/// [`encode_batch_ptr_slots`]'s own safety contract - this function is
/// only ever reached through specs that function builds.
unsafe fn write_ptr_slot_rows(
    bytes: &mut [u8],
    data_off: usize,
    heap_off: usize,
    data: &[u8],
    row_count: u32,
) {
    let mut heap_cursor = 0usize;
    for r in 0..row_count as usize {
        let slot_off = r * INLINE_SLOT_BYTES;
        let slot = &data[slot_off..slot_off + INLINE_SLOT_BYTES];
        let len = u32::from_le_bytes(slot[0..4].try_into().unwrap()) as usize;
        let dst_slot_off = data_off + slot_off;
        if len <= INLINE_SLOT_INLINE_MAX {
            // Inline: the slot is already self-contained - copy verbatim.
            bytes[dst_slot_off..dst_slot_off + INLINE_SLOT_BYTES].copy_from_slice(slot);
            continue;
        }
        // Long slot: len + prefix (bytes 0..8) carry straight over.
        bytes[dst_slot_off..dst_slot_off + 8].copy_from_slice(&slot[0..8]);
        let ptr = usize::from_le_bytes(slot[8..16].try_into().unwrap()) as *const u8;
        // SAFETY: caller's contract (see this fn's doc / the public
        // `encode_batch_ptr_slots` safety contract).
        let value = unsafe { std::slice::from_raw_parts(ptr, len) };
        let dst_heap_off = heap_off + heap_cursor;
        bytes[dst_heap_off..dst_heap_off + len].copy_from_slice(value);
        // Bytes 8..12 are unused for a long slot on the wire (mirrors
        // `encode_batch`'s shape exactly); zero them, then write the
        // computed heap_off at 12..16.
        bytes[dst_slot_off + 8..dst_slot_off + 12].fill(0);
        write_u32_le(
            bytes,
            dst_slot_off + 12,
            u32_from_usize(heap_cursor).unwrap_or(0),
        );
        heap_cursor += len;
    }
}

/// The shared layout-and-write pass behind every `encode_batch*`
/// entry point. See the module's "wire-level header layout" section
/// for the byte format this produces.
fn encode_columns(
    row_count: u32,
    specs: &[ColumnSpec<'_>],
) -> Result<EncodedBatch, AfterburnerError> {
    let column_count = specs.len();
    if column_count > u32::MAX as usize {
        return Err(AfterburnerError::Engine(format!(
            "ColumnarBatch column_count {column_count} exceeds u32::MAX",
        )));
    }

    // ---- validation + per-column byte-count pass ----
    let mut sizes: Vec<ColumnSizes> = Vec::with_capacity(column_count);
    for (idx, spec) in specs.iter().enumerate() {
        if !spec.dtype.is_phase1_supported() {
            return Err(AfterburnerError::Engine(format!(
                "column[{idx}] '{}' has dtype {:?} which is reserved but not yet implemented in this Afterburner version",
                spec.name, spec.dtype,
            )));
        }

        // Validate the validity bitmap's shape up front; its bytes are
        // re-read directly from `spec.validity` in the layout pass
        // below, so nothing needs to be threaded out of this match.
        match (&spec.source, spec.validity) {
            (_, None) => {}
            (ColumnSource::Constant { .. }, Some(bm)) => {
                if bm.len() != 1 {
                    return Err(AfterburnerError::Engine(format!(
                        "column[{idx}] '{}': constant validity must be exactly 1 byte, got {}",
                        spec.name,
                        bm.len(),
                    )));
                }
            }
            (_, Some(bm)) => {
                let need = row_count.div_ceil(8) as usize;
                if bm.len() < need {
                    return Err(AfterburnerError::Engine(format!(
                        "column[{idx}] '{}': validity bitmap has {} bytes but {} rows need ≥ {}",
                        spec.name,
                        bm.len(),
                        row_count,
                        need,
                    )));
                }
            }
        }

        match &spec.source {
            ColumnSource::Rows { data, heap } => {
                let stride = spec.dtype.size_bytes()?;
                let expected = stride
                    .checked_mul(row_count as usize)
                    .ok_or_else(|| size_overflow_err(idx, spec.name, row_count, stride))?;
                if data.len() != expected {
                    return Err(AfterburnerError::Engine(format!(
                        "column[{idx}] '{}': data.len() = {} but expected {} ({} rows × {} bytes)",
                        spec.name,
                        data.len(),
                        expected,
                        row_count,
                        stride,
                    )));
                }
                if spec.dtype.is_fixed_width() {
                    if heap.is_some() {
                        return Err(AfterburnerError::Engine(format!(
                            "column[{idx}] '{}': dtype {:?} is fixed-width - `heap` must be None",
                            spec.name, spec.dtype,
                        )));
                    }
                } else {
                    let Some(heap) = heap else {
                        return Err(AfterburnerError::Engine(format!(
                            "column[{idx}] '{}': dtype {:?} is variable-width - `heap` is required (use Some(&[]) for empty)",
                            spec.name, spec.dtype,
                        )));
                    };
                    validate_slot_heap_offsets(idx, spec.name, data, heap, row_count)?;
                }
                sizes.push(ColumnSizes {
                    data_len: data.len(),
                    heap_present: heap.is_some(),
                    heap_len: heap.map_or(0, |h| h.len()),
                    is_constant: false,
                });
            }
            ColumnSource::Constant { value } => {
                if !spec.dtype.is_fixed_width() {
                    return Err(AfterburnerError::Engine(format!(
                        "column[{idx}] '{}': constant columns support fixed-width dtypes only (got {:?}); \
                         encode a length-1 Rows column with its own heap for a variable-width constant",
                        spec.name, spec.dtype,
                    )));
                }
                let stride = spec.dtype.size_bytes()?;
                if value.len() != stride {
                    return Err(AfterburnerError::Engine(format!(
                        "column[{idx}] '{}': constant value.len() = {} but dtype {:?} needs {}",
                        spec.name,
                        value.len(),
                        spec.dtype,
                        stride,
                    )));
                }
                sizes.push(ColumnSizes {
                    data_len: value.len(),
                    heap_present: false,
                    heap_len: 0,
                    is_constant: true,
                });
            }
            ColumnSource::PtrSlotRows { data } => {
                if spec.dtype.is_fixed_width() {
                    return Err(AfterburnerError::Engine(format!(
                        "column[{idx}] '{}': ptr-slot columns support variable-width dtypes only (got {:?})",
                        spec.name, spec.dtype,
                    )));
                }
                let expected = INLINE_SLOT_BYTES
                    .checked_mul(row_count as usize)
                    .ok_or_else(|| {
                        size_overflow_err(idx, spec.name, row_count, INLINE_SLOT_BYTES)
                    })?;
                if data.len() != expected {
                    return Err(AfterburnerError::Engine(format!(
                        "column[{idx}] '{}': data.len() = {} but expected {} ({} rows × {} bytes)",
                        spec.name,
                        data.len(),
                        expected,
                        row_count,
                        INLINE_SLOT_BYTES,
                    )));
                }
                sizes.push(ColumnSizes {
                    data_len: data.len(),
                    heap_present: true,
                    heap_len: ptr_slot_heap_len(data, row_count)?,
                    is_constant: false,
                });
            }
        }
    }

    // ---- layout pass: header, column-header table, then per column
    // data / validity / name / heap. 8-byte-align every data region so
    // TypedArray views land on natural boundaries - Wasmtime/QuickJS
    // reject a misaligned `new Float64Array(buf, off, len)`. Names and
    // heaps are 1-byte aligned. ----
    let header_end = BATCH_HEADER_BYTES;
    let column_table_end = header_end + COLUMN_HEADER_BYTES * column_count;
    let mut cursor = align_up(column_table_end, 8);

    let mut headers: Vec<ColumnHeader> = Vec::with_capacity(column_count);
    let mut column_data_offsets: Vec<u32> = Vec::with_capacity(column_count);
    for (spec, sz) in specs.iter().zip(sizes.iter()) {
        cursor = align_up(cursor, 8);
        let data_offset = u32_from_usize(cursor)?;
        cursor += sz.data_len;
        column_data_offsets.push(data_offset);

        let validity_offset = if let Some(bm) = spec.validity {
            let v = u32_from_usize(cursor)?;
            cursor += bm.len();
            v
        } else {
            0
        };

        let name_offset = u32_from_usize(cursor)?;
        cursor += spec.name.len();
        let name_len = u32_from_usize(spec.name.len())?;

        let (heap_offset, heap_len) = if sz.heap_present {
            let off = u32_from_usize(cursor)?;
            cursor += sz.heap_len;
            (off, u32_from_usize(sz.heap_len)?)
        } else {
            (0, 0)
        };

        headers.push(ColumnHeader {
            dtype: spec.dtype as u8,
            _pad: [0; 3],
            data_offset,
            validity_offset,
            name_offset,
            name_len,
            heap_offset,
            heap_len,
            is_constant: sz.is_constant as u32,
        });
    }

    // ---- write pass ----
    let mut bytes = vec![0u8; cursor];
    write_u32_le(&mut bytes, 0, row_count);
    write_u32_le(&mut bytes, 4, column_count as u32);
    write_u32_le(&mut bytes, 8, u32_from_usize(header_end)?);
    write_u32_le(&mut bytes, 12, 0);

    let mut h_off = header_end;
    for ch in &headers {
        bytes[h_off] = ch.dtype;
        bytes[h_off + 1] = ch._pad[0];
        bytes[h_off + 2] = ch._pad[1];
        bytes[h_off + 3] = ch._pad[2];
        write_u32_le(&mut bytes, h_off + 4, ch.data_offset);
        write_u32_le(&mut bytes, h_off + 8, ch.validity_offset);
        write_u32_le(&mut bytes, h_off + 12, ch.name_offset);
        write_u32_le(&mut bytes, h_off + 16, ch.name_len);
        write_u32_le(&mut bytes, h_off + 20, ch.heap_offset);
        write_u32_le(&mut bytes, h_off + 24, ch.heap_len);
        write_u32_le(&mut bytes, h_off + 28, ch.is_constant);
        h_off += COLUMN_HEADER_BYTES;
    }

    for (spec, ch) in specs.iter().zip(headers.iter()) {
        let data_off = ch.data_offset as usize;
        match &spec.source {
            ColumnSource::Rows { data, .. } => {
                bytes[data_off..data_off + data.len()].copy_from_slice(data);
            }
            ColumnSource::Constant { value } => {
                bytes[data_off..data_off + value.len()].copy_from_slice(value);
            }
            ColumnSource::PtrSlotRows { data } => {
                // SAFETY: only reachable via `encode_batch_ptr_slots`,
                // whose own `unsafe fn` contract is the caller's
                // obligation for every pointer these slots carry.
                unsafe {
                    write_ptr_slot_rows(
                        &mut bytes,
                        data_off,
                        ch.heap_offset as usize,
                        data,
                        row_count,
                    );
                }
            }
        }
        if let Some(bm) = spec.validity {
            let v_off = ch.validity_offset as usize;
            bytes[v_off..v_off + bm.len()].copy_from_slice(bm);
        }
        let n_off = ch.name_offset as usize;
        bytes[n_off..n_off + spec.name.len()].copy_from_slice(spec.name.as_bytes());
        if let ColumnSource::Rows {
            heap: Some(heap), ..
        } = &spec.source
        {
            let h_off = ch.heap_offset as usize;
            bytes[h_off..h_off + heap.len()].copy_from_slice(heap);
        }
        // `PtrSlotRows` heap bytes are written inside
        // `write_ptr_slot_rows` above - gathered directly from the
        // caller's pointers, no intermediate buffer.
    }

    Ok(EncodedBatch {
        bytes,
        column_data_offsets,
    })
}

/// Serialise a [`ColumnarBatch`] to its on-the-wire byte representation.
/// The output is one contiguous `Vec<u8>` ready to copy into wasm
/// linear memory.
///
/// The serialiser does the *only* host-side `memcpy` per column -
/// from the caller's slice into the staging buffer that becomes the
/// guest blob. The guest reads the blob in place via TypedArray views;
/// no second copy on the guest side.
///
/// Phase 1 errors with [`AfterburnerError::Engine`] if any column has
/// a dtype that's not [`ColumnDtype::is_phase1_supported`] (Utf8 /
/// Bytea / Jsonb / Decimal128 / Interval / Uuid). Tags exist in the
/// enum so the wire format stays stable, but the host path doesn't
/// know how to lay them out yet.
pub fn encode_batch(batch: &ColumnarBatch<'_>) -> Result<EncodedBatch, AfterburnerError> {
    let specs: Vec<ColumnSpec<'_>> = batch
        .columns
        .iter()
        .map(|col| ColumnSpec {
            name: col.name,
            dtype: col.dtype,
            source: ColumnSource::Rows {
                data: col.data,
                heap: col.heap,
            },
            validity: col.validity,
        })
        .collect();
    encode_columns(batch.row_count, &specs)
}

/// Like [`encode_batch`], but additionally accepts [`ConstantColumnRef`]
/// columns: a scalar value broadcast across every row at O(1) transfer
/// cost, appended after `batch`'s ordinary columns. Column order does
/// not affect guest-side access (the dispatcher looks columns up by
/// name), so this is a pure superset of `encode_batch`'s behaviour -
/// `constants: &[]` produces a byte-identical blob to `encode_batch`
/// (every `is_constant` field is `0`).
pub fn encode_batch_with_constants(
    batch: &ColumnarBatch<'_>,
    constants: &[ConstantColumnRef<'_>],
) -> Result<EncodedBatch, AfterburnerError> {
    let mut specs: Vec<ColumnSpec<'_>> = Vec::with_capacity(batch.columns.len() + constants.len());
    specs.extend(batch.columns.iter().map(|col| ColumnSpec {
        name: col.name,
        dtype: col.dtype,
        source: ColumnSource::Rows {
            data: col.data,
            heap: col.heap,
        },
        validity: col.validity,
    }));
    specs.extend(constants.iter().map(|c| ColumnSpec {
        name: c.name,
        dtype: c.dtype,
        source: ColumnSource::Constant { value: c.value },
        validity: if c.valid {
            None
        } else {
            Some(&CONSTANT_NULL_VALIDITY[..])
        },
    }));
    encode_columns(batch.row_count, &specs)
}

/// Like [`encode_batch`], but variable-width columns may be supplied
/// as [`PtrSlotColumnRef`] - long slots carrying a raw host pointer
/// instead of a pre-built heap offset, dereferenced and copied
/// directly into the output blob during the same layout-and-write
/// pass. This eliminates the intermediate slot+heap materialization an
/// embedder would otherwise pay before calling `encode_batch`: ONE
/// copy of each long value's bytes (pointer → blob) instead of TWO
/// (pointer → scratch heap → blob).
///
/// # Safety
/// For every [`PtrSlotColumn::PtrSlot`] column in `batch`, every long
/// slot (`len > 12`) must carry, at byte offset `8..16` (little-endian),
/// a `usize` pointer valid for reads of `len` bytes, and that memory
/// must remain valid and not be mutated for the duration of this call.
pub unsafe fn encode_batch_ptr_slots(
    batch: &PtrSlotBatch<'_>,
) -> Result<EncodedBatch, AfterburnerError> {
    let specs: Vec<ColumnSpec<'_>> = batch
        .columns
        .iter()
        .map(|col| match col {
            PtrSlotColumn::Ref(r) => ColumnSpec {
                name: r.name,
                dtype: r.dtype,
                source: ColumnSource::Rows {
                    data: r.data,
                    heap: r.heap,
                },
                validity: r.validity,
            },
            PtrSlotColumn::PtrSlot(p) => ColumnSpec {
                name: p.name,
                dtype: p.dtype,
                source: ColumnSource::PtrSlotRows { data: p.data },
                validity: p.validity,
            },
        })
        .collect();
    encode_columns(batch.row_count, &specs)
}

/// Decode the columnar reply blob the guest wrote back.
///
/// The guest emits the same wire shape as [`encode_batch`] produces -
/// `BatchHeader` + per-column headers + column buffers - so the host
/// reads it identically. Each output column is `memcpy`'d out of the
/// guest's linmem into a host-owned `Vec<u8>` because the Store is
/// about to drop and the linmem with it.
pub fn decode_batch(blob: &[u8]) -> Result<ColumnarOutput, AfterburnerError> {
    if blob.len() < BATCH_HEADER_BYTES {
        return Err(AfterburnerError::Engine(format!(
            "columnar reply too short: {} bytes < BatchHeader {BATCH_HEADER_BYTES}",
            blob.len(),
        )));
    }
    let row_count = read_u32_le(blob, 0);
    let column_count = read_u32_le(blob, 4);
    let columns_offset = read_u32_le(blob, 8) as usize;
    if columns_offset
        .checked_add(COLUMN_HEADER_BYTES * column_count as usize)
        .is_none_or(|end| end > blob.len())
    {
        return Err(AfterburnerError::Engine(format!(
            "columnar reply column-table out of bounds: columns_offset={columns_offset}, count={column_count}, blob_len={}",
            blob.len(),
        )));
    }

    let mut columns: Vec<OwnedColumn> = Vec::with_capacity(column_count as usize);
    for i in 0..column_count as usize {
        let h_off = columns_offset + i * COLUMN_HEADER_BYTES;
        let dtype = ColumnDtype::from_u8(blob[h_off])?;
        let data_offset = read_u32_le(blob, h_off + 4) as usize;
        let validity_offset = read_u32_le(blob, h_off + 8) as usize;
        let name_offset = read_u32_le(blob, h_off + 12) as usize;
        let name_len = read_u32_le(blob, h_off + 16) as usize;
        let heap_offset = read_u32_le(blob, h_off + 20) as usize;
        let heap_len = read_u32_le(blob, h_off + 24) as usize;
        let is_constant = read_u32_le(blob, h_off + 28);
        if is_constant != 0 {
            // Constant columns (see `encode_batch_with_constants`) are
            // a host→guest optimization only; no guest emits one on
            // the reply path today. Fail loud rather than silently
            // mis-decode a `data` region that is `dtype.size_bytes()`
            // bytes instead of the `row_count`-sized buffer the rest
            // of this function assumes.
            return Err(AfterburnerError::Engine(format!(
                "columnar reply column[{i}]: constant output columns are not supported (is_constant={is_constant})",
            )));
        }

        let stride = dtype.size_bytes()?;
        let data_len = stride.checked_mul(row_count as usize).ok_or_else(|| {
            AfterburnerError::Engine(format!(
                "decode column[{i}] size overflow: {row_count} × {stride}",
            ))
        })?;
        if data_offset
            .checked_add(data_len)
            .is_none_or(|end| end > blob.len())
        {
            return Err(AfterburnerError::Engine(format!(
                "columnar reply column[{i}] data out of bounds: data_offset={data_offset}, len={data_len}, blob_len={}",
                blob.len(),
            )));
        }
        let data = blob[data_offset..data_offset + data_len].to_vec();

        let validity = if validity_offset == 0 {
            None
        } else {
            let v_len = (row_count as usize).div_ceil(8);
            if validity_offset
                .checked_add(v_len)
                .is_none_or(|end| end > blob.len())
            {
                return Err(AfterburnerError::Engine(format!(
                    "columnar reply column[{i}] validity out of bounds: validity_offset={validity_offset}, len={v_len}, blob_len={}",
                    blob.len(),
                )));
            }
            Some(blob[validity_offset..validity_offset + v_len].to_vec())
        };

        if name_offset
            .checked_add(name_len)
            .is_none_or(|end| end > blob.len())
        {
            return Err(AfterburnerError::Engine(format!(
                "columnar reply column[{i}] name out of bounds: name_offset={name_offset}, len={name_len}, blob_len={}",
                blob.len(),
            )));
        }
        let name = std::str::from_utf8(&blob[name_offset..name_offset + name_len])
            .map_err(|e| {
                AfterburnerError::Engine(format!("columnar reply column[{i}] name not UTF-8: {e}"))
            })?
            .to_string();

        // Read the heap buffer for variable-width dtypes. Fixed-width
        // columns must have heap_len == 0 (and heap_offset == 0); we
        // tolerate non-zero heap_offset for fixed-width as long as
        // heap_len is zero (defensive - guest may write any value).
        let heap = if dtype.is_fixed_width() {
            if heap_len != 0 {
                return Err(AfterburnerError::Engine(format!(
                    "columnar reply column[{i}] '{name}': fixed-width dtype {dtype:?} has non-zero heap_len {heap_len}",
                )));
            }
            None
        } else {
            if heap_offset
                .checked_add(heap_len)
                .is_none_or(|end| end > blob.len())
            {
                return Err(AfterburnerError::Engine(format!(
                    "columnar reply column[{i}] '{name}' heap out of bounds: heap_offset={heap_offset}, len={heap_len}, blob_len={}",
                    blob.len(),
                )));
            }
            Some(blob[heap_offset..heap_offset + heap_len].to_vec())
        };

        columns.push(OwnedColumn {
            name,
            dtype,
            data,
            heap,
            validity,
        });
    }

    Ok(ColumnarOutput { row_count, columns })
}

// ---- helpers ----------------------------------------------------------

fn align_up(x: usize, a: usize) -> usize {
    debug_assert!(a.is_power_of_two());
    (x + a - 1) & !(a - 1)
}

fn u32_from_usize(x: usize) -> Result<u32, AfterburnerError> {
    u32::try_from(x)
        .map_err(|_| AfterburnerError::Engine(format!("columnar offset {x} exceeds u32::MAX")))
}

fn write_u32_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Validate that `name` is safe to interpolate verbatim into generated
/// guest source. Used by [`crate::pyodide_columnar`] and
/// [`crate::ruby_columnar`], whose columnar invocation primitive
/// composes a driver script around a caller-supplied entry-point name
/// (there is no host-import call boundary for those runtimes the way
/// there is for the wasm/JS plugin - see each module's docs). Restricted
/// to a plain identifier (`[A-Za-z_][A-Za-z0-9_]*`) so it can never break
/// out of the call-expression position it is spliced into, regardless of
/// where the name ultimately originated (e.g. a UDF catalog row).
pub(crate) fn validate_entry_fn_name(name: &str) -> Result<(), AfterburnerError> {
    let mut chars = name.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        return Err(AfterburnerError::Engine(format!(
            "columnar UDF entry_fn {name:?} is not a valid identifier \
             ([A-Za-z_][A-Za-z0-9_]*) - refusing to splice it into generated guest source",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_validity_for(row_count: u32) -> Vec<u8> {
        // Every row valid: all bits set up to row_count, padding bits 0.
        let bytes = (row_count as usize).div_ceil(8);
        let full = vec![0xffu8; bytes];
        if !row_count.is_multiple_of(8) {
            let mut v = full.clone();
            let last = bytes - 1;
            let bits = (row_count % 8) as u8;
            v[last] = (1u8 << bits) - 1;
            v
        } else {
            full
        }
    }

    #[test]
    fn dtype_size_bytes_fixed_width() {
        assert_eq!(ColumnDtype::Bool.size_bytes().unwrap(), 1);
        assert_eq!(ColumnDtype::Int8.size_bytes().unwrap(), 1);
        assert_eq!(ColumnDtype::Int16.size_bytes().unwrap(), 2);
        assert_eq!(ColumnDtype::Int32.size_bytes().unwrap(), 4);
        assert_eq!(ColumnDtype::Int64.size_bytes().unwrap(), 8);
        assert_eq!(ColumnDtype::Float32.size_bytes().unwrap(), 4);
        assert_eq!(ColumnDtype::Float64.size_bytes().unwrap(), 8);
        assert_eq!(ColumnDtype::Date32.size_bytes().unwrap(), 4);
        assert_eq!(ColumnDtype::Timestamp.size_bytes().unwrap(), 8);
        assert_eq!(ColumnDtype::Decimal128.size_bytes().unwrap(), 16);
        assert_eq!(ColumnDtype::Uuid.size_bytes().unwrap(), 16);
        assert_eq!(ColumnDtype::Interval.size_bytes().unwrap(), 16);
    }

    #[test]
    fn dtype_size_bytes_variable_width_returns_inline_slot() {
        // Phase 1.5: variable-width dtypes return INLINE_SLOT_BYTES
        // (16) for the slot array. The actual bytes for >12-byte
        // values live in a separate heap buffer.
        assert_eq!(ColumnDtype::Utf8.size_bytes().unwrap(), INLINE_SLOT_BYTES);
        assert_eq!(ColumnDtype::Bytea.size_bytes().unwrap(), INLINE_SLOT_BYTES);
        assert_eq!(ColumnDtype::Jsonb.size_bytes().unwrap(), INLINE_SLOT_BYTES);
    }

    #[test]
    fn dtype_phase1_supported_matches_expectation() {
        // Numeric / Bool / Date32 / Timestamp ship in Phase 1.
        for d in [
            ColumnDtype::Bool,
            ColumnDtype::Int8,
            ColumnDtype::Int16,
            ColumnDtype::Int32,
            ColumnDtype::Int64,
            ColumnDtype::UInt8,
            ColumnDtype::UInt16,
            ColumnDtype::UInt32,
            ColumnDtype::UInt64,
            ColumnDtype::Float32,
            ColumnDtype::Float64,
            ColumnDtype::Date32,
            ColumnDtype::Timestamp,
            // Phase 1.5: variable-width dtypes are now supported.
            ColumnDtype::Utf8,
            ColumnDtype::Bytea,
            ColumnDtype::Jsonb,
        ] {
            assert!(d.is_phase1_supported(), "{:?} should be supported", d);
        }
        // 16-byte fixed dtypes are reserved for a later phase.
        for d in [
            ColumnDtype::Decimal128,
            ColumnDtype::Uuid,
            ColumnDtype::Interval,
        ] {
            assert!(!d.is_phase1_supported(), "{:?} should be unsupported", d);
        }
    }

    #[test]
    fn from_u8_roundtrips_every_known_tag() {
        for tag in 1u8..=19 {
            let d = ColumnDtype::from_u8(tag).unwrap();
            assert_eq!(d as u8, tag, "tag {tag} round-trips to itself");
        }
    }

    #[test]
    fn from_u8_unknown_tag_is_err() {
        assert!(ColumnDtype::from_u8(0).is_err());
        assert!(ColumnDtype::from_u8(99).is_err());
        assert!(ColumnDtype::from_u8(255).is_err());
    }

    #[test]
    fn encode_decode_roundtrip_two_int32_columns_no_validity() {
        // 4 rows × 2 Int32 columns: c0 = [1,2,3,4], c1 = [10,20,30,40].
        let c0_data: Vec<u8> = [1i32, 2, 3, 4]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let c1_data: Vec<u8> = [10i32, 20, 30, 40]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let mut batch = ColumnarBatch::new(4);
        batch.push(ColumnRef {
            name: "c0",
            dtype: ColumnDtype::Int32,
            data: &c0_data,
            heap: None,
            validity: None,
        });
        batch.push(ColumnRef {
            name: "c1",
            dtype: ColumnDtype::Int32,
            data: &c1_data,
            heap: None,
            validity: None,
        });

        let encoded = encode_batch(&batch).unwrap();
        // Decode through the same path the host uses for the reply
        // (the wire format is symmetric in/out).
        let decoded = decode_batch(&encoded.bytes).unwrap();

        assert_eq!(decoded.row_count, 4);
        assert_eq!(decoded.columns.len(), 2);
        assert_eq!(decoded.columns[0].name, "c0");
        assert_eq!(decoded.columns[0].dtype, ColumnDtype::Int32);
        assert_eq!(decoded.columns[0].data, c0_data);
        assert!(decoded.columns[0].validity.is_none());
        assert_eq!(decoded.columns[1].name, "c1");
        assert_eq!(decoded.columns[1].data, c1_data);
    }

    #[test]
    fn encode_decode_roundtrip_with_validity() {
        let data: Vec<u8> = [100i64, 200, 300]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let validity = dummy_validity_for(3);
        let mut batch = ColumnarBatch::new(3);
        batch.push(ColumnRef {
            name: "with_validity",
            dtype: ColumnDtype::Int64,
            data: &data,
            heap: None,
            validity: Some(&validity),
        });

        let encoded = encode_batch(&batch).unwrap();
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.row_count, 3);
        assert_eq!(decoded.columns[0].dtype, ColumnDtype::Int64);
        assert_eq!(decoded.columns[0].data, data);
        let v = decoded.columns[0].validity.as_ref().unwrap();
        // Bits 0..3 set, the rest are padding.
        assert_eq!(v[0] & 0b111, 0b111);
    }

    #[test]
    fn encode_rejects_data_length_mismatch() {
        // Int32 column with 4 rows but only 12 bytes (3 elements).
        let data = vec![0u8; 12];
        let mut batch = ColumnarBatch::new(4);
        batch.push(ColumnRef {
            name: "bad",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: None,
            validity: None,
        });
        let err = encode_batch(&batch).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("data.len()"), "got {msg}");
    }

    #[test]
    fn encode_rejects_phase1_unsupported_dtype() {
        let data = vec![0u8; 16]; // 1 row × 16 bytes (decimal128 width)
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "amount",
            dtype: ColumnDtype::Decimal128,
            data: &data,
            heap: None,
            validity: None,
        });
        let err = encode_batch(&batch).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("Decimal128"), "got {msg}");
        assert!(msg.contains("not yet implemented"), "got {msg}",);
    }

    #[test]
    fn encode_rejects_validity_too_short() {
        let data = vec![0u8; 4];
        let bm = vec![]; // 0 bytes
        let mut batch = ColumnarBatch::new(4);
        batch.push(ColumnRef {
            name: "c",
            dtype: ColumnDtype::Int8,
            data: &data,
            heap: None,
            validity: Some(&bm),
        });
        let err = encode_batch(&batch).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("validity"), "got {msg}");
    }

    #[test]
    fn decode_rejects_short_blob() {
        let err = decode_batch(&[0u8; 8]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("too short"), "got {msg}");
    }

    #[test]
    fn decode_rejects_unknown_dtype_tag() {
        // Build a minimal valid blob then corrupt the dtype byte.
        let data: Vec<u8> = 1u32.to_le_bytes().to_vec();
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: None,
            validity: None,
        });
        let mut encoded = encode_batch(&batch).unwrap();
        let h_off = BATCH_HEADER_BYTES; // first column header
        encoded.bytes[h_off] = 0xFE; // bogus tag
        let err = decode_batch(&encoded.bytes).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("unknown ColumnDtype"), "got {msg}");
    }

    #[test]
    fn encoded_offsets_are_eight_byte_aligned() {
        // QuickJS's `new Float64Array(buf, off, len)` rejects with
        // `RangeError: invalid offset` if `off & 7 != 0`. The encoder
        // must guarantee 8-aligned starts for *every* column data
        // buffer in the blob, even when previous columns had short
        // (≤ 7-byte) names that would otherwise leave the cursor
        // mid-word.
        let f64_data: Vec<u8> = [1.0f64, 2.0, 3.0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let mut batch = ColumnarBatch::new(3);
        // Six Float64 columns with 2-character names - exactly the
        // shape that broke the previous encoder (each "cN" name was
        // 4-byte aligned at the end, leaving the next column's data
        // offset at +4 mod 8).
        for n in ["c0", "c1", "c2", "c3", "c4", "c5"] {
            batch.push(ColumnRef {
                name: n,
                dtype: ColumnDtype::Float64,
                data: &f64_data,
                heap: None,
                validity: None,
            });
        }
        let encoded = encode_batch(&batch).unwrap();
        for (i, off) in encoded.column_data_offsets.iter().enumerate() {
            assert_eq!(
                *off as usize % 8,
                0,
                "column[{i}] data offset {off} must be 8-aligned",
            );
        }
    }

    #[test]
    fn encode_zero_rows_produces_header_only_blob() {
        let mut batch = ColumnarBatch::new(0);
        batch.push(ColumnRef {
            name: "empty",
            dtype: ColumnDtype::Int64,
            data: &[],
            heap: None,
            validity: None,
        });
        let encoded = encode_batch(&batch).unwrap();
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.row_count, 0);
        assert_eq!(decoded.columns.len(), 1);
        assert!(decoded.columns[0].data.is_empty());
    }

    #[test]
    fn encode_zero_columns_is_legal() {
        let batch = ColumnarBatch::new(2048);
        let encoded = encode_batch(&batch).unwrap();
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.row_count, 2048);
        assert_eq!(decoded.columns.len(), 0);
    }

    #[test]
    fn encode_max_columns_typical_workload() {
        // 32 columns × 2048 rows × Float64 - the user's billion-row
        // bench shape. Confirm the encoder handles it cleanly and
        // the resulting blob is within the per-Store linmem budget
        // (1 GiB default).
        let row_count = 2048u32;
        let col_count = 32usize;
        let buf: Vec<u8> = (0..(row_count as usize))
            .flat_map(|i| (i as f64).to_le_bytes())
            .collect();
        let mut batch = ColumnarBatch::new(row_count);
        let names: Vec<String> = (0..col_count).map(|i| format!("c{i}")).collect();
        for n in &names {
            batch.push(ColumnRef {
                name: n.as_str(),
                dtype: ColumnDtype::Float64,
                data: &buf,
                heap: None,
                validity: None,
            });
        }
        let encoded = encode_batch(&batch).unwrap();
        // Expected: 16 header + 32 × 24 col headers + 32 × (2048×8 +
        // padding + name) ≈ 528 KB. Well under any reasonable cap.
        assert!(
            encoded.bytes.len() < 1024 * 1024,
            "{} bytes",
            encoded.bytes.len()
        );
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.row_count, row_count);
        assert_eq!(decoded.columns.len(), col_count);
        for (i, col) in decoded.columns.iter().enumerate() {
            assert_eq!(col.name, format!("c{i}"));
            assert_eq!(col.dtype, ColumnDtype::Float64);
            assert_eq!(col.data, buf);
        }
    }

    /// Build a `(slots: Vec<u8>, heap: Vec<u8>)` pair from a list of
    /// byte sequences using DuckDB-style inline-or-pointer slots.
    /// Test-only - production callers (an embedder-side adapter, etc.)
    /// build their slot arrays from their own internal layouts.
    fn build_var_column(values: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
        let mut slots = vec![0u8; values.len() * INLINE_SLOT_BYTES];
        let mut heap = Vec::new();
        for (i, v) in values.iter().enumerate() {
            let sb = i * INLINE_SLOT_BYTES;
            let len_bytes = (v.len() as u32).to_le_bytes();
            slots[sb..sb + 4].copy_from_slice(&len_bytes);
            if v.len() <= INLINE_SLOT_INLINE_MAX {
                slots[sb + 4..sb + 4 + v.len()].copy_from_slice(v);
            } else {
                slots[sb + 4..sb + 8].copy_from_slice(&v[0..4]);
                let heap_off = (heap.len() as u32).to_le_bytes();
                slots[sb + 12..sb + 16].copy_from_slice(&heap_off);
                heap.extend_from_slice(v);
            }
        }
        (slots, heap)
    }

    #[test]
    fn encode_decode_roundtrip_utf8_inline_only() {
        let strs: Vec<&[u8]> = vec![b"a", b"hi", b"world!", b"hello12byte!"]; // all ≤ 12 bytes
        let (slots, heap) = build_var_column(&strs);
        let mut batch = ColumnarBatch::new(strs.len() as u32);
        batch.push(ColumnRef {
            name: "msg",
            dtype: ColumnDtype::Utf8,
            data: &slots,
            heap: Some(&heap),
            validity: None,
        });
        let encoded = encode_batch(&batch).unwrap();
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.row_count, 4);
        assert_eq!(decoded.columns[0].dtype, ColumnDtype::Utf8);
        assert_eq!(decoded.columns[0].data, slots);
        // Heap is empty (no values > 12 bytes).
        assert_eq!(decoded.columns[0].heap.as_ref().unwrap().len(), 0);
        for (i, expect) in strs.iter().enumerate() {
            assert_eq!(decoded.columns[0].row_str(i).unwrap().as_bytes(), *expect);
        }
    }

    #[test]
    fn encode_decode_roundtrip_utf8_with_heap() {
        let long: &[u8] = b"hello there friend, this is over twelve bytes for sure!";
        let strs: Vec<&[u8]> = vec![b"hi", long, b"ok", long];
        let (slots, heap) = build_var_column(&strs);
        let mut batch = ColumnarBatch::new(strs.len() as u32);
        batch.push(ColumnRef {
            name: "txt",
            dtype: ColumnDtype::Utf8,
            data: &slots,
            heap: Some(&heap),
            validity: None,
        });
        let encoded = encode_batch(&batch).unwrap();
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.row_count, 4);
        for (i, expect) in strs.iter().enumerate() {
            assert_eq!(
                decoded.columns[0].row_str(i).unwrap().as_bytes(),
                *expect,
                "row {i}",
            );
        }
    }

    #[test]
    fn encode_decode_roundtrip_bytea_with_heap() {
        let b1: Vec<u8> = (0..32).collect();
        let b2: Vec<u8> = vec![1, 2, 3];
        let strs: Vec<&[u8]> = vec![&b1, &b2, &b1];
        let (slots, heap) = build_var_column(&strs);
        let mut batch = ColumnarBatch::new(strs.len() as u32);
        batch.push(ColumnRef {
            name: "blob",
            dtype: ColumnDtype::Bytea,
            data: &slots,
            heap: Some(&heap),
            validity: None,
        });
        let encoded = encode_batch(&batch).unwrap();
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.row_count, 3);
        assert_eq!(decoded.columns[0].dtype, ColumnDtype::Bytea);
        assert_eq!(decoded.columns[0].row_bytes(0).unwrap(), b1.as_slice());
        assert_eq!(decoded.columns[0].row_bytes(1).unwrap(), b2.as_slice());
        assert_eq!(decoded.columns[0].row_bytes(2).unwrap(), b1.as_slice());
    }

    #[test]
    fn encode_rejects_var_width_without_heap() {
        let strs: Vec<&[u8]> = vec![b"hi"];
        let (slots, _) = build_var_column(&strs);
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Utf8,
            data: &slots,
            heap: None,
            validity: None,
        });
        let err = encode_batch(&batch).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("variable-width"), "got {msg}");
    }

    #[test]
    fn encode_rejects_fixed_width_with_heap() {
        let data = vec![0u8; 4]; // 1 row × Int32
        let heap = vec![1u8; 8];
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: Some(&heap),
            validity: None,
        });
        let err = encode_batch(&batch).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("fixed-width"), "got {msg}");
    }

    #[test]
    fn encode_rejects_var_width_long_slot_out_of_heap() {
        // Hand-craft a slot that claims a 16-byte value with
        // heap_offset that points past the end of the heap.
        let mut slots = vec![0u8; INLINE_SLOT_BYTES];
        slots[0..4].copy_from_slice(&13u32.to_le_bytes()); // len=13 (long)
        slots[12..16].copy_from_slice(&100u32.to_le_bytes()); // heap_off=100
        let heap = vec![0u8; 8]; // only 8 bytes - out of range
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Utf8,
            data: &slots,
            heap: Some(&heap),
            validity: None,
        });
        let err = encode_batch(&batch).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("out of bounds"), "got {msg}");
    }

    #[test]
    fn header_struct_sizes_match_constants() {
        assert_eq!(
            BATCH_HEADER_BYTES, 16,
            "BatchHeader must be exactly 16 bytes"
        );
        // Phase 1.5: ColumnHeader grew from 20 to 28 bytes (added
        // heap_offset + heap_len for variable-width dtypes), then to
        // 32 bytes (added is_constant for the constant-column ABI
        // tag). The JS dispatcher's COL_HDR constant must stay in
        // sync (asserted by the b_columnar_udf integration tests).
        assert_eq!(
            COLUMN_HEADER_BYTES, 32,
            "ColumnHeader must be exactly 32 bytes"
        );
    }

    // ---- E6 ptr-slot ingest ----------------------------------------

    #[test]
    fn encode_batch_ptr_slots_matches_encode_batch_byte_for_byte() {
        // Same logical batch (one fixed-width column, one var-width
        // column with a mix of inline + long values), encoded via the
        // ordinary heap-prebuilt path and via the ptr-slot path. The
        // two blobs must be byte-identical - the E6 path is a pure
        // write-side optimization, never a wire-format change.
        let ints = i32_slice_bytes(&[1, 2, 3]);
        let strs: Vec<&[u8]> = vec![b"hi", b"a value well over twelve bytes long", b"ok"];
        let (heap_slots, heap) = build_var_column(&strs);

        let mut ref_batch = ColumnarBatch::new(3);
        ref_batch.push(ColumnRef {
            name: "n",
            dtype: ColumnDtype::Int32,
            data: &ints,
            heap: None,
            validity: None,
        });
        ref_batch.push(ColumnRef {
            name: "s",
            dtype: ColumnDtype::Utf8,
            data: &heap_slots,
            heap: Some(&heap),
            validity: None,
        });
        let expected = encode_batch(&ref_batch).unwrap();

        // Ptr-slot form: same strings, but each long slot carries a raw
        // pointer into an owned buffer instead of a pre-built heap.
        let owned: Vec<Vec<u8>> = strs.iter().map(|s| s.to_vec()).collect();
        let ptr_slots = build_ptr_slot_column(&owned);

        let mut ptr_batch = PtrSlotBatch::new(3);
        ptr_batch.push(PtrSlotColumn::Ref(ColumnRef {
            name: "n",
            dtype: ColumnDtype::Int32,
            data: &ints,
            heap: None,
            validity: None,
        }));
        ptr_batch.push(PtrSlotColumn::PtrSlot(PtrSlotColumnRef {
            name: "s",
            dtype: ColumnDtype::Utf8,
            data: &ptr_slots,
            validity: None,
        }));
        // SAFETY: `owned`'s buffers outlive this call and are never
        // mutated while `ptr_batch` (which points into them) is alive.
        let got = unsafe { encode_batch_ptr_slots(&ptr_batch).unwrap() };

        assert_eq!(
            got.bytes, expected.bytes,
            "ptr-slot encode must be byte-identical to the heap-prebuilt encode"
        );
    }

    #[test]
    fn encode_batch_ptr_slots_no_intermediate_heap_buffer() {
        // COPIED_BYTES proof (structural + size-exact, mirroring this
        // file's existing `encode_max_columns_typical_workload` size
        // idiom): `PtrSlotColumnRef` has no `heap` field at all, so the
        // caller cannot pre-materialize a scratch heap even if it
        // wanted to - the ONLY place long-value bytes are copied is
        // inside `encode_batch_ptr_slots` itself, straight from the
        // caller's pointer into the returned blob. Confirm the output
        // size accounts for exactly one copy of the heap bytes (not
        // zero, not two).
        let long_a = vec![b'a'; 40];
        let long_b = vec![b'b'; 100];
        let owned = vec![long_a.clone(), long_b.clone()];
        let ptr_slots = build_ptr_slot_column(&owned);

        let mut batch = PtrSlotBatch::new(2);
        batch.push(PtrSlotColumn::PtrSlot(PtrSlotColumnRef {
            name: "v",
            dtype: ColumnDtype::Bytea,
            data: &ptr_slots,
            validity: None,
        }));
        // SAFETY: `owned` outlives this call and is not mutated.
        let encoded = unsafe { encode_batch_ptr_slots(&batch).unwrap() };

        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.columns[0].row_bytes(0).unwrap(), long_a.as_slice());
        assert_eq!(decoded.columns[0].row_bytes(1).unwrap(), long_b.as_slice());

        // header(16) + 1 col-header(32) -> align8 -> slot array
        // (2*16=32, already 8-aligned) -> name(1 byte "v") -> align
        // not required before heap (1-byte aligned) -> heap
        // (40+100=140 bytes, exactly once).
        let header_and_table = align_up(16 + 32, 8);
        let after_slots = header_and_table + 32;
        let after_name = after_slots + 1;
        let expected_len = after_name + (long_a.len() + long_b.len());
        assert_eq!(
            encoded.bytes.len(),
            expected_len,
            "blob length must reflect exactly one copy of the heap bytes"
        );
    }

    #[test]
    fn encode_batch_ptr_slots_rejects_fixed_width_dtype() {
        let data = vec![0u8; INLINE_SLOT_BYTES];
        let mut batch = PtrSlotBatch::new(1);
        batch.push(PtrSlotColumn::PtrSlot(PtrSlotColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &data,
            validity: None,
        }));
        // SAFETY: no long slots present (all-zero len), nothing is
        // dereferenced; this call only exercises the validation error.
        let err = unsafe { encode_batch_ptr_slots(&batch).unwrap_err() };
        let msg = format!("{err:?}");
        assert!(msg.contains("variable-width dtypes only"), "got {msg}");
    }

    #[test]
    fn encode_batch_ptr_slots_all_inline_needs_no_pointer() {
        // Every value ≤ 12 bytes: no long slot exists, so no pointer is
        // ever dereferenced - proves the inline path never touches the
        // `unsafe` contract.
        let owned = vec![b"short".to_vec(), b"also-ok".to_vec()];
        let ptr_slots = build_ptr_slot_column(&owned);
        let mut batch = PtrSlotBatch::new(2);
        batch.push(PtrSlotColumn::PtrSlot(PtrSlotColumnRef {
            name: "s",
            dtype: ColumnDtype::Utf8,
            data: &ptr_slots,
            validity: None,
        }));
        // SAFETY: no long slots, so the pointer contract is vacuous.
        let encoded = unsafe { encode_batch_ptr_slots(&batch).unwrap() };
        let decoded = decode_batch(&encoded.bytes).unwrap();
        assert_eq!(decoded.columns[0].row_str(0).unwrap(), "short");
        assert_eq!(decoded.columns[0].row_str(1).unwrap(), "also-ok");
    }

    /// Build a ptr-slot column (E6 form) from owned byte buffers: short
    /// values inline exactly like `build_var_column`; long values carry
    /// a raw pointer into the owned buffer instead of a heap offset.
    /// Test-only - `owned` must outlive every use of the returned slots.
    fn build_ptr_slot_column(owned: &[Vec<u8>]) -> Vec<u8> {
        let mut slots = vec![0u8; owned.len() * INLINE_SLOT_BYTES];
        for (i, v) in owned.iter().enumerate() {
            let sb = i * INLINE_SLOT_BYTES;
            slots[sb..sb + 4].copy_from_slice(&(v.len() as u32).to_le_bytes());
            if v.len() <= INLINE_SLOT_INLINE_MAX {
                slots[sb + 4..sb + 4 + v.len()].copy_from_slice(v);
            } else {
                slots[sb + 4..sb + 8].copy_from_slice(&v[0..4]);
                let ptr = v.as_ptr() as usize;
                slots[sb + 8..sb + 16].copy_from_slice(&ptr.to_le_bytes());
            }
        }
        slots
    }

    fn i32_slice_bytes(xs: &[i32]) -> Vec<u8> {
        xs.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    // ---- constant-column ABI tag ------------------------------------

    #[test]
    fn encode_batch_with_constants_empty_constants_matches_encode_batch() {
        let data = i32_slice_bytes(&[1, 2, 3]);
        let mut batch = ColumnarBatch::new(3);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: None,
            validity: None,
        });
        let plain = encode_batch(&batch).unwrap();
        let with_none = encode_batch_with_constants(&batch, &[]).unwrap();
        assert_eq!(
            plain.bytes, with_none.bytes,
            "an empty constants slice must be byte-identical to encode_batch"
        );
    }

    #[test]
    fn encode_batch_with_constants_round_trips_o1_value() {
        let data = i32_slice_bytes(&[1, 2, 3, 4]);
        let mut batch = ColumnarBatch::new(4);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: None,
            validity: None,
        });
        let five: i32 = 5;
        let five_bytes = five.to_le_bytes();
        let constants = [ConstantColumnRef {
            name: "k",
            dtype: ColumnDtype::Int32,
            value: &five_bytes,
            valid: true,
        }];
        let encoded = encode_batch_with_constants(&batch, &constants).unwrap();

        // The constant column's DATA region is exactly 4 bytes (one
        // Int32), not 4 rows × 4 bytes - the O(1) transfer proof.
        let decoded_header = read_column_header_for_name(&encoded.bytes, "k");
        assert_eq!(decoded_header.is_constant, 1);

        // decode_batch only understands the reply direction (which
        // never carries a constant); assert directly against the
        // encoded bytes for the input-direction shape instead.
        let row_count = read_u32_le(&encoded.bytes, 0);
        assert_eq!(row_count, 4, "batch row_count is unaffected");
    }

    #[test]
    fn encode_batch_with_constants_null_constant_is_one_byte_validity() {
        let data = i32_slice_bytes(&[1]);
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: None,
            validity: None,
        });
        let zero: i32 = 0;
        let zero_bytes = zero.to_le_bytes();
        let constants = [ConstantColumnRef {
            name: "k",
            dtype: ColumnDtype::Int32,
            value: &zero_bytes,
            valid: false,
        }];
        let encoded = encode_batch_with_constants(&batch, &constants).unwrap();
        let h = read_column_header_for_name(&encoded.bytes, "k");
        assert_ne!(
            h.validity_offset, 0,
            "a NULL constant must carry a validity offset"
        );
        assert_eq!(
            encoded.bytes[h.validity_offset as usize], 0,
            "bit 0 clear = invalid, matching the bit-set-valid convention"
        );
    }

    #[test]
    fn encode_batch_with_constants_rejects_var_width_dtype() {
        let batch = ColumnarBatch::new(1);
        let value = 0u32.to_le_bytes();
        let constants = [ConstantColumnRef {
            name: "s",
            dtype: ColumnDtype::Utf8,
            value: &value,
            valid: true,
        }];
        let err = encode_batch_with_constants(&batch, &constants).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("fixed-width dtypes only"), "got {msg}");
    }

    #[test]
    fn encode_batch_with_constants_rejects_wrong_value_length() {
        let batch = ColumnarBatch::new(1);
        let value = [0u8; 2]; // Int32 needs 4 bytes
        let constants = [ConstantColumnRef {
            name: "k",
            dtype: ColumnDtype::Int32,
            value: &value,
            valid: true,
        }];
        let err = encode_batch_with_constants(&batch, &constants).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("constant value.len()"), "got {msg}");
    }

    #[test]
    fn decode_batch_rejects_constant_reply_column() {
        // A guest that (incorrectly) emitted a constant output column
        // must be a loud decode error, never a mis-decoded short read.
        let data = i32_slice_bytes(&[7]);
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &data,
            heap: None,
            validity: None,
        });
        let constants = [ConstantColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            value: &data,
            valid: true,
        }];
        // Reuse the constant encoder to synthesize a reply-shaped blob
        // with is_constant=1 - decode_batch must reject it outright.
        let encoded = encode_batch_with_constants(&ColumnarBatch::new(1), &constants).unwrap();
        let err = decode_batch(&encoded.bytes).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("constant output columns"), "got {msg}");
    }

    /// Test-only helper: locate a column header by name inside an
    /// encoded blob (linear scan - fine for small test batches).
    fn read_column_header_for_name(blob: &[u8], name: &str) -> ColumnHeader {
        let column_count = read_u32_le(blob, 4);
        let columns_offset = read_u32_le(blob, 8) as usize;
        for i in 0..column_count as usize {
            let h_off = columns_offset + i * COLUMN_HEADER_BYTES;
            let name_offset = read_u32_le(blob, h_off + 12) as usize;
            let name_len = read_u32_le(blob, h_off + 16) as usize;
            let got_name = std::str::from_utf8(&blob[name_offset..name_offset + name_len]).unwrap();
            if got_name == name {
                return ColumnHeader {
                    dtype: blob[h_off],
                    _pad: [0; 3],
                    data_offset: read_u32_le(blob, h_off + 4),
                    validity_offset: read_u32_le(blob, h_off + 8),
                    name_offset: read_u32_le(blob, h_off + 12),
                    name_len: read_u32_le(blob, h_off + 16),
                    heap_offset: read_u32_le(blob, h_off + 20),
                    heap_len: read_u32_le(blob, h_off + 24),
                    is_constant: read_u32_le(blob, h_off + 28),
                };
            }
        }
        panic!("column '{name}' not found in encoded blob");
    }
}
