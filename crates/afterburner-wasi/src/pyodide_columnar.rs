// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Columnar-batch invocation primitive for the Python runtime.
//!
//! [`pyodide_runner`](crate::pyodide_runner) only exposes a `run_source`-
//! shaped facade (`run_python` / `run_pyodide_source`): boot the
//! interpreter, run one script via `python -c`, capture stdout/stderr and
//! at most one typed return value. There is no columnar-batch entry point
//! and no `ScriptId`-style persistent registration - each call boots a
//! fresh interpreter from source, which is the existing runner's own
//! contract (unchanged here).
//!
//! This module adds that entry point,
//! [`run_python_columnar`](crate::pyodide_columnar::run_python_columnar),
//! reusing the SAME wire ABI the wasm/JS columnar path uses
//! ([`crate::columnar::encode_batch`] / [`decode_batch`](crate::columnar::decode_batch) -
//! one canonical columnar format, never a parallel one) and the existing
//! `run_pyodide_with_preopens` boot/run machinery unchanged.
//!
//! ## Why file-preopen transfer, not linear-memory host imports
//!
//! The wasm/JS columnar path (`crates/afterburner-plugin`) works by
//! linking two host-import functions
//! (`__AB_GET_COLUMNAR_INPUT__` / `__AB_COLUMNAR_REPLY__`) that the
//! QuickJS-in-wasm guest calls directly. Pyodide (and CRuby, see
//! [`crate::ruby_columnar`]) are booted as **plain WASI command modules**
//! (`pyodide_runner` / `ruby_runner` docs) - user Python/Ruby code has no
//! mechanism to call an arbitrary custom host import; the only host
//! channel a guest script can reach is the WASI filesystem (preopens),
//! which is exactly what `run_pyodide_with_preopens` already wires. So
//! the encoded batch blob crosses via a preopened read-write directory
//! (`std::fs::write` the input, run, `std::fs::read` the output) instead
//! of a linear-memory import - the architecturally correct channel for
//! this runtime shape, not a workaround.
//!
//! ## What this delivers vs. what is deferred (named honestly)
//!
//! Delivered: a real, tested, end-to-end columnar invocation - decode
//! every Phase-1 dtype (fixed-width, Utf8, Bytea, Jsonb) into native
//! Python values, call a caller-named entry function once with the whole
//! batch, encode its `{row_count, columns}` result back to the same wire
//! format.
//!
//! Deferred, named:
//! - **Not zero-copy on the guest side.** The Rust→file→Python boundary
//!   is one `memcpy`-equivalent each way (identical cost class to the
//!   wasm/JS path's linear-memory `Memory::write` / `Memory::data()`
//!   crossings - see `columnar.rs` module docs); inside Python, values
//!   are unpacked into plain lists via the stdlib `struct` module rather
//!   than exposed as zero-copy typed views (`memoryview.cast` could do
//!   that as a follow-up; a per-row interpreted Python loop dominates
//!   the cost either way, so the marginal win is small until a
//!   numpy-vectorized UDF style is the actual target).
//! - **Dtype inference on OUTPUT.** The wire format's `ColumnDtype` is
//!   explicit on input; on output, this module infers a column's dtype
//!   from its first Python value (`bool`→Bool, `int`→Int64, `float`→
//!   Float64, `str`→Utf8, `bytes`→Bytea) - a UDF wanting Int32 / Float32
//!   / Date32 / Timestamp output has no way to select those narrower
//!   tags today. An empty output column cannot be typed this way and is
//!   a loud, actionable error, never a silent guess.
//! - **Decimal128 / Uuid / Interval** never reach Python: `encode_batch`
//!   already rejects them before any bytes cross (Phase 1 ceiling,
//!   unchanged by this module).

use afterburner_core::{AfterburnerError, Result};

use crate::columnar::{ColumnarBatch, ColumnarOutput, decode_batch, validate_entry_fn_name};
use crate::pyodide_runner::run_pyodide_with_preopens;
use crate::ruby_runner::unique_tmp_dir;

const INPUT_FILE: &str = "input.bin";
const OUTPUT_FILE: &str = "output.bin";
const GUEST_MOUNT: &str = "/data";

/// Decode + encode helpers the driver script needs, defined once ahead
/// of the caller's source so `entry_fn` can call straight into them
/// indirectly (it never needs to know they exist).
///
/// Kept intentionally close to the JS dispatcher's algorithm
/// (`crates/afterburner-plugin/src/globals/columnar.rs`) - same header
/// layout, same slot/heap rules - just expressed with `struct` instead
/// of `DataView`.
const PY_COLUMNAR_PREAMBLE: &str = r#"
import struct as _ab_struct

_AB_HEADER = 16
_AB_COL_HDR = 32
_AB_DTYPE_FMT = {1:'B',2:'b',3:'h',4:'i',5:'q',6:'B',7:'H',8:'I',9:'Q',10:'f',11:'d',13:'i',14:'q'}
_AB_VARWIDTH = (12, 18, 19)
_AB_INLINE_MAX = 12
_AB_SLOT = 16


class _AbConstantColumn:
    """O(1) broadcast view: every index 0..row_count reads the same
    value. Mirrors the JS dispatcher's Proxy-based constant column."""

    __slots__ = ("_value", "_row_count")

    def __init__(self, value, row_count):
        self._value = value
        self._row_count = row_count

    def __len__(self):
        return self._row_count

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self._value for _ in range(*i.indices(self._row_count))]
        if 0 <= i < self._row_count:
            return self._value
        raise IndexError("constant column index out of range")

    def __iter__(self):
        for _ in range(self._row_count):
            yield self._value


def _ab_dtype_size(dtype):
    if dtype in (1, 2, 6):
        return 1
    if dtype in (3, 7):
        return 2
    if dtype in (4, 8, 10, 13):
        return 4
    if dtype in (5, 9, 11, 14):
        return 8
    raise ValueError("columnar UDF: unknown fixed-width dtype " + str(dtype))


def _ab_decode_batch(blob):
    row_count, column_count, columns_offset, _reserved = _ab_struct.unpack_from('<IIII', blob, 0)
    columns = {}
    for i in range(column_count):
        off = columns_offset + i * _AB_COL_HDR
        dtype = blob[off]
        data_off, validity_off, name_off, name_len, heap_off, heap_len, is_constant = \
            _ab_struct.unpack_from('<IIIIIII', blob, off + 4)
        name = bytes(blob[name_off:name_off + name_len]).decode('utf-8')
        count = 1 if is_constant else row_count
        if dtype in _AB_VARWIDTH:
            heap = blob[heap_off:heap_off + heap_len] if heap_len else b''
            values = []
            for r in range(count):
                sb = data_off + r * _AB_SLOT
                (slen,) = _ab_struct.unpack_from('<I', blob, sb)
                if slen <= _AB_INLINE_MAX:
                    raw = bytes(blob[sb + 4:sb + 4 + slen])
                else:
                    (hoff,) = _ab_struct.unpack_from('<I', blob, sb + 12)
                    raw = bytes(heap[hoff:hoff + slen])
                values.append(raw.decode('utf-8') if dtype == 12 else raw)
        else:
            fmt = _AB_DTYPE_FMT.get(dtype)
            if fmt is None:
                raise ValueError("columnar UDF: unsupported dtype tag " + str(dtype) + " for column '" + name + "'")
            raw_vals = list(_ab_struct.unpack_from('<' + fmt * count, blob, data_off))
            values = [bool(v) for v in raw_vals] if dtype == 1 else raw_vals
        columns[name] = _AbConstantColumn(values[0], row_count) if is_constant else values
    return row_count, columns


def _ab_align8(x):
    return (x + 7) & ~7


def _ab_classify(name, v):
    if len(v) == 0:
        raise ValueError("columnar UDF: column '" + name + "' is empty; output dtype cannot be inferred")
    sample = v[0]
    if isinstance(sample, bool):
        return 1, False
    if isinstance(sample, int):
        return 5, False
    if isinstance(sample, float):
        return 11, False
    if isinstance(sample, str):
        return 12, True
    if isinstance(sample, (bytes, bytearray)):
        return 18, True
    raise TypeError("columnar UDF: column '" + name + "' has unsupported element type " + type(sample).__name__)


def _ab_encode_batch(row_count, out_columns):
    metas = []
    for name, v in out_columns.items():
        v = list(v)
        if len(v) != row_count:
            raise ValueError("columnar UDF: column '" + name + "' length " + str(len(v)) + " != row_count " + str(row_count))
        dtype, is_var = _ab_classify(name, v)
        if is_var:
            slots = bytearray(row_count * _AB_SLOT)
            heap = bytearray()
            for r, item in enumerate(v):
                raw = item.encode('utf-8') if dtype == 12 else bytes(item)
                sb = r * _AB_SLOT
                _ab_struct.pack_into('<I', slots, sb, len(raw))
                if len(raw) <= _AB_INLINE_MAX:
                    slots[sb + 4:sb + 4 + len(raw)] = raw
                else:
                    slots[sb + 4:sb + 8] = raw[0:4]
                    _ab_struct.pack_into('<I', slots, sb + 12, len(heap))
                    heap += raw
            metas.append((name, dtype, bytes(slots), bytes(heap)))
        else:
            fmt = _AB_DTYPE_FMT[dtype]
            if dtype in (10, 11):
                packed = _ab_struct.pack('<' + fmt * row_count, *[float(x) for x in v])
            elif dtype == 1:
                packed = _ab_struct.pack('<' + fmt * row_count, *[1 if x else 0 for x in v])
            else:
                packed = _ab_struct.pack('<' + fmt * row_count, *[int(x) for x in v])
            metas.append((name, dtype, packed, b''))

    header_end = _AB_HEADER
    col_table_end = header_end + len(metas) * _AB_COL_HDR
    cursor = _ab_align8(col_table_end)
    layouts = []
    for name, dtype, data, heap in metas:
        cursor = _ab_align8(cursor)
        data_off = cursor
        cursor += len(data)
        name_bytes = name.encode('utf-8')
        name_off = cursor
        cursor += len(name_bytes)
        heap_off = 0
        if len(heap) > 0:
            heap_off = cursor
            cursor += len(heap)
        layouts.append((dtype, data_off, name_off, name_bytes, heap_off, len(heap), data, heap))

    out = bytearray(cursor)
    _ab_struct.pack_into('<IIII', out, 0, row_count, len(metas), header_end, 0)
    h = header_end
    for dtype, data_off, name_off, name_bytes, heap_off, heap_len, _data, _heap in layouts:
        out[h] = dtype
        _ab_struct.pack_into('<IIIIIII', out, h + 4, data_off, 0, name_off, len(name_bytes), heap_off, heap_len, 0)
        h += _AB_COL_HDR
    for _dtype, data_off, name_off, name_bytes, heap_off, heap_len, data, heap in layouts:
        out[data_off:data_off + len(data)] = data
        out[name_off:name_off + len(name_bytes)] = name_bytes
        if heap_len > 0:
            out[heap_off:heap_off + heap_len] = heap
    return bytes(out)
"#;

/// Build the driver code appended after the caller's source: reads the
/// input blob, calls `entry_fn`, validates the result shape, writes the
/// output blob. `entry_fn` was already validated by
/// [`validate_entry_fn_name`] before this is called, so splicing it
/// verbatim into the call expression is safe.
fn py_columnar_driver(entry_fn: &str) -> String {
    // `concat!` joins fully self-contained literals - unlike a `"...\`
    // backslash-newline continuation, it never strips the leading
    // spaces a continued line starts with, so the 4-space Python
    // indentation below survives verbatim (indentation is syntax in
    // Python; a stripped line here is a silent `IndentationError`).
    format!(
        concat!(
            "\n",
            "with open('{mount}/{input}', 'rb') as _ab_f:\n",
            "    _ab_blob = _ab_f.read()\n",
            "_ab_row_count, _ab_columns = _ab_decode_batch(_ab_blob)\n",
            "_ab_result = {entry_fn}({{'row_count': _ab_row_count, 'columns': _ab_columns}})\n",
            "if not isinstance(_ab_result, dict) or 'row_count' not in _ab_result or 'columns' not in _ab_result:\n",
            "    raise ValueError(\"columnar UDF: result must be a dict with 'row_count' and 'columns'\")\n",
            "_ab_out_bytes = _ab_encode_batch(_ab_result['row_count'], _ab_result['columns'])\n",
            "with open('{mount}/{output}', 'wb') as _ab_f:\n",
            "    _ab_f.write(_ab_out_bytes)\n",
        ),
        mount = GUEST_MOUNT,
        input = INPUT_FILE,
        output = OUTPUT_FILE,
        entry_fn = entry_fn,
    )
}

/// Invoke a Python function over a columnar batch, offline, through the
/// bundled (or `BURN_PYTHON_RUNTIME`-overridden) Pyodide runtime.
///
/// `python_source` must define a top-level function named `entry_fn`
/// taking one argument - a `dict` shaped `{'row_count': int, 'columns':
/// {name: list}}` (fixed-width columns as `list[int|float|bool]`,
/// `Utf8` as `list[str]`, `Bytea`/`Jsonb` as `list[bytes]`) - and
/// returning a `dict` of the same shape.
///
/// Boots a fresh interpreter per call (this runner's existing,
/// unchanged contract - see [`crate::pyodide_runner`]); batch the work
/// inside `entry_fn` (loop over `row_count` once) rather than calling
/// this function per row.
///
/// # Errors
/// Returns `Err` when: no Python runtime is available, `entry_fn` is
/// not a valid identifier, `batch` fails
/// [`encode_batch`](crate::columnar::encode_batch)'s validation (e.g.
/// an unsupported dtype), the Python process exits non-zero (a user
/// exception - the error names stderr), or the result blob fails to
/// decode (a malformed `{row_count, columns}` shape from `entry_fn`).
pub fn run_python_columnar(
    python_source: &str,
    entry_fn: &str,
    batch: &ColumnarBatch<'_>,
) -> Result<ColumnarOutput> {
    run_python_columnar_with_constants(python_source, entry_fn, batch, &[])
}

/// Like [`run_python_columnar`], but `constants` carries scalar
/// arguments broadcast across every row at O(1) transfer cost - the
/// same [`crate::columnar::ConstantColumnRef`] mechanism the wasm/JS
/// path uses (`encode_batch_with_constants`). A constant column
/// presents to `entry_fn` as an O(1) broadcast view supporting
/// `len()` / indexing / iteration, not a materialized list.
/// `constants: &[]` behaves identically to [`run_python_columnar`].
///
/// # Errors
/// Same as [`run_python_columnar`].
pub fn run_python_columnar_with_constants(
    python_source: &str,
    entry_fn: &str,
    batch: &ColumnarBatch<'_>,
    constants: &[crate::columnar::ConstantColumnRef<'_>],
) -> Result<ColumnarOutput> {
    validate_entry_fn_name(entry_fn)?;
    let encoded = crate::columnar::encode_batch_with_constants(batch, constants)?;
    let rt = crate::pyodide_runner::resolve_runtime()?;

    let dir = unique_tmp_dir("burn-py-columnar");
    std::fs::create_dir_all(&dir)
        .map_err(|e| AfterburnerError::Engine(format!("create {}: {e}", dir.display())))?;
    let input_path = dir.join(INPUT_FILE);
    let write_result = std::fs::write(&input_path, &encoded.bytes)
        .map_err(|e| AfterburnerError::Engine(format!("write {}: {e}", input_path.display())));

    let result = write_result.and_then(|()| {
        let full_source = format!(
            "{PY_COLUMNAR_PREAMBLE}\n{python_source}\n{}",
            py_columnar_driver(entry_fn)
        );
        let rw_preopens = [(dir.clone(), GUEST_MOUNT.to_owned())];
        let run = run_pyodide_with_preopens(&rt, &full_source, &rw_preopens)?;
        if run.exit_code != 0 {
            return Err(AfterburnerError::Engine(format!(
                "columnar python UDF '{entry_fn}' exited {}: {}",
                run.exit_code,
                String::from_utf8_lossy(&run.stderr),
            )));
        }
        let output_path = dir.join(OUTPUT_FILE);
        let bytes = std::fs::read(&output_path).map_err(|e| {
            AfterburnerError::Engine(format!(
                "columnar python UDF '{entry_fn}' produced no output ({}: {e})",
                output_path.display(),
            ))
        })?;
        decode_batch(&bytes)
    });

    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::columnar::{ColumnDtype, ColumnRef, ConstantColumnRef};

    fn i32_le_bytes(xs: &[i32]) -> Vec<u8> {
        xs.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// A Python `int` always classifies as Int64 on output (see
    /// `_ab_classify`), so every UDF result column built from plain
    /// Python ints - regardless of the input dtype - decodes with this
    /// helper (there is no `read_i32_col`: no test here decodes an
    /// Int32 OUTPUT column, since `_ab_classify` never infers Int32).
    fn read_i64_col(data: &[u8]) -> Vec<i64> {
        data.chunks_exact(8)
            .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    /// End-to-end: a Python UDF sums two Int32 columns row-wise,
    /// offline from the resolved (bundled or `~/.burn`-cached) runtime.
    /// `#[ignore]`: needs the real Python runtime, matching every other
    /// runtime-dependent test in `pyodide_runner`/`ruby_runner`.
    #[test]
    #[ignore = "uses the real python runtime (bundled or ~/.burn); run explicitly"]
    fn run_python_columnar_sums_two_columns() {
        let c0 = i32_le_bytes(&[1, 2, 3, 4, 5]);
        let c1 = i32_le_bytes(&[10, 20, 30, 40, 50]);
        let mut batch = ColumnarBatch::new(5);
        batch.push(ColumnRef {
            name: "c0",
            dtype: ColumnDtype::Int32,
            data: &c0,
            heap: None,
            validity: None,
        });
        batch.push(ColumnRef {
            name: "c1",
            dtype: ColumnDtype::Int32,
            data: &c1,
            heap: None,
            validity: None,
        });

        // A raw string, not a `"...\`-continued literal: Rust's
        // backslash-newline continuation strips ALL leading whitespace
        // off the next line, which would silently flatten this
        // function body's indentation into a Python `IndentationError`
        // (indentation is syntax here, unlike in `rustfmt`-wrapped Rust
        // source). A raw string keeps every byte, including the
        // indentation, exactly as written.
        let source = r#"
def add_cols(b):
    n = b['row_count']
    c0 = b['columns']['c0']
    c1 = b['columns']['c1']
    return {'row_count': n, 'columns': {'sum': [c0[i] + c1[i] for i in range(n)]}}
"#;
        let out = run_python_columnar(source, "add_cols", &batch).expect("run_python_columnar");
        assert_eq!(out.row_count, 5);
        assert_eq!(out.columns[0].name, "sum");
        assert_eq!(out.columns[0].dtype, ColumnDtype::Int64);
        assert_eq!(
            out.columns[0]
                .data
                .chunks_exact(8)
                .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
                .collect::<Vec<_>>(),
            vec![11, 22, 33, 44, 55]
        );
    }

    /// End-to-end string handling: Utf8 input (mixing an inline and a
    /// heap-backed value) uppercased and returned as Utf8 output,
    /// proving the var-width slot+heap path round-trips correctly
    /// through the real interpreter.
    #[test]
    #[ignore = "uses the real python runtime (bundled or ~/.burn); run explicitly"]
    fn run_python_columnar_utf8_round_trip() {
        let names: Vec<&[u8]> = vec![b"ada", b"a much longer name over twelve bytes"];
        let (slots, heap) = build_var_column(&names);
        let mut batch = ColumnarBatch::new(names.len() as u32);
        batch.push(ColumnRef {
            name: "name",
            dtype: ColumnDtype::Utf8,
            data: &slots,
            heap: Some(&heap),
            validity: None,
        });

        let source = r#"
def shout(b):
    n = b['row_count']
    xs = b['columns']['name']
    return {'row_count': n, 'columns': {'out': [xs[i].upper() for i in range(n)]}}
"#;
        let out = run_python_columnar(source, "shout", &batch).expect("run_python_columnar");
        assert_eq!(out.columns[0].dtype, ColumnDtype::Utf8);
        assert_eq!(out.columns[0].row_str(0).unwrap(), "ADA");
        assert_eq!(
            out.columns[0].row_str(1).unwrap(),
            "A MUCH LONGER NAME OVER TWELVE BYTES"
        );
    }

    /// A constant input column (O(1) scalar argument, via
    /// [`run_python_columnar_with_constants`]) presents as an
    /// `_AbConstantColumn` broadcast view: indexing, `len()`, and
    /// iteration all answer with the same value for every row -
    /// summed here alongside an ordinary per-row column in one UDF.
    #[test]
    #[ignore = "uses the real python runtime (bundled or ~/.burn); run explicitly"]
    fn run_python_columnar_constant_column_broadcasts() {
        let xs = i32_le_bytes(&[1, 2, 3, 4]);
        let mut batch = ColumnarBatch::new(4);
        batch.push(ColumnRef {
            name: "x",
            dtype: ColumnDtype::Int32,
            data: &xs,
            heap: None,
            validity: None,
        });
        let hundred: i32 = 100;
        let hundred_bytes = hundred.to_le_bytes();
        let constants = [ConstantColumnRef {
            name: "k",
            dtype: ColumnDtype::Int32,
            value: &hundred_bytes,
            valid: true,
        }];

        let source = r#"
def add_k(b):
    n = b['row_count']
    xs = b['columns']['x']
    k = b['columns']['k']
    total = sum(k[i] for i in range(len(k)))
    return {
        'row_count': n,
        'columns': {
            'sum': [xs[i] + k[i] for i in range(n)],
            'kcount': [len(k)] * n,
            'ktotal': [total] * n,
        },
    }
"#;
        let out = run_python_columnar_with_constants(source, "add_k", &batch, &constants)
            .expect("run_python_columnar_with_constants");
        // Every result column is built from plain Python ints, so all
        // three decode as Int64 (see `_ab_classify` / `read_i64_col`).
        let sum_col = out.columns.iter().find(|c| c.name == "sum").unwrap();
        assert_eq!(read_i64_col(&sum_col.data), vec![101, 102, 103, 104]);
        let kcount = out.columns.iter().find(|c| c.name == "kcount").unwrap();
        assert_eq!(
            read_i64_col(&kcount.data),
            vec![4, 4, 4, 4],
            "len(k) == row_count"
        );
        let ktotal = out.columns.iter().find(|c| c.name == "ktotal").unwrap();
        // sum(100,100,100,100) = 400 - proves iteration, not just len().
        assert_eq!(read_i64_col(&ktotal.data), vec![400, 400, 400, 400]);
    }

    fn build_var_column(values: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
        use crate::columnar::{INLINE_SLOT_BYTES, INLINE_SLOT_INLINE_MAX};
        let mut slots = vec![0u8; values.len() * INLINE_SLOT_BYTES];
        let mut heap = Vec::new();
        for (i, v) in values.iter().enumerate() {
            let sb = i * INLINE_SLOT_BYTES;
            slots[sb..sb + 4].copy_from_slice(&(v.len() as u32).to_le_bytes());
            if v.len() <= INLINE_SLOT_INLINE_MAX {
                slots[sb + 4..sb + 4 + v.len()].copy_from_slice(v);
            } else {
                slots[sb + 4..sb + 8].copy_from_slice(&v[0..4]);
                slots[sb + 12..sb + 16].copy_from_slice(&(heap.len() as u32).to_le_bytes());
                heap.extend_from_slice(v);
            }
        }
        (slots, heap)
    }

    #[test]
    fn run_python_columnar_rejects_bad_entry_fn_name() {
        let batch = ColumnarBatch::new(0);
        let err = run_python_columnar("def x(b): return b", "not an ident", &batch)
            .expect_err("invalid identifier must be rejected before any run");
        assert!(err.to_string().contains("not a valid identifier"), "{err}");
    }

    #[test]
    fn run_python_columnar_rejects_unsupported_dtype_before_running() {
        let data = vec![0u8; 16];
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "amount",
            dtype: ColumnDtype::Decimal128,
            data: &data,
            heap: None,
            validity: None,
        });
        let err = run_python_columnar("def f(b): return b", "f", &batch)
            .expect_err("Decimal128 is rejected by encode_batch before any process spawns");
        assert!(err.to_string().contains("Decimal128"), "{err}");
    }
}
