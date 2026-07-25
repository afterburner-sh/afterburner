// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Columnar-batch invocation primitive for the Ruby runtime.
//!
//! [`ruby_runner`](crate::ruby_runner) only exposes a `run_source`-shaped
//! facade (`run_ruby` / `run_ruby_package_with`): boot the interpreter,
//! run one script, capture stdout/stderr and at most one typed return
//! value. There is no columnar-batch entry point. This module adds that
//! entry point, [`run_ruby_columnar`](crate::ruby_columnar::run_ruby_columnar),
//! reusing the SAME wire ABI the
//! wasm/JS columnar path uses ([`crate::columnar::encode_batch`] /
//! [`decode_batch`](crate::columnar::decode_batch) - one canonical
//! columnar format, never a parallel one) and the existing
//! `run_ruby_package_with` boot/run machinery unchanged.
//!
//! ## Why file-preopen transfer, not linear-memory host imports
//!
//! See [`crate::pyodide_columnar`]'s module docs - the identical
//! reasoning applies here: CRuby's WASI build is a plain command module
//! (`ruby_runner` docs), so the encoded batch blob crosses via the
//! package directory's read-write preopen (already wired by
//! `run_ruby_package_with`) rather than a linear-memory host import.
//!
//! ## What this delivers vs. what is deferred (named honestly)
//!
//! Same shape as [`crate::pyodide_columnar`]'s honesty section: NOT
//! zero-copy on the guest side (one file-boundary crossing each way,
//! then `String#unpack` into plain Ruby values - a follow-up could
//! expose zero-copy typed views); output dtype is INFERRED from the
//! first Ruby value of each result column (`true`/`false`→Bool,
//! `Integer`→Int64, `Float`→Float64, a UTF-8-encoded `String`→Utf8, an
//! `ASCII-8BIT`-encoded `String`→Bytea) - an empty output column cannot
//! be typed this way and is a loud, actionable error, never a silent
//! guess; Decimal128 / Uuid / Interval never reach Ruby (`encode_batch`
//! rejects them before any bytes cross).

use afterburner_core::{AfterburnerError, Result};

use crate::columnar::{
    ColumnarBatch, ColumnarOutput, ConstantColumnRef, decode_batch, encode_batch_with_constants,
    validate_entry_fn_name,
};
use crate::ruby_runner::{
    RubyRuntime, resolve_ruby_runtime, run_ruby_package_with, unique_tmp_dir,
};

const INPUT_FILE: &str = "input.bin";
const OUTPUT_FILE: &str = "output.bin";
const ENTRY_SCRIPT: &str = "main.rb";

/// Decode + encode helpers the driver script needs, defined once ahead
/// of the caller's source. Kept intentionally close to the JS
/// dispatcher's algorithm
/// (`crates/afterburner-plugin/src/globals/columnar.rs`) and to
/// [`crate::pyodide_columnar`]'s Python preamble - same header layout,
/// same slot/heap rules - just expressed with `Array#pack` /
/// `String#unpack` instead of `struct`.
const RB_COLUMNAR_PREAMBLE: &str = r#"
AB_HEADER = 16
AB_COL_HDR = 32
AB_DTYPE_FMT = {1=>'C',2=>'c',3=>'s<',4=>'l<',5=>'q<',6=>'C',7=>'S<',8=>'L<',9=>'Q<',10=>'e',11=>'E',13=>'l<',14=>'q<'}.freeze
AB_VARWIDTH = [12, 18, 19].freeze
AB_INLINE_MAX = 12
AB_SLOT = 16

# O(1) broadcast view: every index 0..row_count reads the same value.
# Mirrors the JS dispatcher's Proxy-based constant column.
class AbConstantColumn
  include Enumerable

  def initialize(value, row_count)
    @value = value
    @row_count = row_count
  end

  def length
    @row_count
  end

  def [](i)
    return Array.new(i.size) { @value } if i.is_a?(Range)
    raise IndexError, "constant column index out of range" unless i >= 0 && i < @row_count
    @value
  end

  def each
    return enum_for(:each) unless block_given?
    @row_count.times { yield @value }
  end
end

def ab_dtype_size(dtype)
  case dtype
  when 1, 2, 6 then 1
  when 3, 7 then 2
  when 4, 8, 10, 13 then 4
  when 5, 9, 11, 14 then 8
  else raise "columnar UDF: unknown fixed-width dtype #{dtype}"
  end
end

def ab_decode_batch(blob)
  row_count, column_count, columns_offset, _reserved = blob[0, 16].unpack('L<4')
  columns = {}
  column_count.times do |i|
    off = columns_offset + i * AB_COL_HDR
    dtype = blob.getbyte(off)
    data_off, _validity_off, name_off, name_len, heap_off, heap_len, is_constant =
      blob[off + 4, 28].unpack('L<7')
    name = blob[name_off, name_len].force_encoding('UTF-8')
    count = is_constant != 0 ? 1 : row_count
    if AB_VARWIDTH.include?(dtype)
      heap = heap_len > 0 ? blob[heap_off, heap_len] : ''.b
      values = (0...count).map do |r|
        sb = data_off + r * AB_SLOT
        slen = blob[sb, 4].unpack1('L<')
        raw = if slen <= AB_INLINE_MAX
          blob[sb + 4, slen]
        else
          hoff = blob[sb + 12, 4].unpack1('L<')
          heap[hoff, slen]
        end
        dtype == 12 ? raw.force_encoding('UTF-8') : raw
      end
    else
      fmt = AB_DTYPE_FMT[dtype]
      raise "columnar UDF: unsupported dtype tag #{dtype} for column '#{name}'" unless fmt
      size = ab_dtype_size(dtype)
      raw_vals = blob[data_off, count * size].unpack(fmt + count.to_s)
      values = dtype == 1 ? raw_vals.map { |v| v != 0 } : raw_vals
    end
    columns[name] = is_constant != 0 ? AbConstantColumn.new(values[0], row_count) : values
  end
  [row_count, columns]
end

def ab_align8(x)
  (x + 7) & ~7
end

def ab_classify(name, v)
  raise "columnar UDF: column '#{name}' is empty; output dtype cannot be inferred" if v.empty?
  sample = v[0]
  case sample
  when true, false then [1, false]
  when Integer then [5, false]
  when Float then [11, false]
  when String then sample.encoding == Encoding::ASCII_8BIT ? [18, true] : [12, true]
  else raise TypeError, "columnar UDF: column '#{name}' has unsupported element type #{sample.class}"
  end
end

def ab_encode_batch(row_count, out_columns)
  metas = []
  out_columns.each do |name, v|
    v = v.to_a
    raise "columnar UDF: column '#{name}' length #{v.length} != row_count #{row_count}" if v.length != row_count
    dtype, is_var = ab_classify(name, v)
    if is_var
      slots = ("\x00".b * (row_count * AB_SLOT))
      heap = ''.b
      v.each_with_index do |item, r|
        raw = dtype == 12 ? item.encode('UTF-8').b : item.b
        sb = r * AB_SLOT
        slots[sb, 4] = [raw.bytesize].pack('L<')
        if raw.bytesize <= AB_INLINE_MAX
          slots[sb + 4, raw.bytesize] = raw
        else
          slots[sb + 4, 4] = raw[0, 4]
          slots[sb + 12, 4] = [heap.bytesize].pack('L<')
          heap += raw
        end
      end
      metas << [name, dtype, slots, heap]
    else
      fmt = AB_DTYPE_FMT[dtype]
      packed = dtype == 1 ? v.map { |b| b ? 1 : 0 }.pack('C*') : v.pack(fmt + '*')
      metas << [name, dtype, packed, ''.b]
    end
  end

  header_end = AB_HEADER
  col_table_end = header_end + metas.length * AB_COL_HDR
  cursor = ab_align8(col_table_end)
  layouts = []
  metas.each do |name, dtype, data, heap|
    cursor = ab_align8(cursor)
    data_off = cursor
    cursor += data.bytesize
    name_bytes = name.encode('UTF-8').b
    name_off = cursor
    cursor += name_bytes.bytesize
    heap_off = 0
    if heap.bytesize > 0
      heap_off = cursor
      cursor += heap.bytesize
    end
    layouts << [dtype, data_off, name_off, name_bytes, heap_off, heap.bytesize, data, heap]
  end

  out = ("\x00".b * cursor)
  out[0, 16] = [row_count, metas.length, header_end, 0].pack('L<4')
  h = header_end
  layouts.each do |dtype, data_off, name_off, name_bytes, heap_off, heap_len, _data, _heap|
    out[h, 1] = [dtype].pack('C')
    out[h + 4, 28] = [data_off, 0, name_off, name_bytes.bytesize, heap_off, heap_len, 0].pack('L<7')
    h += AB_COL_HDR
  end
  layouts.each do |_dtype, data_off, name_off, name_bytes, heap_off, heap_len, data, heap|
    out[data_off, data.bytesize] = data
    out[name_off, name_bytes.bytesize] = name_bytes
    out[heap_off, heap_len] = heap if heap_len > 0
  end
  out
end
"#;

/// Build the driver code appended after the caller's source: reads the
/// input blob, calls `entry_fn`, validates the result shape, writes the
/// output blob. `entry_fn` was already validated by
/// [`validate_entry_fn_name`] before this is called, so splicing it
/// verbatim into the call expression is safe.
fn rb_columnar_driver(entry_fn: &str) -> String {
    // `concat!` joins fully self-contained literals rather than
    // relying on a `"...\` backslash-newline continuation, which
    // strips all leading whitespace off the next line (Ruby doesn't
    // need indentation for correctness, unlike the Python driver, but
    // a stripped line here would still read confusingly in a
    // traceback - keep the two drivers' construction style matched).
    format!(
        concat!(
            "\n",
            "input = File.binread('/pkg/{input}')\n",
            "_ab_row_count, _ab_columns = ab_decode_batch(input)\n",
            "_ab_result = {entry_fn}({{row_count: _ab_row_count, columns: _ab_columns}})\n",
            "unless _ab_result.is_a?(Hash) && _ab_result.key?(:row_count) && _ab_result.key?(:columns)\n",
            "  raise 'columnar UDF: result must be a Hash with :row_count and :columns'\n",
            "end\n",
            "out_bytes = ab_encode_batch(_ab_result[:row_count], _ab_result[:columns])\n",
            "File.binwrite('/pkg/{output}', out_bytes)\n",
        ),
        input = INPUT_FILE,
        output = OUTPUT_FILE,
        entry_fn = entry_fn,
    )
}

/// Invoke a Ruby function over a columnar batch, offline, through the
/// bundled (or `BURN_RUBY_RUNTIME`-overridden) CRuby runtime.
///
/// `ruby_source` must define a top-level method named `entry_fn` taking
/// one argument - a `Hash` shaped `{row_count:, columns:}` where
/// `columns` maps each column name (`String`) to its values (fixed-width
/// columns as `Array` of `Integer`/`Float`/`true`|`false`, `Utf8` as
/// `Array<String>`, `Bytea`/`Jsonb` as `Array<String>` with
/// `Encoding::ASCII_8BIT`) - and returning a `Hash` of the same shape.
///
/// Boots a fresh interpreter per call (this runner's existing,
/// unchanged contract - see [`crate::ruby_runner`]); batch the work
/// inside `entry_fn` (loop over `row_count` once) rather than calling
/// this function per row.
///
/// # Errors
/// Returns `Err` when: no Ruby runtime is available, `entry_fn` is not
/// a valid identifier, `batch` fails
/// [`encode_batch`](crate::columnar::encode_batch)'s validation (e.g.
/// an unsupported dtype), the Ruby process exits non-zero (an uncaught
/// exception - the error names stderr), or the result blob fails to
/// decode (a malformed `{row_count:, columns:}` shape from `entry_fn`).
pub fn run_ruby_columnar(
    ruby_source: &str,
    entry_fn: &str,
    batch: &ColumnarBatch<'_>,
) -> Result<ColumnarOutput> {
    run_ruby_columnar_with_constants(ruby_source, entry_fn, batch, &[])
}

/// Like [`run_ruby_columnar`], but `constants` carries scalar arguments
/// broadcast across every row at O(1) transfer cost - the same
/// [`ConstantColumnRef`] mechanism the wasm/JS path uses
/// (`encode_batch_with_constants`). A constant column presents to
/// `entry_fn` as an O(1) broadcast view (`AbConstantColumn`) supporting
/// `length` / indexing / `each`, not a materialized `Array`.
/// `constants: &[]` behaves identically to [`run_ruby_columnar`].
///
/// # Errors
/// Same as [`run_ruby_columnar`].
pub fn run_ruby_columnar_with_constants(
    ruby_source: &str,
    entry_fn: &str,
    batch: &ColumnarBatch<'_>,
    constants: &[ConstantColumnRef<'_>],
) -> Result<ColumnarOutput> {
    validate_entry_fn_name(entry_fn)?;
    let encoded = encode_batch_with_constants(batch, constants)?;
    let rt: RubyRuntime = resolve_ruby_runtime()?;

    let dir = unique_tmp_dir("burn-rb-columnar");
    std::fs::create_dir_all(&dir)
        .map_err(|e| AfterburnerError::Engine(format!("create {}: {e}", dir.display())))?;
    let input_path = dir.join(INPUT_FILE);
    let write_result = std::fs::write(&input_path, &encoded.bytes)
        .map_err(|e| AfterburnerError::Engine(format!("write {}: {e}", input_path.display())));

    let result = write_result.and_then(|()| {
        let full_source = format!(
            "{RB_COLUMNAR_PREAMBLE}\n{ruby_source}\n{}",
            rb_columnar_driver(entry_fn)
        );
        let script_path = dir.join(ENTRY_SCRIPT);
        std::fs::write(&script_path, &full_source).map_err(|e| {
            AfterburnerError::Engine(format!("write {}: {e}", script_path.display()))
        })?;
        let run = run_ruby_package_with(&rt, &dir, ENTRY_SCRIPT)?;
        if run.exit_code != 0 {
            return Err(AfterburnerError::Engine(format!(
                "columnar ruby UDF '{entry_fn}' exited {}: {}",
                run.exit_code,
                String::from_utf8_lossy(&run.stderr),
            )));
        }
        let output_path = dir.join(OUTPUT_FILE);
        let bytes = std::fs::read(&output_path).map_err(|e| {
            AfterburnerError::Engine(format!(
                "columnar ruby UDF '{entry_fn}' produced no output ({}: {e})",
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
    use crate::columnar::{ColumnDtype, ColumnRef, INLINE_SLOT_BYTES, INLINE_SLOT_INLINE_MAX};

    fn i32_le_bytes(xs: &[i32]) -> Vec<u8> {
        xs.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// A Ruby `Integer` always classifies as Int64 on output (see
    /// `ab_classify`), so every UDF result column built from plain
    /// Ruby integers decodes with this helper (there is no
    /// `read_i32_col`: no test here decodes an Int32 OUTPUT column,
    /// since `ab_classify` never infers Int32).
    fn read_i64_col(data: &[u8]) -> Vec<i64> {
        data.chunks_exact(8)
            .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    fn build_var_column(values: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
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

    /// End-to-end: a Ruby UDF sums two Int32 columns row-wise, offline
    /// from the resolved (`BURN_RUBY_RUNTIME`-overridden or
    /// `~/.burn`-cached) runtime. `#[ignore]`: needs the real Ruby
    /// runtime, matching every other runtime-dependent test in
    /// `pyodide_runner`/`ruby_runner`.
    #[test]
    #[ignore = "uses the real ruby runtime (bundled or ~/.burn); run explicitly"]
    fn run_ruby_columnar_sums_two_columns() {
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

        let source = "def add_cols(b)\n\
             n = b[:row_count]\n\
             c0 = b[:columns]['c0']\n\
             c1 = b[:columns]['c1']\n\
             { row_count: n, columns: { 'sum' => (0...n).map { |i| c0[i] + c1[i] } } }\n\
           end\n";
        let out = run_ruby_columnar(source, "add_cols", &batch).expect("run_ruby_columnar");
        assert_eq!(out.row_count, 5);
        assert_eq!(out.columns[0].name, "sum");
        assert_eq!(out.columns[0].dtype, ColumnDtype::Int64);
        assert_eq!(read_i64_col(&out.columns[0].data), vec![11, 22, 33, 44, 55]);
    }

    /// End-to-end string handling: Utf8 input (mixing an inline and a
    /// heap-backed value) uppercased and returned as Utf8 output.
    #[test]
    #[ignore = "uses the real ruby runtime (bundled or ~/.burn); run explicitly"]
    fn run_ruby_columnar_utf8_round_trip() {
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

        let source = "def shout(b)\n\
             n = b[:row_count]\n\
             xs = b[:columns]['name']\n\
             { row_count: n, columns: { 'out' => (0...n).map { |i| xs[i].upcase } } }\n\
           end\n";
        let out = run_ruby_columnar(source, "shout", &batch).expect("run_ruby_columnar");
        assert_eq!(out.columns[0].dtype, ColumnDtype::Utf8);
        assert_eq!(out.columns[0].row_str(0).unwrap(), "ADA");
        assert_eq!(
            out.columns[0].row_str(1).unwrap(),
            "A MUCH LONGER NAME OVER TWELVE BYTES"
        );
    }

    /// A constant input column (O(1) scalar argument, via
    /// [`run_ruby_columnar_with_constants`]) presents as an
    /// `AbConstantColumn` broadcast view: indexing, `length`, and `each`
    /// all answer with the same value for every row - summed here
    /// alongside an ordinary per-row column in one UDF.
    #[test]
    #[ignore = "uses the real ruby runtime (bundled or ~/.burn); run explicitly"]
    fn run_ruby_columnar_constant_column_broadcasts() {
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

        let source = "def add_k(b)\n\
             n = b[:row_count]\n\
             xs = b[:columns]['x']\n\
             k = b[:columns]['k']\n\
             total = 0\n\
             k.each { |v| total += v }\n\
             {\n\
               row_count: n,\n\
               columns: {\n\
                 'sum' => (0...n).map { |i| xs[i] + k[i] },\n\
                 'kcount' => Array.new(n, k.length),\n\
                 'ktotal' => Array.new(n, total),\n\
               },\n\
             }\n\
           end\n";
        let out = run_ruby_columnar_with_constants(source, "add_k", &batch, &constants)
            .expect("run_ruby_columnar_with_constants");
        let sum_col = out.columns.iter().find(|c| c.name == "sum").unwrap();
        assert_eq!(read_i64_col(&sum_col.data), vec![101, 102, 103, 104]);
        let kcount = out.columns.iter().find(|c| c.name == "kcount").unwrap();
        assert_eq!(
            read_i64_col(&kcount.data),
            vec![4, 4, 4, 4],
            "length == row_count"
        );
        let ktotal = out.columns.iter().find(|c| c.name == "ktotal").unwrap();
        // 100 * 4 = 400 via #each, not just #length - proves iteration.
        assert_eq!(read_i64_col(&ktotal.data), vec![400, 400, 400, 400]);
    }

    #[test]
    fn run_ruby_columnar_rejects_bad_entry_fn_name() {
        let batch = ColumnarBatch::new(0);
        let err = run_ruby_columnar("def x(b); b; end", "not an ident", &batch)
            .expect_err("invalid identifier must be rejected before any run");
        assert!(err.to_string().contains("not a valid identifier"), "{err}");
    }

    #[test]
    fn run_ruby_columnar_rejects_unsupported_dtype_before_running() {
        let data = vec![0u8; 16];
        let mut batch = ColumnarBatch::new(1);
        batch.push(ColumnRef {
            name: "amount",
            dtype: ColumnDtype::Decimal128,
            data: &data,
            heap: None,
            validity: None,
        });
        let err = run_ruby_columnar("def f(b); b; end", "f", &batch)
            .expect_err("Decimal128 is rejected by encode_batch before any process spawns");
        assert!(err.to_string().contains("Decimal128"), "{err}");
    }
}
