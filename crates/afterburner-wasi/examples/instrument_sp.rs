// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Binary-instrumentation pass: record every `i32.store`/`f32.store` whose
//! stored value matches the observed corruption bit-pattern (`0xC200????`) into
//! a ring buffer in guest linear memory, then let the original store execute.
//!
//! ## Purpose
//!
//! The previous trap-on-value pass pinpointed that func 9779 stores a value in
//! the `0xC2000000..0xC2FFFFFF` range. But a float `-32.0` IS a valid float
//! value in numpy's float16 buffer work, so value-alone is ambiguous. This pass
//! records BOTH the store's target address AND the value so we can identify the
//! outlier store that hits a CPython type/code object rather than a float buffer.
//!
//! ## Ring layout in guest memory
//!
//! The ring lives at `RING_BASE` (0x1C00000 = 28 MiB), safely above the numpy
//! import-time heap (which stays in the ~15-25 MiB range):
//!
//!   [RING_BASE+0]  head: i32   -- next write slot index (monotone, not wrapped)
//!   [RING_BASE+4]  _pad: i32   -- reserved, always 0
//!   [RING_BASE+8 .. RING_BASE+8+RING_CAP*8]  entries:
//!       entry[i] = { addr: i32 @ +0, val: i32 @ +4 }
//!
//! `RING_CAP` = 1024: holds the last 1024 matching stores (ring wrap = oldest
//! overwritten). Total footprint = 8 + 1024*8 = 8200 bytes.
//!
//! ## Injected gadget (per matching store)
//!
//! For `i32.store` with stack `[.., addr, value]`:
//!
//!   ; save value and addr into scratch locals, restore stack
//!   local.set  scratch_val          ; pop value
//!   local.tee  scratch_addr         ; save addr, addr stays on stack
//!   local.get  scratch_val          ; restore value -> stack = [addr, value]
//!   ; check pattern
//!   local.get  scratch_val
//!   i32.const  0xFFFF0000
//!   i32.and
//!   i32.const  0xC2000000
//!   i32.eq
//!   if                              ; if match, record
//!     ... ring-write gadget ...
//!   end
//!   ; original store executes with [addr, value] intact
//!   i32.store ...
//!
//! For `f32.store` with stack `[.., addr, f32_value]`:
//!   save f32 into scratch_f32, reinterpret to i32 for the bit check.
//!
//! ## Usage
//!
//!   cargo run -q -p afterburner-wasi --example instrument_sp
//!
//!   BURN_PROBE_WASM=/tmp/pyodide-spcheck.wasm \
//!     cargo run -q -p afterburner-wasi --example numpy_import_probe \
//!     2>&1 | grep -iE 'STORE-REC|addr=|val=|memory fault' | tail -60
//!
//! ## Environment
//!
//!   BURN_INPUT_WASM  -- input wasm path  (default: /tmp/pyodide-exnref.wasm)
//!   BURN_OUTPUT_WASM -- output wasm path (default: /tmp/pyodide-spcheck.wasm)

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, Instruction, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{CompositeInnerType, Operator, Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-spcheck.wasm";

/// Ring buffer base address in guest linear memory (28 MiB).
/// Chosen to be above the typical numpy import-time heap (~15-25 MiB) and
/// well within the 30 MiB initial Pyodide linear memory allocation.
#[allow(dead_code)] // diagnostic probe scaffolding
const RING_BASE: u32 = 0x1C0_0000;

/// Number of ring entries (power of two for cheap wrap).
#[allow(dead_code)] // diagnostic probe scaffolding
const RING_CAP: u32 = 1024;

/// Byte offset from RING_BASE where entries start (skip 8-byte header).
#[allow(dead_code)] // diagnostic probe scaffolding
const RING_ENTRIES_OFFSET: u32 = 8;

/// Corruption bit-pattern mask and expected high bits: (val & MASK) == EXPECTED
/// matches the f32 ~-32.0 family (0xC200????) observed in the corruption.
const PATTERN_MASK: u32 = 0xFFFF_0000;
const PATTERN_EXPECTED: u32 = 0xC200_0000;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());

    eprintln!("[instrument_sp] reading {input}");
    let wasm = match fs::read(&input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: cannot read {input}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[instrument_sp] {} bytes read", wasm.len());

    eprintln!("[instrument_sp] pre-parsing type + function sections ...");
    let (param_counts, local_counts, import_func_count) = match pre_parse(&wasm) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: pre-parse failed: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "[instrument_sp] {} combined function slots, {} imported",
        param_counts.len(),
        import_func_count,
    );

    eprintln!("[instrument_sp] reencoding with store-record instrumentation ...");
    let instrumented =
        match reencode_with_records(&wasm, &param_counts, &local_counts, import_func_count) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("ERROR: reencode failed: {e}");
                std::process::exit(1);
            }
        };
    eprintln!(
        "[instrument_sp] instrumented module: {} bytes",
        instrumented.len()
    );

    match fs::write(&output, &instrumented) {
        Ok(()) => eprintln!("[instrument_sp] wrote {output}"),
        Err(e) => {
            eprintln!("ERROR: cannot write {output}: {e}");
            std::process::exit(1);
        }
    }

    // Quick sanity: the output must still parse.
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[instrument_sp] output wasm parses OK"),
        Some(Err(e)) => {
            eprintln!("WARN: output wasm parse check: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 1: pre-parse -- collect param counts and local counts per function.
//
// Returns (param_counts, local_counts, import_func_count):
//   param_counts[i] = number of parameters for combined function index i
//   local_counts[i] = number of declared locals for code-section body i
//                     (index into code section, not combined index)
//   import_func_count = how many combined slots are imports (no code body)
// ---------------------------------------------------------------------------

fn pre_parse(wasm: &[u8]) -> Result<(Vec<u32>, Vec<u32>, usize), String> {
    let mut types: Vec<u32> = Vec::new();
    let mut func_type_indices: Vec<u32> = Vec::new();
    let mut import_func_count: usize = 0;
    let mut local_counts: Vec<u32> = Vec::new();

    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.map_err(|e| format!("parse error: {e}"))?;
        match payload {
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group = rec_group.map_err(|e| format!("type section: {e}"))?;
                    for sub_type in rec_group.into_types() {
                        let param_count = match sub_type.composite_type.inner {
                            CompositeInnerType::Func(ref ft) => ft.params().len() as u32,
                            _ => 0,
                        };
                        types.push(param_count);
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|e| format!("import section: {e}"))?;
                    if let TypeRef::Func(ty_idx) = import.ty {
                        func_type_indices.push(ty_idx);
                        import_func_count += 1;
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty_idx in reader {
                    let ty_idx = ty_idx.map_err(|e| format!("function section: {e}"))?;
                    func_type_indices.push(ty_idx);
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut count = 0u32;
                for pair in body
                    .get_locals_reader()
                    .map_err(|e| format!("locals: {e}"))?
                {
                    let (cnt, _) = pair.map_err(|e| format!("local pair: {e}"))?;
                    count += cnt;
                }
                local_counts.push(count);
            }
            _ => {}
        }
    }

    let param_counts: Vec<u32> = func_type_indices
        .iter()
        .map(|&ty_idx| types.get(ty_idx as usize).copied().unwrap_or(0))
        .collect();

    Ok((param_counts, local_counts, import_func_count))
}

// ---------------------------------------------------------------------------
// Phase 2: reencode with injected record gadgets.
//
// Extra locals appended to each function (indices after existing params+locals):
//   scratch_val:  i32  -- captured integer value being stored
//   scratch_addr: i32  -- captured base address (wasm stack operand, not eff.)
//   scratch_head: i32  -- current ring head (loaded once per record)
//   scratch_slot: i32  -- byte pointer to the ring entry being written
//   scratch_f32:  f32  -- f32 capture for f32.store path
// ---------------------------------------------------------------------------

struct StoreRecorder {
    param_counts: Vec<u32>,
    local_counts: Vec<u32>,
    import_func_count: usize,
    body_index: usize,
    stores_instrumented: u64,
}

impl StoreRecorder {
    fn new(param_counts: Vec<u32>, local_counts: Vec<u32>, import_func_count: usize) -> Self {
        Self {
            param_counts,
            local_counts,
            import_func_count,
            body_index: 0,
            stores_instrumented: 0,
        }
    }
}

/// Emit a 4-deep shift register of local1 (the chain node) at every func-3871
/// store, so the node survives local1 being reused before the trap. Slots:
///   [0x1C00018] newest .. [0x1C00024] oldest. The trapping node is the one
/// whose +24 cache == the garbage pointer (e.g. 10).
fn emit_local1_history(f: &mut Function) {
    let ma = wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    };
    let shift = |f: &mut Function, dst: i32, src: i32| {
        f.instruction(&Instruction::I32Const(dst));
        f.instruction(&Instruction::I32Const(src));
        f.instruction(&Instruction::I32Load(ma));
        f.instruction(&Instruction::I32Store(ma));
    };
    shift(f, 0x1C0_0024, 0x1C0_0020);
    shift(f, 0x1C0_0020, 0x1C0_001C);
    shift(f, 0x1C0_001C, 0x1C0_0018);
    f.instruction(&Instruction::I32Const(0x1C0_0018));
    f.instruction(&Instruction::LocalGet(1));
    f.instruction(&Instruction::I32Store(ma));
}

/// Emit the gadget that, at the near-NULL store in func 3871, saves the
/// diagnostic context to fixed scratch slots so the probe can dump it:
///   [0x1C00000] = local0 (param0 = the frame being cleared)
///   [0x1C00004] = effective store address (base + offset): 10 vs 22
///                 disambiguates the INCREF path (188) from the link path (173)
///   [0x1C00008] = local1 (the node in the frame_obj chain)
///   [0x1C0000C] = local3 (the garbage cache/return value, e.g. 10)
/// Used only in func 3871.
fn emit_param0_save(f: &mut Function, scratch_addr: u32, offset: u64) {
    let st_local = |f: &mut Function, slot: i32, local: u32| {
        let ma = wasm_encoder::MemArg {
            offset: 0,
            align: 2,
            memory_index: 0,
        };
        f.instruction(&Instruction::I32Const(slot));
        f.instruction(&Instruction::LocalGet(local));
        f.instruction(&Instruction::I32Store(ma));
    };
    st_local(f, 0x1C0_0000, 0);
    st_local(f, 0x1C0_0008, 1);
    st_local(f, 0x1C0_000C, 3);
    st_local(f, 0x1C0_0010, 2); // local2 = frame_obj (the chain root)
    st_local(f, 0x1C0_0014, 4); // local4 = call 3817 result
    // effective address = scratch_addr + offset
    let ma = wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    };
    f.instruction(&Instruction::I32Const(0x1C0_0004));
    f.instruction(&Instruction::LocalGet(scratch_addr));
    f.instruction(&Instruction::I32Const(offset as i32));
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::I32Store(ma));
}

impl Reencode for StoreRecorder {
    type Error = String;

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func_body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReencodeError<String>> {
        let combined_idx = self.import_func_count + self.body_index;
        let body_idx = self.body_index;
        self.body_index += 1;

        let param_count: u32 = self.param_counts.get(combined_idx).copied().unwrap_or(0);
        let existing_local_count: u32 = self.local_counts.get(body_idx).copied().unwrap_or(0);

        // Collect existing locals for the Function builder.
        let mut locals: Vec<(u32, ValType)> = Vec::new();
        for pair in func_body
            .get_locals_reader()
            .map_err(ReencodeError::ParseError)?
        {
            let (cnt, ty) = pair.map_err(ReencodeError::ParseError)?;
            locals.push((cnt, self.val_type(ty)?));
        }

        // Append 4 i32 scratch locals + 1 f32 scratch local.
        locals.push((4, ValType::I32));
        locals.push((1, ValType::F32));
        locals.push((1, ValType::I64));

        // Local indices (0-based from start of function, params included):
        //   params: [0 .. param_count)
        //   existing locals: [param_count .. param_count + existing_local_count)
        //   scratch_val:  param_count + existing_local_count
        //   scratch_addr: param_count + existing_local_count + 1
        //   scratch_head: param_count + existing_local_count + 2
        //   scratch_slot: param_count + existing_local_count + 3
        //   scratch_f32:  param_count + existing_local_count + 4
        let base = param_count + existing_local_count;
        let scratch_val = base;
        let scratch_addr = base + 1;
        let scratch_head = base + 2;
        let _scratch_slot = base + 3;
        let scratch_f32 = base + 4;
        let scratch_i64 = base + 5;

        let mut f = Function::new(locals);
        // func 3871 (the frame clear/dealloc) recurses via the dealloc
        // dispatcher (call 2314), so capturing param0 at entry grabs the wrong
        // (nested, clean) frame. Instead we save local 0 (param0 = the trapping
        // frame) at the near-NULL store itself, just before the trap.
        let is_target_3871 = combined_idx == 3871;

        let mut reader = func_body
            .get_operators_reader()
            .map_err(ReencodeError::ParseError)?;

        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;

            match op {
                Operator::I32Store { memarg } => {
                    // Stack before i32.store: [.., addr:i32, value:i32]
                    // Capture both into scratch locals, restore stack.
                    f.instruction(&Instruction::LocalSet(scratch_val)); // pop value
                    f.instruction(&Instruction::LocalTee(scratch_addr)); // save addr, keep on stack
                    f.instruction(&Instruction::LocalGet(scratch_val)); // restore value
                    // Stack is now [addr, value] as required by i32.store.
                    if is_target_3871 {
                        emit_local1_history(&mut f);
                    }

                    // Trap if the effective address (base + offset) < 1024: the
                    // reserved low region. A near-NULL write = the corruption.
                    let _ = (scratch_val, PATTERN_MASK, PATTERN_EXPECTED);
                    // Near-NULL write (eff < 1024): func 3871's INCREF of the
                    // corrupt frame_obj pointer. Captures the frame for the dump
                    // (confirms the corrupt frame address is still 0xf51dac).
                    f.instruction(&Instruction::LocalGet(scratch_addr));
                    f.instruction(&Instruction::I32Const(memarg.offset as i32));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Const(1024));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    if is_target_3871 {
                        emit_param0_save(&mut f, scratch_addr, memarg.offset);
                    }
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);

                    // Original store.
                    let enc_memarg = self.mem_arg(memarg)?;
                    f.instruction(&Instruction::I32Store(enc_memarg));
                    self.stores_instrumented += 1;
                }
                Operator::F32Store { memarg } => {
                    // Stack before f32.store: [.., addr:i32, f32_value:f32]
                    // Save f32 into scratch_f32, addr into scratch_addr; restore stack.
                    f.instruction(&Instruction::LocalSet(scratch_f32)); // pop f32
                    f.instruction(&Instruction::LocalTee(scratch_addr)); // save addr, keep
                    f.instruction(&Instruction::LocalGet(scratch_f32)); // restore f32
                    // Stack is [addr, f32_value] as required by f32.store.
                    if is_target_3871 {
                        emit_local1_history(&mut f);
                    }

                    // Trap if effective addr < 1024 (near-NULL write = corruption).
                    f.instruction(&Instruction::LocalGet(scratch_addr));
                    f.instruction(&Instruction::I32Const(memarg.offset as i32));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Const(1024));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    if is_target_3871 {
                        emit_param0_save(&mut f, scratch_addr, memarg.offset);
                    }
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);

                    // Original store.
                    let enc_memarg = self.mem_arg(memarg)?;
                    f.instruction(&Instruction::F32Store(enc_memarg));
                    self.stores_instrumented += 1;
                }
                Operator::I64Store { memarg } => {
                    // A paired i64 write of a frame's `previous` = "expandtabs"
                    // (0x18be8c0). previous can be the low word (i64 store at
                    // frame+4 = 0xf51db0) or the high word (i64 store at
                    // frame+0 = 0xf51dac). Trap on either.
                    f.instruction(&Instruction::LocalSet(scratch_i64)); // pop value
                    f.instruction(&Instruction::LocalTee(scratch_addr)); // peek addr
                    f.instruction(&Instruction::LocalGet(scratch_i64)); // push value
                    f.instruction(&Instruction::LocalGet(scratch_addr));
                    f.instruction(&Instruction::I32Const(memarg.offset as i32));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::LocalSet(scratch_head)); // scratch_head = eff
                    // condA: eff == 0xf51db0 && low32(value) == 0x18be8c0
                    f.instruction(&Instruction::LocalGet(scratch_head));
                    f.instruction(&Instruction::I32Const(0xf51db0u32 as i32));
                    f.instruction(&Instruction::I32Eq);
                    f.instruction(&Instruction::LocalGet(scratch_i64));
                    f.instruction(&Instruction::I32WrapI64);
                    f.instruction(&Instruction::I32Const(0x18be8c0));
                    f.instruction(&Instruction::I32Eq);
                    f.instruction(&Instruction::I32And);
                    // condB: eff == 0xf51dac && high32(value) == 0x18be8c0
                    f.instruction(&Instruction::LocalGet(scratch_head));
                    f.instruction(&Instruction::I32Const(0xf51dacu32 as i32));
                    f.instruction(&Instruction::I32Eq);
                    f.instruction(&Instruction::LocalGet(scratch_i64));
                    f.instruction(&Instruction::I64Const(32));
                    f.instruction(&Instruction::I64ShrU);
                    f.instruction(&Instruction::I32WrapI64);
                    f.instruction(&Instruction::I32Const(0x18be8c0));
                    f.instruction(&Instruction::I32Eq);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::I32Or);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);
                    let enc_memarg = self.mem_arg(memarg)?;
                    f.instruction(&Instruction::I64Store(enc_memarg));
                    self.stores_instrumented += 1;
                }
                Operator::MemoryCopy { dst_mem, src_mem } => {
                    // Stack: [dest, src, len]. Trap if the copy covers 0xf51db0
                    // (a frame's `previous` slot): catches the corruption when
                    // it arrives via a frame copy rather than a direct store.
                    f.instruction(&Instruction::LocalSet(scratch_head)); // len
                    f.instruction(&Instruction::LocalSet(scratch_val)); // src
                    f.instruction(&Instruction::LocalTee(scratch_addr)); // dest (keep)
                    f.instruction(&Instruction::LocalGet(scratch_val)); // src
                    f.instruction(&Instruction::LocalGet(scratch_head)); // len
                    // (0xf51db0 - dest) <u len  <=>  dest <= 0xf51db0 < dest+len
                    f.instruction(&Instruction::I32Const(0xf51db0u32 as i32));
                    f.instruction(&Instruction::LocalGet(scratch_addr));
                    f.instruction(&Instruction::I32Sub);
                    f.instruction(&Instruction::LocalGet(scratch_head));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);
                    f.instruction(&Instruction::MemoryCopy { src_mem, dst_mem });
                    self.stores_instrumented += 1;
                }
                other => {
                    let enc = self.instruction(other)?;
                    f.instruction(&enc);
                }
            }
        }

        code.function(&f);
        Ok(())
    }
}

/// Emit the ring-write gadget into function `f`.
///
/// Preconditions: `scratch_addr` holds the store base address (i32),
/// `scratch_val` holds the integer value (i32). After this gadget the ring
/// at `RING_BASE` has one new entry and head is incremented.
///
/// Ring layout:
///   RING_BASE+0: head (i32, monotonically incrementing, never wrapped)
///   RING_BASE+4: _pad (i32, 0)
///   RING_BASE+8 + ((head & (RING_CAP-1)) * 8): { addr:i32, val:i32 }
#[allow(dead_code)] // diagnostic probe scaffolding
fn emit_ring_write(
    f: &mut Function,
    scratch_addr: u32,
    scratch_val: u32,
    scratch_head: u32,
    scratch_slot: u32,
) {
    // Load current head from RING_BASE+0.
    f.instruction(&Instruction::I32Const(RING_BASE as i32));
    f.instruction(&Instruction::I32Load(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));
    f.instruction(&Instruction::LocalSet(scratch_head));

    // slot_ptr = RING_BASE + RING_ENTRIES_OFFSET + (head & (RING_CAP-1)) * 8
    f.instruction(&Instruction::LocalGet(scratch_head));
    f.instruction(&Instruction::I32Const((RING_CAP - 1) as i32));
    f.instruction(&Instruction::I32And);
    f.instruction(&Instruction::I32Const(8)); // sizeof entry
    f.instruction(&Instruction::I32Mul);
    f.instruction(&Instruction::I32Const(
        (RING_BASE + RING_ENTRIES_OFFSET) as i32,
    ));
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::LocalSet(scratch_slot));

    // Store addr at slot+0.
    f.instruction(&Instruction::LocalGet(scratch_slot));
    f.instruction(&Instruction::LocalGet(scratch_addr));
    f.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));

    // Store val at slot+4.
    f.instruction(&Instruction::LocalGet(scratch_slot));
    f.instruction(&Instruction::LocalGet(scratch_val));
    f.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 4,
        align: 2,
        memory_index: 0,
    }));

    // Increment head: *(RING_BASE+0) = head + 1
    f.instruction(&Instruction::I32Const(RING_BASE as i32));
    f.instruction(&Instruction::LocalGet(scratch_head));
    f.instruction(&Instruction::I32Const(1));
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    }));
}

fn reencode_with_records(
    wasm: &[u8],
    param_counts: &[u32],
    local_counts: &[u32],
    import_func_count: usize,
) -> Result<Vec<u8>, String> {
    let mut recorder = StoreRecorder::new(
        param_counts.to_vec(),
        local_counts.to_vec(),
        import_func_count,
    );
    let mut module = Module::new();

    recorder
        .parse_core_module(&mut module, Parser::new(0), wasm)
        .map_err(|e| format!("reencode error: {e}"))?;

    eprintln!(
        "[instrument_sp] instrumented {} store sites (i32.store + f32.store)",
        recorder.stores_instrumented
    );

    Ok(module.finish())
}
