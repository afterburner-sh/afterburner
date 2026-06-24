// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Binary-instrumentation pass for a SIDE_MODULE `.so`: trap at the first
//! `i32.store` whose stored value equals a target u32 (default: the wild
//! `0x2371caa` numpy-core "$device" pointer), recording the combined function
//! index and the per-function store ordinal into a fixed scratch region so a
//! `WasmBacktrace` and the captured indices pinpoint the corrupting write.
//!
//! ## Why a separate pass from `instrument_sp`
//!
//! `instrument_sp` instruments the MAIN module. The numpy.random corruption is
//! written by a SIDE module (`bit_generator.so`) during its `__wasm_call_ctors`.
//! We instrument that side module's own code, mount it via `BURN_FS_OVERRIDE`,
//! and let the trap fire inside the side module so the backtrace names the side
//! module's function. Uses appended i32 locals (per function), so no global
//! section is required (Cython side modules have none).
//!
//! ## Scratch layout (SCRATCH = 0x1BE_0000, distinct from the other passes):
//!   [SCRATCH+0]  magic    : i32 = 0x5DE0_57E1 once the target store is seen
//!   [SCRATCH+4]  func     : i32 = combined function index of the storing func
//!   [SCRATCH+8]  ordinal  : i32 = per-function i32.store ordinal (0-based)
//!   [SCRATCH+12] addr     : i32 = effective store address (base + offset)
//!
//! ## Usage
//!
//!   BURN_INPUT_WASM=/tmp/bit_generator....so \
//!   BURN_OUTPUT_WASM=/tmp/bit_generator.instr.so \
//!   BURN_TRAP_VALUE=0x2371caa \
//!     cargo run -q -p afterburner-wasi --example instrument_sidemod_store

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{CompositeInnerType, Operator, Parser, Payload, TypeRef};

const SCRATCH: u32 = 0x1BE_0000;
const MAGIC: i32 = 0x5DE0_57E1u32 as i32;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").expect("set BURN_INPUT_WASM");
    let output = std::env::var("BURN_OUTPUT_WASM").expect("set BURN_OUTPUT_WASM");
    let target = std::env::var("BURN_TRAP_VALUE")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x2371caa);
    // BURN_TRAP_OP=store (default) traps on i32.store of `target`; =load traps on
    // i32.load that produces `target`; =callret traps right after a `call` (or
    // `call_indirect`) whose single i32 result equals `target` (to find which
    // C-API call yields the corrupt pointer).
    let op = std::env::var("BURN_TRAP_OP").unwrap_or_else(|_| "store".to_owned());
    let trap_on_load = op == "load";
    let trap_on_callret = op == "callret";

    eprintln!("[instr-sidemod] reading {input}; trap value = {target:#x}; op = {op}");
    let wasm = fs::read(&input).expect("read input");

    let (param_counts, local_counts, import_func_count, func_single_i32_ret, type_single_i32_ret) =
        pre_parse(&wasm);
    eprintln!(
        "[instr-sidemod] {} function slots, {import_func_count} imported",
        param_counts.len()
    );

    let mut recorder = StoreTrap {
        param_counts,
        local_counts,
        import_func_count,
        body_index: 0,
        target,
        trap_on_load,
        trap_on_callret,
        func_single_i32_ret,
        type_single_i32_ret,
        instrumented: 0,
    };
    let mut out = Module::new();
    recorder
        .parse_core_module(&mut out, Parser::new(0), &wasm)
        .expect("reencode");
    let instrumented = out.finish();
    eprintln!(
        "[instr-sidemod] instrumented {} i32.store sites, {} bytes",
        recorder.instrumented,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[instr-sidemod] output parses OK"),
        Some(Err(e)) => eprintln!("WARN: output parse: {e}"),
    }
}

/// Collect param counts (per combined func index), local counts (per code body),
/// and the imported-function count, mirroring `instrument_sp::pre_parse`.
/// Also returns, per combined function index, whether the function's single
/// result is i32 (for call-return trapping).
fn pre_parse(wasm: &[u8]) -> (Vec<u32>, Vec<u32>, usize, Vec<bool>, Vec<bool>) {
    let mut type_params: Vec<u32> = Vec::new();
    let mut type_single_i32_ret: Vec<bool> = Vec::new();
    let mut func_type_indices: Vec<u32> = Vec::new();
    let mut import_func_count = 0usize;
    let mut local_counts: Vec<u32> = Vec::new();

    for payload in Parser::new(0).parse_all(wasm) {
        match payload.expect("parse") {
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    for sub_type in rec_group.expect("type").into_types() {
                        let (pc, single_i32) = match sub_type.composite_type.inner {
                            CompositeInnerType::Func(ref ft) => {
                                let results: Vec<_> = ft.results().to_vec();
                                let single = results.len() == 1
                                    && matches!(results[0], wasmparser::ValType::I32);
                                (ft.params().len() as u32, single)
                            }
                            _ => (0, false),
                        };
                        type_params.push(pc);
                        type_single_i32_ret.push(single_i32);
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports().flatten() {
                    if let TypeRef::Func(ty_idx) = import.ty {
                        func_type_indices.push(ty_idx);
                        import_func_count += 1;
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty_idx in reader.into_iter().flatten() {
                    func_type_indices.push(ty_idx);
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut count = 0u32;
                for pair in body
                    .get_locals_reader()
                    .expect("locals")
                    .into_iter()
                    .flatten()
                {
                    count += pair.0;
                }
                local_counts.push(count);
            }
            _ => {}
        }
    }

    let param_counts: Vec<u32> = func_type_indices
        .iter()
        .map(|&ty_idx| type_params.get(ty_idx as usize).copied().unwrap_or(0))
        .collect();
    let func_single_i32_ret: Vec<bool> = func_type_indices
        .iter()
        .map(|&ty_idx| {
            type_single_i32_ret
                .get(ty_idx as usize)
                .copied()
                .unwrap_or(false)
        })
        .collect();
    (
        param_counts,
        local_counts,
        import_func_count,
        func_single_i32_ret,
        type_single_i32_ret,
    )
}

/// Emit the post-call result test gadget: tee the i32 result into `scratch_val`,
/// compare to `target` (and the magic guard), and on match record the caller
/// index, the site ordinal, and `callee` into the scratch region, then trap.
/// The result is left on the stack for the original program.
#[allow(clippy::too_many_arguments)]
fn emit_result_check(
    f: &mut Function,
    scratch_val: u32,
    target: u32,
    caller_idx: i32,
    ordinal: i32,
    callee: i32,
    ma: MemArg,
) {
    f.instruction(&Instruction::LocalTee(scratch_val));
    f.instruction(&Instruction::LocalGet(scratch_val));
    f.instruction(&Instruction::I32Const(target as i32));
    f.instruction(&Instruction::I32Eq);
    f.instruction(&Instruction::I32Const(SCRATCH as i32));
    f.instruction(&Instruction::I32Load(ma));
    f.instruction(&Instruction::I32Const(MAGIC));
    f.instruction(&Instruction::I32Ne);
    f.instruction(&Instruction::I32And);
    f.instruction(&Instruction::If(BlockType::Empty));
    let st = |f: &mut Function, off: i32, instr: &Instruction| {
        f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
        f.instruction(instr);
        f.instruction(&Instruction::I32Store(ma));
    };
    st(f, 4, &Instruction::I32Const(caller_idx));
    st(f, 8, &Instruction::I32Const(ordinal));
    st(f, 12, &Instruction::I32Const(callee));
    st(f, 0, &Instruction::I32Const(MAGIC));
    f.instruction(&Instruction::Unreachable);
    f.instruction(&Instruction::End);
}

struct StoreTrap {
    param_counts: Vec<u32>,
    local_counts: Vec<u32>,
    import_func_count: usize,
    body_index: usize,
    target: u32,
    trap_on_load: bool,
    trap_on_callret: bool,
    func_single_i32_ret: Vec<bool>,
    type_single_i32_ret: Vec<bool>,
    instrumented: u64,
}

impl Reencode for StoreTrap {
    type Error = String;

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func_body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReencodeError<String>> {
        let combined_idx = self.import_func_count + self.body_index;
        let body_idx = self.body_index;
        self.body_index += 1;

        let param_count = self.param_counts.get(combined_idx).copied().unwrap_or(0);
        let existing_local_count = self.local_counts.get(body_idx).copied().unwrap_or(0);

        let mut locals: Vec<(u32, ValType)> = Vec::new();
        for pair in func_body
            .get_locals_reader()
            .map_err(ReencodeError::ParseError)?
        {
            let (cnt, ty) = pair.map_err(ReencodeError::ParseError)?;
            locals.push((cnt, self.val_type(ty)?));
        }
        // Two appended i32 locals: scratch_val, scratch_addr.
        locals.push((2, ValType::I32));
        let base = param_count + existing_local_count;
        let scratch_val = base;
        let scratch_addr = base + 1;

        let mut f = Function::new(locals);
        let mut reader = func_body
            .get_operators_reader()
            .map_err(ReencodeError::ParseError)?;
        let mut store_ordinal: i32 = 0;
        let ma = MemArg {
            offset: 0,
            align: 2,
            memory_index: 0,
        };

        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            match op {
                Operator::I32Load { memarg } if self.trap_on_load => {
                    // Stack before: [.. addr]. Capture addr, do the load, capture
                    // the loaded value, then test it. Stack after gadget: [value].
                    f.instruction(&Instruction::LocalTee(scratch_addr)); // save addr, keep
                    let enc = self.mem_arg(memarg)?;
                    f.instruction(&Instruction::I32Load(enc)); // [.. value]
                    f.instruction(&Instruction::LocalTee(scratch_val)); // save value, keep
                    // cond = (value == target) & (magic unset)
                    f.instruction(&Instruction::LocalGet(scratch_val));
                    f.instruction(&Instruction::I32Const(self.target as i32));
                    f.instruction(&Instruction::I32Eq);
                    f.instruction(&Instruction::I32Const(SCRATCH as i32));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::I32Ne);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    let st = |f: &mut Function, off: i32, instr: &Instruction| {
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
                        f.instruction(instr);
                        f.instruction(&Instruction::I32Store(ma));
                    };
                    st(&mut f, 4, &Instruction::I32Const(combined_idx as i32));
                    st(&mut f, 8, &Instruction::I32Const(store_ordinal));
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 12));
                    f.instruction(&Instruction::LocalGet(scratch_addr));
                    f.instruction(&Instruction::I32Const(memarg.offset as i32));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Store(ma));
                    st(&mut f, 0, &Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);
                    // value already on stack as the load result.
                    store_ordinal += 1;
                    self.instrumented += 1;
                }
                Operator::I32Store { memarg } if !self.trap_on_load => {
                    // Stack: [.. addr, value]. Capture both into scratch locals,
                    // restore the stack, then test the value.
                    f.instruction(&Instruction::LocalSet(scratch_val)); // pop value
                    f.instruction(&Instruction::LocalTee(scratch_addr)); // save addr, keep
                    f.instruction(&Instruction::LocalGet(scratch_val)); // restore value
                    // stack now [addr, value] for the original store.

                    // cond = (value == target) & (magic unset)
                    f.instruction(&Instruction::LocalGet(scratch_val));
                    f.instruction(&Instruction::I32Const(self.target as i32));
                    f.instruction(&Instruction::I32Eq);
                    f.instruction(&Instruction::I32Const(SCRATCH as i32));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::I32Ne);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    let st = |f: &mut Function, off: i32, instr: &Instruction| {
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
                        f.instruction(instr);
                        f.instruction(&Instruction::I32Store(ma));
                    };
                    st(&mut f, 4, &Instruction::I32Const(combined_idx as i32));
                    st(&mut f, 8, &Instruction::I32Const(store_ordinal));
                    // effective addr = scratch_addr + memarg.offset
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 12));
                    f.instruction(&Instruction::LocalGet(scratch_addr));
                    f.instruction(&Instruction::I32Const(memarg.offset as i32));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Store(ma));
                    st(&mut f, 0, &Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);

                    let enc = self.mem_arg(memarg)?;
                    f.instruction(&Instruction::I32Store(enc));
                    store_ordinal += 1;
                    self.instrumented += 1;
                }
                Operator::Call { function_index }
                    if self.trap_on_callret
                        && self
                            .func_single_i32_ret
                            .get(function_index as usize)
                            .copied()
                            .unwrap_or(false) =>
                {
                    // Emit the call, then tee its i32 result and test it. If a C-API
                    // call returns `target`, trap recording the callee index (in
                    // SCRATCH+12) and this caller (SCRATCH+4) + call ordinal.
                    let enc = self.function_index(function_index)?;
                    f.instruction(&Instruction::Call(enc));
                    emit_result_check(
                        &mut f,
                        scratch_val,
                        self.target,
                        combined_idx as i32,
                        store_ordinal,
                        function_index as i32,
                        ma,
                    );
                    store_ordinal += 1;
                    self.instrumented += 1;
                }
                Operator::CallIndirect {
                    type_index,
                    table_index,
                } if self.trap_on_callret
                    && self
                        .type_single_i32_ret
                        .get(type_index as usize)
                        .copied()
                        .unwrap_or(false) =>
                {
                    let enc_ty = self.type_index(type_index)?;
                    f.instruction(&Instruction::CallIndirect {
                        type_index: enc_ty,
                        table_index,
                    });
                    // callee index unknown for indirect; record -1 in SCRATCH+12.
                    emit_result_check(
                        &mut f,
                        scratch_val,
                        self.target,
                        combined_idx as i32,
                        store_ordinal,
                        -1,
                        ma,
                    );
                    store_ordinal += 1;
                    self.instrumented += 1;
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
