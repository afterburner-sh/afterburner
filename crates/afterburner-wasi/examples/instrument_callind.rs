// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Binary-instrumentation pass: trap at the first `call_indirect` whose table
//! index lands in the null gap [6074..6643) or is 0, recording the exact index,
//! the calling function, and the call-site ordinal into a fixed scratch region.
//!
//! ## Purpose
//!
//! The numpy-import trap is `IndirectCallToNull` on a DIRECT call_indirect (not
//! via an invoke_* trampoline). The element segment fills table slots [1..6074);
//! slots [6074..6643) stay null. We need the EXACT slot a baked function pointer
//! targets and which function should live there. This pass makes the guest trap
//! at that precise call_indirect and stashes the index so the probe can read it.
//!
//! ## Scratch layout in guest memory (at SCRATCH = 0x1BF_0000, below the
//! store-ring at 0x1C0_0000 so the two instrumenters can coexist):
//!
//!   [SCRATCH+0]  magic   : i32  = 0xCA11_1DCA once a gap/null call is seen
//!   [SCRATCH+4]  index   : i32  = the offending table index
//!   [SCRATCH+8]  func    : i32  = combined function index of the caller
//!   [SCRATCH+12] callsite: i32  = per-function call_indirect ordinal (0-based)
//!
//! The gadget records ONLY the first offending call (magic guards re-entry) and
//! then traps, so the captured values are exactly the trapping call.
//!
//! ## Usage
//!
//!   cargo run -q -p afterburner-wasi --example instrument_callind
//!   BURN_PROBE_WASM=/tmp/pyodide-callind.wasm \
//!     cargo run -q -p afterburner-wasi --example numpy_import_probe 2>&1 | tail -60
//!
//! ## Environment
//!
//!   BURN_INPUT_WASM  -- input wasm path  (default: /tmp/pyodide-exnref.wasm)
//!   BURN_OUTPUT_WASM -- output wasm path (default: /tmp/pyodide-callind.wasm)

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Operator, Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-callind.wasm";

/// Scratch base in guest linear memory (just below the store-ring at 0x1C00000).
const SCRATCH: u32 = 0x1BF_0000;
/// Magic written when a gap/null indirect target is observed.
const MAGIC: i32 = 0xCA11_1DCAu32 as i32;

/// Gap bounds: table slots the element segment never fills.
const GAP_LO: i32 = 6074;
const GAP_HI: i32 = 6643;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());

    eprintln!("[instrument_callind] reading {input}");
    let wasm = match fs::read(&input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: cannot read {input}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[instrument_callind] {} bytes read", wasm.len());

    let import_func_count = match pre_parse(&wasm) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ERROR: pre-parse failed: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[instrument_callind] {import_func_count} imported functions");

    let mut recorder = CallIndRecorder {
        import_func_count,
        body_index: 0,
        instrumented: 0,
    };
    let mut out = Module::new();
    if let Err(e) = recorder.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[instrument_callind] instrumented {} call_indirect sites, module {} bytes",
        recorder.instrumented,
        instrumented.len()
    );

    match fs::write(&output, &instrumented) {
        Ok(()) => eprintln!("[instrument_callind] wrote {output}"),
        Err(e) => {
            eprintln!("ERROR: cannot write {output}: {e}");
            std::process::exit(1);
        }
    }
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[instrument_callind] output wasm parses OK"),
        Some(Err(e)) => eprintln!("WARN: output wasm parse check: {e}"),
    }
}

/// Count imported functions (combined index base for code bodies).
fn pre_parse(wasm: &[u8]) -> Result<usize, String> {
    let mut import_func_count = 0usize;
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.map_err(|e| format!("parse error: {e}"))?;
        if let Payload::ImportSection(reader) = payload {
            for import in reader.into_imports() {
                let import = import.map_err(|e| format!("import section: {e}"))?;
                if let TypeRef::Func(_) = import.ty {
                    import_func_count += 1;
                }
            }
        }
    }
    Ok(import_func_count)
}

struct CallIndRecorder {
    import_func_count: usize,
    body_index: usize,
    instrumented: u64,
}

impl Reencode for CallIndRecorder {
    type Error = String;

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func_body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReencodeError<String>> {
        let combined_idx = (self.import_func_count + self.body_index) as i32;
        self.body_index += 1;

        // Collect existing locals, then append one i32 scratch local for the index.
        let mut locals: Vec<(u32, ValType)> = Vec::new();
        let mut existing_local_count = 0u32;
        for pair in func_body
            .get_locals_reader()
            .map_err(ReencodeError::ParseError)?
        {
            let (cnt, ty) = pair.map_err(ReencodeError::ParseError)?;
            existing_local_count += cnt;
            locals.push((cnt, self.val_type(ty)?));
        }
        locals.push((1, ValType::I32));

        // Scratch local index = params + existing locals. We need the param count;
        // recover it from the function type via the body's type is not available
        // here, so use a conservative approach: the appended local sits after all
        // existing locals AND params. wasm-encoder Function::new counts locals
        // from after params, but LocalGet/Set indices are param+local space. We do
        // not know param_count here, so we cannot safely index the scratch local
        // by absolute position. Instead, avoid a scratch local entirely: duplicate
        // the index via a local.tee into a NEW local whose absolute index we DO
        // know only if we know params. To keep this robust, we instead use a
        // global. See below: we use I32 global `g_scratch_idx`.
        let _ = existing_local_count;

        let mut f = Function::new(locals);
        let mut reader = func_body
            .get_operators_reader()
            .map_err(ReencodeError::ParseError)?;
        let mut callsite_ordinal: i32 = 0;
        let ma = MemArg {
            offset: 0,
            align: 2,
            memory_index: 0,
        };

        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            match op {
                Operator::CallIndirect {
                    type_index,
                    table_index,
                } => {
                    // Stack top is the table index. Record it to memory via a
                    // store that consumes a duplicate: we dup using a global so we
                    // do not need to know the function's local-index base.
                    //
                    // Sequence (stack: [.. idx]):
                    //   global.set g_idx          ; pop idx -> global (stack: [..])
                    //   ; if (g_idx in gap || g_idx==0) && magic unset: record+trap
                    //   ... checks reading global ...
                    //   global.get g_idx          ; push idx back (stack: [.. idx])
                    //   call_indirect
                    f.instruction(&Instruction::GlobalSet(G_IDX));

                    // cond = (idx == 0) | ((idx >= GAP_LO) & (idx < GAP_HI))
                    f.instruction(&Instruction::GlobalGet(G_IDX));
                    f.instruction(&Instruction::I32Eqz); // idx == 0
                    f.instruction(&Instruction::GlobalGet(G_IDX));
                    f.instruction(&Instruction::I32Const(GAP_LO));
                    f.instruction(&Instruction::I32GeU);
                    f.instruction(&Instruction::GlobalGet(G_IDX));
                    f.instruction(&Instruction::I32Const(GAP_HI));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::I32Or);
                    // & (magic unset)
                    f.instruction(&Instruction::I32Const(SCRATCH as i32));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::I32Ne);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    // record magic/index/func/callsite then trap.
                    let st = |f: &mut Function, off: i32, val_instr: &Instruction| {
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
                        f.instruction(val_instr);
                        f.instruction(&Instruction::I32Store(ma));
                    };
                    st(&mut f, 4, &Instruction::GlobalGet(G_IDX));
                    st(&mut f, 8, &Instruction::I32Const(combined_idx));
                    st(&mut f, 12, &Instruction::I32Const(callsite_ordinal));
                    // Capture the value of global 568 (the dispatch-table base
                    // _PyEval_EvalFrameDefault reads) at the trapping call.
                    st(&mut f, 16, &Instruction::GlobalGet(568));
                    // In func 3530 (_PyEval_EvalFrameDefault) the dispatch index
                    // is local3; local5/local7 are the bytecode ptr and the
                    // operand stack ptr. Capture them to classify the null call:
                    // a sane small local3 => incomplete table; garbage => upstream
                    // corruption of the index/data.
                    if combined_idx == 3530 {
                        st(&mut f, 20, &Instruction::LocalGet(3));
                        st(&mut f, 24, &Instruction::LocalGet(5));
                        st(&mut f, 28, &Instruction::LocalGet(7));
                    }
                    // magic last so a reader never sees a half-written record.
                    st(&mut f, 0, &Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);

                    f.instruction(&Instruction::GlobalGet(G_IDX));
                    let enc_ty = self.type_index(type_index);
                    f.instruction(&Instruction::CallIndirect {
                        type_index: enc_ty?,
                        table_index,
                    });
                    callsite_ordinal += 1;
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

    fn parse_global_section(
        &mut self,
        globals: &mut wasm_encoder::GlobalSection,
        section: wasmparser::GlobalSectionReader<'_>,
    ) -> Result<(), ReencodeError<String>> {
        // Re-emit all existing globals, then append our scratch global g_idx.
        for g in section {
            let g = g.map_err(ReencodeError::ParseError)?;
            self.parse_global(globals, g)?;
        }
        globals.global(
            wasm_encoder::GlobalType {
                val_type: ValType::I32,
                mutable: true,
                shared: false,
            },
            &wasm_encoder::ConstExpr::i32_const(0),
        );
        Ok(())
    }
}

/// Index of the appended scratch global. The module declares 1776 defined
/// globals plus 286 imported globals (= 2062 total: indices 0..2062). Our
/// appended global is the next one. The Reencode pass preserves global ordering,
/// so the new global's index equals the original total global count.
///
/// Imported globals (286) occupy indices 0..286, defined globals (1776) occupy
/// 286..2062. The appended global is index 2062.
const G_IDX: u32 = 2062;
