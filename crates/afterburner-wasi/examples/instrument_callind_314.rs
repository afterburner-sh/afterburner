// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 `call_indirect` null-target localizer.
//!
//! The 314 exnref-translated module traps `IndirectCallToNull` (slot 0) while
//! compiling a class/decorator. The table is fully populated (only slot 0 is the
//! null trap slot), so a function-pointer VALUE of 0 is being used as a table
//! index. This pass instruments every `call_indirect` so the FIRST one whose
//! index is 0 records the caller's (combined) function index and the per-function
//! call-site ordinal into a fixed guest scratch region, then traps - pinning the
//! exact site that calls through the null pointer.
//!
//! Scratch layout (guest memory) at `SCRATCH`:
//!   [SCRATCH+0]  magic    : i32 = 0xCA11_1DCA once a null call is seen
//!   [SCRATCH+4]  index    : i32 = the offending table index (0)
//!   [SCRATCH+8]  func     : i32 = combined function index of the caller
//!   [SCRATCH+12] callsite : i32 = per-function call_indirect ordinal (0-based)
//!
//! Environment:
//!   BURN_INPUT_WASM  -- input wasm path  (default: /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM -- output wasm path (default: /tmp/pyodide-314-callind.wasm)

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Operator, Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-callind.wasm";

/// Scratch base in guest linear memory. 314 grows memory well past this on a
/// 480-page (30 MiB) initial; the probe pre-grows enough. Use a high, unused
/// static address (just below the probe's 0x1C0_0000 store ring).
const SCRATCH: u32 = 0x2E0_0000;
const MAGIC: i32 = 0xCA11_1DCAu32 as i32;

/// Appended scratch global index = total globals in the 314 module (280 imported
/// + 1146 defined = 1426). The Reencode pass preserves global ordering, so the
///   appended global lands at the next index.
const G_IDX: u32 = 1426;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());

    eprintln!("[instrument_callind_314] reading {input}");
    let wasm = match fs::read(&input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: cannot read {input}: {e}");
            std::process::exit(1);
        }
    };
    let import_func_count = match pre_parse(&wasm) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ERROR: pre-parse failed: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[instrument_callind_314] {import_func_count} imported functions");

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
        "[instrument_callind_314] instrumented {} call_indirect sites, module {} bytes",
        recorder.instrumented,
        instrumented.len()
    );
    match fs::write(&output, &instrumented) {
        Ok(()) => eprintln!("[instrument_callind_314] wrote {output}"),
        Err(e) => {
            eprintln!("ERROR: cannot write {output}: {e}");
            std::process::exit(1);
        }
    }
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[instrument_callind_314] output wasm parses OK"),
        Some(Err(e)) => eprintln!("WARN: output wasm parse check: {e}"),
    }
}

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

        let mut locals: Vec<(u32, ValType)> = Vec::new();
        for pair in func_body
            .get_locals_reader()
            .map_err(ReencodeError::ParseError)?
        {
            let (cnt, ty) = pair.map_err(ReencodeError::ParseError)?;
            locals.push((cnt, self.val_type(ty)?));
        }

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
                    // Stack top is the table index. Stash it into G_IDX, test for
                    // 0 with magic-unset, record+trap if so, then re-push + call.
                    f.instruction(&Instruction::GlobalSet(G_IDX));
                    // cond = (idx == 0) & (magic != MAGIC)
                    f.instruction(&Instruction::GlobalGet(G_IDX));
                    f.instruction(&Instruction::I32Eqz);
                    f.instruction(&Instruction::I32Const(SCRATCH as i32));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::I32Ne);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    let st = |f: &mut Function, off: i32, val: &Instruction| {
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
                        f.instruction(val);
                        f.instruction(&Instruction::I32Store(ma));
                    };
                    st(&mut f, 4, &Instruction::GlobalGet(G_IDX));
                    st(&mut f, 8, &Instruction::I32Const(combined_idx));
                    st(&mut f, 12, &Instruction::I32Const(callsite_ordinal));
                    // For the known _Py_Dealloc tp_dealloc site (module func 2413,
                    // ordinal 2), capture the object and its type so the probe can
                    // inspect why tp_dealloc (PyTypeObject offset 24) is null.
                    // Param 0 (`$0`) is the object pointer; ob_type = mem[obj+4].
                    if combined_idx == 2413 && callsite_ordinal == 2 {
                        // [SCRATCH+16] = obj
                        st(&mut f, 16, &Instruction::LocalGet(0));
                        // [SCRATCH+20] = ob_type = mem[obj+4]
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + 20));
                        f.instruction(&Instruction::LocalGet(0));
                        f.instruction(&Instruction::I32Load(MemArg {
                            offset: 4,
                            align: 2,
                            memory_index: 0,
                        }));
                        f.instruction(&Instruction::I32Store(ma));
                        // [SCRATCH+24] = mem[ob_type+24] = tp_dealloc (re-read)
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + 24));
                        f.instruction(&Instruction::LocalGet(0));
                        f.instruction(&Instruction::I32Load(MemArg {
                            offset: 4,
                            align: 2,
                            memory_index: 0,
                        }));
                        f.instruction(&Instruction::I32Load(MemArg {
                            offset: 24,
                            align: 2,
                            memory_index: 0,
                        }));
                        f.instruction(&Instruction::I32Store(ma));
                        // [SCRATCH+28] = mem[ob_type+84] = tp_flags
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + 28));
                        f.instruction(&Instruction::LocalGet(0));
                        f.instruction(&Instruction::I32Load(MemArg {
                            offset: 4,
                            align: 2,
                            memory_index: 0,
                        }));
                        f.instruction(&Instruction::I32Load(MemArg {
                            offset: 84,
                            align: 2,
                            memory_index: 0,
                        }));
                        f.instruction(&Instruction::I32Store(ma));
                        // [SCRATCH+32] = mem[ob_type+12] = tp_name (3.14 PyTypeObject
                        // layout: ob_refcnt(0,8) ob_type(8) ... actually 32-bit:
                        // ob_refcnt(0) ob_type(4? ) - we capture ob_type+12 and +60
                        // as candidate tp_name pointers; the probe reads the cstring.
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + 32));
                        f.instruction(&Instruction::LocalGet(0));
                        f.instruction(&Instruction::I32Load(MemArg {
                            offset: 4,
                            align: 2,
                            memory_index: 0,
                        }));
                        f.instruction(&Instruction::I32Load(MemArg {
                            offset: 12,
                            align: 2,
                            memory_index: 0,
                        }));
                        f.instruction(&Instruction::I32Store(ma));
                    }
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
