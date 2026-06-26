// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 stack-pointer low-water-mark recorder.
//!
//! Hypothesis under test: the 314 module self-provides a 10 MiB C stack
//! (`__stack_low`=0x3e0110 .. `__stack_high`=0xde0110) which afterburner cannot
//! override (unlike the 0.28.x host-provided 32 MiB stack), so deep CPython
//! recursion overflows it and corrupts memory below `__stack_low`.
//!
//! This pass instruments every write to the C stack pointer (`global $0`, the
//! emscripten `__stack_pointer`) to track the minimum value ever stored, into a
//! fixed scratch word. The probe reads it after the run: if min-SP descends
//! below `__stack_low` (0x3e0110), the stack overflowed.
//!
//! Scratch (guest memory):
//!   [SCRATCH+0]  magic  : i32 = 0x5159_5159 once any SP write was seen
//!   [SCRATCH+4]  min_sp : i32 = lowest value ever stored to global $0
//!
//! Environment:
//!   BURN_INPUT_WASM  (default /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM (default /tmp/pyodide-314-minsp.wasm)

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Operator, Parser};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-minsp.wasm";

/// Scratch base (high static address, within the 480-page initial memory).
const SCRATCH: u32 = 0x1BE_0000;
const MAGIC: i32 = 0x5159_5159;
/// The emscripten C stack pointer is global index 280 (the module's exported
/// `__stack_pointer`; verified: 280 imported globals, `__stack_pointer` is the
/// first defined global at index 280).
const SP_GLOBAL: u32 = 280;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let wasm = fs::read(&input).expect("read input wasm");
    eprintln!("[instrument_minsp_314] {} bytes", wasm.len());

    let mut recorder = MinSpRecorder { instrumented: 0 };
    let mut out = Module::new();
    if let Err(e) = recorder.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[instrument_minsp_314] instrumented {} global.set $sp sites, {} bytes",
        recorder.instrumented,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[instrument_minsp_314] output parses OK"),
        Some(Err(e)) => eprintln!("WARN parse: {e}"),
    }
}

struct MinSpRecorder {
    instrumented: u64,
}

impl Reencode for MinSpRecorder {
    type Error = String;

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func_body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReencodeError<String>> {
        let mut locals: Vec<(u32, ValType)> = Vec::new();
        for pair in func_body
            .get_locals_reader()
            .map_err(ReencodeError::ParseError)?
        {
            let (cnt, ty) = pair.map_err(ReencodeError::ParseError)?;
            locals.push((cnt, self.val_type(ty)?));
        }
        // Append one i32 scratch local for the SP value we are about to store.
        // Its index is params + existing locals; we cannot know params here, so
        // we use a global scratch slot instead (G_SCRATCH) to avoid local-index
        // math. Simpler: read the SP value from the global AFTER the set.
        let mut f = Function::new(locals);
        let mut reader = func_body
            .get_operators_reader()
            .map_err(ReencodeError::ParseError)?;
        let ma = MemArg {
            offset: 0,
            align: 2,
            memory_index: 0,
        };
        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            match op {
                Operator::GlobalSet { global_index } if global_index == SP_GLOBAL => {
                    // Emit the original global.set, then read the new SP value
                    // and update the min-tracker if it is lower (or first write).
                    let enc = self.instruction(Operator::GlobalSet { global_index })?;
                    f.instruction(&enc);
                    // if (magic != MAGIC) || (sp < stored_min) { store sp; magic=MAGIC }
                    // cond1 = magic != MAGIC
                    f.instruction(&Instruction::I32Const(SCRATCH as i32));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::I32Ne);
                    // cond2 = sp <_u stored_min
                    f.instruction(&Instruction::GlobalGet(SP_GLOBAL));
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 4));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::I32Or);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    // store min_sp = sp
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 4));
                    f.instruction(&Instruction::GlobalGet(SP_GLOBAL));
                    f.instruction(&Instruction::I32Store(ma));
                    // magic = MAGIC
                    f.instruction(&Instruction::I32Const(SCRATCH as i32));
                    f.instruction(&Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::I32Store(ma));
                    f.instruction(&Instruction::End);
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
