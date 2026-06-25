// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 `_Py_Dealloc` type-log recorder.
//!
//! Records, into a guest ring, the (object ptr, ob_type ptr, ob_refcnt) of every
//! object passed to `_Py_Dealloc` (combined func index 2413, param 0 = object).
//! The double-free trap is the SECOND dealloc of one object (header already
//! zeroed); the entries just before the trap therefore show the type of every
//! object freed on the path to it, so the probe can read each type's `tp_name`
//! and name what is being double-freed. ob_refcnt is captured too: a clean
//! dealloc enters with refcnt 0, so any non-zero value flags a premature free.
//!
//! Ring (guest memory) at RING:
//!   [RING+0]  head : i32 = monotone count of dealloc calls
//!   [RING+8 + (i%CAP)*12]  entry: { obj:i32, ob_type:i32, ob_refcnt:i32 }
//! CAP = 1024.
//!
//! Environment:
//!   BURN_INPUT_WASM  (default /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM (default /tmp/pyodide-314-dealloclog.wasm)

use std::fs;

use wasm_encoder::{
    CodeSection, Function, Instruction, MemArg, Module,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-dealloclog.wasm";
const RING: u32 = 0x1B8_0000;
const RING_CAP: i32 = 1024;
/// Combined function index of `_Py_Dealloc` in the 314 module (exported).
const DEALLOC_FUNC: usize = 2413;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let wasm = fs::read(&input).expect("read input wasm");
    let import_func_count = pre_parse(&wasm);
    eprintln!(
        "[dealloclog] {} bytes, {import_func_count} imported funcs",
        wasm.len()
    );

    let mut rec = DeallocLog {
        import_func_count,
        body_index: 0,
        instrumented: false,
    };
    let mut out = Module::new();
    if let Err(e) = rec.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[dealloclog] instrumented _Py_Dealloc entry: {}, {} bytes",
        rec.instrumented,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[dealloclog] output parses OK"),
        Some(Err(e)) => eprintln!("WARN parse: {e}"),
    }
}

fn pre_parse(wasm: &[u8]) -> usize {
    let mut import_func_count = 0usize;
    for payload in Parser::new(0).parse_all(wasm) {
        if let Ok(Payload::ImportSection(reader)) = payload {
            for import in reader.into_imports().flatten() {
                if let TypeRef::Func(_) = import.ty {
                    import_func_count += 1;
                }
            }
        }
    }
    import_func_count
}

struct DeallocLog {
    import_func_count: usize,
    body_index: usize,
    instrumented: bool,
}

impl Reencode for DeallocLog {
    type Error = String;

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func_body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReencodeError<String>> {
        let combined_idx = self.import_func_count + self.body_index;
        self.body_index += 1;

        let mut locals = Vec::new();
        for pair in func_body
            .get_locals_reader()
            .map_err(ReencodeError::ParseError)?
        {
            let (cnt, ty) = pair.map_err(ReencodeError::ParseError)?;
            locals.push((cnt, self.val_type(ty)?));
        }
        let mut f = Function::new(locals);

        // At entry of _Py_Dealloc(obj=param0): record obj, ob_type=mem[obj+4],
        // ob_refcnt=mem[obj+0] into the ring, then head++.
        if combined_idx == DEALLOC_FUNC {
            self.instrumented = true;
            let ma = MemArg {
                offset: 0,
                align: 2,
                memory_index: 0,
            };
            // head++
            f.instruction(&Instruction::I32Const(RING as i32));
            f.instruction(&Instruction::I32Const(RING as i32));
            f.instruction(&Instruction::I32Load(ma));
            f.instruction(&Instruction::I32Const(1));
            f.instruction(&Instruction::I32Add);
            f.instruction(&Instruction::I32Store(ma));
            // entry_base = RING+8 + ((head-1)%CAP)*12  (leave on stack via helper)
            let entry_base = |f: &mut Function| {
                f.instruction(&Instruction::I32Const(RING as i32));
                f.instruction(&Instruction::I32Load(ma));
                f.instruction(&Instruction::I32Const(1));
                f.instruction(&Instruction::I32Sub);
                f.instruction(&Instruction::I32Const(RING_CAP));
                f.instruction(&Instruction::I32RemU);
                f.instruction(&Instruction::I32Const(12));
                f.instruction(&Instruction::I32Mul);
                f.instruction(&Instruction::I32Const(RING as i32 + 8));
                f.instruction(&Instruction::I32Add);
            };
            // entry.obj = param0
            entry_base(&mut f);
            f.instruction(&Instruction::LocalGet(0));
            f.instruction(&Instruction::I32Store(ma));
            // entry.ob_type = mem[obj+4]
            entry_base(&mut f);
            f.instruction(&Instruction::LocalGet(0));
            f.instruction(&Instruction::I32Load(MemArg {
                offset: 4,
                align: 2,
                memory_index: 0,
            }));
            f.instruction(&Instruction::I32Store(MemArg {
                offset: 4,
                align: 2,
                memory_index: 0,
            }));
            // entry.ob_refcnt = mem[obj+0]
            entry_base(&mut f);
            f.instruction(&Instruction::LocalGet(0));
            f.instruction(&Instruction::I32Load(MemArg {
                offset: 0,
                align: 2,
                memory_index: 0,
            }));
            f.instruction(&Instruction::I32Store(MemArg {
                offset: 8,
                align: 2,
                memory_index: 0,
            }));
        }

        let mut reader = func_body
            .get_operators_reader()
            .map_err(ReencodeError::ParseError)?;
        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            let enc = self.instruction(op)?;
            f.instruction(&enc);
        }
        code.function(&f);
        Ok(())
    }
}
