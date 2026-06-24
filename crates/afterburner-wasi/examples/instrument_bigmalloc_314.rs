// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 large-allocation recorder.
//!
//! `import ctypes` on 314 raises `MemoryError` even with a huge linear memory,
//! so the guest is requesting an absurd allocation size (a corrupted / miscomputed
//! length) rather than genuinely running out. This pass instruments `malloc`
//! (combined func 14530) at entry: when the requested size exceeds a threshold
//! (default 16 MiB) it records the size into a guest ring so the bad request is
//! named. malloc's param 0 is the byte size.
//!
//! Ring (guest memory) at RING:
//!   [RING+0]  head : i32 = monotone count of recorded big allocations
//!   [RING+8 + (i%CAP)*4]  size : i32
//! CAP = 256. Placed high (above the guest heap); the probe pre-grows memory.
//!
//! Environment:
//!   BURN_INPUT_WASM   (default /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM  (default /tmp/pyodide-314-bigmalloc.wasm)
//!   BURN_BIG_THRESHOLD (decimal bytes, default 16777216)

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, Instruction, MemArg, Module,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-bigmalloc.wasm";
const RING: u32 = 0x300_0000;
const RING_CAP: i32 = 256;
const MALLOC_FUNC: usize = 14530;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let threshold: i32 = std::env::var("BURN_BIG_THRESHOLD")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(16_777_216);
    let wasm = fs::read(&input).expect("read input wasm");
    let import_func_count = pre_parse(&wasm);
    eprintln!(
        "[bigmalloc] {} bytes, {import_func_count} imported funcs, threshold {threshold}",
        wasm.len()
    );

    let mut rec = BigMalloc {
        import_func_count,
        body_index: 0,
        threshold,
        done: false,
    };
    let mut out = Module::new();
    if let Err(e) = rec.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[bigmalloc] instrumented malloc={}, {} bytes",
        rec.done,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[bigmalloc] output parses OK"),
        Some(Err(e)) => eprintln!("WARN parse: {e}"),
    }
}

fn pre_parse(wasm: &[u8]) -> usize {
    let mut n = 0usize;
    for payload in Parser::new(0).parse_all(wasm) {
        if let Ok(Payload::ImportSection(reader)) = payload {
            for import in reader.into_imports().flatten() {
                if let TypeRef::Func(_) = import.ty {
                    n += 1;
                }
            }
        }
    }
    n
}

struct BigMalloc {
    import_func_count: usize,
    body_index: usize,
    threshold: i32,
    done: bool,
}

impl Reencode for BigMalloc {
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

        if combined_idx == MALLOC_FUNC {
            self.done = true;
            let ma = MemArg {
                offset: 0,
                align: 2,
                memory_index: 0,
            };
            // if (size_u >= threshold) record size; size = param0.
            f.instruction(&Instruction::LocalGet(0));
            f.instruction(&Instruction::I32Const(self.threshold));
            f.instruction(&Instruction::I32GeU);
            f.instruction(&Instruction::If(BlockType::Empty));
            // head++
            f.instruction(&Instruction::I32Const(RING as i32));
            f.instruction(&Instruction::I32Const(RING as i32));
            f.instruction(&Instruction::I32Load(ma));
            f.instruction(&Instruction::I32Const(1));
            f.instruction(&Instruction::I32Add);
            f.instruction(&Instruction::I32Store(ma));
            // entry = RING+8 + ((head-1)%CAP)*4 ; store size
            f.instruction(&Instruction::I32Const(RING as i32));
            f.instruction(&Instruction::I32Load(ma));
            f.instruction(&Instruction::I32Const(1));
            f.instruction(&Instruction::I32Sub);
            f.instruction(&Instruction::I32Const(RING_CAP));
            f.instruction(&Instruction::I32RemU);
            f.instruction(&Instruction::I32Const(4));
            f.instruction(&Instruction::I32Mul);
            f.instruction(&Instruction::I32Const(RING as i32 + 8));
            f.instruction(&Instruction::I32Add);
            f.instruction(&Instruction::LocalGet(0));
            f.instruction(&Instruction::I32Store(ma));
            f.instruction(&Instruction::End);
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
