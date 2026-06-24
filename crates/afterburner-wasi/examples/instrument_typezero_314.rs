// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 all-write watch for a single address (Step 1 corruption source).
//!
//! `instrument_addr_watch_314` only instruments `i32.store`, so a header field
//! zeroed by a bulk-memory op is invisible to it. The double-freed int's
//! `ob_type` (obj+4) reads 0 at the second `_Py_Dealloc` even though its last
//! `i32.store` wrote the int type - so the zeroing must come from `memory.fill`,
//! `memory.copy`, an `i64.store`, or a store under a different alignment. This
//! pass watches ONE effective address for EVERY write kind that can touch it:
//! `i32.store`, `i64.store`, `i32.store8/16`, `memory.fill`, `memory.copy`, and
//! `memory.init`. Each matching write records `(func_idx, opcode_tag, value_lo)`
//! into a guest ring so the exact instruction that zeroes the header is named.
//!
//! opcode tags: 1=i32.store 2=i64.store(lo) 3=store8 4=store16 5=memory.fill
//!              6=memory.copy 7=memory.init
//!
//! Ring (guest memory) at RING:
//!   [RING+0]  head : i32
//!   [RING+8 + (i%CAP)*12]  entry: { func:i32, tag:i32, val:i32 }
//! CAP = 256.
//!
//! Environment:
//!   BURN_INPUT_WASM  (default /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM (default /tmp/pyodide-314-typezero.wasm)
//!   BURN_WATCH_ADDR  (hex, required) - the single byte address to watch.

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, GlobalSection, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{GlobalSectionReader, Operator, Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-typezero.wasm";
/// Ring base at 42 MiB, above the guest heap usage (see instrument_immortal_314).
/// Requires the probe to pre-grow memory (BURN_PREGROW_PAGES).
const RING: u32 = 0x2A0_0000;
const RING_CAP: i32 = 256;
/// Scratch globals appended after the module's globals (280 imported + 1146
/// defined = 1426 for the 314 module). Reencode preserves order; ours land next.
const G_A: u32 = 1426;
const G_B: u32 = 1427;
const G_C: u32 = 1428;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let watch: i32 = std::env::var("BURN_WATCH_ADDR")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .map(|v| v as i32)
        .expect("set BURN_WATCH_ADDR=<hex>");
    let wasm = fs::read(&input).expect("read input");
    let import_func_count = pre_parse(&wasm);
    eprintln!("[typezero] watching byte {watch:#x}; {import_func_count} imported funcs");

    let mut rec = TypeZero {
        import_func_count,
        body_index: 0,
        watch,
        instrumented: 0,
    };
    let mut out = Module::new();
    if let Err(e) = rec.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[typezero] instrumented {} write sites, {} bytes",
        rec.instrumented,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[typezero] output parses OK"),
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

struct TypeZero {
    import_func_count: usize,
    body_index: usize,
    watch: i32,
    instrumented: u64,
}

const MA: MemArg = MemArg {
    offset: 0,
    align: 2,
    memory_index: 0,
};

/// Record `(func, tag, val)` into the ring. Caller leaves nothing on the stack;
/// `val` is supplied by `push_val`.
fn record(f: &mut Function, func_idx: i32, tag: i32, push_val: impl Fn(&mut Function)) {
    // head++
    f.instruction(&Instruction::I32Const(RING as i32));
    f.instruction(&Instruction::I32Const(RING as i32));
    f.instruction(&Instruction::I32Load(MA));
    f.instruction(&Instruction::I32Const(1));
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::I32Store(MA));
    let entry = |f: &mut Function, off: i32| {
        f.instruction(&Instruction::I32Const(RING as i32));
        f.instruction(&Instruction::I32Load(MA));
        f.instruction(&Instruction::I32Const(1));
        f.instruction(&Instruction::I32Sub);
        f.instruction(&Instruction::I32Const(RING_CAP));
        f.instruction(&Instruction::I32RemU);
        f.instruction(&Instruction::I32Const(12));
        f.instruction(&Instruction::I32Mul);
        f.instruction(&Instruction::I32Const(RING as i32 + 8 + off));
        f.instruction(&Instruction::I32Add);
    };
    entry(f, 0);
    f.instruction(&Instruction::I32Const(func_idx));
    f.instruction(&Instruction::I32Store(MA));
    entry(f, 4);
    f.instruction(&Instruction::I32Const(tag));
    f.instruction(&Instruction::I32Store(MA));
    entry(f, 8);
    push_val(f);
    f.instruction(&Instruction::I32Store(MA));
}

impl Reencode for TypeZero {
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
        let w = self.watch;

        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            match op {
                // Scalar i32 / i32.store8 / i32.store16: stack [addr_base, value].
                // Record if addr_base+off == w. (i64.store is passed through: the
                // PyObject header type field is i32, never written by an i64 store,
                // and an i64 value cannot round-trip through an i32 scratch global.)
                Operator::I32Store { memarg }
                | Operator::I32Store8 { memarg }
                | Operator::I32Store16 { memarg } => {
                    let off = memarg.offset as i32;
                    let tag = match op {
                        Operator::I32Store { .. } => 1,
                        Operator::I32Store8 { .. } => 3,
                        _ => 4,
                    };
                    // stash value then addr.
                    f.instruction(&Instruction::GlobalSet(G_A));
                    f.instruction(&Instruction::GlobalSet(G_B)); // addr_base
                    // eff = addr_base + off
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::I32Const(off));
                    f.instruction(&Instruction::I32Add);
                    // if eff == w
                    f.instruction(&Instruction::I32Const(w));
                    f.instruction(&Instruction::I32Eq);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    record(&mut f, combined_idx, tag, |f| {
                        f.instruction(&Instruction::GlobalGet(G_A));
                    });
                    f.instruction(&Instruction::End);
                    // restore stack and emit original
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::GlobalGet(G_A));
                    let enc = self.instruction(op)?;
                    f.instruction(&enc);
                    self.instrumented += 1;
                }
                // memory.fill: stack [dest, val, len]. Record if w in [dest, dest+len).
                Operator::MemoryFill { mem: _ } => {
                    // stash len, val, dest
                    f.instruction(&Instruction::GlobalSet(G_C)); // len
                    f.instruction(&Instruction::GlobalSet(G_A)); // val
                    f.instruction(&Instruction::GlobalSet(G_B)); // dest
                    // if dest <= w < dest+len
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::I32Const(w));
                    f.instruction(&Instruction::I32LeU);
                    f.instruction(&Instruction::I32Const(w));
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::GlobalGet(G_C));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    record(&mut f, combined_idx, 5, |f| {
                        f.instruction(&Instruction::GlobalGet(G_A));
                    });
                    f.instruction(&Instruction::End);
                    // restore [dest,val,len] and emit
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::GlobalGet(G_A));
                    f.instruction(&Instruction::GlobalGet(G_C));
                    let enc = self.instruction(op)?;
                    f.instruction(&enc);
                    self.instrumented += 1;
                }
                // memory.copy: stack [dest, src, len]. Record if w in [dest, dest+len).
                Operator::MemoryCopy { .. } => {
                    f.instruction(&Instruction::GlobalSet(G_C)); // len
                    f.instruction(&Instruction::GlobalSet(G_A)); // src
                    f.instruction(&Instruction::GlobalSet(G_B)); // dest
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::I32Const(w));
                    f.instruction(&Instruction::I32LeU);
                    f.instruction(&Instruction::I32Const(w));
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::GlobalGet(G_C));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    record(&mut f, combined_idx, 6, |f| {
                        f.instruction(&Instruction::GlobalGet(G_A)); // src addr
                    });
                    f.instruction(&Instruction::End);
                    f.instruction(&Instruction::GlobalGet(G_B));
                    f.instruction(&Instruction::GlobalGet(G_A));
                    f.instruction(&Instruction::GlobalGet(G_C));
                    let enc = self.instruction(op)?;
                    f.instruction(&enc);
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
        globals: &mut GlobalSection,
        section: GlobalSectionReader<'_>,
    ) -> Result<(), ReencodeError<String>> {
        for g in section {
            self.parse_global(globals, g.map_err(ReencodeError::ParseError)?)?;
        }
        for _ in 0..3 {
            globals.global(
                wasm_encoder::GlobalType {
                    val_type: ValType::I32,
                    mutable: true,
                    shared: false,
                },
                &wasm_encoder::ConstExpr::i32_const(0),
            );
        }
        Ok(())
    }
}
