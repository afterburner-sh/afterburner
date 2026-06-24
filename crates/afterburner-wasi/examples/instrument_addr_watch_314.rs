// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 address-watch store recorder (global-scratch variant).
//!
//! Records, into a guest ring buffer, every `i32.store` whose effective address
//! falls within a watched window `[BURN_WATCH_ADDR .. +BURN_WATCH_LEN)`, tagging
//! each with the storing function index and the stored value. This reconstructs
//! the write history of the corrupt PyObject header so the premature-free /
//! wild-write source is identified.
//!
//! Uses two appended mutable i32 GLOBALS for scratch (value, effective-addr) so
//! no per-function param/local index math is needed. The 314 module has 1426
//! globals (280 imported + 1146 defined); the appended scratch globals land at
//! indices 1426 and 1427 (the Reencode pass preserves global order).
//!
//! Ring layout (guest memory) at RING (0x1B00000, within the 480-page initial
//! memory, above the heap-import range and below the other scratch windows):
//!   [RING+0]  head : i32 = monotone count of matching stores
//!   [RING+8 + (i % CAP)*12]  entry: { func:i32, val:i32, addr:i32 }
//! CAP = 256.

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, GlobalSection, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{GlobalSectionReader, Operator, Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-addrwatch.wasm";
const RING: u32 = 0x1B0_0000;
const RING_CAP: i32 = 256;
const G_VAL: u32 = 1426;
const G_ADDR: u32 = 1427;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let watch_addr: i32 = std::env::var("BURN_WATCH_ADDR")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .map(|v| v as i32)
        .expect("set BURN_WATCH_ADDR=<hex>");
    let watch_len: i32 = std::env::var("BURN_WATCH_LEN")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(8);

    let wasm = fs::read(&input).expect("read input");
    let import_func_count = pre_parse(&wasm);
    eprintln!(
        "[addrwatch] watching [{:#x}..{:#x}); {import_func_count} imported funcs",
        watch_addr,
        watch_addr + watch_len
    );

    let mut recorder = AddrWatch {
        import_func_count,
        body_index: 0,
        watch_lo: watch_addr,
        watch_hi: watch_addr + watch_len,
        instrumented: 0,
    };
    let mut out = Module::new();
    if let Err(e) = recorder.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[addrwatch] instrumented {} i32.store sites, {} bytes",
        recorder.instrumented,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[addrwatch] output parses OK"),
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

struct AddrWatch {
    import_func_count: usize,
    body_index: usize,
    watch_lo: i32,
    watch_hi: i32,
    instrumented: u64,
}

impl Reencode for AddrWatch {
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
        let ma = MemArg {
            offset: 0,
            align: 2,
            memory_index: 0,
        };
        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            match op {
                Operator::I32Store { memarg } => {
                    let off = memarg.offset as i32;
                    // stack: [.., addr_base, value] -> stash both into globals.
                    f.instruction(&Instruction::GlobalSet(G_VAL)); // pop value
                    f.instruction(&Instruction::GlobalSet(G_ADDR)); // pop addr_base
                    // G_ADDR = addr_base + off (effective addr)
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(off));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::GlobalSet(G_ADDR));
                    // if eff in [lo,hi): record
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(self.watch_lo));
                    f.instruction(&Instruction::I32GeU);
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(self.watch_hi));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    // head++ ; entry = RING+8 + (head_old % CAP)*12
                    f.instruction(&Instruction::I32Const(RING as i32));
                    f.instruction(&Instruction::I32Const(RING as i32));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(1));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Store(ma));
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
                    entry_base(&mut f);
                    f.instruction(&Instruction::I32Const(combined_idx));
                    f.instruction(&Instruction::I32Store(ma));
                    entry_base(&mut f);
                    f.instruction(&Instruction::GlobalGet(G_VAL));
                    f.instruction(&Instruction::I32Store(MemArg {
                        offset: 4,
                        align: 2,
                        memory_index: 0,
                    }));
                    entry_base(&mut f);
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Store(MemArg {
                        offset: 8,
                        align: 2,
                        memory_index: 0,
                    }));
                    f.instruction(&Instruction::End);
                    // restore stack [addr_base, value]
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(off));
                    f.instruction(&Instruction::I32Sub);
                    f.instruction(&Instruction::GlobalGet(G_VAL));
                    let enc = self.instruction(Operator::I32Store { memarg })?;
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
        for _ in 0..2 {
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
