// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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
/// Ring base at 44 MiB, ABOVE the guest heap usage (~31 MiB), so the ring does
/// not corrupt the live guest heap. Requires the probe to pre-grow memory
/// (BURN_PREGROW_PAGES) so the address is committed. (Was 0x1B00000, which sat
/// inside the guest heap and perturbed the very allocations under study.)
const RING: u32 = 0x2C0_0000;
const RING_CAP: i32 = 256;
const G_VAL: u32 = 1426;
const G_ADDR: u32 = 1427;
const G_LEN: u32 = 1428;
/// i64 scratch for round-tripping an `i64.store` value (the 8-byte PyObject
/// header refcnt+type can be written as one i64.store, which an i32-only watch
/// misses). Index 1429, appended after the three i32 scratch globals.
const G_I64: u32 = 1429;

/// Record `(func, tag_or_val, addr)` into the ring for a bulk-memory write whose
/// destination range intersects the watched window. The ring layout matches the
/// i32.store path: entry = { func, val, addr }; here `addr` is the bulk dest and
/// the tag (0xF111_0000 fill / 0xF222_0000 copy) is OR-ed into the val slot.
fn bulk_record(f: &mut Function, combined_idx: i32, tag: i32, push_val: impl Fn(&mut Function)) {
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
    entry_base(f);
    f.instruction(&Instruction::I32Const(combined_idx));
    f.instruction(&Instruction::I32Store(ma));
    // val slot = tag | (pushed value & 0xFF)
    entry_base(f);
    f.instruction(&Instruction::I32Const(tag));
    push_val(f);
    f.instruction(&Instruction::I32Const(0xFF));
    f.instruction(&Instruction::I32And);
    f.instruction(&Instruction::I32Or);
    f.instruction(&Instruction::I32Store(MemArg {
        offset: 4,
        align: 2,
        memory_index: 0,
    }));
    // addr slot = G_ADDR (bulk dest)
    entry_base(f);
    f.instruction(&Instruction::GlobalGet(G_ADDR));
    f.instruction(&Instruction::I32Store(MemArg {
        offset: 8,
        align: 2,
        memory_index: 0,
    }));
}

/// Record an `i64.store` whose 8-byte range intersects the window. func slot is
/// OR-ed with 0x8000_0000 (the i64.store marker); val slot = hi32 of the stored
/// i64 (the type slot when the store base is obj+0); addr slot = effective addr
/// (in G_ADDR). G_I64 holds the stored i64 value.
fn i64_record(f: &mut Function, combined_idx: i32) {
    let ma = MemArg {
        offset: 0,
        align: 2,
        memory_index: 0,
    };
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
    entry_base(f);
    f.instruction(&Instruction::I32Const(
        combined_idx | (0x8000_0000u32 as i32),
    ));
    f.instruction(&Instruction::I32Store(ma));
    entry_base(f);
    f.instruction(&Instruction::GlobalGet(G_I64));
    f.instruction(&Instruction::I64Const(32));
    f.instruction(&Instruction::I64ShrU);
    f.instruction(&Instruction::I32WrapI64);
    f.instruction(&Instruction::I32Store(MemArg {
        offset: 4,
        align: 2,
        memory_index: 0,
    }));
    entry_base(f);
    f.instruction(&Instruction::GlobalGet(G_ADDR));
    f.instruction(&Instruction::I32Store(MemArg {
        offset: 8,
        align: 2,
        memory_index: 0,
    }));
}

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
                // i32.store / store8 / store16: stack [addr_base, value]. All write
                // at least one byte at addr_base+off; record if eff in [lo,hi). A
                // byte/halfword store can zero a header field without a full
                // i32.store, so all three are watched.
                Operator::I32Store { memarg }
                | Operator::I32Store8 { memarg }
                | Operator::I32Store16 { memarg } => {
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
                    // Re-emit the ORIGINAL op (i32.store / store8 / store16), not a
                    // hardcoded i32.store, so a byte/halfword store keeps its width.
                    let enc = self.instruction(op)?;
                    f.instruction(&enc);
                    self.instrumented += 1;
                }
                // i64.store: stack [addr_base, value(i64)]. Writes 8 bytes at
                // [addr_base+off .. +8). If the watched window intersects that
                // range, record (func, 0xF644_0000 | hi32_lowbyte, addr_base+off)
                // and the full hi/lo via two ring entries. The PyObject header
                // (refcnt at +0, type at +4) can be written as one i64.store, so
                // an i32-only watch would miss a type-field write done this way.
                Operator::I64Store { memarg } => {
                    let off = memarg.offset as i32;
                    f.instruction(&Instruction::GlobalSet(G_I64)); // i64 value
                    f.instruction(&Instruction::GlobalSet(G_ADDR)); // addr_base
                    // eff = addr_base + off
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(off));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::GlobalSet(G_ADDR));
                    // intersect [eff, eff+8) with [lo,hi): eff < hi && eff+8 > lo
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(self.watch_hi));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(8));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Const(self.watch_lo));
                    f.instruction(&Instruction::I32GtU);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    // record the FULL hi32 of the i64 (= bytes at eff+4, i.e. the
                    // type slot when eff==obj+0). func is OR-ed with 0x8000_0000 as
                    // an "i64.store" marker; val slot = hi32; addr slot = eff.
                    i64_record(&mut f, combined_idx);
                    f.instruction(&Instruction::End);
                    // restore [addr_base, value]; addr_base = eff - off
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(off));
                    f.instruction(&Instruction::I32Sub);
                    f.instruction(&Instruction::GlobalGet(G_I64));
                    let enc = self.instruction(op)?;
                    f.instruction(&enc);
                    self.instrumented += 1;
                }
                // memory.fill: stack [dest, val, len]. If the watched window
                // intersects [dest, dest+len), record (func, 0xF111_<val8>, dest).
                // This catches a header field zeroed by a bulk memset, which an
                // i32.store-only watch misses.
                Operator::MemoryFill { .. } => {
                    f.instruction(&Instruction::GlobalSet(G_LEN)); // len
                    f.instruction(&Instruction::GlobalSet(G_VAL)); // val
                    f.instruction(&Instruction::GlobalSet(G_ADDR)); // dest
                    // intersect [dest,dest+len) with [lo,hi):  dest < hi && dest+len > lo
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(self.watch_hi));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::GlobalGet(G_LEN));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Const(self.watch_lo));
                    f.instruction(&Instruction::I32GtU);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    bulk_record(&mut f, combined_idx, 0xF111_0000u32 as i32, |f| {
                        f.instruction(&Instruction::GlobalGet(G_VAL));
                    });
                    f.instruction(&Instruction::End);
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::GlobalGet(G_VAL));
                    f.instruction(&Instruction::GlobalGet(G_LEN));
                    let enc = self.instruction(op)?;
                    f.instruction(&enc);
                    self.instrumented += 1;
                }
                // memory.copy: stack [dest, src, len]. If the watched window
                // intersects [dest, dest+len), record (func, 0xF222_0000, src).
                Operator::MemoryCopy { .. } => {
                    f.instruction(&Instruction::GlobalSet(G_LEN)); // len
                    f.instruction(&Instruction::GlobalSet(G_VAL)); // src
                    f.instruction(&Instruction::GlobalSet(G_ADDR)); // dest
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::I32Const(self.watch_hi));
                    f.instruction(&Instruction::I32LtU);
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::GlobalGet(G_LEN));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Const(self.watch_lo));
                    f.instruction(&Instruction::I32GtU);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    bulk_record(&mut f, combined_idx, 0xF222_0000u32 as i32, |f| {
                        f.instruction(&Instruction::GlobalGet(G_VAL));
                    });
                    f.instruction(&Instruction::End);
                    f.instruction(&Instruction::GlobalGet(G_ADDR));
                    f.instruction(&Instruction::GlobalGet(G_VAL));
                    f.instruction(&Instruction::GlobalGet(G_LEN));
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
        // Scratch globals: G_VAL, G_ADDR, G_LEN (i32; 1426-1428) + G_I64 (i64; 1429).
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
        globals.global(
            wasm_encoder::GlobalType {
                val_type: ValType::I64,
                mutable: true,
                shared: false,
            },
            &wasm_encoder::ConstExpr::i64_const(0),
        );
        Ok(())
    }
}
