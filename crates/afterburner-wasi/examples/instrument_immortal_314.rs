// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 immortalization + dealloc unified event recorder (Step 1).
//!
//! Decisive probe for the str refcount-underflow / double-free. Records, into a
//! single guest ring, two event kinds in interleaved program order:
//!
//!   kind=1  `_Py_SetImmortal` (combined func 2462) ENTRY: an object is being
//!           immortalized. Captures the object ptr, its `ob_refcnt` BEFORE the
//!           write, and the runtime-state pointer the function reads via the
//!           `i32.const 4002588; i32.load; i32.load offset=8` chain (the current
//!           tstate cache -> interp). So we can see (a) whether the interned
//!           strings get immortalized at all and (b) what runtime pointer the
//!           immortalize path resolves on the 314 self-providing module.
//!
//!   kind=2  `_Py_Dealloc` (combined func 2413) ENTRY: an object is being freed.
//!           Captures the object ptr, its `ob_type`, and its `ob_refcnt`. The
//!           double-free trap is the SECOND dealloc of one object; the last entry
//!           before the trap is the trapping object, and scanning backward shows
//!           whether that exact object was ever immortalized (kind=1) or stayed
//!           mortal and cycled through refcounts.
//!
//! Ring (guest memory) at RING:
//!   [RING+0]  head  : i32 = monotone count of recorded events
//!   [RING+8 + (i%CAP)*20]  entry: { kind:i32, obj:i32, a:i32, b:i32, c:i32 }
//!     kind=1 (immortal): a=ob_refcnt_before, b=runtime_ptr (mem[4002588]),
//!                        c=interp_ptr (mem[mem[4002588]+8])
//!     kind=2 (dealloc):  a=ob_type, b=ob_refcnt, c=0
//! CAP = 4096 (20 bytes/entry -> 80 KiB ring; fits below the other scratch wins).
//!
//! Environment:
//!   BURN_INPUT_WASM  (default /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM (default /tmp/pyodide-314-immortal.wasm)

use std::fs;

use wasm_encoder::{
    CodeSection, Function, Instruction, MemArg, Module,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-immortal.wasm";

/// Ring base in guest linear memory. Placed at 40 MiB, well ABOVE the guest's
/// actual heap usage (~31 MiB for `import operator`), so the ring is NOT inside
/// the live guest heap and does not corrupt the very corruption it measures. The
/// probe must pre-grow memory (BURN_PREGROW_PAGES) so this address is committed.
const RING: u32 = 0x280_0000;
const RING_CAP: i32 = 4096;
const ENTRY_BYTES: i32 = 20;

/// Combined function index of `_Py_SetImmortal` in the 314 module.
const SET_IMMORTAL_FUNC: usize = 2462;
/// Combined function index of `_Py_Dealloc` in the 314 module.
const DEALLOC_FUNC: usize = 2413;
/// Combined function index of `long_dealloc` (the PyLong dealloc) in the 314
/// module. It checks `obj->lv_tag & 4` (the immortal bit) and, if set, calls
/// `_Py_SetImmortal` and returns without freeing; otherwise it frees / free-lists
/// the int. Recording entry here shows whether the trapping int reached
/// long_dealloc with its immortal bit set or cleared.
const LONG_DEALLOC_FUNC: usize = 2039;
/// BSS address of the current-tstate cache read by `_Py_SetImmortal`.
const TSTATE_CACHE_ADDR: i32 = 4_002_588;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let wasm = fs::read(&input).expect("read input wasm");
    let import_func_count = pre_parse(&wasm);
    eprintln!(
        "[immortal] {} bytes, {import_func_count} imported funcs",
        wasm.len()
    );

    let mut rec = ImmortalLog {
        import_func_count,
        body_index: 0,
        immortal_done: false,
        dealloc_done: false,
        long_dealloc_done: false,
    };
    let mut out = Module::new();
    if let Err(e) = rec.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[immortal] instrumented SetImmortal={} Dealloc={} LongDealloc={}, {} bytes",
        rec.immortal_done,
        rec.dealloc_done,
        rec.long_dealloc_done,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[immortal] output parses OK"),
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

struct ImmortalLog {
    import_func_count: usize,
    body_index: usize,
    immortal_done: bool,
    dealloc_done: bool,
    long_dealloc_done: bool,
}

const MA: MemArg = MemArg {
    offset: 0,
    align: 2,
    memory_index: 0,
};
fn ma_off(off: u64) -> MemArg {
    MemArg {
        offset: off,
        align: 2,
        memory_index: 0,
    }
}

/// Emit code that leaves the address of the current entry's field `field_off`
/// on the stack: `RING+8 + ((head-1) % CAP)*ENTRY_BYTES + field_off`.
fn entry_field(f: &mut Function, field_off: i32) {
    f.instruction(&Instruction::I32Const(RING as i32));
    f.instruction(&Instruction::I32Load(MA));
    f.instruction(&Instruction::I32Const(1));
    f.instruction(&Instruction::I32Sub);
    f.instruction(&Instruction::I32Const(RING_CAP));
    f.instruction(&Instruction::I32RemU);
    f.instruction(&Instruction::I32Const(ENTRY_BYTES));
    f.instruction(&Instruction::I32Mul);
    f.instruction(&Instruction::I32Const(RING as i32 + 8 + field_off));
    f.instruction(&Instruction::I32Add);
}

/// Emit `head++`.
fn bump_head(f: &mut Function) {
    f.instruction(&Instruction::I32Const(RING as i32));
    f.instruction(&Instruction::I32Const(RING as i32));
    f.instruction(&Instruction::I32Load(MA));
    f.instruction(&Instruction::I32Const(1));
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::I32Store(MA));
}

/// Store an i32 value (left on the stack by `push_val`) into the current entry's
/// field at `field_off`.
fn store_field(f: &mut Function, field_off: i32, push_val: impl Fn(&mut Function)) {
    entry_field(f, field_off);
    push_val(f);
    f.instruction(&Instruction::I32Store(MA));
}

impl Reencode for ImmortalLog {
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

        if combined_idx == SET_IMMORTAL_FUNC {
            self.immortal_done = true;
            bump_head(&mut f);
            // kind=1
            store_field(&mut f, 0, |f| {
                f.instruction(&Instruction::I32Const(1));
            });
            // obj = param0
            store_field(&mut f, 4, |f| {
                f.instruction(&Instruction::LocalGet(0));
            });
            // a = ob_refcnt_before = mem[obj+0]
            store_field(&mut f, 8, |f| {
                f.instruction(&Instruction::LocalGet(0));
                f.instruction(&Instruction::I32Load(MA));
            });
            // b = runtime_ptr = mem[4002588]
            store_field(&mut f, 12, |f| {
                f.instruction(&Instruction::I32Const(TSTATE_CACHE_ADDR));
                f.instruction(&Instruction::I32Load(MA));
            });
            // c = interp_ptr = mem[mem[4002588] + 8]. Reading mem[0+8] when the
            // tstate cache is still null is in-bounds (low linear memory is
            // always mapped), so no guard is needed for a diagnostic read.
            entry_field(&mut f, 16);
            f.instruction(&Instruction::I32Const(TSTATE_CACHE_ADDR));
            f.instruction(&Instruction::I32Load(MA));
            f.instruction(&Instruction::I32Load(ma_off(8)));
            f.instruction(&Instruction::I32Store(MA));
        }

        if combined_idx == LONG_DEALLOC_FUNC {
            self.long_dealloc_done = true;
            bump_head(&mut f);
            // kind=3
            store_field(&mut f, 0, |f| {
                f.instruction(&Instruction::I32Const(3));
            });
            // obj = param0
            store_field(&mut f, 4, |f| {
                f.instruction(&Instruction::LocalGet(0));
            });
            // a = lv_tag = mem[obj+8]
            store_field(&mut f, 8, |f| {
                f.instruction(&Instruction::LocalGet(0));
                f.instruction(&Instruction::I32Load(ma_off(8)));
            });
            // b = immortal-bit (lv_tag & 4)
            store_field(&mut f, 12, |f| {
                f.instruction(&Instruction::LocalGet(0));
                f.instruction(&Instruction::I32Load(ma_off(8)));
                f.instruction(&Instruction::I32Const(4));
                f.instruction(&Instruction::I32And);
            });
            // c = ob_type = mem[obj+4]
            store_field(&mut f, 16, |f| {
                f.instruction(&Instruction::LocalGet(0));
                f.instruction(&Instruction::I32Load(ma_off(4)));
            });
        }

        if combined_idx == DEALLOC_FUNC {
            self.dealloc_done = true;
            bump_head(&mut f);
            // kind=2
            store_field(&mut f, 0, |f| {
                f.instruction(&Instruction::I32Const(2));
            });
            // obj = param0
            store_field(&mut f, 4, |f| {
                f.instruction(&Instruction::LocalGet(0));
            });
            // a = ob_type = mem[obj+4]
            store_field(&mut f, 8, |f| {
                f.instruction(&Instruction::LocalGet(0));
                f.instruction(&Instruction::I32Load(ma_off(4)));
            });
            // b = ob_refcnt = mem[obj+0]
            store_field(&mut f, 12, |f| {
                f.instruction(&Instruction::LocalGet(0));
                f.instruction(&Instruction::I32Load(MA));
            });
            // c = 0
            store_field(&mut f, 16, |f| {
                f.instruction(&Instruction::I32Const(0));
            });
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
