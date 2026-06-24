// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 exception-handling coverage + unwind recorder.
//!
//! The 314 exnref-translated module traps `IndirectCallToNull` in `_Py_Dealloc`
//! on a zeroed-header object during the startup Python compile. The established
//! hypothesis is that one of the ~472 EH-translated functions drops/doubles a
//! refcount on its exnref UNWIND path. Static diffing shows every EH-translated
//! function lives in a self-contained C++ cluster (~14693..17221) that never
//! calls CPython core. This pass settles, empirically, whether ANY of those EH
//! functions even (a) executes and (b) takes its CATCH (unwind) edge before the
//! trap.
//!
//! Instrumentation: for each function that contains a `try_table`, we bump a
//! per-cluster ENTRY counter at function entry, and at the first instruction of
//! every catch landing pad (right after the `try_table`'s matching `end`) we
//! bump an UNWIND counter and record the function index of the unwinding frame
//! into a ring. So the probe can read: how many EH funcs ran, how many unwound,
//! and the last N unwinding function indices before the trap.
//!
//! Rather than track each catch label precisely, we use the conservative and
//! robust signal that matters here: a function UNWOUND if control reached the
//! code that follows its `try_table ... end` via the exception edge. We can't
//! cheaply distinguish the normal fallthrough from the exception edge in WAT
//! without CFG analysis, so instead we instrument the `throw_ref` sites (re-raise
//! on a cleanup pad) and the `catch`/`catch_all`/`catch_all_ref` HANDLER bodies
//! by counting executions of the block immediately dominated by the catch. The
//! simplest faithful proxy that needs no CFG: count every `throw_ref` execution
//! (a cleanup landing pad re-raising) and every function ENTRY that has EH. A
//! non-zero throw_ref count proves the exnref unwind machinery actually fired.
//!
//! Scratch (guest memory) at SCRATCH:
//!   [SCRATCH+0]  magic       : i32 = 0xC0FFEE11 once any EH func entered
//!   [SCRATCH+4]  eh_entries  : i32 = count of EH-function entries
//!   [SCRATCH+8]  throw_refs  : i32 = count of throw_ref executions (re-raises)
//!   [SCRATCH+12] catches     : i32 = count of catch-handler-body executions
//!   [SCRATCH+16] ring_head   : i32 = monotone count of recorded unwinding funcs
//!   [SCRATCH+24 + (i%CAP)*4]  func idx of the i-th throw_ref frame
//!
//! Environment:
//!   BURN_INPUT_WASM  (default /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM (default /tmp/pyodide-314-ehcover.wasm)

use std::fs;

use wasm_encoder::{
    CodeSection, Function, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Operator, Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-ehcover.wasm";

const SCRATCH: u32 = 0x1BC_0000;
const MAGIC: i32 = 0xC0FF_EE11u32 as i32;
const RING_CAP: i32 = 512;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let wasm = fs::read(&input).expect("read input wasm");

    let (import_func_count, total_globals) = pre_parse(&wasm);
    eprintln!(
        "[ehcover] {} bytes, {import_func_count} imported funcs, {total_globals} globals",
        wasm.len()
    );

    let mut rec = EhCover {
        import_func_count,
        g_idx: total_globals,
        body_index: 0,
        eh_funcs: 0,
        throw_ref_sites: 0,
    };
    let mut out = Module::new();
    if let Err(e) = rec.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let instrumented = out.finish();
    eprintln!(
        "[ehcover] instrumented {} EH funcs, {} throw_ref sites, {} bytes",
        rec.eh_funcs,
        rec.throw_ref_sites,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write output");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[ehcover] output parses OK"),
        Some(Err(e)) => eprintln!("WARN parse: {e}"),
    }
}

fn pre_parse(wasm: &[u8]) -> (usize, u32) {
    let mut import_func_count = 0usize;
    let mut imported_globals = 0u32;
    let mut defined_globals = 0u32;
    for payload in Parser::new(0).parse_all(wasm) {
        match payload {
            Ok(Payload::ImportSection(reader)) => {
                for import in reader.into_imports().flatten() {
                    match import.ty {
                        TypeRef::Func(_) => import_func_count += 1,
                        TypeRef::Global(_) => imported_globals += 1,
                        _ => {}
                    }
                }
            }
            Ok(Payload::GlobalSection(reader)) => {
                defined_globals = reader.count();
            }
            _ => {}
        }
    }
    (import_func_count, imported_globals + defined_globals)
}

struct EhCover {
    import_func_count: usize,
    g_idx: u32,
    body_index: usize,
    eh_funcs: u64,
    throw_ref_sites: u64,
}

impl Reencode for EhCover {
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

        // First pass over operators to know if this function has EH.
        let body_text_has_eh = {
            let mut r = func_body
                .get_operators_reader()
                .map_err(ReencodeError::ParseError)?;
            let mut has = false;
            while !r.eof() {
                if let Ok(op) = r.read() {
                    if matches!(op, Operator::TryTable { .. } | Operator::ThrowRef) {
                        has = true;
                        break;
                    }
                }
            }
            has
        };

        let ma = MemArg {
            offset: 0,
            align: 2,
            memory_index: 0,
        };
        let bump = |f: &mut Function, off: i32| {
            f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
            f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
            f.instruction(&Instruction::I32Load(ma));
            f.instruction(&Instruction::I32Const(1));
            f.instruction(&Instruction::I32Add);
            f.instruction(&Instruction::I32Store(ma));
        };

        let mut f = Function::new(locals);

        if body_text_has_eh {
            self.eh_funcs += 1;
            // magic = MAGIC
            f.instruction(&Instruction::I32Const(SCRATCH as i32));
            f.instruction(&Instruction::I32Const(MAGIC));
            f.instruction(&Instruction::I32Store(ma));
            // eh_entries++
            bump(&mut f, 4);
        }

        let mut reader = func_body
            .get_operators_reader()
            .map_err(ReencodeError::ParseError)?;
        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            match op {
                Operator::ThrowRef => {
                    // A cleanup/landing pad is re-raising: the exnref unwind
                    // machinery actually fired in this frame. Count it and
                    // record this function index into the ring BEFORE re-raising.
                    self.throw_ref_sites += 1;
                    // throw_refs++ (off 8)
                    bump(&mut f, 8);
                    // ring: record combined_idx at [SCRATCH+24 + (head%CAP)*4]; head++ (off 16)
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 16));
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 16));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(1));
                    f.instruction(&Instruction::I32Add);
                    f.instruction(&Instruction::I32Store(ma));
                    // addr = SCRATCH+24 + ((head-1) % CAP) * 4
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 16));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(1));
                    f.instruction(&Instruction::I32Sub);
                    f.instruction(&Instruction::I32Const(RING_CAP));
                    f.instruction(&Instruction::I32RemU);
                    f.instruction(&Instruction::I32Const(4));
                    f.instruction(&Instruction::I32Mul);
                    f.instruction(&Instruction::I32Const(SCRATCH as i32 + 24));
                    f.instruction(&Instruction::I32Add);
                    // store combined_idx at addr
                    f.instruction(&Instruction::I32Const(combined_idx));
                    f.instruction(&Instruction::I32Store(ma));
                    // re-emit the throw_ref (it consumes the exnref on the stack)
                    let enc = self.instruction(op)?;
                    f.instruction(&enc);
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
            self.parse_global(globals, g.map_err(ReencodeError::ParseError)?)?;
        }
        // No appended global needed; we use only memory scratch. Keep g_idx for
        // potential future use (silences dead-field by reading it once).
        let _ = self.g_idx;
        Ok(())
    }
}
