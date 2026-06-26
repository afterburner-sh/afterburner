// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Binary-instrumentation pass for the MAIN module: trap at the first
//! `call_indirect` whose table index is >= a threshold (an out-of-bounds index),
//! recording the index, the calling function, and the call-site ordinal into a
//! fixed scratch region so the probe (or the loader) can read which baked
//! function pointer went out of bounds.
//!
//! Companion to `instrument_callind` (which targets the null gap). This one
//! targets the `TableOutOfBounds` trap seen after the shared-stack-pointer fix.
//!
//! ## Scratch layout (SCRATCH = 0x1BD_0000):
//!   [SCRATCH+0]  magic    : i32 = 0x00B_00B once an OOB index is seen
//!   [SCRATCH+4]  index    : i32 = the offending table index
//!   [SCRATCH+8]  func     : i32 = combined function index of the caller
//!   [SCRATCH+12] callsite : i32 = per-function call_indirect ordinal
//!
//! ## Usage
//!   BURN_THRESHOLD=11802 cargo run -q -p afterburner-wasi --example instrument_callind_oob
//!   BURN_PROBE_WASM=/tmp/pyodide-oob.wasm BURN_OOB_DUMP=1 \
//!     cargo run -q -p afterburner-wasi --example pandas_import_probe ...

use std::fs;

use wasm_encoder::{
    BlockType, CodeSection, Function, Instruction, MemArg, Module, ValType,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Operator, Parser, Payload, TypeRef};

const DEFAULT_INPUT: &str = "/tmp/pyodide-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-oob.wasm";

const SCRATCH: u32 = 0x1BD_0000;
const MAGIC: i32 = 0x00B_00Bu32 as i32;

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let threshold: i32 = std::env::var("BURN_THRESHOLD")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(11802);

    eprintln!("[instr-oob] reading {input}; OOB threshold = {threshold}");
    let wasm = fs::read(&input).expect("read input");
    let (import_func_count, total_globals) = pre_parse(&wasm);
    eprintln!(
        "[instr-oob] {import_func_count} imported functions, {total_globals} globals (G_IDX={total_globals})"
    );

    // Optional: capture a local of a specific function at the OOB trap.
    // BURN_CAPTURE_FUNC=<combined_idx>,BURN_CAPTURE_LOCAL=<local_index>.
    let capture_func: Option<i32> = std::env::var("BURN_CAPTURE_FUNC")
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let capture_local_idx: u32 = std::env::var("BURN_CAPTURE_LOCAL")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(2);

    let mut recorder = OobRecorder {
        import_func_count,
        g_idx: total_globals,
        threshold,
        body_index: 0,
        instrumented: 0,
        capture_func,
        capture_local_idx,
        capture_local: None,
    };
    let mut out = Module::new();
    recorder
        .parse_core_module(&mut out, Parser::new(0), &wasm)
        .expect("reencode");
    let instrumented = out.finish();
    eprintln!(
        "[instr-oob] instrumented {} call_indirect sites, {} bytes",
        recorder.instrumented,
        instrumented.len()
    );
    fs::write(&output, &instrumented).expect("write");
    match Parser::new(0).parse_all(&instrumented).last() {
        Some(Ok(_)) | None => eprintln!("[instr-oob] output parses OK"),
        Some(Err(e)) => eprintln!("WARN: output parse: {e}"),
    }
}

fn pre_parse(wasm: &[u8]) -> (usize, u32) {
    let mut import_func_count = 0usize;
    let mut imported_globals = 0u32;
    let mut defined_globals = 0u32;
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.expect("parse") {
            Payload::ImportSection(reader) => {
                for import in reader.into_imports().flatten() {
                    match import.ty {
                        TypeRef::Func(_) => import_func_count += 1,
                        TypeRef::Global(_) => imported_globals += 1,
                        _ => {}
                    }
                }
            }
            Payload::GlobalSection(reader) => defined_globals += reader.count(),
            _ => {}
        }
    }
    (import_func_count, imported_globals + defined_globals)
}

struct OobRecorder {
    import_func_count: usize,
    g_idx: u32,
    threshold: i32,
    body_index: usize,
    instrumented: u64,
    capture_func: Option<i32>,
    capture_local_idx: u32,
    /// Set per-body to `Some(local_idx)` when this body is the capture target.
    capture_local: Option<u32>,
}

impl Reencode for OobRecorder {
    type Error = String;

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func_body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReencodeError<String>> {
        let combined_idx = (self.import_func_count + self.body_index) as i32;
        self.body_index += 1;
        self.capture_local = if self.capture_func == Some(combined_idx) {
            Some(self.capture_local_idx)
        } else {
            None
        };

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
        let mut callsite: i32 = 0;
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
                    // Stack top = table index. Stash into the scratch global, test
                    // for >= threshold (OOB) with the magic guard, then restore.
                    f.instruction(&Instruction::GlobalSet(self.g_idx));
                    f.instruction(&Instruction::GlobalGet(self.g_idx));
                    f.instruction(&Instruction::I32Const(self.threshold));
                    f.instruction(&Instruction::I32GeU);
                    f.instruction(&Instruction::I32Const(SCRATCH as i32));
                    f.instruction(&Instruction::I32Load(ma));
                    f.instruction(&Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::I32Ne);
                    f.instruction(&Instruction::I32And);
                    f.instruction(&Instruction::If(BlockType::Empty));
                    let st = |f: &mut Function, off: i32, instr: &Instruction| {
                        f.instruction(&Instruction::I32Const(SCRATCH as i32 + off));
                        f.instruction(instr);
                        f.instruction(&Instruction::I32Store(ma));
                    };
                    st(&mut f, 4, &Instruction::GlobalGet(self.g_idx));
                    st(&mut f, 8, &Instruction::I32Const(combined_idx));
                    st(&mut f, 12, &Instruction::I32Const(callsite));
                    // For the known OOB site (numpy core func 2823, callsite 0)
                    // also capture local 2 (= the obj param) so its address and
                    // header can be inspected to see what corrupted it.
                    if let Some(obj_local) = self.capture_local {
                        st(&mut f, 16, &Instruction::LocalGet(obj_local));
                    }
                    st(&mut f, 0, &Instruction::I32Const(MAGIC));
                    f.instruction(&Instruction::Unreachable);
                    f.instruction(&Instruction::End);
                    f.instruction(&Instruction::GlobalGet(self.g_idx));
                    let enc_ty = self.type_index(type_index)?;
                    f.instruction(&Instruction::CallIndirect {
                        type_index: enc_ty,
                        table_index,
                    });
                    callsite += 1;
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
