// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pyodide-314 EH-neutralizing rewrite (decisive translation-vs-execution test).
//!
//! Coverage instrumentation proved that NO exnref unwind (`throw_ref`) fires
//! before the 314 startup trap: the program never throws on the path to the
//! `_Py_Dealloc` double-free. So on the path that matters, a `try_table`'s only
//! effect is its NORMAL (fall-through) execution; the catch handlers are dead.
//!
//! This pass rewrites every `try_table (catch ...) BODY end` into a plain
//! `block BODY end` of the SAME block type (the body keeps branching to the same
//! label index, so control flow on the no-throw path is byte-for-byte the same),
//! and turns every `throw_ref` into `unreachable`. The result contains ZERO
//! exnref/EH instructions, so if it STILL hits the identical double-free trap,
//! afterburner's exnref EXECUTION is exonerated (the bug is not in try_table /
//! throw_ref / catch handling); if it diverges, exnref execution is implicated.
//!
//! Environment:
//!   BURN_INPUT_WASM  (default /tmp/pyodide-314-exnref.wasm)
//!   BURN_OUTPUT_WASM (default /tmp/pyodide-314-stripeh.wasm)

use std::fs;

use wasm_encoder::{
    CodeSection, Function, Instruction, Module,
    reencode::{Error as ReencodeError, Reencode},
};
use wasmparser::{Operator, Parser};

const DEFAULT_INPUT: &str = "/tmp/pyodide-314-exnref.wasm";
const DEFAULT_OUTPUT: &str = "/tmp/pyodide-314-stripeh.wasm";

fn main() {
    let input = std::env::var("BURN_INPUT_WASM").unwrap_or_else(|_| DEFAULT_INPUT.to_owned());
    let output = std::env::var("BURN_OUTPUT_WASM").unwrap_or_else(|_| DEFAULT_OUTPUT.to_owned());
    let wasm = fs::read(&input).expect("read input wasm");
    eprintln!("[strip_exnref] {} bytes", wasm.len());

    let mut rec = StripEh {
        try_tables: 0,
        throw_refs: 0,
    };
    let mut out = Module::new();
    if let Err(e) = rec.parse_core_module(&mut out, Parser::new(0), &wasm) {
        eprintln!("ERROR: reencode failed: {e}");
        std::process::exit(1);
    }
    let stripped = out.finish();
    eprintln!(
        "[strip_exnref] rewrote {} try_table -> block, {} throw_ref -> unreachable, {} bytes",
        rec.try_tables,
        rec.throw_refs,
        stripped.len()
    );
    fs::write(&output, &stripped).expect("write output");
    match Parser::new(0).parse_all(&stripped).last() {
        Some(Ok(_)) | None => eprintln!("[strip_exnref] output parses OK"),
        Some(Err(e)) => eprintln!("WARN parse: {e}"),
    }
}

struct StripEh {
    try_tables: u64,
    throw_refs: u64,
}

impl Reencode for StripEh {
    type Error = String;

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func_body: wasmparser::FunctionBody<'_>,
    ) -> Result<(), ReencodeError<String>> {
        let mut locals = Vec::new();
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
        while !reader.eof() {
            let op = reader.read().map_err(ReencodeError::ParseError)?;
            match op {
                Operator::TryTable { try_table } => {
                    // Replace `try_table TY (catches...)` with `block TY`. The
                    // matching `end` already in the stream closes the block. The
                    // body's branch targets (the try_table's own label depth) are
                    // identical for a `block`, so the no-throw path is unchanged.
                    let bt = self.block_type(try_table.ty)?;
                    f.instruction(&Instruction::Block(bt));
                    self.try_tables += 1;
                }
                Operator::ThrowRef => {
                    // Unreachable on the no-throw path; if ever reached it traps
                    // loudly rather than silently mis-handling an exnref.
                    f.instruction(&Instruction::Unreachable);
                    self.throw_refs += 1;
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
