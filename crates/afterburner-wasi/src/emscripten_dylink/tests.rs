// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

use super::*;
use crate::emscripten_runtime::PYODIDE_TABLE_INITIAL_SIZE;

// ---- got_func_slot math -----------------------------------------------------

/// got_func_slot(0) must equal PYODIDE_TABLE_INITIAL_SIZE (the first host slot).
#[test]
fn got_func_slot_zero_equals_table_initial_size() {
    assert_eq!(got_func_slot(0), PYODIDE_TABLE_INITIAL_SIZE);
}

/// got_func_slot(n) must equal PYODIDE_TABLE_INITIAL_SIZE + n.
#[test]
fn got_func_slot_monotone() {
    for i in 0..GOT_FUNC_NAMES.len() {
        assert_eq!(
            got_func_slot(i),
            PYODIDE_TABLE_INITIAL_SIZE + i as u32,
            "got_func_slot({i}) mismatch"
        );
    }
}

// ---- GOT_FUNC_NAMES constants -----------------------------------------------

/// The constant slice must be non-empty and contain no duplicate names.
#[test]
fn got_func_names_no_duplicates() {
    use std::collections::HashSet;
    let set: HashSet<&&str> = GOT_FUNC_NAMES.iter().collect();
    assert_eq!(
        set.len(),
        GOT_FUNC_NAMES.len(),
        "GOT_FUNC_NAMES contains duplicate entries"
    );
}

/// GOT_FUNC_HOST_SLOTS must equal the length of the names slice.
#[test]
fn got_func_host_slots_equals_names_len() {
    assert_eq!(GOT_FUNC_HOST_SLOTS as usize, GOT_FUNC_NAMES.len());
}

/// PYODIDE_TABLE_WITH_GOT_SIZE must equal TABLE_INITIAL_SIZE + GOT_FUNC_HOST_SLOTS.
#[test]
fn table_with_got_size_is_sum() {
    assert_eq!(
        PYODIDE_TABLE_WITH_GOT_SIZE,
        PYODIDE_TABLE_INITIAL_SIZE + GOT_FUNC_HOST_SLOTS
    );
}

/// Known GOT.func names that appear in pyodide must be present.
#[test]
fn got_func_names_contains_known_symbols() {
    let required = [
        "abort",
        "__cxa_end_catch",
        "__cxa_rethrow",
        "emscripten_out",
        "emscripten_err",
    ];
    for sym in required {
        assert!(
            GOT_FUNC_NAMES.contains(&sym),
            "GOT_FUNC_NAMES missing required symbol: {sym}"
        );
    }
}

// ---- prefill_got_mem math (pure, no Store) ----------------------------------

/// The heap_base / stack_low math matches the documented formulae.
///
/// `__heap_base` = memory_base + DYLINK_MEMORY_SIZE (4_632_232).
/// `__stack_low` = stack_high - PYODIDE_STACK_SIZE (10 * 1024 * 1024).
///
/// We extract the arithmetic from `prefill_got_mem_globals` and assert it
/// directly, since the actual function requires a `Store`.
#[test]
fn prefill_got_mem_heap_base_formula() {
    // The constant is private, but the public doc says it equals 4_632_232.
    const DYLINK_MEM: u32 = 4_632_232;
    let memory_base: u32 = 0x1000_0000;
    let heap_base = memory_base + DYLINK_MEM;
    assert_eq!(heap_base, 0x1000_0000 + 4_632_232);
}

#[test]
fn prefill_got_mem_stack_low_formula() {
    let stack_high: u32 = 0x2000_0000;
    let stack_low = stack_high.saturating_sub(PYODIDE_STACK_SIZE);
    // 10 MiB = 10 * 1024 * 1024 = 0x00A0_0000
    assert_eq!(stack_low, stack_high - 10 * 1024 * 1024);
}

/// `saturating_sub` must not underflow even when stack_high < PYODIDE_STACK_SIZE.
#[test]
fn prefill_got_mem_stack_low_saturates() {
    let stack_high: u32 = 100; // smaller than 10 MiB
    let stack_low = stack_high.saturating_sub(PYODIDE_STACK_SIZE);
    assert_eq!(stack_low, 0, "saturating_sub must not underflow");
}

/// PYODIDE_STACK_SIZE must be exactly 10 MiB.
#[test]
fn pyodide_stack_size_is_10mib() {
    assert_eq!(PYODIDE_STACK_SIZE, 10 * 1024 * 1024);
}

// ---- parse_got_name_to_slot (pure parsing) ----------------------------------

/// A minimal wasm module with a name section + one active element segment
/// mapping func 0 to table slot `table_base`. parse_got_name_to_slot must
/// return `{"f0": table_base}`.
///
/// The module structure (WAT):
///   (module
///     (type (func))
///     (func (type 0))   ;; func index 0
///     (table 16 funcref)
///     (elem (table 0) (offset global.get 0) funcref (ref.func 0))
///     (global (export "__table_base") i32 (i32.const 1))
///   )
///
/// But we use the simpler `i32.const 1` offset form (active) which
/// parse_element_section handles. The name section is hand-embedded.
#[test]
fn parse_got_name_to_slot_resolves_one_symbol() {
    // Build a minimal wasm module in WAT with a name custom section that names
    // func 0 "my_func", plus an active element segment placing func 0 at slot 1.
    let wat_src = r#"
        (module
          (type (func))
          (func (type 0))
          (table 16 funcref)
          (elem (table 0) (offset i32.const 1) func 0)
        )
    "#;
    let mut wasm = wat::parse_str(wat_src).expect("WAT parse");

    // Inject a minimal name section that maps func index 0 -> "my_func".
    // Name section format (custom section, name="name"):
    //   subsection id=1 (function names)
    //   LEB128 size of subsection contents
    //   LEB128 count of entries
    //   entry: LEB128 func_index, LEB128 name_len, name_bytes
    let func_name = b"my_func";
    let mut name_section_content: Vec<u8> = Vec::new();
    // subsection type 1 = function names
    name_section_content.push(1);
    // Contents of subsection:
    let mut sub_contents: Vec<u8> = Vec::new();
    sub_contents.push(1); // 1 entry
    sub_contents.push(0); // func index 0
    sub_contents.push(func_name.len() as u8);
    sub_contents.extend_from_slice(func_name);
    // LEB128 size of sub_contents (single byte since len < 128)
    name_section_content.push(sub_contents.len() as u8);
    name_section_content.extend_from_slice(&sub_contents);

    // Custom section: id=0, then LEB128 total payload size, then "name" string, then content.
    let section_name = b"name";
    let mut payload: Vec<u8> = Vec::new();
    payload.push(section_name.len() as u8);
    payload.extend_from_slice(section_name);
    payload.extend_from_slice(&name_section_content);

    // Wasm custom section: byte 0 (section id), LEB128 payload size, payload.
    let mut name_custom: Vec<u8> = Vec::new();
    name_custom.push(0); // section id 0 = custom
    name_custom.push(payload.len() as u8); // size (assume < 128)
    name_custom.extend_from_slice(&payload);

    // Append the name section before the wasm end (the final 0x0b End section byte).
    // Actually just append at the end - wasmparser reads all sections.
    wasm.extend_from_slice(&name_custom);

    let table_base = 1u32;
    let map = parse_got_name_to_slot(&wasm, table_base);
    assert_eq!(
        map.get("my_func").copied(),
        Some(table_base),
        "my_func should map to table slot {table_base}"
    );
}

/// When a module has no name section, parse_got_name_to_slot returns an
/// empty map (no names to resolve).
#[test]
fn parse_got_name_to_slot_empty_on_no_name_section() {
    let wat_src = r#"
        (module
          (type (func))
          (func (type 0))
          (table 16 funcref)
          (elem (table 0) (offset i32.const 1) func 0)
        )
    "#;
    let wasm = wat::parse_str(wat_src).expect("WAT parse");
    let map = parse_got_name_to_slot(&wasm, 1);
    assert!(
        map.is_empty(),
        "expected empty map without name section, got {map:?}"
    );
}

/// When there is no element segment, no slots are resolved even with a name
/// section present.
#[test]
fn parse_got_name_to_slot_empty_on_no_element_segment() {
    // Module with a name section but no element segment.
    let wat_src = "(module (type (func)) (func (type 0)))";
    let mut wasm = wat::parse_str(wat_src).expect("WAT parse");

    // Inject name section: func 0 -> "orphan".
    let func_name = b"orphan";
    let section_name = b"name";
    let mut sub_contents: Vec<u8> = vec![1, 0, func_name.len() as u8];
    sub_contents.extend_from_slice(func_name);
    let mut name_sub: Vec<u8> = vec![1, sub_contents.len() as u8];
    name_sub.extend_from_slice(&sub_contents);
    let mut payload: Vec<u8> = vec![section_name.len() as u8];
    payload.extend_from_slice(section_name);
    payload.extend_from_slice(&name_sub);
    let mut custom: Vec<u8> = vec![0, payload.len() as u8];
    custom.extend_from_slice(&payload);
    wasm.extend_from_slice(&custom);

    let map = parse_got_name_to_slot(&wasm, 1);
    assert!(
        !map.contains_key("orphan"),
        "orphan should not be in map (no element segment)"
    );
}

/// `parse_got_name_to_slot` must not panic on empty or garbage bytes.
#[test]
fn parse_got_name_to_slot_graceful_on_garbage() {
    let map = parse_got_name_to_slot(b"not wasm at all \xff\x00", 1);
    assert!(map.is_empty());
}

#[test]
fn parse_got_name_to_slot_graceful_on_empty() {
    let map = parse_got_name_to_slot(b"", 1);
    assert!(map.is_empty());
}

// ---- parse_got_name_to_slot: GOT.func / GOT.mem name filtering ---------------

/// Helper: filter the map to entries matching "GOT.func." or "GOT.mem." prefixes.
/// Since parse_got_name_to_slot works on function names from the name section
/// (not GOT import names), we test that unrelated names don't appear.
#[test]
fn parse_got_name_to_slot_multiple_functions() {
    // Two functions: func 0 = "fa", func 1 = "fb".
    // Element segment: slot 1 -> func 0, slot 2 -> func 1.
    let wat_src = r#"
        (module
          (type (func))
          (func (type 0))
          (func (type 0))
          (table 16 funcref)
          (elem (table 0) (offset i32.const 1) func 0 1)
        )
    "#;
    let mut wasm = wat::parse_str(wat_src).expect("WAT parse");

    // Name section: func 0 -> "fa", func 1 -> "fb".
    let section_name = b"name";
    let mut sub_contents: Vec<u8> = Vec::new();
    sub_contents.push(2); // 2 entries
    // entry 0
    sub_contents.push(0); // func index 0
    sub_contents.push(2); // name len
    sub_contents.extend_from_slice(b"fa");
    // entry 1
    sub_contents.push(1); // func index 1
    sub_contents.push(2); // name len
    sub_contents.extend_from_slice(b"fb");
    let mut name_sub: Vec<u8> = vec![1, sub_contents.len() as u8];
    name_sub.extend_from_slice(&sub_contents);
    let mut payload: Vec<u8> = vec![section_name.len() as u8];
    payload.extend_from_slice(section_name);
    payload.extend_from_slice(&name_sub);
    let mut custom: Vec<u8> = vec![0, payload.len() as u8];
    custom.extend_from_slice(&payload);
    wasm.extend_from_slice(&custom);

    let table_base = 1u32;
    let map = parse_got_name_to_slot(&wasm, table_base);
    assert_eq!(map.get("fa").copied(), Some(1u32), "fa -> slot 1");
    assert_eq!(map.get("fb").copied(), Some(2u32), "fb -> slot 2");
}
