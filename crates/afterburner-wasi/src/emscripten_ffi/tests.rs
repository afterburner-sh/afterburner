// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Unit tests for the libffi host bridge.
//!
//! These build a tiny synthetic Emscripten-shaped module (imports `env.memory`
//! and `env.__indirect_function_table`, exports `malloc`/`free` and a few target
//! functions) so `ffi_call_js` and the closure trampoline can be exercised end
//! to end without LLVM or a real Pyodide image. The cif and arg/return values
//! are written into guest memory exactly as `_ctypes` would, and the marshalled
//! results are asserted byte-exact.

use wasmtime::{Engine, Instance, Linker, Module, Ref, Store, Val};

use crate::embedder_vm::EmbedderState;

use super::*;

// FFI_TYPE ids (mirrors the module constants; duplicated here so a drift in the
// non-test constants is caught by a failing test rather than silently tracking).
const T_VOID: u16 = 0;
const T_INT: u16 = 1;
const T_FLOAT: u16 = 2;
const T_DOUBLE: u16 = 3;
const T_UINT64: u16 = 11;
const T_POINTER: u16 = 14;

/// A synthetic module: imports memory + table, exports a bump `malloc`/`free`,
/// and four target functions covering the scalar ABI paths. The bump allocator
/// hands out 16-byte-aligned blocks from a high water mark stored at address 0.
const WAT: &str = r#"
(module
  (import "env" "memory" (memory 4))
  (import "env" "__indirect_function_table" (table 8 funcref))
  ;; ffi imports, called through exported wrappers so the host fn runs with this
  ;; instance as the caller (so caller.get_export("malloc") resolves), exactly as
  ;; CPython's _ctypes reaches them in production.
  (import "env" "ffi_closure_alloc_js" (func $alloc_js (param i32 i32) (result i32)))
  (import "env" "ffi_prep_closure_loc_js" (func $prep_js (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "ffi_closure_free_js" (func $free_js (param i32)))

  ;; add_i32(a, b) -> a + b
  (func $add (export "t_add") (param i32 i32) (result i32)
    local.get 0 local.get 1 i32.add)
  ;; add_f64(a, b) -> a + b
  (func $addd (export "t_addd") (param f64 f64) (result f64)
    local.get 0 local.get 1 f64.add)
  ;; id_ptr(p) -> p
  (func $idp (export "t_idp") (param i32) (result i32) local.get 0)
  ;; mul_u64(a, b) -> a * b
  (func $mulj (export "t_mulj") (param i64 i64) (result i64)
    local.get 0 local.get 1 i64.mul)

  ;; type for an int(int) closure trampoline, called via call_indirect.
  (type $int_int (func (param i32) (result i32)))

  ;; exported wrappers that forward to the ffi imports.
  (func (export "w_alloc") (param i32 i32) (result i32)
    local.get 0 local.get 1 call $alloc_js)
  (func (export "w_prep") (param i32 i32 i32 i32 i32) (result i32)
    local.get 0 local.get 1 local.get 2 local.get 3 local.get 4 call $prep_js)
  (func (export "w_free") (param i32) local.get 0 call $free_js)
  ;; invoke the int(int) trampoline at table[slot] with `arg`, from inside this
  ;; guest activation (so the trampoline's caller.get_export("malloc") resolves,
  ;; exactly as a C library calling a ctypes callback does in production).
  (func (export "w_call_tramp") (param $slot i32) (param $arg i32) (result i32)
    local.get $arg local.get $slot call_indirect (type $int_int))

  ;; bump malloc: water mark at [0], starts at 1024. align to 16.
  (func $malloc (export "malloc") (param $n i32) (result i32)
    (local $p i32)
    (if (i32.eqz (i32.load (i32.const 0)))
      (then (i32.store (i32.const 0) (i32.const 1024))))
    (local.set $p (i32.load (i32.const 0)))
    (i32.store (i32.const 0)
      (i32.and
        (i32.add (i32.add (local.get $p) (local.get $n)) (i32.const 15))
        (i32.const -16)))
    (local.get $p))
  (func $free (export "free") (param i32))
)
"#;

/// Build the synthetic module, wire `env.memory`, the indirect function table,
/// and the ffi imports, instantiate, and record the memory/table handles into
/// the store data (as the real boot path does). Returns the store and instance.
fn setup() -> (Store<EmbedderState>, Instance) {
    let engine = Engine::default();
    let module = Module::new(&engine, WAT).expect("compile synthetic module");

    let mut linker: Linker<EmbedderState> = Linker::new(&engine);
    linker.allow_shadowing(true);

    let mut store = Store::new(&engine, EmbedderState::for_emscripten());

    // env.memory (4 pages) and env.__indirect_function_table (8 slots).
    let mem_ty = wasmtime::MemoryType::new(4, None);
    let memory = wasmtime::Memory::new(&mut store, mem_ty).expect("memory");
    linker.define(&mut store, "env", "memory", memory).unwrap();
    store.data_mut().pyodide_memory = Some(memory);

    let tbl_ty = wasmtime::TableType::new(wasmtime::RefType::FUNCREF, 8, None);
    let table = wasmtime::Table::new(&mut store, tbl_ty, Ref::Func(None)).expect("table");
    linker
        .define(&mut store, "env", "__indirect_function_table", table)
        .unwrap();
    store.data_mut().pyodide_table = Some(table);

    super::wire_emscripten_ffi(&engine, &mut linker).expect("wire ffi");

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");

    // Place each target function into a known table slot so ffi_call can reach
    // it by index. Slots 1..=4 (slot 0 left null).
    for (slot, name) in [(1u32, "t_add"), (2, "t_addd"), (3, "t_idp"), (4, "t_mulj")] {
        let f = instance.get_func(&mut store, name).unwrap();
        table
            .set(&mut store, slot as u64, Ref::Func(Some(f)))
            .unwrap();
    }
    (store, instance)
}

/// Call the guest bump allocator to reserve `n` bytes; returns the guest ptr.
fn galloc(store: &mut Store<EmbedderState>, instance: &Instance, n: u32) -> u32 {
    let malloc = instance.get_func(&mut *store, "malloc").unwrap();
    let mut out = [Val::I32(0)];
    malloc
        .call(&mut *store, &[Val::I32(n as i32)], &mut out)
        .unwrap();
    match out[0] {
        Val::I32(p) => p as u32,
        _ => panic!("malloc"),
    }
}

fn wr_u32(store: &mut Store<EmbedderState>, ptr: u32, v: u32) {
    let mem = store.data().pyodide_memory.unwrap();
    mem.data_mut(&mut *store)[ptr as usize..ptr as usize + 4].copy_from_slice(&v.to_le_bytes());
}
fn wr_u16(store: &mut Store<EmbedderState>, ptr: u32, v: u16) {
    let mem = store.data().pyodide_memory.unwrap();
    mem.data_mut(&mut *store)[ptr as usize..ptr as usize + 2].copy_from_slice(&v.to_le_bytes());
}
fn wr_bytes(store: &mut Store<EmbedderState>, ptr: u32, b: &[u8]) {
    let mem = store.data().pyodide_memory.unwrap();
    mem.data_mut(&mut *store)[ptr as usize..ptr as usize + b.len()].copy_from_slice(b);
}
fn rd_u32(store: &mut Store<EmbedderState>, ptr: u32) -> u32 {
    let mem = store.data().pyodide_memory.unwrap();
    let d = mem.data(&*store);
    u32::from_le_bytes(d[ptr as usize..ptr as usize + 4].try_into().unwrap())
}
fn rd_bytes(store: &mut Store<EmbedderState>, ptr: u32, n: usize) -> Vec<u8> {
    let mem = store.data().pyodide_memory.unwrap();
    mem.data(&*store)[ptr as usize..ptr as usize + n].to_vec()
}

/// Extract an i32 from a wasm `Val` (which does not implement `PartialEq`).
fn as_i32(v: &Val) -> i32 {
    match v {
        Val::I32(i) => *i,
        other => panic!("expected i32, got {other:?}"),
    }
}

/// Build an ffi_type at a guest pointer: size, align, typeid, elements=0.
fn write_type(
    store: &mut Store<EmbedderState>,
    instance: &Instance,
    id: u16,
    size: u32,
    align: u16,
) -> u32 {
    let p = galloc(store, instance, 16);
    wr_u32(store, p + TYPE_SIZE, size);
    wr_u16(store, p + TYPE_ALIGN, align);
    wr_u16(store, p + TYPE_TYPEID, id);
    wr_u32(store, p + TYPE_ELEMENTS, 0);
    p
}

/// Build an ffi_cif at a guest pointer for the given arg types and return type.
fn write_cif(
    store: &mut Store<EmbedderState>,
    instance: &Instance,
    arg_type_ptrs: &[u32],
    rtype_ptr: u32,
) -> u32 {
    let nargs = arg_type_ptrs.len() as u32;
    // arg_types array (nargs pointers).
    let arg_types = galloc(store, instance, nargs.max(1) * 4);
    for (i, &tp) in arg_type_ptrs.iter().enumerate() {
        wr_u32(store, arg_types + i as u32 * 4, tp);
    }
    let cif = galloc(store, instance, 28);
    wr_u32(store, cif, 24); // cif+0 = abi = FFI_WASM32_EMSCRIPTEN (value unchecked here)
    wr_u32(store, cif + CIF_NARGS, nargs);
    wr_u32(store, cif + CIF_ARGTYPES, arg_types);
    wr_u32(store, cif + CIF_RTYPE, rtype_ptr);
    wr_u32(store, cif + CIF_FLAGS, 0);
    wr_u32(store, cif + CIF_NFIXEDARGS, nargs);
    cif
}

/// Invoke the real [`super::ffi_call_js`] for the given cif against table slot
/// `fn_idx`, writing the marshalled return into `rvalue`. `ffi_call_js` takes a
/// live `Caller`, so we wrap it in a host [`wasmtime::Func`] and call that
/// against the store, exactly as the guest reaches the `env.ffi_call_js` import.
fn call_ffi(
    store: &mut Store<EmbedderState>,
    _instance: &Instance,
    cif: u32,
    fn_idx: u32,
    rvalue: u32,
    avalue: u32,
) {
    let ffi = wasmtime::Func::wrap(
        &mut *store,
        move |caller: wasmtime::Caller<'_, EmbedderState>, c: i32, f: i32, r: i32, a: i32| {
            super::ffi_call_js(caller, c, f, r, a)
        },
    );
    ffi.call(
        &mut *store,
        &[
            Val::I32(cif as i32),
            Val::I32(fn_idx as i32),
            Val::I32(rvalue as i32),
            Val::I32(avalue as i32),
        ],
        &mut [],
    )
    .expect("ffi_call_js");
}

#[test]
fn ffi_call_add_two_i32() {
    let (mut store, instance) = setup();
    let int_ty = write_type(&mut store, &instance, T_INT, 4, 4);
    let cif = write_cif(&mut store, &instance, &[int_ty, int_ty], int_ty);

    // avalue = [&a, &b]; a=7, b=35.
    let a = galloc(&mut store, &instance, 4);
    wr_u32(&mut store, a, 7);
    let b = galloc(&mut store, &instance, 4);
    wr_u32(&mut store, b, 35);
    let avalue = galloc(&mut store, &instance, 8);
    wr_u32(&mut store, avalue, a);
    wr_u32(&mut store, avalue + 4, b);
    let rvalue = galloc(&mut store, &instance, 4);

    call_ffi(&mut store, &instance, cif, 1, rvalue, avalue);
    assert_eq!(rd_u32(&mut store, rvalue), 42, "7 + 35 == 42 via ffi_call");
}

#[test]
fn ffi_call_add_two_f64() {
    let (mut store, instance) = setup();
    let dbl_ty = write_type(&mut store, &instance, T_DOUBLE, 8, 8);
    let cif = write_cif(&mut store, &instance, &[dbl_ty, dbl_ty], dbl_ty);

    let a = galloc(&mut store, &instance, 8);
    wr_bytes(&mut store, a, &1.5f64.to_le_bytes());
    let b = galloc(&mut store, &instance, 8);
    wr_bytes(&mut store, b, &2.25f64.to_le_bytes());
    let avalue = galloc(&mut store, &instance, 8);
    wr_u32(&mut store, avalue, a);
    wr_u32(&mut store, avalue + 4, b);
    let rvalue = galloc(&mut store, &instance, 8);

    call_ffi(&mut store, &instance, cif, 2, rvalue, avalue);
    let got = f64::from_le_bytes(rd_bytes(&mut store, rvalue, 8).try_into().unwrap());
    assert!(
        (got - 3.75).abs() < f64::EPSILON,
        "1.5 + 2.25 == 3.75, got {got}"
    );
}

#[test]
fn ffi_call_pointer_identity() {
    let (mut store, instance) = setup();
    let ptr_ty = write_type(&mut store, &instance, T_POINTER, 4, 4);
    let cif = write_cif(&mut store, &instance, &[ptr_ty], ptr_ty);

    let a = galloc(&mut store, &instance, 4);
    wr_u32(&mut store, a, 0xCAFE_F00D);
    let avalue = galloc(&mut store, &instance, 4);
    wr_u32(&mut store, avalue, a);
    let rvalue = galloc(&mut store, &instance, 4);

    call_ffi(&mut store, &instance, cif, 3, rvalue, avalue);
    assert_eq!(
        rd_u32(&mut store, rvalue),
        0xCAFE_F00D,
        "ptr passes through"
    );
}

#[test]
fn ffi_call_mul_u64() {
    let (mut store, instance) = setup();
    let u64_ty = write_type(&mut store, &instance, T_UINT64, 8, 8);
    let cif = write_cif(&mut store, &instance, &[u64_ty, u64_ty], u64_ty);

    let a = galloc(&mut store, &instance, 8);
    wr_bytes(&mut store, a, &1_000_003u64.to_le_bytes());
    let b = galloc(&mut store, &instance, 8);
    wr_bytes(&mut store, b, &1_000_033u64.to_le_bytes());
    let avalue = galloc(&mut store, &instance, 8);
    wr_u32(&mut store, avalue, a);
    wr_u32(&mut store, avalue + 4, b);
    let rvalue = galloc(&mut store, &instance, 8);

    call_ffi(&mut store, &instance, cif, 4, rvalue, avalue);
    let got = u64::from_le_bytes(rd_bytes(&mut store, rvalue, 8).try_into().unwrap());
    assert_eq!(got, 1_000_003u64 * 1_000_033u64, "u64 mul via ffi_call");
}

#[test]
fn ffi_call_null_funcref_traps() {
    let (mut store, instance) = setup();
    let int_ty = write_type(&mut store, &instance, T_INT, 4, 4);
    let cif = write_cif(&mut store, &instance, &[], int_ty);
    let rvalue = galloc(&mut store, &instance, 4);
    let avalue = galloc(&mut store, &instance, 4);

    // Slot 0 is null. Calling it must error, not silently succeed.
    let ffi = wasmtime::Func::wrap(
        &mut store,
        move |caller: wasmtime::Caller<'_, EmbedderState>, c: i32, f: i32, r: i32, a: i32| {
            super::ffi_call_js(caller, c, f, r, a)
        },
    );
    let res = ffi.call(
        &mut store,
        &[
            Val::I32(cif as i32),
            Val::I32(0),
            Val::I32(rvalue as i32),
            Val::I32(avalue as i32),
        ],
        &mut [],
    );
    assert!(res.is_err(), "calling a null table slot must error");
}

#[test]
fn closure_alloc_prep_and_invoke() {
    // Allocate a closure, prep it with an int(int) signature whose body doubles
    // its argument, then invoke the installed trampoline through the table and
    // assert it returns 2*arg.
    let (mut store, instance) = setup();

    // Closure body `fun(cif, ret, args, user_data)`: read args[0] -> *p (i32),
    // compute 2*x, store into *ret. We need this as a guest function in the
    // table. Build a second module that exports it, sharing the same memory.
    let dbl_body_wat = r#"
    (module
      (import "env" "memory" (memory 4))
      ;; fun(cif, ret, args, user_data): ret <- 2 * *(*(args))
      (func $fun (export "fun") (param i32 i32 i32 i32)
        (local $argp i32)
        (local.set $argp (i32.load (local.get 2)))   ;; args[0] -> pointer to arg0
        (i32.store (local.get 1)
          (i32.mul (i32.const 2) (i32.load (local.get $argp)))))
    )"#;
    let engine = store.engine().clone();
    let body_mod = Module::new(&engine, dbl_body_wat).unwrap();
    let mut body_linker: Linker<EmbedderState> = Linker::new(&engine);
    let mem = store.data().pyodide_memory.unwrap();
    body_linker
        .define(&mut store, "env", "memory", mem)
        .unwrap();
    let body_inst = body_linker.instantiate(&mut store, &body_mod).unwrap();
    let fun = body_inst.get_func(&mut store, "fun").unwrap();
    // Install the body at table slot 6.
    let table = store.data().pyodide_table.unwrap();
    table.set(&mut store, 6, Ref::Func(Some(fun))).unwrap();

    // cif: int(int).
    let int_ty = write_type(&mut store, &instance, T_INT, 4, 4);
    let cif = write_cif(&mut store, &instance, &[int_ty], int_ty);

    // ffi_closure_alloc_js(size=16, code=&codeloc) via the exported wrapper, so
    // the host fn runs with the instance as caller (production-faithful).
    let code_ptr = galloc(&mut store, &instance, 4);
    let w_alloc = instance.get_func(&mut store, "w_alloc").unwrap();
    let mut out = [Val::I32(0)];
    w_alloc
        .call(
            &mut store,
            &[Val::I32(16), Val::I32(code_ptr as i32)],
            &mut out,
        )
        .unwrap();
    let closure = as_i32(&out[0]) as u32;
    assert!(closure != 0, "closure alloc must not be NULL");
    let codeloc = rd_u32(&mut store, code_ptr);

    // ffi_prep_closure_loc_js(closure, cif, fun=slot 6, user_data=0, codeloc).
    let w_prep = instance.get_func(&mut store, "w_prep").unwrap();
    let mut pout = [Val::I32(-1)];
    w_prep
        .call(
            &mut store,
            &[
                Val::I32(closure as i32),
                Val::I32(cif as i32),
                Val::I32(6), // fun table slot
                Val::I32(0),
                Val::I32(codeloc as i32),
            ],
            &mut pout,
        )
        .unwrap();
    assert_eq!(as_i32(&pout[0]), 0, "ffi_prep_closure_loc_js -> FFI_OK");

    // Invoke the trampoline at `codeloc` the way a C library would: from inside
    // the guest via call_indirect (so its caller.get_export resolves). sig
    // int(int); call with 21 -> expect 42.
    let w_call = instance.get_func(&mut store, "w_call_tramp").unwrap();
    let mut r = [Val::I32(0)];
    w_call
        .call(
            &mut store,
            &[Val::I32(codeloc as i32), Val::I32(21)],
            &mut r,
        )
        .unwrap();
    assert_eq!(as_i32(&r[0]), 42, "closure trampoline returns 2*arg");

    // Free the closure; its slot should be recycled for the next alloc.
    let w_free = instance.get_func(&mut store, "w_free").unwrap();
    w_free
        .call(&mut store, &[Val::I32(closure as i32)], &mut [])
        .unwrap();
    assert_eq!(
        store.data().ffi_free_slots.last().copied(),
        Some(codeloc),
        "freed closure slot is recycled"
    );
}

#[test]
fn mem_read_rejects_out_of_bounds() {
    // A read past the end of guest memory must error, never read host memory.
    let (mut store, _instance) = setup();
    let ffi = wasmtime::Func::wrap(
        &mut store,
        move |caller: wasmtime::Caller<'_, EmbedderState>,
              p: i32,
              l: i32|
              -> wasmtime::Result<i32> {
            let _ = super::mem_read(&caller, p as u32, l as usize)?;
            Ok(0)
        },
    );
    // 4 pages = 256 KiB; read 64 bytes starting 16 bytes before the end -> OOB.
    let res = ffi.call(
        &mut store,
        &[Val::I32(4 * 65536 - 16), Val::I32(64)],
        &mut [Val::I32(0)],
    );
    assert!(res.is_err(), "OOB read must be rejected");
}

#[test]
fn type_and_cif_offsets_match_libffi() {
    // Guard the wasm32 libffi field offsets these reads depend on.
    assert_eq!(
        (
            CIF_NARGS,
            CIF_ARGTYPES,
            CIF_RTYPE,
            CIF_FLAGS,
            CIF_NFIXEDARGS
        ),
        (4, 8, 12, 20, 24)
    );
    assert_eq!(
        (TYPE_SIZE, TYPE_ALIGN, TYPE_TYPEID, TYPE_ELEMENTS),
        (0, 4, 6, 8)
    );
    assert_eq!(
        (CLOSURE_WRAPPER, CLOSURE_CIF, CLOSURE_FUN, CLOSURE_USER_DATA),
        (0, 4, 8, 12)
    );
    // FFI_TYPE ids used by the marshaller.
    assert_eq!(
        (FFI_TYPE_VOID, FFI_TYPE_INT, FFI_TYPE_FLOAT, FFI_TYPE_DOUBLE),
        (T_VOID, T_INT, T_FLOAT, T_DOUBLE)
    );
    assert_eq!((FFI_TYPE_UINT64, FFI_TYPE_POINTER), (T_UINT64, T_POINTER));
}

#[test]
fn resolve_rejects_cyclic_struct_type() {
    // A struct ffi_type whose sole element points back to itself would spin the
    // unbox loop forever; the depth cap must turn it into an error, not a hang.
    // If the cap regressed, this test would hang (caught as a CI timeout) rather
    // than pass, which is the honest failure mode for a missing bound.
    const T_STRUCT: u16 = 13;
    let (mut store, instance) = setup();

    // Cyclic struct at `p`: id=STRUCT, size=8 (<=16 so the loop unboxes),
    // elements=[p, 0] -> single field that is the struct itself.
    let p = galloc(&mut store, &instance, 16);
    let elements = galloc(&mut store, &instance, 8);
    wr_u32(&mut store, p + TYPE_SIZE, 8);
    wr_u16(&mut store, p + TYPE_ALIGN, 8);
    wr_u16(&mut store, p + TYPE_TYPEID, T_STRUCT);
    wr_u32(&mut store, p + TYPE_ELEMENTS, elements);
    wr_u32(&mut store, elements, p); // first = self (the cycle)
    wr_u32(&mut store, elements + 4, 0); // second = 0 (single field)

    // Use the cyclic type as a cif return type; Cif::read resolves it and must
    // error (bounded) rather than loop. Build the cif by hand (write_cif can't
    // express a hand-rolled rtype pointer).
    let int_ty = write_type(&mut store, &instance, T_INT, 4, 4);
    let arg_types = galloc(&mut store, &instance, 4);
    wr_u32(&mut store, arg_types, int_ty);
    let cif = galloc(&mut store, &instance, 28);
    wr_u32(&mut store, cif + CIF_NARGS, 0);
    wr_u32(&mut store, cif + CIF_ARGTYPES, arg_types);
    wr_u32(&mut store, cif + CIF_RTYPE, p);
    wr_u32(&mut store, cif + CIF_FLAGS, 0);
    wr_u32(&mut store, cif + CIF_NFIXEDARGS, 0);

    let rvalue = galloc(&mut store, &instance, 8);
    let avalue = galloc(&mut store, &instance, 4);
    let ffi = wasmtime::Func::wrap(
        &mut store,
        move |caller: wasmtime::Caller<'_, EmbedderState>, c: i32, f: i32, r: i32, a: i32| {
            super::ffi_call_js(caller, c, f, r, a)
        },
    );
    let res = ffi.call(
        &mut store,
        &[
            Val::I32(cif as i32),
            Val::I32(1),
            Val::I32(rvalue as i32),
            Val::I32(avalue as i32),
        ],
        &mut [],
    );
    assert!(res.is_err(), "cyclic struct ffi_type must error, not hang");
}
