// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! libffi host bridge for CPython `ctypes` plus file-backed `mmap`.
//!
//! Pyodide's CPython is built against the wasm32 port of libffi
//! (`libffi/src/wasm/ffi.c`), which does not contain machine trampolines.
//! Instead it imports five host functions and delegates the entire C ABI to
//! them:
//!
//! | import                    | role                                            |
//! |---------------------------|-------------------------------------------------|
//! | `ffi_call_js`             | call a C function pointer: marshal args, invoke, marshal return |
//! | `ffi_closure_alloc_js`    | allocate a closure + reserve a function-table slot |
//! | `ffi_prep_closure_loc_js` | install a C->guest callback trampoline in the table |
//! | `ffi_closure_free_js`     | free the closure and recycle its table slot     |
//! | `ffi_closure_free_js`     | (paired free)                                   |
//!
//! In the reference (Emscripten) build these are `EM_JS` functions that read the
//! `ffi_cif` out of guest memory, marshal arguments through the JS<->wasm type
//! conversion, and dispatch via the wasm function table. This module is a
//! faithful host (wasmtime) port of that exact logic: it reads the same cif and
//! `ffi_type` layout, marshals arguments to and from guest linear memory, and
//! dispatches through `EmbedderState::pyodide_table` (the same
//! `__indirect_function_table` the `invoke_*` trampolines use).
//!
//! Without this bridge `from _ctypes import ...` raises `MemoryError`: the stock
//! no-op fill returns NULL from `ffi_closure_alloc_js`, and `_ctypes`' module
//! init treats that NULL as out-of-memory. ctypes underpins `polars._cpu_check`,
//! `numpy._core._internal`, and pandas, so this is the last blocker for those.
//!
//! ## Security
//!
//! Every guest-supplied pointer and length is bounds-checked against the wasm
//! memory size BEFORE any dereference (see [`mem_read`] / [`mem_write`]). A cif
//! or arg pointer that escapes the guest heap aborts the call with a trap rather
//! than reading host memory. The function-table index handed to a dispatch is
//! validated by wasmtime's own `Table::get` (returns `None` out of range). No
//! host pointer is ever exposed to the guest.
//!
//! ## Determinism
//!
//! All allocation is delegated to the guest's own `malloc` (deterministic bump
//! allocator over linear memory) and to deterministic table growth; there is no
//! clock, randomness, or address-space-layout dependence. The same program runs
//! byte-identically and consumes identical fuel across runs.

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Engine, Func, FuncType, Linker, Ref, Val};

use crate::{embedder_vm::EmbedderState, pyo_trace};

// ---- libffi ABI constants ---------------------------------------------------
//
// From libffi `include/ffi.h` (FFI_TYPE_*) and the wasm32 `ffi.c` field-offset
// macros (CIF__*, FFI_TYPE__*). wasm32 is a 32-bit target, so every pointer and
// every cif/type field is 4 bytes and `long double` is just `double`.

const FFI_TYPE_VOID: u16 = 0;
const FFI_TYPE_INT: u16 = 1;
const FFI_TYPE_FLOAT: u16 = 2;
const FFI_TYPE_DOUBLE: u16 = 3;
// On wasm32 FFI_TYPE_LONGDOUBLE is #defined to FFI_TYPE_DOUBLE (== 3), so it
// never appears as a distinct id here; the `double` arm handles it.
const FFI_TYPE_UINT8: u16 = 5;
const FFI_TYPE_SINT8: u16 = 6;
const FFI_TYPE_UINT16: u16 = 7;
const FFI_TYPE_SINT16: u16 = 8;
const FFI_TYPE_UINT32: u16 = 9;
const FFI_TYPE_SINT32: u16 = 10;
const FFI_TYPE_UINT64: u16 = 11;
const FFI_TYPE_SINT64: u16 = 12;
const FFI_TYPE_STRUCT: u16 = 13;
const FFI_TYPE_POINTER: u16 = 14;
const FFI_TYPE_COMPLEX: u16 = 15;

/// libffi `FFI_OK`.
const FFI_OK: i32 = 0;
/// libffi `FFI_BAD_TYPEDEF` (closure trampoline could not be built).
const FFI_BAD_TYPEDEF: i32 = 1;

/// `cif->nargs > MAX_ARGS` is rejected, matching the reference's guard. Caps the
/// host-side work a single guest call can request (DoS / runaway bound).
const MAX_ARGS: u32 = 1000;

// ffi_cif field byte offsets (wasm32: pointer = 4 bytes).
//   struct ffi_cif { ffi_abi abi; unsigned nargs; ffi_type **arg_types;
//                    ffi_type *rtype; unsigned bytes; unsigned flags;
//                    unsigned nfixedargs; }
const CIF_NARGS: u32 = 4; // 4*1
const CIF_ARGTYPES: u32 = 8; // 4*2
const CIF_RTYPE: u32 = 12; // 4*3
const CIF_FLAGS: u32 = 20; // 4*5
const CIF_NFIXEDARGS: u32 = 24; // 4*6

// ffi_type field byte offsets.
//   struct ffi_type { size_t size; unsigned short alignment; unsigned short type;
//                     ffi_type **elements; }
const TYPE_SIZE: u32 = 0;
const TYPE_ALIGN: u32 = 4;
const TYPE_TYPEID: u32 = 6;
const TYPE_ELEMENTS: u32 = 8;

// ffi_closure field byte offsets (wasm32).
//   struct ffi_closure { void *ftramp; ffi_cif *cif; void (*fun)(); void *user_data; }
// `ftramp` (offset 0) holds the table-slot index in this port (the wrapper).
const CLOSURE_WRAPPER: u32 = 0;
const CLOSURE_CIF: u32 = 4;
const CLOSURE_FUN: u32 = 8;
const CLOSURE_USER_DATA: u32 = 12;

/// `cif->flags & VARARGS_FLAG`.
const VARARGS_FLAG: u32 = 1;

mod marshal;
mod mmap;

#[cfg(test)]
mod tests;

use marshal::Cif;

// ---- bounds-checked guest memory access -------------------------------------

/// Read `len` bytes from guest linear memory at `ptr`. Returns a trap (not a
/// silent default) when the memory handle is absent or the range escapes the
/// guest bounds, so a corrupt cif pointer can never read host memory.
fn mem_read(caller: &Caller<'_, EmbedderState>, ptr: u32, len: usize) -> wasmtime::Result<Vec<u8>> {
    let mem = caller
        .data()
        .pyodide_memory
        .ok_or_else(|| AfterburnerError::Engine("ffi: no guest memory".into()))?;
    let data = mem.data(caller);
    let start = ptr as usize;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| {
            AfterburnerError::Engine(format!(
                "ffi: out-of-bounds read ptr={ptr:#x} len={len} (mem={})",
                data.len()
            ))
        })?;
    Ok(data[start..end].to_vec())
}

/// Write `bytes` into guest linear memory at `ptr`, bounds-checked like
/// [`mem_read`].
fn mem_write(
    caller: &mut Caller<'_, EmbedderState>,
    ptr: u32,
    bytes: &[u8],
) -> wasmtime::Result<()> {
    let mem = caller
        .data()
        .pyodide_memory
        .ok_or_else(|| AfterburnerError::Engine("ffi: no guest memory".into()))?;
    let data = mem.data_mut(caller);
    let start = ptr as usize;
    let end = start
        .checked_add(bytes.len())
        .filter(|&e| e <= data.len())
        .ok_or_else(|| {
            AfterburnerError::Engine(format!(
                "ffi: out-of-bounds write ptr={ptr:#x} len={} (mem={})",
                bytes.len(),
                data.len()
            ))
        })?;
    data[start..end].copy_from_slice(bytes);
    Ok(())
}

/// Read a little-endian u32 from guest memory.
fn read_u32(caller: &Caller<'_, EmbedderState>, ptr: u32) -> wasmtime::Result<u32> {
    let b = mem_read(caller, ptr, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a little-endian u16 from guest memory.
fn read_u16(caller: &Caller<'_, EmbedderState>, ptr: u32) -> wasmtime::Result<u16> {
    let b = mem_read(caller, ptr, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

/// Write a little-endian u32 to guest memory.
fn write_u32(caller: &mut Caller<'_, EmbedderState>, ptr: u32, v: u32) -> wasmtime::Result<()> {
    mem_write(caller, ptr, &v.to_le_bytes())
}

// ---- guest helper calls -----------------------------------------------------

/// Call the guest's exported `malloc(size)` and return the guest pointer
/// (0 on allocation failure). Used by `ffi_closure_alloc_js` and the scratch
/// allocator for by-value struct arguments. Calling a guest export from inside
/// a host import is sound in wasmtime (it is another guest activation on the
/// same store).
fn guest_malloc(caller: &mut Caller<'_, EmbedderState>, size: u32) -> wasmtime::Result<u32> {
    let malloc = caller
        .get_export("malloc")
        .and_then(|e| e.into_func())
        .ok_or_else(|| AfterburnerError::Engine("ffi: guest exports no malloc".into()))?;
    let mut out = [Val::I32(0)];
    malloc.call(&mut *caller, &[Val::I32(size as i32)], &mut out)?;
    match out[0] {
        Val::I32(p) => Ok(p as u32),
        _ => Err(AfterburnerError::Engine("ffi: malloc returned non-i32".into()).into()),
    }
}

/// Call the guest's exported `free(ptr)`.
fn guest_free(caller: &mut Caller<'_, EmbedderState>, ptr: u32) -> wasmtime::Result<()> {
    if ptr == 0 {
        return Ok(());
    }
    let free = caller
        .get_export("free")
        .and_then(|e| e.into_func())
        .ok_or_else(|| AfterburnerError::Engine("ffi: guest exports no free".into()))?;
    free.call(&mut *caller, &[Val::I32(ptr as i32)], &mut [])?;
    Ok(())
}

/// Reserve an empty `__indirect_function_table` slot (the host equivalent of
/// Emscripten's `getEmptyTableSlot`): reuse a slot freed by
/// `ffi_closure_free_js` if one is available, else grow the table by one. The
/// returned slot is left null until `ffi_prep_closure_loc_js` installs the
/// trampoline there.
fn get_empty_table_slot(caller: &mut Caller<'_, EmbedderState>) -> wasmtime::Result<u32> {
    if let Some(slot) = caller.data_mut().ffi_free_slots.pop() {
        return Ok(slot);
    }
    let table = caller
        .data()
        .pyodide_table
        .ok_or_else(|| AfterburnerError::Engine("ffi: no guest table".into()))?;
    let slot = table.size(&*caller) as u32;
    table
        .grow(&mut *caller, 1, Ref::Func(None))
        .map_err(|e| AfterburnerError::Engine(format!("ffi: table grow: {e}")))?;
    Ok(slot)
}

// ---- ffi_call ---------------------------------------------------------------

/// `ffi_call_js(cif, fn, rvalue, avalue)`: invoke the C function pointer `fn`.
///
/// Reads the cif, marshals each fixed argument from `avalue[i]` (a guest
/// pointer to the argument value) into a wasm [`Val`] per its `ffi_type`,
/// invokes the funcref at table index `fn`, then marshals the return value back
/// into `rvalue`. Structs returned by value (and `long double`) are returned via
/// a hidden pointer argument that is `rvalue` itself, exactly as the reference
/// does.
///
/// Varargs and by-value struct arguments are copied onto a scratch region
/// obtained from the guest allocator (rather than the C stack the JS reference
/// pokes directly); the onward call sees identical memory. The scratch is freed
/// before return.
fn ffi_call_js(
    mut caller: Caller<'_, EmbedderState>,
    cif_ptr: i32,
    fn_idx: i32,
    rvalue: i32,
    avalue: i32,
) -> wasmtime::Result<()> {
    let cif = Cif::read(&caller, cif_ptr as u32)?;
    if cif.nargs > MAX_ARGS {
        return Err(AfterburnerError::Engine(format!(
            "ffi_call: nargs {} exceeds MAX_ARGS {MAX_ARGS}",
            cif.nargs
        ))
        .into());
    }
    let rvalue = rvalue as u32;
    let avalue = avalue as u32;

    let mut args: Vec<Val> = Vec::with_capacity(cif.nargs as usize + 1);
    // Scratch guest allocations (struct-by-value copies) to free after the call.
    let mut scratch: Vec<u32> = Vec::new();

    // Return-by-argument: a multi-field struct or long double return makes the
    // onward call take a leading pointer to the return slot. We already hold one
    // (rvalue), so reuse it.
    let ret_by_arg = matches!(cif.rtype.id, FFI_TYPE_STRUCT) || cif.rtype.is_long_double;
    if ret_by_arg {
        args.push(Val::I32(rvalue as i32));
    } else if cif.rtype.id == FFI_TYPE_COMPLEX {
        return Err(AfterburnerError::Engine("ffi_call: complex return nyi".into()).into());
    }

    for i in 0..cif.nfixedargs {
        let arg_ptr = read_u32(&caller, avalue + i * 4)?;
        let at = cif.arg_type(&caller, i)?;
        marshal::push_arg(&mut caller, &at, arg_ptr, &mut args, &mut scratch)?;
    }

    // Varargs (flags & VARARGS_FLAG): the onward call takes one extra pointer to
    // a packed region holding the variadic values. ctypes' import path does not
    // use varargs, but keep parity with the reference for completeness.
    if cif.flags & VARARGS_FLAG != 0 {
        let va_ptr = marshal::pack_varargs(&mut caller, &cif, avalue, &mut scratch)?;
        args.push(Val::I32(va_ptr as i32));
    }

    // Dispatch through the indirect function table (the funcref at `fn_idx`).
    let table = caller
        .data()
        .pyodide_table
        .ok_or_else(|| AfterburnerError::Engine("ffi_call: no guest table".into()))?;
    let slot = table.get(&mut caller, fn_idx as u64);
    let func = match slot {
        Some(Ref::Func(Some(f))) => f,
        _ => {
            for p in scratch {
                let _ = guest_free(&mut caller, p);
            }
            return Err(AfterburnerError::Engine(format!(
                "ffi_call: null/absent funcref at table[{fn_idx}]"
            ))
            .into());
        }
    };

    // The callee's declared result count tells us whether it returns a scalar.
    let func_ty = func.ty(&caller);
    let nresults = func_ty.results().len();
    let mut results = vec![Val::I32(0); nresults];

    let call_res = func.call(&mut caller, &args, &mut results);

    // Free scratch regardless of call outcome so a trapping callee does not leak.
    for p in scratch {
        let _ = guest_free(&mut caller, p);
    }
    call_res?;

    if ret_by_arg {
        // The onward call already wrote the struct/long-double into rvalue.
        return Ok(());
    }
    if nresults == 0 {
        // void return.
        return Ok(());
    }
    marshal::store_return(&mut caller, &cif.rtype, &results[0], rvalue)?;
    Ok(())
}

// ---- ffi_closure_alloc ------------------------------------------------------

/// `ffi_closure_alloc_js(size, code) -> closure`: allocate the closure object in
/// guest memory and reserve a function-table slot for its trampoline.
///
/// Writes the reserved slot index to `*code` (the executable address ctypes
/// hands to C as the callback function pointer) and to the closure's wrapper
/// field. The slot is filled with the real trampoline by
/// `ffi_prep_closure_loc_js`. Returns the writable closure pointer, or 0
/// (NULL -> the caller raises MemoryError) if guest malloc fails.
fn ffi_closure_alloc_js(
    mut caller: Caller<'_, EmbedderState>,
    size: i32,
    code: i32,
) -> wasmtime::Result<i32> {
    let closure = guest_malloc(&mut caller, size as u32)?;
    if closure == 0 {
        pyo_trace!("[ffi] ffi_closure_alloc_js: guest malloc({size}) failed -> NULL");
        return Ok(0);
    }
    let slot = get_empty_table_slot(&mut caller)?;
    // *code = slot ; closure->wrapper = slot
    write_u32(&mut caller, code as u32, slot)?;
    write_u32(&mut caller, closure + CLOSURE_WRAPPER, slot)?;
    pyo_trace!("[ffi] ffi_closure_alloc_js size={size} -> closure={closure:#x} slot={slot}");
    Ok(closure as i32)
}

/// `ffi_closure_free_js(closure)`: recycle the closure's table slot and free its
/// guest memory.
fn ffi_closure_free_js(
    mut caller: Caller<'_, EmbedderState>,
    closure: i32,
) -> wasmtime::Result<()> {
    let closure = closure as u32;
    let slot = read_u32(&caller, closure + CLOSURE_WRAPPER)?;
    // Null the slot so a stale call traps rather than dispatching a freed closure,
    // then return it to the free list for reuse.
    if let Some(table) = caller.data().pyodide_table
        && (slot as u64) < table.size(&caller)
    {
        let _ = table.set(&mut caller, slot as u64, Ref::Func(None));
    }
    caller.data_mut().ffi_free_slots.push(slot);
    guest_free(&mut caller, closure)?;
    pyo_trace!("[ffi] ffi_closure_free_js closure={closure:#x} slot={slot} recycled");
    Ok(())
}

// ---- ffi_prep_closure_loc ---------------------------------------------------

/// `ffi_prep_closure_loc_js(closure, cif, fun, user_data, codeloc) -> status`:
/// install the C->guest callback trampoline.
///
/// Builds a host [`Func`] whose wasm signature matches the closure's C signature
/// (derived from the cif) and installs it at table slot `codeloc`. When the
/// guest later calls that slot, the trampoline marshals the wasm arguments into
/// a libffi `(cif, rvalue, avalue, user_data)` frame and dispatches to the C
/// closure body `fun` through the table, then marshals the return back. The
/// closure's cif/fun/user_data fields are written so the trampoline (and any
/// later C code) can read them.
///
/// Returns `FFI_OK` on success or `FFI_BAD_TYPEDEF` if the signature could not
/// be built (matching the reference's `catch` path).
fn ffi_prep_closure_loc_js(
    mut caller: Caller<'_, EmbedderState>,
    closure: i32,
    cif_ptr: i32,
    fun: i32,
    user_data: i32,
    codeloc: i32,
) -> wasmtime::Result<i32> {
    let closure = closure as u32;
    let cif = Cif::read(&caller, cif_ptr as u32)?;
    if cif.nargs > MAX_ARGS {
        return Ok(FFI_BAD_TYPEDEF);
    }

    // Build the wasm signature (params + result) of the trampoline the guest will
    // call, and capture the per-argument marshalling plan.
    let engine = caller.engine().clone();
    let plan = match marshal::ClosurePlan::build(&caller, &cif) {
        Ok(p) => p,
        Err(_) => return Ok(FFI_BAD_TYPEDEF),
    };
    let func_ty = FuncType::new(
        &engine,
        plan.params.iter().cloned(),
        plan.results.iter().cloned(),
    );

    // The trampoline captures only the closure pointer and the marshalling plan;
    // cif/fun/user_data are read from the closure struct at call time (like the
    // reference, which reads CLOSURE__cif/fun/user_data inside the trampoline).
    // Func::new is created in the caller's store context.
    let trampoline = Func::new(
        &mut caller,
        func_ty,
        move |mut caller: Caller<'_, EmbedderState>, params: &[Val], results: &mut [Val]| {
            marshal::run_closure(&mut caller, closure, &plan, params, results)
        },
    );

    let table = caller
        .data()
        .pyodide_table
        .ok_or_else(|| AfterburnerError::Engine("ffi_prep_closure: no guest table".into()))?;
    table
        .set(&mut caller, codeloc as u64, Ref::Func(Some(trampoline)))
        .map_err(|e| AfterburnerError::Engine(format!("ffi_prep_closure: table.set: {e}")))?;

    write_u32(&mut caller, closure + CLOSURE_CIF, cif_ptr as u32)?;
    write_u32(&mut caller, closure + CLOSURE_FUN, fun as u32)?;
    write_u32(&mut caller, closure + CLOSURE_USER_DATA, user_data as u32)?;
    pyo_trace!(
        "[ffi] ffi_prep_closure_loc_js closure={closure:#x} fun={fun:#x} codeloc={codeloc} OK"
    );
    Ok(FFI_OK)
}

// ---- wiring -----------------------------------------------------------------

/// Wire the five libffi imports and the three mmap imports into `linker` under
/// `env`. Idempotent against shadowing (the linker is configured with
/// `allow_shadowing`), so this can run on both the 0.28 and 314 boot paths
/// without conflicting with earlier stub definitions.
///
/// Signatures match the 314 `pyodide.asm.wasm` import section exactly:
///   ffi_call_js            (i32,i32,i32,i32) -> ()
///   ffi_closure_alloc_js   (i32,i32)         -> i32
///   ffi_closure_free_js    (i32)             -> ()
///   ffi_prep_closure_loc_js(i32,i32,i32,i32,i32) -> i32
///   _mmap_js   (i32,i32,i32,i32,i64,i32,i32) -> i32
///   _munmap_js (i32,i32,i32,i32,i32,i64)     -> i32
///   _msync_js  (i32,i32,i32,i32,i32,i64)     -> i32
pub fn wire_emscripten_ffi(_engine: &Engine, linker: &mut Linker<EmbedderState>) -> Result<()> {
    linker.allow_shadowing(true);

    macro_rules! def {
        ($name:expr, $func:expr) => {
            linker
                .func_wrap("env", $name, $func)
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        };
    }

    def!("ffi_call_js", ffi_call_js);
    def!("ffi_closure_alloc_js", ffi_closure_alloc_js);
    def!("ffi_closure_free_js", ffi_closure_free_js);
    def!("ffi_prep_closure_loc_js", ffi_prep_closure_loc_js);

    mmap::wire_mmap(linker)?;
    Ok(())
}
