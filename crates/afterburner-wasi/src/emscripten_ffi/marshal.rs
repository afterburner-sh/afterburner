// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Argument and return-value marshalling between the C ABI (guest linear
//! memory) and wasm [`Val`]s, plus the C->guest closure trampoline runner.
//!
//! This is a direct port of the type switches in libffi's wasm32 `ffi.c`
//! (`ffi_call_js` and the `trampoline` inside `ffi_prep_closure_loc_js`). Each C
//! value is read from / written to guest memory exactly as the reference does;
//! the only difference is the dispatch target (a wasmtime funcref instead of a
//! JS `getWasmTableEntry(...).apply`).

use wasmtime::{Caller, Ref, Val, ValType};

use afterburner_core::AfterburnerError;

use super::{
    CIF_ARGTYPES, CIF_FLAGS, CIF_NARGS, CIF_NFIXEDARGS, CIF_RTYPE, EmbedderState, FFI_TYPE_COMPLEX,
    FFI_TYPE_DOUBLE, FFI_TYPE_FLOAT, FFI_TYPE_INT, FFI_TYPE_POINTER, FFI_TYPE_SINT8,
    FFI_TYPE_SINT16, FFI_TYPE_SINT32, FFI_TYPE_SINT64, FFI_TYPE_STRUCT, FFI_TYPE_UINT8,
    FFI_TYPE_UINT16, FFI_TYPE_UINT32, FFI_TYPE_UINT64, FFI_TYPE_VOID, TYPE_ALIGN, TYPE_ELEMENTS,
    TYPE_SIZE, TYPE_TYPEID, guest_free, guest_malloc, mem_read, mem_write, read_u16, read_u32,
    write_u32,
};

type WtResult<T> = wasmtime::Result<T>;

/// Max struct-unbox depth before [`ArgType::resolve`] rejects the type. The
/// ffi_type graph lives in guest memory, so a cyclic single-field struct
/// (`first -> ... -> itself`) would otherwise spin the host forever; no
/// legitimate struct nests anywhere near this deep.
const MAX_STRUCT_UNBOX_DEPTH: u32 = 32;

/// A resolved `ffi_type`: the (possibly unboxed) type pointer, its type id, and
/// its size/alignment. On wasm32 `long double` shares the id 3 with `double`, so
/// [`Self::is_long_double`] records whether the original (pre-unbox) type was a
/// long double for return-by-argument purposes.
#[derive(Clone, Copy, Debug)]
pub(super) struct ArgType {
    pub id: u16,
    pub size: u32,
    pub align: u16,
    /// True when the original cif type was `long double` (16 bytes). wasm32
    /// folds the id into `double`, so this flag preserves the distinction the
    /// reference makes via `rtype_id === FFI_TYPE_LONGDOUBLE`.
    pub is_long_double: bool,
}

impl ArgType {
    /// Resolve and unbox the `ffi_type` at guest pointer `type_ptr`, following
    /// libffi's `unbox_small_structs`: a struct of size <= 16 with a single
    /// non-null element is replaced by that element (recursively); a 0-element
    /// struct becomes VOID.
    fn resolve(caller: &Caller<'_, EmbedderState>, type_ptr: u32) -> WtResult<ArgType> {
        let mut tp = type_ptr;
        let mut id = read_u16(caller, tp + TYPE_TYPEID)?;
        let orig_size = read_u32(caller, tp + TYPE_SIZE)?;
        // long double on wasm32 is a 16-byte type whose id reads back as DOUBLE
        // (3); detect it by the size so return-by-arg logic stays correct.
        let is_long_double = id == FFI_TYPE_DOUBLE && orig_size == 16;

        let mut depth = 0u32;
        while id == FFI_TYPE_STRUCT {
            depth += 1;
            if depth > MAX_STRUCT_UNBOX_DEPTH {
                return Err(AfterburnerError::Engine(
                    "ffi: struct unbox exceeded max depth (cyclic or malicious ffi_type)".into(),
                )
                .into());
            }
            let size = read_u32(caller, tp + TYPE_SIZE)?;
            if size > 16 {
                break;
            }
            let elements = read_u32(caller, tp + TYPE_ELEMENTS)?;
            if elements == 0 {
                id = FFI_TYPE_VOID;
                break;
            }
            let first = read_u32(caller, elements)?;
            let second = read_u32(caller, elements + 4)?;
            if first == 0 {
                id = FFI_TYPE_VOID;
                break;
            } else if second == 0 {
                tp = first;
                id = read_u16(caller, tp + TYPE_TYPEID)?;
            } else {
                break;
            }
        }

        let size = read_u32(caller, tp + TYPE_SIZE)?;
        let align = read_u16(caller, tp + TYPE_ALIGN)?;
        Ok(ArgType {
            id,
            size,
            align,
            is_long_double,
        })
    }
}

/// A parsed `ffi_cif`: the fields needed to marshal a call. Mirrors the
/// `CIF__*` macro reads in the reference.
#[derive(Clone, Debug)]
pub(super) struct Cif {
    pub nargs: u32,
    pub nfixedargs: u32,
    pub flags: u32,
    arg_types_ptr: u32,
    pub rtype: ArgType,
}

impl Cif {
    /// Read and parse the cif at guest pointer `cif_ptr`.
    pub(super) fn read(caller: &Caller<'_, EmbedderState>, cif_ptr: u32) -> WtResult<Cif> {
        let nargs = read_u32(caller, cif_ptr + CIF_NARGS)?;
        let nfixedargs = read_u32(caller, cif_ptr + CIF_NFIXEDARGS)?;
        let flags = read_u32(caller, cif_ptr + CIF_FLAGS)?;
        let arg_types_ptr = read_u32(caller, cif_ptr + CIF_ARGTYPES)?;
        let rtype_ptr = read_u32(caller, cif_ptr + CIF_RTYPE)?;
        let rtype = ArgType::resolve(caller, rtype_ptr)?;
        Ok(Cif {
            nargs,
            nfixedargs,
            flags,
            arg_types_ptr,
            rtype,
        })
    }

    /// Resolve the `i`th argument type (`arg_types[i]`), unboxed.
    pub(super) fn arg_type(&self, caller: &Caller<'_, EmbedderState>, i: u32) -> WtResult<ArgType> {
        let type_ptr = read_u32(caller, self.arg_types_ptr + i * 4)?;
        ArgType::resolve(caller, type_ptr)
    }
}

// ---- C value -> wasm Val (ffi_call argument marshalling) --------------------

/// Marshal one C argument at guest pointer `arg_ptr` (the value, per its type)
/// into a wasm [`Val`] appended to `args`. Struct-by-value arguments are copied
/// onto a fresh guest allocation recorded in `scratch` (freed by the caller),
/// matching the reference's "copy onto the stack" with a malloc'd region.
pub(super) fn push_arg(
    caller: &mut Caller<'_, EmbedderState>,
    at: &ArgType,
    arg_ptr: u32,
    args: &mut Vec<Val>,
    scratch: &mut Vec<u32>,
) -> WtResult<()> {
    match at.id {
        FFI_TYPE_INT | FFI_TYPE_SINT32 | FFI_TYPE_UINT32 => {
            args.push(Val::I32(read_u32(caller, arg_ptr)? as i32));
        }
        FFI_TYPE_POINTER => {
            args.push(Val::I32(read_u32(caller, arg_ptr)? as i32));
        }
        FFI_TYPE_FLOAT => {
            // wasmtime `Val::F32` carries the raw f32 BITS as a u32.
            let bits = read_u32(caller, arg_ptr)?;
            args.push(Val::F32(bits));
        }
        FFI_TYPE_DOUBLE => {
            // `Val::F64` carries the raw f64 BITS as a u64. Covers `long double`
            // on wasm32 (size 16): the onward call takes the low 8 bytes as the
            // double then 8 more bytes which the reference passes as a second
            // BigInt; we push the low half as F64 bits plus the high half as i64.
            let lo = read_u64(caller, arg_ptr)?;
            if at.is_long_double {
                let hi = read_u64(caller, arg_ptr + 8)?;
                args.push(Val::I64(lo as i64));
                args.push(Val::I64(hi as i64));
            } else {
                args.push(Val::F64(lo));
            }
        }
        FFI_TYPE_UINT8 => args.push(Val::I32(mem_read(caller, arg_ptr, 1)?[0] as i32)),
        FFI_TYPE_SINT8 => args.push(Val::I32(mem_read(caller, arg_ptr, 1)?[0] as i8 as i32)),
        FFI_TYPE_UINT16 => args.push(Val::I32(read_u16(caller, arg_ptr)? as i32)),
        FFI_TYPE_SINT16 => args.push(Val::I32(read_u16(caller, arg_ptr)? as i16 as i32)),
        FFI_TYPE_UINT64 | FFI_TYPE_SINT64 => {
            args.push(Val::I64(read_u64(caller, arg_ptr)? as i64));
        }
        FFI_TYPE_STRUCT => {
            // Non-trivial struct: pass by pointer, but the C ABI is by value, so
            // copy the bytes onto a fresh guest region and pass that pointer.
            let size = at.size;
            let buf = mem_read(caller, arg_ptr, size as usize)?;
            let dst = guest_malloc(caller, size.max(1))?;
            if dst == 0 {
                return Err(
                    AfterburnerError::Engine("ffi_call: struct copy malloc failed".into()).into(),
                );
            }
            mem_write(caller, dst, &buf)?;
            scratch.push(dst);
            args.push(Val::I32(dst as i32));
        }
        FFI_TYPE_COMPLEX => {
            return Err(AfterburnerError::Engine("ffi_call: complex arg nyi".into()).into());
        }
        other => {
            return Err(
                AfterburnerError::Engine(format!("ffi_call: unexpected arg type {other}")).into(),
            );
        }
    }
    Ok(())
}

/// Read a little-endian u64 from guest memory.
pub(super) fn read_u64(caller: &Caller<'_, EmbedderState>, ptr: u32) -> WtResult<u64> {
    let b = mem_read(caller, ptr, 8)?;
    // `mem_read` returned exactly 8 bytes; convert without a panicking unwrap.
    let arr: [u8; 8] = b
        .try_into()
        .map_err(|_| AfterburnerError::Engine("ffi: short u64 read".into()))?;
    Ok(u64::from_le_bytes(arr))
}

/// Pack variadic arguments (`avalue[nfixedargs..nargs]`) into a fresh guest
/// region and return its pointer, mirroring the reference's separate varargs
/// stack. Only the scalar/pointer cases the import path can hit are packed; a
/// by-value struct vararg is unsupported (the import path never uses it).
pub(super) fn pack_varargs(
    caller: &mut Caller<'_, EmbedderState>,
    cif: &Cif,
    avalue: u32,
    scratch: &mut Vec<u32>,
) -> WtResult<u32> {
    // Compute the total packed size first (8 bytes per slot is a safe upper
    // bound for every scalar; structs are rejected). Allocate once.
    let n = cif.nargs.saturating_sub(cif.nfixedargs);
    let size = (n as u64 * 16).max(16) as u32;
    let base = guest_malloc(caller, size)?;
    if base == 0 {
        return Err(AfterburnerError::Engine("ffi_call: varargs malloc failed".into()).into());
    }
    scratch.push(base);

    let mut cur = base;
    for i in cif.nfixedargs..cif.nargs {
        let arg_ptr = read_u32(caller, avalue + i * 4)?;
        let at = cif.arg_type(caller, i)?;
        match at.id {
            FFI_TYPE_UINT8 | FFI_TYPE_SINT8 => {
                let v = mem_read(caller, arg_ptr, 1)?;
                mem_write(caller, cur, &v)?;
                cur += 1;
            }
            FFI_TYPE_UINT16 | FFI_TYPE_SINT16 => {
                let v = mem_read(caller, arg_ptr, 2)?;
                mem_write(caller, cur, &v)?;
                cur += 2;
            }
            FFI_TYPE_INT | FFI_TYPE_UINT32 | FFI_TYPE_SINT32 | FFI_TYPE_FLOAT
            | FFI_TYPE_POINTER => {
                let v = mem_read(caller, arg_ptr, 4)?;
                mem_write(caller, cur, &v)?;
                cur += 4;
            }
            FFI_TYPE_DOUBLE | FFI_TYPE_UINT64 | FFI_TYPE_SINT64 => {
                let v = mem_read(caller, arg_ptr, 8)?;
                mem_write(caller, cur, &v)?;
                cur += 8;
            }
            other => {
                return Err(AfterburnerError::Engine(format!(
                    "ffi_call: unsupported vararg type {other}"
                ))
                .into());
            }
        }
    }
    Ok(base)
}

// ---- wasm Val -> C value (ffi_call return marshalling) ----------------------

/// Write the scalar wasm result `result` into the C return slot `rvalue` per the
/// return type. Mirrors the reference's return switch. Struct / long-double
/// returns are handled by the caller (return-by-argument) and never reach here.
pub(super) fn store_return(
    caller: &mut Caller<'_, EmbedderState>,
    rtype: &ArgType,
    result: &Val,
    rvalue: u32,
) -> WtResult<()> {
    match rtype.id {
        FFI_TYPE_VOID => {}
        FFI_TYPE_INT | FFI_TYPE_UINT32 | FFI_TYPE_SINT32 | FFI_TYPE_POINTER => {
            write_u32(caller, rvalue, as_i32(result)? as u32)?;
        }
        FFI_TYPE_FLOAT => {
            // `Val::F32` is the raw f32 bits (u32).
            let bits = match result {
                Val::F32(b) => *b,
                Val::I32(i) => *i as u32,
                _ => return Err(type_err("float return")),
            };
            mem_write(caller, rvalue, &bits.to_le_bytes())?;
        }
        FFI_TYPE_DOUBLE => {
            // `Val::F64` is the raw f64 bits (u64).
            let bits = match result {
                Val::F64(b) => *b,
                Val::I64(i) => *i as u64,
                _ => return Err(type_err("double return")),
            };
            mem_write(caller, rvalue, &bits.to_le_bytes())?;
        }
        FFI_TYPE_UINT8 | FFI_TYPE_SINT8 => {
            mem_write(caller, rvalue, &[(as_i32(result)? as u8)])?;
        }
        FFI_TYPE_UINT16 | FFI_TYPE_SINT16 => {
            mem_write(caller, rvalue, &(as_i32(result)? as u16).to_le_bytes())?;
        }
        FFI_TYPE_UINT64 | FFI_TYPE_SINT64 => {
            mem_write(caller, rvalue, &as_i64(result)?.to_le_bytes())?;
        }
        FFI_TYPE_COMPLEX => return Err(type_err("complex return")),
        other => {
            return Err(
                AfterburnerError::Engine(format!("ffi_call: unexpected rtype {other}")).into(),
            );
        }
    }
    Ok(())
}

fn as_i32(v: &Val) -> WtResult<i32> {
    match v {
        Val::I32(i) => Ok(*i),
        Val::I64(i) => Ok(*i as i32),
        _ => Err(type_err("expected i32 result")),
    }
}

fn as_i64(v: &Val) -> WtResult<i64> {
    match v {
        Val::I64(i) => Ok(*i),
        Val::I32(i) => Ok(*i as i64),
        _ => Err(type_err("expected i64 result")),
    }
}

fn type_err(what: &str) -> wasmtime::Error {
    AfterburnerError::Engine(format!("ffi_call: {what}")).into()
}

// ---- closure trampoline -----------------------------------------------------

/// One closure argument's marshalling info, precomputed at prep time so the hot
/// trampoline does no cif re-parsing.
#[derive(Clone, Copy, Debug)]
struct ClosureArg {
    id: u16,
    size: u32,
    align: u16,
}

/// The precomputed plan for a closure: the wasm signature the guest calls us
/// with, plus per-argument info to rebuild the C `avalue` frame. Built once in
/// `ffi_prep_closure_loc_js`; captured by the host trampoline.
#[derive(Clone, Debug)]
pub(super) struct ClosurePlan {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
    args: Vec<ClosureArg>,
    nfixedargs: u32,
    /// The closure returns via a leading pointer argument (struct / long double).
    ret_by_arg: bool,
    /// Scalar return kind for reading the C return slot back into a wasm result.
    ret_id: u16,
    ret_is_long_double: bool,
}

impl ClosurePlan {
    /// Build the trampoline signature and marshalling plan from the cif, exactly
    /// as the reference constructs `sig` and the unboxed arg-type lists. Errors
    /// (an unsupported type) map to `FFI_BAD_TYPEDEF` by the caller.
    pub(super) fn build(caller: &Caller<'_, EmbedderState>, cif: &Cif) -> WtResult<ClosurePlan> {
        let mut params: Vec<ValType> = Vec::new();
        let mut results: Vec<ValType> = Vec::new();

        let ret_by_arg = matches!(cif.rtype.id, FFI_TYPE_STRUCT) || cif.rtype.is_long_double;
        match cif.rtype.id {
            FFI_TYPE_VOID => {}
            FFI_TYPE_STRUCT => params.push(ValType::I32), // leading rvalue pointer
            _ if cif.rtype.is_long_double => params.push(ValType::I32),
            FFI_TYPE_INT | FFI_TYPE_UINT8 | FFI_TYPE_SINT8 | FFI_TYPE_UINT16 | FFI_TYPE_SINT16
            | FFI_TYPE_UINT32 | FFI_TYPE_SINT32 => results.push(ValType::I32),
            FFI_TYPE_POINTER => results.push(ValType::I32),
            FFI_TYPE_FLOAT => results.push(ValType::F32),
            FFI_TYPE_DOUBLE => results.push(ValType::F64),
            FFI_TYPE_UINT64 | FFI_TYPE_SINT64 => results.push(ValType::I64),
            other => {
                return Err(
                    AfterburnerError::Engine(format!("closure: unexpected rtype {other}")).into(),
                );
            }
        }

        let mut args: Vec<ClosureArg> = Vec::with_capacity(cif.nargs as usize);
        for i in 0..cif.nargs {
            let at = cif.arg_type(caller, i)?;
            args.push(ClosureArg {
                id: at.id,
                size: at.size,
                align: at.align,
            });
        }
        for arg in args.iter().take(cif.nfixedargs as usize) {
            match arg.id {
                FFI_TYPE_INT | FFI_TYPE_UINT8 | FFI_TYPE_SINT8 | FFI_TYPE_UINT16
                | FFI_TYPE_SINT16 | FFI_TYPE_UINT32 | FFI_TYPE_SINT32 => params.push(ValType::I32),
                FFI_TYPE_FLOAT => params.push(ValType::F32),
                FFI_TYPE_DOUBLE => params.push(ValType::F64),
                FFI_TYPE_UINT64 | FFI_TYPE_SINT64 => params.push(ValType::I64),
                FFI_TYPE_STRUCT | FFI_TYPE_POINTER => params.push(ValType::I32),
                other => {
                    return Err(AfterburnerError::Engine(format!(
                        "closure: unexpected argtype {other}"
                    ))
                    .into());
                }
            }
        }
        if cif.nfixedargs < cif.nargs {
            params.push(ValType::I32); // pointer to varargs region
        }

        Ok(ClosurePlan {
            params,
            results,
            args,
            nfixedargs: cif.nfixedargs,
            ret_by_arg,
            ret_id: cif.rtype.id,
            ret_is_long_double: cif.rtype.is_long_double,
        })
    }
}

/// The C->guest closure trampoline body: called by the guest with the closure's
/// C signature, it rebuilds the libffi `(cif, rvalue, avalue, user_data)` frame
/// in guest memory and dispatches to the closure body `fun` through the table,
/// then reads the C return slot back into the wasm `results`.
///
/// Mirrors the JS `trampoline` in the reference, but allocates the argument
/// frame from the guest allocator instead of poking the C stack pointer, which
/// is unsafe to do from a host activation while a guest frame is live. The frame
/// is freed before return.
pub(super) fn run_closure(
    caller: &mut Caller<'_, EmbedderState>,
    closure: u32,
    plan: &ClosurePlan,
    params: &[Val],
    results: &mut [Val],
) -> WtResult<()> {
    use super::{CLOSURE_CIF, CLOSURE_FUN, CLOSURE_USER_DATA};

    let cif_ptr = read_u32(caller, closure + CLOSURE_CIF)?;
    let fun_idx = read_u32(caller, closure + CLOSURE_FUN)?;
    let user_data = read_u32(caller, closure + CLOSURE_USER_DATA)?;

    let nargs = plan.args.len() as u32;
    let mut scratch: Vec<u32> = Vec::new();

    // Allocate the avalue pointer array (nargs * 4) and the return slot (8).
    let args_ptr = if nargs > 0 {
        let p = guest_malloc(caller, nargs * 4)?;
        if p == 0 {
            return Err(AfterburnerError::Engine("closure: avalue malloc failed".into()).into());
        }
        scratch.push(p);
        p
    } else {
        0
    };

    // Return slot: reuse the caller-provided pointer for ret-by-arg, else a
    // fresh 8-byte region we read back from.
    let mut jsarg = 0usize;
    let ret_ptr = if plan.ret_by_arg {
        let p = as_u32(&params[jsarg])?;
        jsarg += 1;
        p
    } else {
        let p = guest_malloc(caller, 8)?;
        if p == 0 {
            for s in &scratch {
                let _ = guest_free(caller, *s);
            }
            return Err(AfterburnerError::Engine("closure: ret malloc failed".into()).into());
        }
        scratch.push(p);
        p
    };

    // For each fixed C argument, allocate a slot holding the value and store its
    // pointer into args_ptr[i]. (The guest passed us already-converted scalars.)
    let mut carg = 0u32;
    while carg < plan.nfixedargs {
        let arg = plan.args[carg as usize];
        let cur = params[jsarg];
        jsarg += 1;
        let slot = match arg.id {
            FFI_TYPE_UINT8 | FFI_TYPE_SINT8 => {
                let p = guest_malloc(caller, 4)?;
                scratch.push(p);
                mem_write(caller, p, &[(as_u32(&cur)? as u8)])?;
                p
            }
            FFI_TYPE_UINT16 | FFI_TYPE_SINT16 => {
                let p = guest_malloc(caller, 4)?;
                scratch.push(p);
                mem_write(caller, p, &(as_u32(&cur)? as u16).to_le_bytes())?;
                p
            }
            FFI_TYPE_INT | FFI_TYPE_UINT32 | FFI_TYPE_SINT32 | FFI_TYPE_POINTER => {
                let p = guest_malloc(caller, 4)?;
                scratch.push(p);
                write_u32(caller, p, as_u32(&cur)?)?;
                p
            }
            FFI_TYPE_FLOAT => {
                let p = guest_malloc(caller, 4)?;
                scratch.push(p);
                let bits = match cur {
                    Val::F32(b) => b, // raw f32 bits
                    Val::I32(i) => i as u32,
                    _ => return Err(type_err("closure float arg")),
                };
                mem_write(caller, p, &bits.to_le_bytes())?;
                p
            }
            FFI_TYPE_DOUBLE => {
                let p = guest_malloc(caller, 8)?;
                scratch.push(p);
                let bits = match cur {
                    Val::F64(b) => b, // raw f64 bits
                    Val::I64(i) => i as u64,
                    _ => return Err(type_err("closure double arg")),
                };
                mem_write(caller, p, &bits.to_le_bytes())?;
                p
            }
            FFI_TYPE_UINT64 | FFI_TYPE_SINT64 => {
                let p = guest_malloc(caller, 8)?;
                scratch.push(p);
                mem_write(caller, p, &as_u64(&cur)?.to_le_bytes())?;
                p
            }
            FFI_TYPE_STRUCT => {
                // cur is a pointer to the struct; copy it by value into a slot.
                let src = as_u32(&cur)?;
                let bytes = mem_read(caller, src, arg.size as usize)?;
                let p = guest_malloc(caller, arg.size.max(1))?;
                scratch.push(p);
                mem_write(caller, p, &bytes)?;
                p
            }
            other => {
                for s in &scratch {
                    let _ = guest_free(caller, *s);
                }
                return Err(AfterburnerError::Engine(format!(
                    "closure: unexpected fixed argtype {other}"
                ))
                .into());
            }
        };
        let _ = arg.align; // alignment is satisfied by malloc (>= 8-byte aligned)
        write_u32(caller, args_ptr + carg * 4, slot)?;
        carg += 1;
    }

    // Varargs: the guest passed a single trailing pointer to the packed region;
    // walk it, storing a pointer per remaining arg into args_ptr.
    if plan.nfixedargs < nargs {
        let mut varargs = as_u32(&params[params.len() - 1])?;
        while carg < nargs {
            let arg = plan.args[carg as usize];
            if arg.id == FFI_TYPE_STRUCT {
                let struct_ptr = read_u32(caller, varargs)?;
                let bytes = mem_read(caller, struct_ptr, arg.size as usize)?;
                let p = guest_malloc(caller, arg.size.max(1))?;
                scratch.push(p);
                mem_write(caller, p, &bytes)?;
                write_u32(caller, args_ptr + carg * 4, p)?;
            } else {
                write_u32(caller, args_ptr + carg * 4, varargs)?;
            }
            varargs += 4;
            carg += 1;
        }
    }

    // Dispatch to the closure body: fun(cif, ret_ptr, args_ptr, user_data).
    let table = caller
        .data()
        .pyodide_table
        .ok_or_else(|| AfterburnerError::Engine("closure: no guest table".into()))?;
    let fun = match table.get(&mut *caller, fun_idx as u64) {
        Some(Ref::Func(Some(f))) => f,
        _ => {
            for s in &scratch {
                let _ = guest_free(caller, *s);
            }
            return Err(AfterburnerError::Engine(format!(
                "closure: null funcref at table[{fun_idx}]"
            ))
            .into());
        }
    };
    let call_res = fun.call(
        &mut *caller,
        &[
            Val::I32(cif_ptr as i32),
            Val::I32(ret_ptr as i32),
            Val::I32(args_ptr as i32),
            Val::I32(user_data as i32),
        ],
        &mut [],
    );

    // Read the return slot back into wasm results BEFORE freeing scratch (the
    // ret slot for the non-ret-by-arg path lives in scratch).
    let read_res = (|| -> WtResult<()> {
        if plan.ret_by_arg || results.is_empty() {
            return Ok(());
        }
        results[0] = match plan.ret_id {
            // F32/F64 carry the raw bits (u32 / u64) in wasmtime's Val.
            FFI_TYPE_FLOAT => Val::F32(read_u32(caller, ret_ptr)?),
            FFI_TYPE_DOUBLE if !plan.ret_is_long_double => Val::F64(read_u64(caller, ret_ptr)?),
            FFI_TYPE_UINT64 | FFI_TYPE_SINT64 => Val::I64(read_u64(caller, ret_ptr)? as i64),
            _ => Val::I32(read_u32(caller, ret_ptr)? as i32),
        };
        Ok(())
    })();

    for s in scratch {
        let _ = guest_free(caller, s);
    }
    call_res?;
    read_res
}

fn as_u32(v: &Val) -> WtResult<u32> {
    match v {
        Val::I32(i) => Ok(*i as u32),
        Val::I64(i) => Ok(*i as u32),
        _ => Err(type_err("expected i32 closure arg")),
    }
}

fn as_u64(v: &Val) -> WtResult<u64> {
    match v {
        Val::I64(i) => Ok(*i as u64),
        Val::I32(i) => Ok(*i as u32 as u64),
        _ => Err(type_err("expected i64 closure arg")),
    }
}
