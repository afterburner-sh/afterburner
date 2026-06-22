// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Table-dispatch trampolines for Emscripten: `invoke_*` and Pyodide PyCFunction
//! bridges (`_PyEM_TrampolineCall_JS`, `_PyImport_InitFunc_TrampolineCall`).
//!
//! All functions here share the same dispatch model: `params[0]` is a funcref
//! table index; `params[1..]` are forwarded to the callee. The implementation
//! delegates to [`crate::emscripten_runtime::invoke_dispatch`].

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Engine, FuncType, Linker, ValType};

use crate::{embedder_vm::EmbedderState, emscripten_runtime::invoke_dispatch};

/// Wire all table-dispatch trampolines into `linker`:
///
/// - `_PyEM_TrampolineCall_JS`            (i32, i32, i32, i32) -> i32
/// - `_PyImport_InitFunc_TrampolineCall`  (i32)                -> i32
/// - All `invoke_*` variants (v/i/j/vi/ii/... families)
///
/// Every entry shares `invoke_dispatch`: `params[0]` is the table slot,
/// `params[1..]` are forwarded to the function at that slot.
pub(crate) fn wire_invoke_trampolines(
    engine: &Engine,
    linker: &mut Linker<EmbedderState>,
) -> Result<()> {
    linker.allow_shadowing(true);

    // ---- Pyodide PyCFunction trampolines ------------------------------------
    //
    // Pyodide routes all PyCFunction calls through two JS trampolines to satisfy
    // wasm function-signature strictness. Semantics: params[0] is the funcref
    // table index, params[1..] are forwarded to the callee. This is identical
    // to how the invoke_* trampolines work, so we reuse invoke_dispatch.
    //
    // Wasm signatures (read from the module's import section):
    //   _PyEM_TrampolineCall_JS            (i32, i32, i32, i32) -> i32
    //   _PyImport_InitFunc_TrampolineCall  (i32)                -> i32
    {
        use ValType::I32;
        let trampoline_sigs: &[(&str, &[ValType], &[ValType])] = &[
            ("_PyEM_TrampolineCall_JS", &[I32, I32, I32, I32], &[I32]),
            ("_PyImport_InitFunc_TrampolineCall", &[I32], &[I32]),
        ];
        for &(name, params, results) in trampoline_sigs {
            let ft = FuncType::new(engine, params.iter().cloned(), results.iter().cloned());
            linker
                .func_new("env", name, ft, invoke_dispatch)
                .map_err(|e| AfterburnerError::Engine(format!("{name}: {e}")))?;
        }
    }

    // ---- invoke_* trampolines (data-driven via invoke_dispatch) --------------
    //
    // All invoke_* functions use the same generic `invoke_dispatch` closure:
    // params[0] is the table index, params[1..] are forwarded to the funcref.
    // FuncTypes are built from the signature implied by each name.
    {
        use ValType::{F32, F64, I32, I64};
        // (name, param_types_including_i32_index, result_types)
        let sigs: &[(&str, &[ValType], &[ValType])] = &[
            ("invoke_v", &[I32], &[]),
            ("invoke_i", &[I32], &[I32]),
            ("invoke_j", &[I32], &[I64]),
            ("invoke_vi", &[I32, I32], &[]),
            ("invoke_ii", &[I32, I32], &[I32]),
            ("invoke_ji", &[I32, I32], &[I64]),
            ("invoke_vii", &[I32, I32, I32], &[]),
            ("invoke_iii", &[I32, I32, I32], &[I32]),
            ("invoke_jii", &[I32, I32, I32], &[I64]),
            ("invoke_viii", &[I32, I32, I32, I32], &[]),
            ("invoke_iiii", &[I32, I32, I32, I32], &[I32]),
            ("invoke_jiii", &[I32, I32, I32, I32], &[I64]),
            ("invoke_fiii", &[I32, I32, I32, I32], &[F32]),
            ("invoke_diii", &[I32, I32, I32, I32], &[F64]),
            ("invoke_viiii", &[I32, I32, I32, I32, I32], &[]),
            ("invoke_iiiii", &[I32, I32, I32, I32, I32], &[I32]),
            ("invoke_jiiii", &[I32, I32, I32, I32, I32], &[I64]),
            ("invoke_viiiii", &[I32, I32, I32, I32, I32, I32], &[]),
            ("invoke_iiiiii", &[I32, I32, I32, I32, I32, I32], &[I32]),
            ("invoke_viiiiii", &[I32, I32, I32, I32, I32, I32, I32], &[]),
            (
                "invoke_iiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_viiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32],
                &[],
            ),
            (
                "invoke_iiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_viiiiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32],
                &[],
            ),
            (
                "invoke_iiiiiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_iiiiiiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_iiiiiiiiiiiii",
                &[
                    I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32,
                ],
                &[I32],
            ),
            (
                "invoke_viiiiiiiiiiiiiii",
                &[
                    I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32,
                ],
                &[],
            ),
            ("invoke_iiji", &[I32, I32, I64, I32], &[I32]),
            ("invoke_iiiiij", &[I32, I32, I32, I32, I32, I64], &[I32]),
            (
                "invoke_iiiiijj",
                &[I32, I32, I32, I32, I32, I64, I64],
                &[I32],
            ),
            ("invoke_viid", &[I32, I32, I32, F64], &[]),
            ("invoke_viif", &[I32, I32, I32, F32], &[]),
            ("invoke_viiidi", &[I32, I32, I32, I32, F64, I32], &[]),
            ("invoke_viiifi", &[I32, I32, I32, I32, F32, I32], &[]),
            ("invoke_viijii", &[I32, I32, I32, I64, I32, I32], &[]),
            ("invoke_viijj", &[I32, I32, I32, I64, I64], &[]),
            ("invoke_iiiiid", &[I32, I32, I32, I32, I32, F64], &[I32]),
        ];
        for &(name, params, results) in sigs {
            let ft = FuncType::new(engine, params.iter().cloned(), results.iter().cloned());
            linker
                .func_new("env", name, ft, invoke_dispatch)
                .map_err(|e| AfterburnerError::Engine(format!("{name}: {e}")))?;
        }
    }

    Ok(())
}
