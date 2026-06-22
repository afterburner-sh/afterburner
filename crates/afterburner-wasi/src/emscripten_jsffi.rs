// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! JS-FFI recording trap-stubs for `externref`-bearing Pyodide env.* imports.

use std::sync::Arc;

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Engine, FuncType, Linker, Val, ValType};

use crate::{embedder_vm::EmbedderState, emscripten_runtime::JsFfiCallLog};

/// Wire all `env.*` imports that use `externref` parameters (the JS-FFI bridge).
///
/// Uses `linker.func_new` with an explicit `FuncType` because `func_wrap`
/// cannot express `externref` without the `gc` Cargo feature.
///
/// All stubs record their name via `log` and return safe zero/null defaults.
pub(crate) fn wire_jsffi_stubs(
    engine: &Engine,
    linker: &mut Linker<EmbedderState>,
    log: Arc<JsFfiCallLog>,
) -> Result<()> {
    let ext = ValType::EXTERNREF;
    let i32t = ValType::I32;

    let ft = |params: &[ValType], results: &[ValType]| -> FuncType {
        FuncType::new(engine, params.iter().cloned(), results.iter().cloned())
    };

    macro_rules! jsffi {
        ($name:expr, $func_type:expr) => {{
            let log2 = Arc::clone(&log);
            let name: &'static str = $name;
            linker
                .func_new("env", name, $func_type, move |_caller, _params, results| {
                    log2.record(name);
                    for r in results.iter_mut() {
                        *r = match r {
                            Val::I32(_) => Val::I32(0),
                            Val::I64(_) => Val::I64(0),
                            Val::F32(_) => Val::F32(0),
                            Val::F64(_) => Val::F64(0),
                            Val::ExternRef(_) => Val::ExternRef(None),
                            Val::FuncRef(_) => Val::FuncRef(None),
                            _ => Val::I32(0),
                        };
                    }
                    Ok(())
                })
                .map_err(|e| AfterburnerError::Engine(format!("jsffi {}: {e}", name)))?;
        }};
    }

    // Ground-truth types from wasm-tools dump of pyodide.asm.wasm 0.26.4.

    let ty = ft(std::slice::from_ref(&ext), std::slice::from_ref(&i32t));
    for name in &[
        "JsvArray_Check",
        "JsvFunction_Check",
        "JsvGenerator_Check",
        "JsvAsyncGenerator_Check",
        "JsvPromise_Check",
        "JsvNoValue_Check",
        "Jsv_to_bool",
        "JsProxy_Bool_js",
        "JsProxy_compute_typeflags",
        "JsDoubleProxy_unwrap_helper",
        "JsArray_reverse_js",
        "JsMap_clear_js",
        "get_length_helper",
        "get_length_string",
        "JsObjMap_length_js",
        "Jsv_constructorName",
        "pyproxy_AsPyObject",
        "pyproxy_Check",
        "is_comlink_proxy",
        "js2python_immutable_js",
        "js2python_js",
        "destroy_proxies_js",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(std::slice::from_ref(&ext), &[]);
    for name in &[
        "JsvError_Throw",
        "raw_call_js",
        "set_pyodide_module",
        "set_suspender",
        "restoreState",
        "gc_register_proxies",
        "destroy_jsarray_entries",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(std::slice::from_ref(&ext), std::slice::from_ref(&ext));
    for name in &[
        "JsvArray_ShallowCopy",
        "JsProxy_Dir_js",
        "JsProxy_GetAsyncIter_js",
        "JsProxy_GetIter_js",
        "JsMap_GetIter_js",
        "JsObjMap_GetIter_js",
        "JsvObject_toString",
        "JsvObject_Entries",
        "JsvObject_Keys",
        "JsvObject_Values",
        "Jsv_typeof",
        "JsArray_reversed_iterator",
        "JsvPromise_Resolve",
        "get_async_js_call_done_callback",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[], std::slice::from_ref(&ext));
    for name in &[
        "JsvArray_New",
        "JsvMap_New",
        "JsvObject_New",
        "JsvSet_New",
        "JsvLiteralMap_New",
        "get_suspender",
        "restore_stderr",
        "saveState",
        "my_dict_converter",
        "__hiwire_deduplicate_new",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[ext.clone(), ext.clone()], std::slice::from_ref(&i32t));
    for name in &[
        "Jsv_less_than",
        "Jsv_less_than_equal",
        "Jsv_greater_than",
        "Jsv_greater_than_equal",
        "Jsv_equal",
        "Jsv_not_equal",
        "JsvArray_Push",
        "JsObjMap_contains_js",
        "JsArray_count_js",
        "JsvSet_Add",
        "__hiwire_deduplicate_get",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[ext.clone(), ext.clone()], &[]);
    for name in &[
        "JsvArray_Extend",
        "__hiwire_deduplicate_delete",
        "_python2js_handle_postprocess_list",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[ext.clone(), ext.clone()], std::slice::from_ref(&ext));
    for name in &[
        "JsProxy_subscript_js",
        "JsObjMap_subscript_js",
        "syncifyHandler",
        "wrap_generator",
        "wrap_async_generator",
        "JsvFunction_Call_OneArg",
        "JsvObject_CallMethod_NoArgs",
        "JsvFunction_Construct",
        "_JsArray_PostProcess_helper",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[ext.clone(), i32t.clone()], std::slice::from_ref(&ext));
    for name in &[
        "JsvArray_Get",
        "JsvArray_Delete",
        "JsProxy_GetAttr_js",
        "JsBuffer_DecodeString_js",
        "JsArray_repeat_js",
        "proxy_cache_get",
        "python2js__default_converter_js",
        "_python2js_cache_lookup",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[ext.clone(), i32t.clone()], std::slice::from_ref(&i32t));
    for name in &[
        "JsvBuffer_assignToPtr",
        "JsvBuffer_assignFromPtr",
        "JsvBuffer_intoFile",
        "JsvBuffer_readFromFile",
        "JsvBuffer_writeToFile",
        "JsArray_inplace_repeat_js",
        "JsProxy_DelAttr_js",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[ext.clone(), i32t.clone()], &[]);
    for name in &["destroy_proxy", "destroy_proxies"] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(
        &[ext.clone(), ext.clone(), ext.clone()],
        std::slice::from_ref(&i32t),
    );
    for name in &[
        "JsObjMap_ass_subscript_js",
        "JsvMap_Set",
        "JsvObject_SetAttr",
        "_JsArray_PushEntry_helper",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(
        &[ext.clone(), ext.clone(), ext.clone()],
        std::slice::from_ref(&ext),
    );
    for name in &[
        "JsvFunction_CallBound",
        "JsvObject_CallMethod_OneArg",
        "JsvObject_CallMethod",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(
        &[ext.clone(), ext.clone(), ext.clone(), ext.clone()],
        std::slice::from_ref(&ext),
    );
    jsffi!("JsvObject_CallMethod_TwoArgs", ty);

    let ty = ft(&[i32t.clone(), i32t.clone()], std::slice::from_ref(&ext));
    for name in &[
        "create_once_callable",
        "JsvNum_fromDigits",
        "_python2js_ucs1",
        "_python2js_ucs2",
        "_python2js_ucs4",
        "array_to_js",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(
        &[i32t.clone(), i32t.clone(), i32t.clone()],
        std::slice::from_ref(&ext),
    );
    jsffi!("JsException_new_helper", ty);

    let ty = ft(
        &[ext.clone(), i32t.clone(), ext.clone()],
        std::slice::from_ref(&i32t),
    );
    for name in &[
        "JsProxy_SetAttr_js",
        "JsvArray_Set",
        "JsvArray_Insert",
        "js2python_convert",
        "_python2js_add_to_cache",
    ] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(
        &[i32t.clone(), ext.clone(), i32t.clone()],
        std::slice::from_ref(&ext),
    );
    jsffi!("new_error", ty);

    let ty = ft(
        &[i32t.clone(), i32t.clone(), ext.clone(), i32t.clone()],
        std::slice::from_ref(&ext),
    );
    jsffi!("create_promise_handles", ty);

    let ty = ft(
        &[ext.clone(), i32t.clone(), i32t.clone()],
        std::slice::from_ref(&ext),
    );
    jsffi!("handle_next_result_js", ty);

    let ty = ft(
        &[
            ext.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
        ],
        std::slice::from_ref(&i32t),
    );
    jsffi!("_agen_handle_result_js", ty);

    let ty = ft(
        &[
            ext.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
        ],
        &[],
    );
    jsffi!("JsBuffer_get_info", ty);

    let ty = ft(
        &[
            ext.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
        ],
        std::slice::from_ref(&ext),
    );
    jsffi!("JsvArray_slice", ty);

    let ty = ft(
        &[
            ext.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
        ],
        std::slice::from_ref(&i32t),
    );
    jsffi!("JsvArray_slice_assign", ty);

    let ty = ft(
        &[ext.clone(), ext.clone(), i32t.clone(), i32t.clone()],
        std::slice::from_ref(&i32t),
    );
    jsffi!("JsArray_index_js", ty);

    let ty = ft(std::slice::from_ref(&i32t), std::slice::from_ref(&ext));
    for name in &["JsvUTF8ToString", "JsvNum_fromInt", "pyproxy_new"] {
        jsffi!(*name, ty.clone());
    }

    let ty = ft(&[ValType::F64], std::slice::from_ref(&ext));
    jsffi!("JsvNum_fromDouble", ty);

    let ty = ft(&[ext.clone(), ext.clone(), i32t.clone()], &[]);
    jsffi!("__hiwire_deduplicate_set", ty);

    let ty = ft(&[ext.clone(), i32t.clone(), ext.clone()], &[]);
    jsffi!("proxy_cache_set", ty);

    let ty = ft(&[ext.clone(), ext.clone(), ext.clone(), i32t.clone()], &[]);
    jsffi!("_python2js_addto_postprocess_list", ty);

    let ty = ft(
        &[i32t.clone(), ext.clone(), ext.clone(), ext.clone()],
        std::slice::from_ref(&ext),
    );
    jsffi!("python2js_custom__create_jscontext", ty);

    let ty = ft(
        &[
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
        ],
        std::slice::from_ref(&ext),
    );
    jsffi!("pyproxy_new_ex", ty);

    let ty = ft(
        &[
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
        ],
        std::slice::from_ref(&ext),
    );
    jsffi!("_python2js_buffer_inner", ty);

    let ty = ft(&[i32t.clone(), ext.clone()], std::slice::from_ref(&ext));
    jsffi!("_pyproxyGen_make_result", ty);

    let ty = ft(
        &[
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            ext.clone(),
            ext.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
            i32t.clone(),
        ],
        std::slice::from_ref(&ext),
    );
    jsffi!("_pyproxy_get_buffer_result", ty);

    Ok(())
}
