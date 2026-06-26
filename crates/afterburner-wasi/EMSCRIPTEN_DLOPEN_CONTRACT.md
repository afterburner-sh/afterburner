# Emscripten dynamic-linker contract (for headless side-module dlopen)

Extracted from the Emscripten source (`~/projects/emscripten/src/lib/libdylink.js`
+ `src/struct_info_generated.json`). This is the byte-exact contract our host must
implement so CPython's `import numpy` -> the wasm `dlopen`/`dlsym` -> our env imports
load + resolve the side module (`_multiarray_umath.*.so`). No JS, headless.

## The `dso` handle struct (wasm32, `__size__` = 36)

The wasm `dlopen` passes a pointer to a `dso` struct. Field offsets:

| field            | offset |
|------------------|--------|
| (refcount/list)  | 0      |
| `flags`          | 4      |
| `mem_allocated`  | 8      |
| `mem_addr`       | 12     |
| `mem_size`       | 16     |
| `table_addr`     | 20     |
| `table_size`     | 24     |
| `file_data`      | 28     |
| `file_data_size` | 32     |
| `name`           | 36     |  <- NUL-terminated path string starts at `handle + 36`

## `_dlopen_js(handle: i32) -> i32`

Non-ASYNCIFY path = `dlopenInternal(handle, {loadAsync: false})`:
1. `filename = read_cstr(pyodide_memory, handle + 36)` (dso.name). `PATH.normalize` it.
2. `flags = i32 at handle + 4` (RTLD_* - we can ignore NOW/LAZY).
3. Load the side module from the MEMFS file `filename` via the existing side-module
   loader (parse `dylink.0`, `malloc(mem_size)` -> memory_base, grow table by
   table_size -> table_base, instantiate sharing the main memory + table, run
   `__wasm_apply_data_relocs` then `__wasm_call_ctors`). Reuse if already loaded
   (key by normalized name).
4. Write the assigned bases back into the struct: `mem_addr` (handle+12) = memory_base,
   `table_addr` (handle+20) = table_base.
5. Register `handle -> loaded module` (with its export-name -> table-slot map) in an
   LDSO-like registry (also by name).
6. Return `handle` on success; on failure call `dlSetError` + return 0.

## `_dlsym_js(handle: i32, symbol: i32, symbolIndex: i32) -> i32`

1. `name = read_cstr(pyodide_memory, symbol)`.
2. `lib = registry.by_handle[handle]`.
3. `result = lib.exports[name]`. If it is a function, return its **table slot** (the
   function address = the table index where the loader placed it). Crucially
   `PyInit__multiarray_umath` -> its slot, so CPython calls it to build the module.
4. If not found / stub: `dlSetError("unknown symbol ...")` + return 0.

## Related imports to wire (check the module's actual import list)

- `_dlsym_catchup_js(handle, symbolIndex) -> i32`: return the table addr of the
  `symbolIndex`-th export of `lib` (`Object.keys(lib.exports)[symbolIndex]`).
- `_dlerror() -> i32` (ptr to the last error string), `_dlinit`, `__dlsym_js` /
  `__dlopen_js` variants - implement whichever the module imports, same semantics.

## Why this is the path (not Pyodide's preload)

Pyodide's JS `loadDynlib` (src/js/dynload.ts) preloads via `_emscripten_dlopen_promise`
(ASYNC, JS-promise + stack-switching) - not usable headless. The SYNCHRONOUS
`_dlopen_js`/`_dlsym_js` callbacks above are what the wasm `dlopen`/`dlsym` invoke at
import time, and are the correct headless integration point.
