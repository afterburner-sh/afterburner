# Polyglot demo

Afterburner runs programs compiled from five languages on the **same Wasmtime
engine**. Each program prints a comparable result:

```
<lang>: sum(1..=100)=5050 fib(20)=6765
```

| Language | Source | Build path | Artifact size |
|----------|--------|-----------|--------------|
| Rust | `rust/main.rs` | `rustc --target wasm32-wasip1` | ~42 KB (wasm-opt stripped) |
| Go | `go/main.go` | `GOOS=wasip1 GOARCH=wasm go build` | ~2.4 MB (Go runtime) |
| Python | `python/main.py` | CPython WASM binary (~25 MB, not committed; see below) | N/A |
| JavaScript | `js/main.js` | `javy build` (sealed QuickJS wasm) | ~1.2 MB |
| TypeScript | `ts/main.ts` | `tsc main.ts` then `javy build` | ~1.2 MB |

## How afterburner runs each language

All five are standard **WASI command modules**: they export `_start`, receive
their environment through WASI syscalls, and write output to fd 1 (stdout).
Afterburner's `EmbedderVm::run_command` instantiates each one in a fresh
Wasmtime store, captures stdout, and returns it.

- **Rust / Go** - compiled natively to `wasm32-wasip1`. The Go runtime (~2.4 MB)
  is included in `go.wasm`; it is larger than the 300 KB guideline.
- **JS / TS** - bundled by Javy into a sealed `wasm32-wasip1` module that embeds
  QuickJS. The module writes to fd 1 via `Javy.IO.writeSync`. TS is first
  stripped to JS via `tsc`, then bundled by Javy identically to the JS path.
- **Python** - the `python.wasm` binary is CPython 3.13 compiled to WASI. It is
  **not committed** because of its size (~25 MB). The runner reads it from
  `$PYTHON_WASM` (default `/tmp/python.wasm`). If absent the Python row prints
  `SKIPPED (python.wasm not found)` and the example still passes.

## Build artifacts

```
build.sh          # rebuilds all .wasm artifacts
rust/rust.wasm    # committed (~42 KB)
go/go.wasm        # committed (~2.4 MB, Go runtime included)
js/js.wasm        # committed (~1.2 MB, QuickJS + program)
ts/ts.wasm        # committed (~1.2 MB, QuickJS + program)
```

## Run the demo

```
cargo run -p afterburner-wasi --example polyglot
```
