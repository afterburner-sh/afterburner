# Polyglot burn packages

Six source languages, one burn runtime. Each directory is a valid burn
package (`afb.toml` + `manifold.json` + `source/`). Every program prints:

```
<lang>: sum(1..=100)=5050 fib(20)=6765
```

| Language   | Package dir      | Entry              | Compile + run                    |
|------------|------------------|--------------------|----------------------------------|
| Rust       | `rust/`          | `source/main.rs`   | `burn compile` -> WASM command   |
| Go         | `go/`            | `source/main.go`   | `burn compile` -> WASM command   |
| JavaScript | `js/`            | `source/main.js`   | `burn run source/main.js`        |
| TypeScript | `ts/`            | `source/main.ts`   | `burn run source/main.ts`        |
| Python     | `python/`        | `source/main.py`   | pending (see below)              |
| Ruby       | `ruby/`          | `source/main.rb`   | pending (see below)              |

## Rust

```sh
# from the afterburner repo root
burn compile examples/languages/rust -o rust-demo.afb
burn run rust-demo.afb
# rust: sum(1..=100)=5050 fib(20)=6765
```

Requires: `rustup target add wasm32-wasip1`

## Go

```sh
burn compile examples/languages/go -o go-demo.afb
burn run go-demo.afb
# go: sum(1..=100)=5050 fib(20)=6765
```

Requires: Go 1.21+ (GOOS=wasip1 is built in since Go 1.21)

## JavaScript

JavaScript packages are run through the burn script engine (V8/QuickJS) with
full Node.js compatibility. The `burn compile` step produces a Javy-compiled
`.afb` for the UDF/thrust mode (JSON in -> JSON out). For direct script
execution, use `burn run` on the source file:

```sh
# Direct execution via the script engine:
cd examples/languages/js
burn run source/main.js
# js: sum(1..=100)=5050 fib(20)=6765

# Produce a compiled .afb (for burn thrust UDF mode):
burn compile examples/languages/js -o js-demo.afb
```

## TypeScript

TypeScript is compiled to JavaScript at runtime via oxc (strip-types + ESM
lowering). No tsc required.

```sh
# Direct execution via the script engine:
cd examples/languages/ts
burn run source/main.ts
# ts: sum(1..=100)=5050 fib(20)=6765

# Produce a compiled .afb (for burn thrust UDF mode):
burn compile examples/languages/ts -o ts-demo.afb
```

## Python (pending)

`burn compile examples/languages/python` exits with a clear pending error.
Python-to-WASM support is wired in the CLI but the CPython-WASI runtime
bundle is not yet bundled with afterburner.

The source (`source/main.py`) runs correctly with any CPython 3.x interpreter:
```sh
python3 examples/languages/python/source/main.py
```

## Ruby (pending)

`burn compile examples/languages/ruby` exits with a clear pending error.
Ruby-to-WASM support is wired in the CLI but the ruby.wasm runtime bundle
is not yet bundled with afterburner.

The source (`source/main.rb`) runs correctly with any CRuby 3.x interpreter:
```sh
ruby examples/languages/ruby/source/main.rb
```

## How burn runs each language

**Rust and Go** compile to `wasm32-wasip1` WASI command modules via their
native toolchains (`cargo build --target wasm32-wasip1` and
`GOOS=wasip1 GOARCH=wasm go build`). The resulting `.afb` embeds the WASM
binary and is executed via `EmbedderVm::run_command` (Wasmtime).

**JavaScript and TypeScript** run through the burn script engine: a V8/QuickJS
daemon that provides full `node:*` compatibility, sandboxed by the manifold.
The `burn compile` step produces a Javy-sealed WASM for UDF/thrust mode
(used with `burn thrust` for JSON-in/JSON-out workloads). For scripts that
write directly to stdout, use `burn run <file>`.

**Python and Ruby** are pending. The CLI dispatch and `[package] language`
parsing are wired; only the runtime bundle is missing.
