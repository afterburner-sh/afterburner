# Polyglot examples

Six languages, one runtime. Each directory is a **burn package**: an
`afb.toml` that declares the package's language plus a `source/` tree. The same
`burn` workflow builds and runs every one of them.

Every example computes the same thing and prints:

```
<lang>: sum(1..=100)=5050 fib(20)=6765
```

| Language   | Directory | Entry              |
|------------|-----------|--------------------|
| Rust       | `rust/`   | `source/main.rs`   |
| Go         | `go/`     | `source/main.go`   |
| JavaScript | `js/`     | `source/main.js`   |
| TypeScript | `ts/`     | `source/main.ts`   |
| Python     | `python/` | `source/main.py`   |
| Ruby       | `ruby/`   | `source/main.rb`   |

## Multi-module packages

A burn package in a native language is a real, multi-module project compiled by
its own toolchain, not one file at a time. These examples each have several
source files with cross-module calls, an exported (`pub` / capitalized / header)
API, and at least one PRIVATE item that `main` cannot reach:

| Language | Directory           | Modules                                                         | Prints                 |
|----------|---------------------|-----------------------------------------------------------------|------------------------|
| Rust     | `rust-multimodule/` | `source/main.rs` + `source/geometry.rs` + `source/stats/mod.rs` | `area=50 mean=20`      |
| Go       | `go-multimodule/`   | `source/main.go` + package `source/geometry/`                   | `area=50 perimeter=30` |
| C        | `c-multimodule/`    | `source/main.c` + `source/geometry.c` (+ `geometry.h`)          | `area=50 mean=20`      |
| C++      | `cpp-multimodule/`  | `source/main.cpp` + `source/geometry.cpp` (+ `geometry.hpp`)    | `area=50 mean=20`      |

Encapsulation per language: Rust `pub` vs a private `fn`; Go capitalized
(exported) vs lowercase (package-private); C/C++ `static` / anonymous-namespace
helpers (internal linkage) behind a public header. C and C++ compile ALL of
`source/**` into one `wasm32-wasip1` WASI command module via the wasi-sdk
(`clang`/`clang++ --target=wasm32-wasip1 --sysroot=...`); set `WASI_SDK_PATH` so
`burn compile` can find it. The Rust example uses edition 2024. Build and run
them exactly like the single-file examples:

```sh
burn compile examples/languages/rust-multimodule -o demo.afb
burn run demo.afb
# area=50 mean=20
```

## Build and run

Each example is built and run the same way:

```sh
burn compile examples/languages/rust -o rust-demo.afb
burn run rust-demo.afb
# rust: sum(1..=100)=5050 fib(20)=6765
```

JavaScript and TypeScript can also be run directly as scripts:

```sh
burn run examples/languages/js/source/main.js
# js: sum(1..=100)=5050 fib(20)=6765
```

## Toolchains

The language is declared in each package's `afb.toml`, and `burn compile`
invokes the matching toolchain. Have the relevant one installed:

- **Rust** - the Rust toolchain.
- **Go** - Go 1.21 or newer.
- **JavaScript / TypeScript** - built in; no extra toolchain (TypeScript is
  lowered to JavaScript automatically).
- **Python / Ruby** - run on burn's built-in interpreter for that language.

## Running a loose script

A single file can also be run directly, with its language taken from the file
extension - `burn run script.py`, `burn run script.go`, and so on. Scripts run
sealed by default; pass `-A` (or a granular `--allow-*` grant) to permit
filesystem, network, or environment access.
