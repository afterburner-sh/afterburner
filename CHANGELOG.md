# Changelog

All notable changes to afterburner are documented here. This project adheres to
[Semantic Versioning](https://semver.org).

## [0.2.0] - 2026-06-26

The polyglot release. afterburner goes from a JavaScript/TypeScript sandbox to a
single runtime that runs, compiles, and packages eight languages, each into a
self-contained WebAssembly artifact, with zero configuration.

### Languages

- **Eight languages, one runtime**: JavaScript, TypeScript, Python, Ruby, Rust,
  Go, C, and C++. Every language gets `burn run`, `burn repl --lang`,
  `burn compile`, `burn package`, and a `burn new --lang` scaffold.
- **Python, zero-config**: `burn run script.py` works out of the box and imports
  the scientific stack (numpy, pandas, polars). Network sockets and a durable
  filesystem are available to Python programs.
- **Ruby, zero-config**: `burn run script.rb` and `burn repl --lang ruby` run a
  self-contained Ruby with no setup; gem dependencies are resolved and vendored.

### Compile to WebAssembly

- **Every language compiles to a self-contained `.afb` blob**: Python and Ruby
  pack their interpreter, your source, the standard library, and dependencies
  into one content-addressed WebAssembly artifact; Rust, Go, C, and C++ compile
  natively to `wasm32-wasip1`; JavaScript and TypeScript run on the JS engine.
  The artifact runs anywhere afterburner runs, with no recompile.
- **Multi-module projects**: C/C++/Rust/Go multi-file programs compile as one
  WASI command; Python and Ruby packages resolve sibling imports.

### Dependencies

- **`burn install` for pip, gem, and npm**: one command resolves and vendors
  dependencies across all three ecosystems.
- **One lockfile**: `burn.lock` v2 records pip, gem, and npm dependencies and
  interoperates with `requirements.txt`, `Gemfile`, and `package.json`. It is
  loud when a manifest and the lock disagree.
- **Offline**: vendored wheels and gems mount at run time; no network is needed
  after the first resolve.

### Runtime and sandbox

- **Zero configuration**: no environment variables to run a program. Language
  runtimes are embedded in the binary or fetched once into `~/.burn`, and
  everything works offline thereafter.
- **Sealed by default**: a program gets no filesystem, network, or environment
  access unless granted. `--allow-fs-read`, `--allow-fs-write`, `--allow-net`,
  and `--allow-env` grant narrowly; `-A` allows all.
- **Size-agnostic memory**: the runtime sizes memory to the workload (a 4 GiB
  growable default), configurable per run.

### Scaffolding and tooling

- **`burn new` / `burn init --lang`**: per-language project templates, with the
  language recorded in the package manifest.
- **Toolchain preflight**: `burn compile` checks for the required toolchain up
  front and fails with a clear message instead of a cryptic exit.

### Website

- Rewritten as a polyglot site covering the eight languages, REPLs, multi-module
  packages, the registry, determinism, and the sandbox model.

[0.2.0]: https://github.com/afterburner-sh/afterburner/releases/tag/v0.2.0
[0.1.3]: https://github.com/afterburner-sh/afterburner/releases/tag/v0.1.3
