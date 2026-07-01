# Changelog

All notable changes to afterburner are documented here. This project adheres to
[Semantic Versioning](https://semver.org).

## [0.2.4] - 2026-07-01

The recording release. afterburner gains three runtime capabilities for capturing
and reproducing what a program does, adds real HTTPS for Python, and stays
binary-safe from end to end.

### Python over HTTPS

Python programs make real HTTPS requests out of the box. `urllib` and `requests`
reach live endpoints with zero configuration and no custom runtime. TLS is
terminated on the host (the host validates the server certificate and encrypts
the connection), so the guest sees plaintext and needs no certificate store or
OpenSSL build.

### Effect recording and replay

afterburner records every host-mediated effect a program performs: filesystem
reads and writes, network calls, environment reads, and child processes, each
captured at the runtime boundary with its input, its output, and a content hash.
The same recording replays. On a replay run afterburner serves the recorded
result instead of performing the real effect, so the run reproduces
deterministically without touching the network or the disk. The seam works
across all eight languages.

### Structured results and session filesystems

A run can return a structured result carrying stdout, stderr, the exit code, and
the program's typed return value together, all binary-safe so images, audio, and
other non-text output survive byte for byte. A session keeps one filesystem
across multiple runs, so a multi-step workflow (create a directory, write files,
install dependencies, build) persists from one run to the next.

### Filesystem capture for the compiled languages

The WebAssembly runtime for Ruby, Rust, Go, C, and C++ gains an afterburner-owned
filesystem layer that records each file operation as an effect through its own
wasip1 file-descriptor table. This first increment ships the capture mechanism,
proven end to end over binary data; broader coverage of the full filesystem
surface and each language runtime continues in later releases.

### Multimodal, binary-safe throughout

Every recorded payload, structured result, and captured file carries raw bytes
and never assumes text, so binary and multimodal data (images, audio, video)
round-trips exactly.

## [0.2.3] - 2026-06-29

Outbound HTTP for the compiled languages. Programs written in Rust, Go, C, C++,
and Ruby and compiled to WebAssembly now make HTTP and HTTPS requests through the
host, the same host-mediated networking that JavaScript and Python already had.
No raw sockets are exposed to the guest.

## [0.2.2] - 2026-06-27

Windows build fix. The emscripten filesystem shim now uses cross-platform
positional file I/O (`pread`/`pwrite` that preserve the file offset on Windows
too) and a portable inode, so the runtime compiles and runs on Windows alongside
Linux and macOS.

## [0.2.1] - 2026-06-27

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

[0.2.2]: https://github.com/afterburner-sh/afterburner/releases/tag/v0.2.2
[0.2.1]: https://github.com/afterburner-sh/afterburner/releases/tag/v0.2.1
[0.1.3]: https://github.com/afterburner-sh/afterburner/releases/tag/v0.1.3
