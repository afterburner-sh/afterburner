# Changelog

All notable changes to afterburner are documented here. This project adheres to
[Semantic Versioning](https://semver.org).

## [0.2.7] - 2026-08-15

An embedded-host safety fix: a guest's `process.exit()` can no longer take the
host process down with it.

### Embedded guest-exit policy

`process.exit(code)` inside a daemon shard called `std::process::exit` on the
host. That is correct for the `burn` CLI, where the guest IS the program, and
wrong for an embedder: one daemon package's failed bootstrap could terminate
the entire host process, with no error line.

`set_exit_process_on_guest_exit(false)` selects the embedded policy. Node's
semantics still hold inside the guest (after `process.exit()` no further event
runs there), but the exit now stops THAT SHARD rather than the host: captured
stdout and stderr are flushed first, the pending reply slot is cancelled so a
caller sees a failure instead of hanging, a line naming the shard and the exit
code goes to stderr, and `shards_alive()` drops. Every drain in the shard loop
(http, timers, workers, net, outbound responses, tls, dgram) now checks the
dispatch outcome, so no already-queued event is delivered to a guest that has
exited. The CLI default is unchanged.

`crates/afterburner-wasi/tests/daemon_embedded_exit.rs` pins both halves, and
is deliberately its own test binary: the policy is process-global, and under
the default policy the guest's exit would terminate the test harness itself,
which is precisely the difference being tested.

### Dependencies

`kovan-map`, `kovan-channel` and `kovan-queue` 0.1.16 -> 0.1.19.

### Website and worker

The docs now cover daemon packages: `[metadata.daemon]` autostart and starting
a daemon in-process via `DaemonHttp` / `DaemonShardPool`. The site serves
`llms.txt`, `robots.txt` (with the `Sitemap:` directive), `sitemap.xml`, a
favicon and an apple-touch icon. HTML responses carry RFC 8288 `Link` headers
pointing at `llms.txt` (`rel="describedby"`) and `/docs` (`rel="help"`), built
by a single `htmlHeaders()` function so the apex, `/docs` and the escape hatch
cannot drift apart.

## [0.2.6] - 2026-08-04

Columnar-UDF wire fixes and a ScramDB scaffold template. The three harness
bugs below each produced a real failure against a live engine.

### Variable-width columns decode to values

A `Utf8`/`Bytea`/`Jsonb` column is a 16-byte inline-or-pointer slot per row
(length at `[0..4)`, bytes inline when the length is 12 or under, otherwise a
heap offset at `[12..16)`), not a `TypedArray` of values. The columnar harness
read it as a `Uint8Array`, so a package received a number per row and
`doc[i].toLowerCase()` failed with "not a function". Slots now decode to a JS
array of strings (or `Uint8Array` for `Bytea`), so a package indexes a
variable-width column exactly like every other dtype. A heap slice that runs
past the column's heap length is rejected by name instead of read out of
bounds.

### Constant columns are read once and broadcast

A constant column carries exactly one value for the whole batch: the host
encodes a scalar argument once rather than repeating it per row. The harness
read `row_count` elements from it and handed the package `undefined` for every
scalar argument. It now reads the single element and broadcasts it across the
batch, so the package body cannot tell a constant column from a per-row one.

### Large replies are written in full

`Javy.IO.writeSync` may accept only part of the buffer it is given. A single
call silently truncated a roughly 800KB columnar reply (10k rows of 64-char
hashes) to 148KB, and the host then rejected the short blob as out of bounds.
The reply is now drained in a loop, and a stalled write fails loudly with the
byte counts instead of truncating.

### String result columns

A package returning strings could not reply at all: the result encoder knew
only `TypedArray`s. A plain `Array` is now encoded as a `Utf8` result column
(16-byte slots plus a heap, the same shape the input path reads), with the
payload encoded once up front so the layout pass knows the exact heap size
and never reallocates. The unsupported-type error now names the actual type
rather than assuming a constructor exists.

### `burn scaffold --scramdb`

A new `scramdb` entry-point template (also `--template scramdb`) writes a
columnar batch entry (one batch in, one batch out) plus the
`[[metadata.sql.function]]` block ScramDB reads to register the function on
install, so `SELECT my_function(...)` works with no manual `CREATE FUNCTION`.
The declared argument names are load-bearing: the entry body reads its inputs
by name out of `batch.columns`, and the scaffold keeps the two in sync. An
explicit `--template` still wins over the `--scramdb` shorthand, so the two
can never silently disagree. Every other template's `[metadata]` table is
untouched.

## [0.2.5] - 2026-07-21

Compile-isolation knobs for embedders that run their own thread topology
alongside `WasmCombustor`.

### Embedder-controlled compilation and background threads

`WasmConfig` gains `parallel_compilation`: `Some(false)` forces every
Cranelift compile onto the calling thread, so `WasmCombustor` never touches
the process's global `rayon` pool - useful for an embedder that runs other
CPU-bound work on that same shared pool and does not want a wasm compile
fanning out across it. `WasmConfig` also gains `spawn_epoch_ticker`:
`Some(false)` suppresses `WasmCombustor::new`'s internal
`afterburner-epoch-ticker` thread entirely, so an embedder that already runs
a scheduler of its own can drive `Engine::increment_epoch()` from there
instead (`WasmCombustor::engine()` returns the `Clone`-able handle for this).
Both default to today's behavior (`None` = unchanged) - existing callers see
no difference.

### Embedder-owned AOT cache

`WasmCombustor::serialize_module` and the new (`unsafe`)
`register_precompiled_deserialize` expose wasmtime's compiled-artifact
serialize/deserialize directly, so an embedder can own its on-disk AOT cache
for `register_precompiled` / `register_dyn` modules without afterburner
installing a `wasmtime::Cache` (and its background cache worker) on its
behalf.

### Pool sizing without environment variables

`WasmConfig::pool_total_instances` and
`WasmConfig::pool_max_linear_memory_bytes` size the pooling allocator
programmatically, matching a library embedder's own concurrency ceiling
instead of the generic 128-instance / `BURN_MAX_LINEAR_MEMORY` defaults -
mutating process environment variables from a multithreaded program is
`unsafe` as of Rust 2024, so a library embedder needs a non-environment path.

### Defense in depth

`build_engine` now sets `wasm_threads(false)` unconditionally, matching
`embedder_vm::deterministic_engine`'s posture: the `threads` proposal is
refused at compile time for every module `WasmCombustor` ever compiles.

### Thread governance

New `afterburner-core::governance` module: `ThreadGovernance { nice, affinity,
name_prefix }` plus `apply_governance` and `spawn_governed`, applied to every
thread this workspace spawns - `ThrustEngineConfig::governance` (compute
workers and the admission sweep, overriding the NUMA pin when `affinity` is
set), `AdaptiveCombustor::with_config`'s new `AdaptiveConfig::governance` (the
background compile worker), `WasmConfig::ticker_governance` (the epoch ticker,
for embedders that keep it), and node-compat's capability helper threads (the
DNS resolver's per-call worker, the sqlite3 shadow's per-connection worker) via
`afterburner_core::governance::set_helper_governance` + the
`node_compat::spawn_governed` wrapper that reads it. `nice`/`affinity` are
Linux-only (`setpriority`/`sched_setaffinity`); a governance failure (a
negative nice without `CAP_SYS_NICE`, an unsupported platform) fails loudly at
the spawning call - never silently inside a thread whose caller has already
moved on - and pool construction cleanly unwinds any already-spawned workers
before propagating. Default (`ThreadGovernance::default()`, every field
`None`) is a pure no-op: today's ungoverned threads, unchanged names,
unchanged priority.

### Pluggable memory ledger

New `afterburner-core::ledger` module: the `MemoryLedger` trait
(`reserve`/`release` over `LedgerClass::{ModuleCache, NativeRuntime,
QueuedJob}`) lets an embedder route every tier's coarse-grained resident bytes
through its own accounting. Wired as `WasmConfig::memory_ledger` (charged at
`bytecode_cache` / `sealed_cache` / `dyn_cache` insert and evict/extinguish),
`ThrustEngineConfig::memory_ledger` (charged at job enqueue, released at
execute-or-drop), and `NativeCombustor::with_ledger` (charged at per-thread
`Runtime` creation and at the per-thread compiled-entry cache insert/evict). A
denied reservation fails the triggering call loudly with the new
`AfterburnerError::LedgerDenied`. `WasmCombustor::resident_estimate()` reports
a measured `ResidentBreakdown` (plugin module, each cache's tracked total, the
pooling allocator's keep-resident floor) for truing accounting up against
reality. `None` (the default everywhere) is a pure no-op.

### Reclassifiable memory-cap trap

`FuelGauge::limiter_tripped` is an optional `Arc<AtomicBool>` sink: when set,
it flips to `true` the instant the wasm tier's `ResourceLimiter` denies a
`memory.grow` / `table.grow` request during that call, independent of whatever
trap (if any) the guest runtime's own allocator subsequently produces - an
embedder can read it after the call returns to reclassify an opaque guest trap
as a memory-cap error with confidence, rather than guessing from the trap's
text. `None` (the default) costs nothing.

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

The WebAssembly runtime for the compiled languages (Ruby, Rust, Go, C, C++) gains
an afterburner-owned filesystem layer that records each file operation as an
effect through its own wasip1 file-descriptor table. A real Ruby program's file
reads and writes are captured end to end over binary data, with a record-and-replay
seam that reproduces a recorded read without touching the disk. Per-language
coverage for Rust, Go, and C, and the remaining filesystem surface, continue in
later releases.

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
