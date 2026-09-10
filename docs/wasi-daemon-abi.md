# Non-JS daemon guests: the WASI reactor ABI

Status: implemented for Rust, C, C++, Go. Not implemented for Python, Ruby
(reason below). Companion code: `crates/afterburner-wasi/src/daemon_runtime_native.rs`,
`crates/afterburner/src/cli/daemon_native.rs`.

## Problem

`burn`'s daemon mode (`crates/afterburner/src/cli/daemon.rs`,
`crates/afterburner-wasi/src/daemon_runtime.rs`) is JS-only. The whole path
assumes a persistent `Store<HostState>` running the Javy/QuickJS plugin:
`daemon_step` is called once as `daemon-init` (evaluates the user's JS,
which calls `.listen(port)` / `setInterval` / `setTimeout`), then repeatedly
as `daemon-event` for every inbound request. A Rust, Go, C, C++, Python, or
Ruby package compiles to (or runs as) a plain WASI **command** module: it
exports only `_start`, the host calls it once, it runs to completion and
`proc_exit`s. There is no way for such a module to "keep going" - every
non-JS `burn run` is structurally a one-shot.

The operator wants the same daemon experience (`.listen()`-shaped programs
that serve HTTP and stay up) for the other supported languages.

## The core idea

A WASI command module is one-shot **by construction**: the host calls
`_start`, and that is the only entry point it is guaranteed to have. Making
a module long-lived means giving it a *second* entry point the host can
call as many times as it wants, after `_start` has already run (or instead
of `_start`, for languages whose toolchain builds a "reactor" rather than a
"command"). This is exactly the pattern already in this tree for JS:
`DaemonRuntime` owns one `Store` for the life of the process, and the CLI /
shard pool call `dispatch_event` (-> `daemon_step`) once per HTTP request.
Extending it to native guests means: the guest **exports** functions the
host can call more than once, and the host - not the guest - owns the
socket, the accept loop, and the axum plumbing.

## Exported ABI

A daemon-capable native guest exports four functions, all with WASI-core
(`i32`-only) signatures, plus the implicit `memory` export every
`wasm32-wasip1` module already has:

```
afterburner_alloc(len: i32) -> i32
afterburner_dealloc(ptr: i32, len: i32)
afterburner_daemon_init(ptr: i32, len: i32) -> i32
afterburner_daemon_dispatch(ptr: i32, len: i32) -> i32
```

`i32`-only was chosen deliberately over passing a `(ptr, len)` pair as a
wasm multi-value return, or returning a fat pointer: Go's `//go:wasmexport`
(the only mechanism Go has for exporting a callable-more-than-once function
to a wasip1 host) only lowers plain integer/float scalars, and pinning the
ABI to "the intersection every target toolchain does natively, with zero
extra codegen flags" was worth more than shaving a host-side memory read.

### Byte-buffer calling convention

Every call in and out is a byte buffer living in the guest's own linear
memory (the host has no address space in common with the guest, so it
cannot hand the guest a pointer to *its* memory):

* **Host -> guest**: the host calls `afterburner_alloc(len)`, gets back a
  pointer, writes `len` bytes at that address via `Memory::write`, then
  calls `afterburner_daemon_init` / `afterburner_daemon_dispatch` with
  `(ptr, len)`.
* **Guest -> host**: the guest allocates its own output buffer, writes the
  response bytes into it, and returns a pointer to an 8-byte **response
  header** it also allocated: `[result_ptr: u32 LE][result_len: u32 LE]`.
  The host reads the header, then reads `result_len` bytes at `result_ptr`.
* **Ownership**: whoever allocated a buffer, the *host* frees it, via
  `afterburner_dealloc(ptr, len)`, once it is done reading it - both the
  request buffer it wrote itself, and the response buffer + 8-byte header
  the guest handed back. This is the only way to keep guest memory bounded
  over a daemon's lifetime (nobody else calls `afterburner_dealloc`); a
  guest that returns a pointer without a live allocation, or double-frees,
  is a guest bug (the same category of bug it would be in any FFI).

A single 8-byte header (rather than, say, encoding `len` as the first 4
bytes of the payload itself) keeps the payload region a plain byte string
with no required prefix, which is what `serde_json` / `encoding/json` /
`cJSON` want to read directly.

### Detection: no manifest field, no CLI flag

A module is treated as a daemon if and only if it exports all four
functions above with exactly the expected `i32`-only signatures
(`crates/afterburner-wasi/src/daemon_runtime_native.rs::daemon_shape`).
No `[daemon]` section in `afb.toml`, no `--daemon` flag: the module's own
shape is the single source of truth, exactly mirroring the JS rule ("a
script that calls `.listen()` becomes a daemon; one that doesn't stays a
plain script"). This means:

* A plain `fn main()` Rust/Go/C/C++ program, compiled exactly as it is
  today, keeps behaving exactly as it does today - `run_command` / `_start`,
  one shot, exit code propagates. **Nothing about the existing one-shot
  path changes**, for any language, because it never has these four
  exports.
* A partially-shaped module (some but not all four exports present, or a
  present export with the wrong signature) is a build the author most
  likely got wrong - a typo'd export name, a missing `afterburner_alloc`.
  `burn` refuses to guess which mode was intended and fails loudly, naming
  exactly which export is missing or mismatched, rather than silently
  falling back to one-shot (which would run `main()` once, exit, and leave
  the author wondering why their "server" printed nothing and quit).

### How the guest asks the host to listen

There is no `.listen(port)` host import in this ABI (unlike JS's
`__host_http_listen`) - the host owns the accept loop and there is no
per-language socket syscall layer to hang an import off for Rust/Go/C/C++
command modules (WASI preview 1 has no socket syscalls at all; see
`crates/afterburner/src/cli/run.rs`'s own comment on this: "network access
from native WASM would require the WASI sockets proposal"). Instead, the
guest declares its listen intent in the **response of
`afterburner_daemon_init`**:

```json
{"listen": [{"port": 8080}]}
```

or, if the module decided (at runtime) that it does not want to run as a
server this invocation:

```json
{"listen": []}
```

An empty (or absent) `listen` array after a successful init is treated
exactly like a JS script with no `.listen()` call: `burn` exits 0 after
init, no daemon loop entered. This reuses the existing "has_refs" decision
rule (`DaemonRuntime::has_listeners`) rather than inventing a second one.
An init that wants to fail outright returns `{"error": "message"}`; `burn`
surfaces `message` on stderr and exits 1, exactly like a JS daemon-init
exception today.

### Reusing the existing envelope shapes

The **request** side reuses the *exact* JSON `daemon_envelopes::http_event_to_envelope`
already produces for the JS path - `{"kind":"http-request","server_id":..,
"req_id":..,"req":{"method":..,"url":..,"headers":{...},"body":".."}}` -
serialized to bytes and handed to `afterburner_daemon_dispatch` verbatim.
One encoding for "here is an HTTP request," used by both guest kinds.

The **response** side is new (JS has no equivalent shape: it calls a host
import per byte-range instead of returning one blob), but it is not a
second envelope so much as the byte-safe form of the same `ReplyEnvelope`
the JS path already deserializes into
(`crates/afterburner-wasi/src/daemon_http.rs::ReplyEnvelope`):

```json
{"status": 200, "headers": {"content-type": "text/plain"}, "body_b64": "aGVsbG8="}
```

`body_b64` (not JS's dual `body` text / `body_b64` legacy pair) because a
byte-string round-trip through JSON needs exactly one binary-safe
encoding, and every target language here has a base64 encoder in its
standard library (`base64` crate for Rust, `encoding/base64` for Go,
`libc`-free hand-rolled or `EVP_DecodeBlock` for C - the example packages
include a ~15-line table encoder since libc doesn't ship one). Both parsers
live next to the JS ones in `daemon_envelopes.rs`:
`parse_native_init_response` and `parse_native_dispatch_response`, so the
shapes and their tests stay colocated with every other envelope in the
codebase.

The **init** input envelope is minimal - `{"mode": "daemon-init"}` - unlike
the JS shape it otherwise mirrors, it carries no `argv` / `env` / `cwd`.
Those exist in the JS envelope because the QuickJS guest has no OS-level
channel of its own for them and the host has to smuggle them in as data.
A native guest is a real WASI module: it already receives `argv` and the
environment through the normal `args_get` / `environ_get` WASI imports
`WasiCommandOpts` wires up (`std::env::args()` in Rust, `os.Args` in Go,
`main(argc, argv)` in C) - repeating them in the JSON envelope would be a
second, redundant source of the same data with its own chance to drift
from the first. `cwd` likewise: WASI preopens already scope what
filesystem the guest can see.

## Instance lifecycle

One `Store<NativeDaemonState>` per daemon process, for the life of the
process - no multi-shard pool (see Scope below). Construction
(`NativeDaemonRuntime::instantiate`):

1. Instantiate the module against a plain WASI preview-1 linker
   (`wasmtime_wasi::p1::add_to_linker_sync`) - the same linker shape
   `EmbedderVm::run_command` already uses for one-shot native runs, built
   fresh here rather than through `EmbedderVm` because `EmbedderState`
   carries a large amount of Pyodide/Emscripten-only state (side-module
   registries, FFI closure tables, syscall shims) that has nothing to do
   with a plain Rust/Go/C/C++ reactor; reusing it would mean constructing
   and threading through a dozen `None` fields on every call for no
   payoff. `WasiCommandOpts` (args/env/preopens/stdin/memory-cap) is
   reused unchanged so a daemon guest gets the exact same capability
   grants a one-shot run of the same binary would.
2. If the module exports `_start` (a normal command-shaped Rust or C/C++
   binary with `fn main(){}` / `int main(void)`, which - confirmed by
   direct testing - keeps exporting any other `#[unsafe(no_mangle))]` /
   `__attribute__((export_name(...)))` functions right alongside `_start`
   with zero build-flag changes): call it once.
   * Returns normally, or traps with `I32Exit(0)` - proceed. Rust/C's
     `main()` returning is the "returns normally" case; Go's `//go:wasmexport`
     reactor mode runs `_start` (which runs package `init()`s, then `main()`,
     then `runtime.exit(0)`) and *always* signals completion via
     `I32Exit(0)`, confirmed by direct testing (Go's own runtime otherwise
     refuses every `//go:wasmexport` call with "call `_start` first").
   * Traps with `I32Exit(n)`, `n != 0` - the program explicitly decided not
     to run (matches one-shot's "non-zero exit" convention); instantiate
     fails with that exit code.
   * Traps with a real `Trap` (out-of-fuel, unreachable, OOB) - instantiate
     fails with the trap detail, via the exact same `map_daemon_trap` the
     JS path uses (promoted `pub(crate)` for this reuse - one mapping from
     `wasmtime::Error` to `AfterburnerError` for every daemon flavor,
     never two).
3. Else if the module exports `_initialize` (a WASI **reactor**: C/C++
   built with `-mexec-model=reactor`, confirmed to export `_initialize`
   instead of `_start` and to work identically to the command case once
   `_initialize` has run once): call it once; any trap fails instantiate.
4. Else (neither export - a Rust `#![no_main]` `cdylib`, confirmed by
   direct testing to need no entry call at all: its own module-load-time
   static initialization is sufficient) - proceed straight to
   `afterburner_daemon_init`.

State (a request counter, a connection pool, anything the guest's own
globals or heap hold) survives across calls exactly because the `Store`
and its `Memory` are never torn down between them - confirmed empirically:
an atomic counter incremented once per `afterburner_daemon_dispatch` call
returned 1, 2, 3 across three separate calls into the same instance, for
all three of Rust, C, and Go.

### A trap mid-request

`afterburner_daemon_dispatch` can trap (guest panic -> `unreachable`,
out-of-fuel, an out-of-bounds guest memory access). Unlike a per-request
JS exception - which the JS dispatch wrapper catches *inside* the QuickJS
runtime with a plain `try`/`catch`, so the Store's WASM call frame never
unwinds - a real WASM trap unwinds through the host boundary, and after
that the guest's own invariants (a half-updated allocator free-list, a
struct written half-way through) are not something the host can verify are
still consistent. So: a trap during dispatch is treated as **fatal to the
daemon instance**, exactly as an unhandled panic crashing a real,
un-supervised Rust/Go/C HTTP server process would be. `burn` replies 500 to
the in-flight request if it is still reachable, logs the trap, and shuts
the daemon down rather than continuing to serve out of a Store whose
invariants it can no longer vouch for. A guest that wants to survive its
own per-request bugs is expected to do what a hand-written server in that
language would: catch its own panics inside `afterburner_daemon_dispatch`
(`std::panic::catch_unwind` in Rust, `recover()` behind a `defer` in Go,
careful `setjmp`/`longjmp` in C) before they become a WASM trap. This is
the same posture the operator's own doctrine takes for a production
service - a panic that reaches the top of a request is a bug in that
service, not a platform obligation to paper over.

## Fuel, memory, timeout on a long-lived instance

The JS daemon's own `Store` (`DaemonRuntime::instantiate`) sets
`fuel = u64::MAX` and `epoch_deadline = u64::MAX / 2` once, at
construction - i.e. today's daemon mode does not actually bound per-request
compute at all; it relies on the request itself finishing. That is the
wrong default to copy here, because the task that motivated this design
explicitly calls out the failure mode: a fixed fuel budget that is set once
and never replenished **will** starve every request after the budget from
the first N runs out, silently killing the daemon on its Nth request with
no story for what "budget" even means for a process meant to run forever.

The fix, and the one implemented: fuel is **reset before every call**
(`store.set_fuel(NATIVE_DAEMON_FUEL_PER_CALL)` ahead of both
`afterburner_daemon_init` and every `afterburner_daemon_dispatch`), so the
budget is *per request*, never cumulative - a request that runs away
(an infinite loop with no I/O to block on) traps with `OutOfFuel` and takes
down that one instance the same way any other guest trap does (see above),
instead of slowly bankrupting every future request. The default,
`NATIVE_DAEMON_FUEL_PER_CALL = 100_000_000`, matches `EmbedderVm`'s
`DEFAULT_FUEL` for one-shot native runs, so a handler gets the same compute
budget per call that the same code would get as a one-shot program.

Memory is capped for the **whole instance lifetime**, not reset per call
(`WasiCommandOpts::max_memory_bytes`, applied once at store construction) -
memory is exactly the state that is supposed to survive between requests
(a connection pool, a cache), so resetting it would defeat the entire
point of a daemon. Unbounded by default, exactly like one-shot native
runs; an operator who wants a cap passes the same flag they would for a
one-shot run.

There is no separate wall-clock / epoch timeout. This is not a gap: the
ABI is fully synchronous compute with no host import a guest can block on
(there is no equivalent of JS's outbound `fetch` or `net.connect` in this
ABI - see Scope below), so the only way a call can fail to return is by
burning instructions, which fuel already bounds. Adding epoch interruption
on top would be a second bound on the same failure mode for no
observable benefit, and it is not what the JS daemon precedent does either
(its epoch deadline is effectively infinite).

Both bounds are tested directly, not just asserted in prose.
`daemon_runtime_native`'s `fuel_is_replenished_not_accumulated_across_many_dispatches`
drives a guest that burns a real, measured amount of fuel per call through
100 calls on one instance, asserting the remaining budget after every
single call stays near-full - a fixed one-time budget would exhaust well
before call 40. `memory_cap_applies_for_the_whole_instance_lifetime` grows
the guest's memory once within a configured cap (succeeds) and once far
past it (denied), on the same instance, proving the cap persists rather
than resetting. `native_daemon.rs`'s `rust_daemon_survives_many_sequential_requests`
proves the same fuel claim end to end: 40 real HTTP requests through the
actual `burn run` CLI against the real Rust fixture, asserting the exact
expected sequence number in every response.

## Which languages this ships for, and why

| Language | Ships? | Why |
|---|---|---|
| Rust | Yes | `rustc`/`cargo --target wasm32-wasip1` already exports any `#[unsafe(no_mangle)] pub extern "C" fn` alongside (or instead of, for a `#![no_main]` `cdylib`) `_start`, with zero new build flags. Confirmed by direct instantiate-and-call testing. |
| C | Yes | wasi-sdk `clang --target=wasm32-wasip1` already exports any `__attribute__((export_name("...")))` function alongside `_start`, with zero new build flags (`-mexec-model=reactor` is an available alternative, not a requirement). Confirmed by direct testing, both with and without `-mexec-model=reactor`. |
| C++ | Yes | Same mechanism as C via wasi-sdk `clang++`; exported functions must be declared `extern "C"` (as `export_name` implies no-mangle linkage) exactly as any C++/C FFI boundary already requires. |
| Go | Yes, with Go >= 1.24 | `//go:wasmexport` is the only way Go has to export a repeatedly-callable function to a wasip1 host, and it shipped in Go 1.24 (Feb 2025). Confirmed by direct testing: `_start` must be called exactly once first (Go's runtime refuses every `//go:wasmexport` call otherwise: "wasmexport function called before runtime initialization: call `_start` first"), after which `_start` exits via `I32Exit(0)` and the instance stays fully usable. The existing Go preflight (`crates/afterburner/src/cli/compile/lang.rs::preflight_go`) only requires Go >= 1.21 for the base `wasip1` port; compiling a package whose source contains `//go:wasmexport` now additionally requires >= 1.24, checked up front with an actionable message naming the exact requirement, rather than surfacing whatever cryptic error an old Go compiler gives for an unrecognized directive comment. |
| Python | No | The compiled module a Python *package* runs through is the bundled Pyodide/CPython-WASI interpreter (`pyodide_runner.rs`) - the same fixed binary for every package, run via `Py_Initialize` / eval-source / `Py_Finalize` inside one `run_python` call. There is no "the user's `.py` file exports `afterburner_daemon_dispatch`" surface at all: Python source cannot make the *interpreter binary* export new WASM-level symbols. Note this is a different concern from the *already-shipped* raw-socket path (`DaemonNet`/`DaemonWorkers` syscall shims wired into the Pyodide embedder, exercised by `examples/accept-webserver`'s `ThreadingHTTPServer`) - that lets a single `run_python` call block inside its own `accept()` loop forever, which is a real, working, pre-existing way to keep a Python process alive. It is a different mechanism from this one (guest-exports, host-owned accept loop) and out of scope for this change. Giving Python a `daemon_init`/`daemon_dispatch`-shaped daemon would mean building a `DaemonRuntime`-equivalent bridge *inside* the interpreter (a persistent Python VM plus a host-callable dispatch function evaluated once, analogous to `afterburner-plugin`'s QuickJS bridge) - a legitimately separate, larger feature, not a natural extension of this ABI. |
| Ruby | No | Same reasoning as Python, substituting the bundled `ruby.wasm`/CRuby-WASI interpreter (`ruby_runner.rs`) for Pyodide. |

## Scope: what this change does not do

* **No multi-shard pooling for native daemons.** `DaemonShardPool` compiles
  JS bytecode once and fans it into N per-shard Stores; that shape does not
  translate to "instantiate the same compiled module N times" cleanly
  without its own design pass (worker distribution, per-shard port
  arbitration semantics for a guest that has no notion of "shard"). A
  native daemon runs single-instance, on one HTTP listener thread pool
  managed by the same `DaemonHttp` the JS path uses. Scaling a native
  daemon across cores today means running N `burn` processes behind a
  load balancer, same as running N single-shard JS daemons with
  `BURN_SHARDS=1`.
  `// vertexia: single-instance native daemon; multi-shard needs its own
  design pass, ceiling is CPU-bound native daemons under heavy load.`
* **No outbound networking, raw TCP/TLS/UDP, or worker-thread ABI for
  native guests.** The ABI is strictly "one HTTP request in, one HTTP
  response out, synchronously." `daemon_net` / `daemon_tls` / `daemon_dgram`
  / `daemon_workers` stay JS-only; extending them would mean designing an
  equivalent byte-buffer-and-poll ABI for each, which is real, separate
  scope.
* **No manifest (`afb.toml`) changes.** Detection is purely from the
  compiled module's exports (see above); `Manifest::metadata` remains
  available for a future per-package override (e.g. a default port) should
  one prove necessary, but nothing in this change reads it.

## What was reused vs. what is new

Reused, unchanged: `DaemonHttp` (listener bind, axum/hyper request loop,
pending-reply channel, port-claim arbitration), `daemon_envelopes::http_event_to_envelope`
(request encoding), `ReplyEnvelope` (response type), the CLI's SIGINT/SIGTERM
shutdown pattern, `WasiCommandOpts` (capability grants), `deterministic_engine`
(fuel + determinism profile), `map_daemon_trap` (promoted `pub(crate)` for
this second caller).

New: `NativeDaemonRuntime` (`daemon_runtime_native.rs`) - the native
counterpart to `DaemonRuntime`, same role (own the long-lived Store, expose
init/dispatch), different guest calling convention (exported functions +
linear-memory buffers instead of a `pending_envelope` field + a
`daemon_step` re-entry). `cli/daemon_native.rs` - the native counterpart to
`cli/daemon.rs`, same role (tokio runtime, bind listeners, drive the
request loop, handle signals), much smaller because there is no shard pool,
no bytecode compile, no worker/TLS/net wiring. Two new envelope
parsers colocated in `daemon_envelopes.rs`.
