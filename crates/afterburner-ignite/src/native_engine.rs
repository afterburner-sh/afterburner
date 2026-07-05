// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `NativeCombustor` - executes JS via `rquickjs` FFI directly (no WASM).
//!
//! The trusted-code path. No sandbox beyond QuickJS's own fuel/memory
//! knobs, but startup is <300 μs and throughput is higher than the WASM
//! route for short-lived scripts.
//!
//! ### Concurrency model - thread-local runtimes
//!
//! rquickjs's `Runtime`/`Context` are `!Send`/`!Sync` (without the
//! `parallel` feature, which drags in tokio). Rather than serialize
//! access with a Mutex, each client thread gets its own lazily-created
//! `Runtime` via `thread_local!`. There is **no cross-thread
//! synchronization** on the hot path - two client threads can call
//! `thrust` concurrently without ever talking to each other.
//!
//! Shared state:
//! * `source_store` - lock-free `kovan_map::HopscotchMap` caching the
//!   JS source text, keyed by SHA-256 of the source. Any thread can
//!   read a source another thread ignited.
//!
//! Trade-off: each client thread carries a per-thread Runtime (~100 KB
//! residual memory). In practice the caller is a small pool of worker
//! threads, so the memory footprint is bounded and the throughput win
//! is substantial.

use afterburner_core::log::Level;
use afterburner_core::{
    AfterburnerError, Combustor, EngineMode, FuelGauge, InMemoryStateStore, Result, ScriptId,
    ScriptInvocation, ScriptOutcome, SharedStateStore, ab_event, sha256,
};

/// Normalise a leading hashbang/BOM and bare dynamic `import(...)`
/// expressions so QuickJS will parse and run the source. Same
/// rationale as the wasm-side wrappers in
/// `afterburner-plugin/src/envelope.rs` - we mirror the fix-up here
/// so script files / npm-installed CLI entry points / TS-stripped
/// sources behave identically across the native and wasm engines.
/// Hashbang replacement is length-preserving (`#!` → `//`) so error
/// columns stay aligned with the on-disk file.
fn normalize_user_source(source: &str) -> String {
    let stripped = source.strip_prefix('\u{feff}').unwrap_or(source);
    let after = if let Some(rest) = stripped.strip_prefix("#!") {
        let mut out = String::with_capacity(stripped.len());
        out.push_str("//");
        out.push_str(rest);
        out
    } else if stripped.len() == source.len() {
        source.to_string()
    } else {
        stripped.to_string()
    };
    rewrite_dynamic_imports(&after)
}

/// Twin of the wasm-side rewriter - see envelope.rs for the rationale.
/// QuickJS has no module loader registered so `import('foo')` throws
/// at runtime; we redirect to `globalThis.__ab_dyn_import(foo)`,
/// which the plenum bundle wires to the require resolver.
fn rewrite_dynamic_imports(source: &str) -> String {
    if !source.contains("import") {
        return source.to_string();
    }
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len() + 32);
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'i'
            && i + 6 <= bytes.len()
            && &bytes[i..i + 6] == b"import"
            && (i == 0 || !is_ident_char(bytes[i - 1]))
        {
            let mut j = i + 6;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                out.push_str("globalThis.__ab_dyn_import");
                out.push_str(&source[i + 6..j]);
                out.push_str("(require,");
                i = j + 1;
                continue;
            }
        }
        let ch_len = source[i..]
            .chars()
            .next()
            .map(|c| c.len_utf8())
            .unwrap_or(1);
        out.push_str(&source[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}
use kovan_map::HopscotchMap;
use rquickjs::{
    Context, Ctx, Error as RquickjsError, Function, Persistent, Runtime, Value as RqValue,
};
use serde_json::Value as JsonValue;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// QuickJS V8-CallSite proto patch - adds the seven Node-shaped
/// methods (`isEval`, `getEvalOrigin`, `isToplevel`, `isConstructor`,
/// `getThis`, `getTypeName`, `getMethodName`) that rquickjs / Javy
/// don't expose. depd / morgan / finalhandler probe these at module-
/// load time; without the patch any Express middleware tree crashes
/// with `TypeError: not a function`. Identical snippet to the one
/// the WASM plugin installs at Wizer pre-init
/// (see `crates/afterburner-plugin/src/globals/mod.rs`).
const CALLSITE_PROTO_PATCH: &str = r#"
(function patchCallSiteProto() {
    var sample = {};
    var prev = Error.prepareStackTrace;
    Error.prepareStackTrace = function(_e, frames) { return frames; };
    Error.captureStackTrace(sample);
    var frames = sample.stack;
    Error.prepareStackTrace = prev;
    if (!Array.isArray(frames) || frames.length === 0) return;
    var proto = Object.getPrototypeOf(frames[0]);
    var stubs = {
        isEval:        function() { return false; },
        getEvalOrigin: function() { return undefined; },
        isToplevel:    function() { return false; },
        isConstructor: function() { return false; },
        getThis:       function() { return undefined; },
        getTypeName:   function() { return null; },
        getMethodName: function() { return null; }
    };
    for (var name in stubs) {
        if (typeof proto[name] !== 'function') proto[name] = stubs[name];
    }
})();
"#;

/// Per-thread ceiling on `ENTRY_CACHE`. Compiled UDF entries are small
/// (bytecode), so 512 distinct scripts per thread is generous; past it the
/// least-recently-used entry is evicted (a miss just recompiles once).
const ENTRY_CACHE_CAP: usize = 512;

/// A cached compiled UDF entry plus its last-access tick (for LRU eviction).
type CachedEntry = (Persistent<Function<'static>>, Cell<u64>);

thread_local! {
    /// One rquickjs Runtime per client thread. Lazily initialized on
    /// first use. Wrapped in RefCell because we need `&mut` access to
    /// the interrupt-handler slot; RefCell is single-threaded, not a
    /// synchronization primitive.
    static THREAD_RT: RefCell<Option<ThreadRuntime>> = const { RefCell::new(None) };

    /// When `Some`, native script mode is active on this thread:
    /// `__host_log` writes into the per-call buffers instead of
    /// emitting workspace log events. Set + cleared by
    /// [`ScriptCaptureGuard`]; never observed across calls because
    /// each `run_script` activates and drops its own guard.
    static SCRIPT_CAPTURE: RefCell<Option<ScriptCapture>> = const { RefCell::new(None) };

    /// Per-thread cache of compiled UDF entry functions, keyed by
    /// script hash. QuickJS parsing + compiling the envelope was the
    /// dominant native warm cost (~158us p50) - caching the compiled
    /// `Function` means that work happens once per (thread, script)
    /// instead of once per thrust. Content-addressed key: a hit is
    /// never stale. Bounded to `ENTRY_CACHE_CAP` entries per thread with
    /// LRU eviction (the `Cell<u64>` is each entry's last-access tick), so
    /// a high-cardinality workload (many distinct scripts) cannot grow it
    /// without bound even when `extinguish` never runs on this thread.
    static ENTRY_CACHE: RefCell<HashMap<[u8; 32], CachedEntry>> =
        RefCell::new(HashMap::new());

    /// Monotonic per-thread counter feeding `ENTRY_CACHE`'s LRU order.
    static ENTRY_TICK: Cell<u64> = const { Cell::new(0) };

    /// Per-thread fuel accounting for the shared interrupt handler that
    /// `ThreadRuntime::new` installs ONCE per Runtime. `do_thrust` /
    /// `run_script` reset the counter and set the limit before each call; the
    /// handler bumps the counter and interrupts when it reaches the limit. A
    /// `u64::MAX` limit means fuel is disabled (never interrupt). This replaces
    /// a per-thrust `Arc<AtomicU64>` + boxed closure + two FFI set-calls (#36).
    static FUEL_COUNTER: AtomicU64 = const { AtomicU64::new(0) };
    static FUEL_LIMIT: AtomicU64 = const { AtomicU64::new(u64::MAX) };
}

/// Per-script-mode-call capture buffers that `__host_log` writes into.
#[derive(Default)]
struct ScriptCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// RAII guard that activates script-mode capture for the current
/// thread and takes ownership back on drop. Calling code uses
/// [`ScriptCaptureGuard::take`] to retrieve the buffers - the `Drop`
/// impl is the safety net that fires if the caller panics.
struct ScriptCaptureGuard;

impl ScriptCaptureGuard {
    fn activate() -> Self {
        SCRIPT_CAPTURE.with(|c| {
            *c.borrow_mut() = Some(ScriptCapture::default());
        });
        Self
    }

    fn take(self) -> ScriptCapture {
        // Take BEFORE drop runs so we get the populated buffers
        // (drop's path leaves an empty default in place).
        let captured = SCRIPT_CAPTURE.with(|c| c.borrow_mut().take().unwrap_or_default());
        std::mem::forget(self);
        captured
    }
}

impl Drop for ScriptCaptureGuard {
    fn drop(&mut self) {
        // Caller panicked before `take()` - clear the slot so the
        // next call doesn't observe stale captures.
        SCRIPT_CAPTURE.with(|c| {
            let _ = c.borrow_mut().take();
        });
    }
}

/// Append a captured log line. Handles the "info"/"debug" → stdout vs
/// "warn"/"error" → stderr split that matches Node's console
/// semantics (and what the wasm path does via Javy.IO).
fn append_capture(level: &str, msg: &str) {
    SCRIPT_CAPTURE.with(|c| {
        if let Some(cap) = c.borrow_mut().as_mut() {
            let buf = if matches!(level, "warn" | "error") {
                &mut cap.stderr
            } else {
                &mut cap.stdout
            };
            buf.extend_from_slice(msg.as_bytes());
            buf.push(b'\n');
        }
    });
}

/// True iff the current thread is mid-script-mode capture. The
/// closure-installed `__host_log` consults this to decide whether to
/// route to the capture buffer or emit a workspace log event.
fn capture_is_active() -> bool {
    SCRIPT_CAPTURE.with(|c| c.borrow().is_some())
}

struct ThreadRuntime {
    runtime: Runtime,
    context: Context,
}

impl ThreadRuntime {
    fn new() -> std::result::Result<Self, AfterburnerError> {
        let runtime = Runtime::new()
            .map_err(|e| AfterburnerError::Engine(format!("engine runtime init: {e}")))?;
        let context = Context::full(&runtime)
            .map_err(|e| AfterburnerError::Engine(format!("engine context init: {e}")))?;

        // Eval the plenum bundle once per thread-local Runtime so every
        // thrust on this thread can `require('path')` etc. without
        // paying the ~45 KB parse cost again. Host-backed modules
        // (`fs`, `crypto`, `os`, `http`) are wired here too - the
        // per-thrust Manifold is read via a thread-local slot that
        // `do_thrust` populates for the duration of each call.
        context.with(|ctx| -> std::result::Result<(), AfterburnerError> {
            install_host_globals(&ctx)?;
            afterburner_node_compat::register_native_builtins(&ctx)?;
            ctx.eval::<(), _>(afterburner_node_compat::PLENUM_BUNDLE.as_bytes())
                .map_err(|e| AfterburnerError::Engine(format!("plenum bundle eval: {e}")))?;
            // Patch QuickJS's V8 CallSite prototype - same patch the
            // WASM plugin installs at Wizer pre-init. Real npm packages
            // (depd, morgan, finalhandler) call `callSite.isEval()` /
            // `getEvalOrigin()` / `isToplevel()` etc. at module-load
            // time; without the patch they crash with `not a function`.
            // Native mode runs through rquickjs which has the same
            // partial CallSite surface as the Javy runtime, so the
            // same JS snippet applies.
            ctx.eval::<(), _>(CALLSITE_PROTO_PATCH.as_bytes())
                .map_err(|e| AfterburnerError::Engine(format!("callsite proto patch: {e}")))?;
            Ok(())
        })?;

        // Install the fuel interrupt handler ONCE, after the handler-free setup
        // evals above. It reads the per-thread FUEL_COUNTER/FUEL_LIMIT that each
        // thrust resets, so no per-thrust closure allocation or FFI set-call is
        // needed (#36). u64::MAX limit means fuel is disabled (never interrupt).
        runtime.set_interrupt_handler(Some(Box::new(|| {
            let limit = FUEL_LIMIT.with(|l| l.load(Ordering::Relaxed));
            FUEL_COUNTER.with(|c| c.fetch_add(1, Ordering::Relaxed)) >= limit
        })));

        Ok(Self { runtime, context })
    }
}

/// Install the small set of host-provided globals the plenum bundle
/// expects (currently just `__host_log` for `console.*`). Keeps the JS
/// side agnostic to where logs end up.
fn install_host_globals(ctx: &Ctx<'_>) -> std::result::Result<(), AfterburnerError> {
    use rquickjs::Function;
    let globals = ctx.globals();
    globals
        .set(
            "__host_log",
            Function::new(ctx.clone(), |level: String, msg: String| {
                host_log(&level, &msg);
            })
            .map_err(|e| AfterburnerError::Engine(format!("Function::new host_log: {e}")))?,
        )
        .map_err(|e| AfterburnerError::Engine(format!("globals.set host_log: {e}")))?;
    Ok(())
}

fn host_log(level: &str, msg: &str) {
    // In native script mode, console output is captured per-call so
    // the embedder can hand it back through [`ScriptOutcome`]. Outside
    // script mode (i.e. UDF thrust), it falls through to the workspace
    // logger as before.
    if capture_is_active() {
        append_capture(level, msg);
        return;
    }
    use afterburner_core::ab_event;
    use afterburner_core::log::Level;
    let level = match level {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "debug" => Level::Debug,
        _ => Level::Info,
    };
    ab_event!(level, "script.console", "message" => msg);
}

/// Run a closure with access to the current thread's `ThreadRuntime`,
/// initializing it lazily on first use.
fn with_thread_rt<R>(f: impl FnOnce(&ThreadRuntime) -> Result<R>) -> Result<R> {
    THREAD_RT.with(|slot| {
        let mut borrow = slot.borrow_mut();
        if borrow.is_none() {
            *borrow = Some(ThreadRuntime::new()?);
        }
        let rt = borrow
            .as_ref()
            .ok_or_else(|| AfterburnerError::Engine("thread runtime uninitialized".into()))?;
        f(rt)
    })
}

pub struct NativeCombustor {
    source_store: HopscotchMap<[u8; 32], Arc<str>>,
    state_store: SharedStateStore,
    host_context: Option<Arc<dyn afterburner_core::HostContext>>,
}

impl NativeCombustor {
    pub fn new() -> Result<Self> {
        Self::with_state_store(InMemoryStateStore::shared())
    }

    /// Construct a combustor backed by an explicit state store.
    pub fn with_state_store(state_store: SharedStateStore) -> Result<Self> {
        with_thread_rt(|_rt| Ok(()))?;
        Ok(Self {
            source_store: HopscotchMap::new(),
            state_store,
            host_context: None,
        })
    }

    /// Attach an embedder-provided [`afterburner_core::HostContext`]. Scripts that call
    /// `require('afterburner:host').readColumn` or `emitRow` dispatch
    /// through this context. Default (no context) returns empty
    /// column / swallows emitted rows.
    pub fn with_host_context(mut self, ctx: Arc<dyn afterburner_core::HostContext>) -> Self {
        self.host_context = Some(ctx);
        self
    }

    pub fn state_store(&self) -> &SharedStateStore {
        &self.state_store
    }
}

impl Combustor for NativeCombustor {
    #[fastrace::trace(name = "NativeCombustor::ignite")]
    fn ignite(&self, source: &str) -> Result<ScriptId> {
        // Strip a leading hashbang/BOM before storing or probing -
        // every downstream wrap (probe, thrust stage, script stage)
        // inlines the source either as raw code or as a string
        // literal handed to `new Function(...)`, and QuickJS rejects
        // `#!` in both contexts. Normalising on entry means the
        // source_store, the bytecode hash, and every consumer all see
        // the same `//`-prefixed first line.
        let normalized = normalize_user_source(source);
        let source = normalized.as_str();
        let hash = sha256(source.as_bytes());
        // Fast-path: source already registered - skip the parse probe.
        if self.source_store.contains_key(&hash) {
            ab_event!(Level::Debug, "native.ignite.cache_hit");
            return Ok(ScriptId {
                hash,
                mode: EngineMode::Native,
            });
        }
        // Cheap parse check against this thread's Runtime. Syntax errors
        // surface here rather than at thrust time.
        with_thread_rt(|rt| {
            rt.context.with(|ctx| -> Result<()> {
                let probe = format!("(function(){{ {source}\nreturn undefined; }})");
                let _: RqValue<'_> = ctx.eval(probe.as_bytes()).map_err(|e| {
                    // For a thrown exception (e.g. a SyntaxError), pull the real
                    // message out of the context instead of the engine's opaque
                    // generic Display.
                    if matches!(e, RquickjsError::Exception) {
                        AfterburnerError::CompileFailed(exception_detail(&ctx.catch()))
                    } else {
                        AfterburnerError::CompileFailed(format!("{e}"))
                    }
                })?;
                Ok(())
            })
        })?;
        self.source_store.insert(hash, Arc::from(source));
        ab_event!(Level::Info, "native.ignite.compiled", "source_bytes" => source.len());
        Ok(ScriptId {
            hash,
            mode: EngineMode::Native,
        })
    }

    #[fastrace::trace(name = "NativeCombustor::thrust")]
    fn thrust(&self, id: &ScriptId, input: &JsonValue, limits: &FuelGauge) -> Result<JsonValue> {
        let source = self
            .source_store
            .get(&id.hash)
            .ok_or(AfterburnerError::ScriptNotFound)?;
        let input_json = serde_json::to_string(input)?;
        let output_json = with_thread_rt(|rt| {
            // Thread the engine's state store + optional host context
            // into the per-thrust slots.
            let _g = afterburner_node_compat::state_active::activate(self.state_store.clone());
            let _hg = self
                .host_context
                .as_ref()
                .map(|c| afterburner_node_compat::host_context_active::activate(c.clone()));
            do_thrust(rt, id.hash, &source, &input_json, limits)
        })?;
        Ok(serde_json::from_str(&output_json)?)
    }

    fn extinguish(&self, id: &ScriptId) {
        self.source_store.remove(&id.hash);
        // Drop this thread's compiled entry. Other threads' entries for
        // this script are reclaimed on their own extinguish/exit, or
        // evicted by the per-thread LRU cap (`ENTRY_CACHE_CAP`), so the
        // cache stays bounded regardless of the extinguish pattern.
        ENTRY_CACHE.with(|c| {
            c.borrow_mut().remove(&id.hash);
        });
        ab_event!(Level::Info, "native.extinguish");
    }

    #[fastrace::trace(name = "NativeCombustor::run_script")]
    fn run_script(
        &self,
        source: &str,
        invocation: &ScriptInvocation,
        limits: &FuelGauge,
    ) -> Result<ScriptOutcome> {
        // Same shebang/BOM normalisation `ignite` performs - script
        // mode bypasses ignite, so without this pass a `#!/usr/bin/env
        // node` prologue would land verbatim inside the user-source
        // string literal handed to `new Function(...)` and trip the
        // QuickJS private-name parser.
        let normalized = normalize_user_source(source);
        let source = normalized.as_str();
        let argv_json = serde_json::to_string(&invocation.argv)
            .map_err(|e| AfterburnerError::Engine(format!("argv json: {e}")))?;
        let env_json = serde_json::to_string(&invocation.env)
            .map_err(|e| AfterburnerError::Engine(format!("env json: {e}")))?;
        let cwd_json = serde_json::to_string(
            &(if invocation.cwd.is_empty() {
                "/"
            } else {
                invocation.cwd.as_str()
            }),
        )
        .map_err(|e| AfterburnerError::Engine(format!("cwd json: {e}")))?;
        let stage = build_script_stage(source, &argv_json, &env_json, &cwd_json);

        let _capture_guard = ScriptCaptureGuard::activate();
        let exit_code = with_thread_rt(|rt| {
            let _g = afterburner_node_compat::state_active::activate(self.state_store.clone());
            let _hg = self
                .host_context
                .as_ref()
                .map(|c| afterburner_node_compat::host_context_active::activate(c.clone()));
            let _mg = afterburner_node_compat::active_manifold::activate(limits.manifold.clone());

            rt.runtime
                .set_memory_limit(limits.memory_bytes.unwrap_or(0));
            let fuel_budget = limits.fuel;
            // Shared interrupt handler (installed once in ThreadRuntime::new);
            // reset the per-thread fuel accounting instead of a per-call closure.
            FUEL_COUNTER.with(|c| c.store(0, Ordering::Relaxed));
            FUEL_LIMIT.with(|l| l.store(fuel_budget.unwrap_or(u64::MAX), Ordering::Relaxed));

            let res = rt
                .context
                .with(|ctx| -> Result<()> { run_script_stage(&ctx, &stage) });

            // Translate the JS-side outcome into a Node-style exit code.
            // Anything that's *not* a script-level exception bubbles up
            // as Err - fuel exhaustion and memory limits stay typed.
            match res {
                Ok(()) => Ok(0),
                Err(e) => {
                    if let Some(budget) = fuel_budget
                        && FUEL_COUNTER.with(|c| c.load(Ordering::Relaxed)) >= budget
                    {
                        ab_event!(
                            Level::Warn,
                            "native.script.fuel_exhausted",
                            "budget" => budget,
                        );
                        return Err(AfterburnerError::FuelExhausted);
                    }
                    if matches!(e, AfterburnerError::MemoryLimit) {
                        ab_event!(Level::Warn, "native.script.memory_limit");
                        return Err(e);
                    }
                    // Treat as user-script exception - surface the
                    // message on captured stderr and return exit 1.
                    append_capture("error", &format!("{e}"));
                    Ok(1)
                }
            }
        })?;
        let captured = _capture_guard.take();
        Ok(ScriptOutcome {
            stdout: captured.stdout,
            stderr: captured.stderr,
            exit_code,
        })
    }
}

/// Build the JS stage that script mode evaluates. Sync outer IIFE
/// does the global setup (`__ab_argv`, `__host_env`, refreshing the
/// live `process` polyfill) and runs the user source inside a plain
/// `new Function(...)` wrapper. The wrapper's return value is
/// whatever the user source's last statement yields - typically
/// `undefined` (script mode doesn't JSON-stringify a result).
///
/// **Top-level `await` is NOT supported on this path.** rquickjs's
/// thread-local runtime surfaces a "line 3:1" parse-time exception
/// when we attempt to construct an `AsyncFunction` from here -
/// reproduced against the real `NativeCombustor::run_script` but not
/// against a fresh `Runtime` in isolation, pointing at a
/// version-pinning quirk we'd rather not paper over with a
/// half-working workaround. Scripts that need top-level `await`
/// should run through the WASM / adaptive backends (the default) -
/// that path compiles via Javy's ES-module pipeline where it's
/// first-class. On native, the idiomatic workaround is the
/// self-invoking async IIFE pattern:
///
/// ```js
/// (async () => { const v = await something(); console.log(v); })();
/// ```
///
/// which compiles fine as a sync-returned Promise; the pumping loop
/// below drains its microtasks.
fn build_script_stage(user: &str, argv_json: &str, env_json: &str, cwd_json: &str) -> String {
    let user_lit = js_string_literal(user);
    format!(
        r#"
        (function() {{
            globalThis.__ab_argv = {argv_json};
            globalThis.__host_env = {env_json};
            globalThis.__host_cwd = {cwd_json};
            if (globalThis.process) {{
                globalThis.process.argv = globalThis.__ab_argv;
                globalThis.process.env  = globalThis.__host_env;
            }}
            if (typeof globalThis.__plenum_refresh_entry_require === 'function') {{
                globalThis.__plenum_refresh_entry_require();
            }}
            var __ab_module = {{ exports: {{}} }};
            var __ab_user = new Function(
                'module', 'exports', 'require', {user_lit}
            );
            return __ab_user(__ab_module, __ab_module.exports, globalThis.require);
        }})()
        "#
    )
}

/// Eval the script-mode stage and pump pending jobs until the
/// returned Promise resolves or rejects. Uses the same microtask-cap
/// guardrail as `run_script` (UDF mode) to bound runaway chains even
/// if the interrupt handler under-fires.
fn run_script_stage(ctx: &Ctx<'_>, stage: &str) -> Result<()> {
    let result_val: rquickjs::Value<'_> = ctx
        .eval(stage.as_bytes())
        .map_err(|e| map_script_err(ctx, e))?;

    // Same belt-and-suspenders cap as the UDF path. See run_script in
    // this file for the rationale.
    const MAX_PUMP_ITERATIONS: usize = 1_000_000;
    for _ in 0..MAX_PUMP_ITERATIONS {
        if !ctx.execute_pending_job() {
            break;
        }
    }
    if ctx.execute_pending_job() {
        return Err(AfterburnerError::FuelExhausted);
    }

    // The sync `new Function(...)` wrapper returns whatever the user
    // source's last statement produces. If that's a Promise (e.g. an
    // `(async () => {...})()` IIFE), we pump it; otherwise done.
    // Detect a thenable via duck-typing rather than
    // `Promise::from_value` because the latter errors on non-Promise
    // objects, and script-mode user code commonly returns `undefined`.
    let is_thenable = result_val
        .as_object()
        .and_then(|o| o.get::<_, rquickjs::Value<'_>>("then").ok())
        .map(|v| v.is_function())
        .unwrap_or(false);
    if !is_thenable {
        return Ok(());
    }
    let promise = rquickjs::Promise::from_value(result_val.clone())
        .map_err(|e| AfterburnerError::Engine(format!("Promise::from_value: {e}")))?;
    promise
        .finish::<rquickjs::Value<'_>>()
        .map(|_| ())
        .map_err(|e| map_script_err(ctx, e))
}

/// Maps an rquickjs error to the typed `AfterburnerError` set, extracting the
/// real exception detail via `ctx.catch()` so users see the actual error
/// (e.g. `ReferenceError: x is not defined`) instead of a generic placeholder.
fn map_script_err(ctx: &Ctx<'_>, err: RquickjsError) -> AfterburnerError {
    match err {
        RquickjsError::Allocation => AfterburnerError::MemoryLimit,
        RquickjsError::Unknown => AfterburnerError::Engine("unknown engine error".into()),
        ref other => {
            let base = format!("{other}");
            if base.contains("interrupt") || base.contains("Interrupt") {
                return AfterburnerError::FuelExhausted;
            }
            if base.contains("out of memory") || base.contains("OutOfMemory") {
                return AfterburnerError::MemoryLimit;
            }
            if matches!(other, RquickjsError::Exception) {
                // Pull the actual exception value out of the context.
                let exc_val = ctx.catch();
                let detail = exception_detail(&exc_val);
                return AfterburnerError::CompileFailed(detail);
            }
            AfterburnerError::Engine(base)
        }
    }
}

/// Best-effort human-readable rendering of an rquickjs exception
/// value. Prefers the shape `"Error: <message>\n<stack>"` that Node
/// users recognize - QuickJS's `.stack` lacks the leading "Error:
/// msg" line that V8 includes, so we reassemble it here.
fn exception_detail(value: &rquickjs::Value<'_>) -> String {
    if let Some(obj) = value.as_object() {
        let message = obj
            .get::<_, String>("message")
            .ok()
            .filter(|m| !m.is_empty());
        let stack = obj.get::<_, String>("stack").ok().filter(|s| !s.is_empty());
        let name = obj
            .get::<_, String>("name")
            .ok()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Error".to_string());
        return match (message, stack) {
            (Some(m), Some(s)) => format!("{name}: {m}\n{s}"),
            (Some(m), None) => format!("{name}: {m}"),
            (None, Some(s)) => s,
            (None, None) => name,
        };
    }
    if value.is_string()
        && let Some(s) = value.as_string()
        && let Ok(text) = s.to_string()
    {
        return text;
    }
    format!("uncaught exception (type {})", value.type_of().as_str())
}

/// Actual script execution - runs on the caller's thread against the
/// thread-local `ThreadRuntime`.
fn do_thrust(
    rt: &ThreadRuntime,
    hash: [u8; 32],
    source: &str,
    input_json: &str,
    limits: &FuelGauge,
) -> Result<String> {
    // Activate the per-thrust manifold so host globals can read it. The
    // guard restores the previous value when `do_thrust` returns.
    let _manifold_guard =
        afterburner_node_compat::active_manifold::activate(limits.manifold.clone());

    rt.runtime
        .set_memory_limit(limits.memory_bytes.unwrap_or(0));

    let fuel_budget = limits.fuel;
    // Reset the per-thread fuel accounting for the shared interrupt handler
    // (installed once in ThreadRuntime::new); u64::MAX limit = fuel disabled.
    FUEL_COUNTER.with(|c| c.store(0, Ordering::Relaxed));
    FUEL_LIMIT.with(|l| l.store(fuel_budget.unwrap_or(u64::MAX), Ordering::Relaxed));

    let result = rt
        .context
        .with(|ctx| -> Result<String> { run_script(&ctx, hash, source, input_json) });

    match result {
        Ok(v) => {
            // Output-ceiling parity with the wasm path's capture pipe:
            // the serialized result must fit FuelGauge::output_bytes
            // (exactly-at passes, past errors) regardless of engine tier.
            let ceiling = limits.output_ceiling();
            if v.len() > ceiling {
                ab_event!(Level::Warn, "native.thrust.output_too_large", "limit" => ceiling);
                return Err(AfterburnerError::OutputTooLarge { limit: ceiling });
            }
            Ok(v)
        }
        Err(e) => {
            if let Some(budget) = fuel_budget
                && FUEL_COUNTER.with(|c| c.load(Ordering::Relaxed)) >= budget
            {
                ab_event!(Level::Warn, "native.thrust.fuel_exhausted", "budget" => budget);
                return Err(AfterburnerError::FuelExhausted);
            }
            Err(map_value_api_markers(e))
        }
    }
}

/// Recover typed value-API errors from the envelope's marker exceptions
/// (the JS layer cannot construct Rust error variants directly).
fn map_value_api_markers(e: AfterburnerError) -> AfterburnerError {
    let msg = e.to_string();
    if let Some(pos) = msg.find("__AB_UNEXPECTED_RAW__:") {
        let digits: String = msg[pos + "__AB_UNEXPECTED_RAW__:".len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(len) = digits.parse() {
            return AfterburnerError::UnexpectedRawOutput { len };
        }
    }
    e
}

/// Build the input-independent envelope wrapper for a UDF's compiled
/// entry point. Byte-for-byte the same module/exports/`__abr`
/// semantics `run_script` has always evaluated, except the input
/// arrives as the `__input_json` parameter instead of being spliced
/// into the source text as a string literal (#14) - that's what makes
/// the compiled function safe to cache and reuse across thrusts with
/// different inputs (#24).
fn build_entry_wrapper(source: &str) -> String {
    format!(
        r#"
        (function(__input_json) {{
            var __module = {{ exports: undefined }};
            var module = __module;
            var exports = __module.exports;
            var __input = JSON.parse(__input_json);
            (function() {{
                {user_source}
            }})();
            var __fn = module.exports;
            // __abr: value-API parity with the wasm path - raw byte
            // returns surface the __AB_UNEXPECTED_RAW__ marker (mapped
            // to UnexpectedRawOutput host-side).
            var __abr=function(r){{if(r&&(r instanceof Uint8Array||r instanceof ArrayBuffer))throw Error('__AB_UNEXPECTED_RAW__:'+r.byteLength);return JSON.stringify(r===undefined?null:r);}};
            var __result = (typeof __fn === 'function') ? __fn(__input) : __fn;
            // If the user didn't return a thenable, hand back the
            // stringified result directly - no Promise wrap, no pump.
            if (__result === null || typeof __result !== 'object' || typeof __result.then !== 'function') {{
                return __abr(__result);
            }}
            // Slow path: thenable. Return the Promise chain; caller
            // will pump microtasks and `.finish::<String>()` on it.
            return __result.then(__abr);
        }})
        "#,
        user_source = source,
    )
}

/// Build + evaluate the envelope-wrapped script and return
/// `JSON.stringify(result)`.
///
/// The compiled entry function is cached per (thread, script-hash) in
/// `ENTRY_CACHE` - QuickJS parses and compiles the envelope once per
/// thread instead of once per thrust, which was the dominant native
/// warm cost. Caching the *function* rather than any result preserves
/// the feature-safety invariant: every thrust still runs the user's
/// top-level code against a fresh `module` (reset semantics), so e.g.
/// `let n = 0; module.exports = () => ++n` returns `1` on every
/// thrust - matching the wasm reference path, which constructs a
/// fresh `new Function(...)` per invoke.
///
/// Fast path: the user function returns a non-Promise. We call the
/// cached envelope, get a `String` back, done - no pending-job pump,
/// no extra allocation. This is the vast majority of scripts (UDFs,
/// transforms, flow ops).
///
/// Slow path: the user function returns a Promise (directly or via
/// `async`). We detect that, drain pending microtasks until the
/// Promise resolves, then JSON-stringify the resolved value. Matches
/// the Javy `event_loop(true)` behavior on the WASM side so scripts
/// that use `fetch().then(...)` or `await` work identically across
/// engines.
/// Next per-thread LRU tick for `ENTRY_CACHE`.
fn next_entry_tick() -> u64 {
    ENTRY_TICK.with(|t| {
        let n = t.get().wrapping_add(1);
        t.set(n);
        n
    })
}

fn run_script(ctx: &Ctx<'_>, hash: [u8; 32], source: &str, input_json: &str) -> Result<String> {
    let cached = ENTRY_CACHE.with(|c| {
        c.borrow().get(&hash).map(|(func, tick)| {
            tick.set(next_entry_tick());
            func.clone()
        })
    });
    let entry: Function<'_> = match cached {
        Some(persistent) => persistent
            .restore(ctx)
            .map_err(|e| map_script_err(ctx, e))?,
        None => {
            let wrapper = build_entry_wrapper(source);
            let func: Function<'_> = ctx
                .eval(wrapper.as_bytes())
                .map_err(|e| map_script_err(ctx, e))?;
            ENTRY_CACHE.with(|c| {
                let mut cache = c.borrow_mut();
                // Bound the per-thread cache: when full, evict the
                // least-recently-used entry so a high-cardinality script
                // workload cannot grow it without bound (extinguish only
                // reclaims the calling thread's entry).
                if cache.len() >= ENTRY_CACHE_CAP
                    && !cache.contains_key(&hash)
                    && let Some(lru) = cache
                        .iter()
                        .min_by_key(|(_, (_, tick))| tick.get())
                        .map(|(k, _)| *k)
                {
                    cache.remove(&lru);
                }
                cache.insert(
                    hash,
                    (Persistent::save(ctx, func.clone()), Cell::new(next_entry_tick())),
                );
            });
            func
        }
    };
    let result_val: rquickjs::Value<'_> = entry
        .call((input_json,))
        .map_err(|e| map_script_err(ctx, e))?;

    // Fast path: plain string result - done.
    if let Some(s) = result_val.as_string() {
        return s
            .to_string()
            .map_err(|e| AfterburnerError::Engine(format!("result to_string: {e}")));
    }

    // Slow path: result is a Promise. Pump microtasks until the queue
    // drains, then resolve.
    //
    // Belt-and-suspenders iteration cap: the rquickjs interrupt
    // handler should fire between bytecode ops within each job, which
    // in theory bounds runaway microtask chains via fuel. In practice
    // we've observed `queueMicrotask(step)` recursion where the
    // per-job opcode count is so low that the interrupt handler
    // rarely fires - scripts can run for minutes before the counter
    // accumulates past the fuel budget. The MAX_PUMP_ITERATIONS cap
    // guarantees we can never spin forever even if the interrupt
    // path mis-fires.
    const MAX_PUMP_ITERATIONS: usize = 1_000_000;
    for _ in 0..MAX_PUMP_ITERATIONS {
        if !ctx.execute_pending_job() {
            break;
        }
    }
    if ctx.execute_pending_job() {
        return Err(AfterburnerError::FuelExhausted);
    }
    let promise = rquickjs::Promise::from_value(result_val.clone())
        .map_err(|e| AfterburnerError::Engine(format!("Promise::from_value: {e}")))?;
    promise
        .finish::<String>()
        .map_err(|e| map_script_err(ctx, e))
}

/// Escape a Rust string so it can be embedded as a JS string literal.
fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn combust(source: &str, input: JsonValue) -> Result<JsonValue> {
        let c = NativeCombustor::new()?;
        let id = c.ignite(source)?;
        c.thrust(&id, &input, &FuelGauge::unlimited())
    }

    #[test]
    fn eval_arithmetic() {
        let out = combust("module.exports = () => 1 + 2", json!(null)).unwrap();
        assert_eq!(out, json!(3));
    }

    #[test]
    fn entry_cache_is_bounded_by_cap() {
        // Thrust many DISTINCT scripts on this thread without extinguishing
        // any. The per-thread compile cache must stay <= ENTRY_CACHE_CAP via
        // LRU eviction, so a high-cardinality workload cannot grow it without
        // bound (the failure mode a missing size cap would produce).
        let c = NativeCombustor::new().unwrap();
        for i in 0..(ENTRY_CACHE_CAP + 100) {
            let src = format!("module.exports = () => {i};");
            let id = c.ignite(&src).unwrap();
            let out = c.thrust(&id, &json!(null), &FuelGauge::unlimited()).unwrap();
            assert_eq!(out, json!(i));
        }
        let len = ENTRY_CACHE.with(|cache| cache.borrow().len());
        assert!(
            len <= ENTRY_CACHE_CAP,
            "ENTRY_CACHE grew to {len}, exceeding cap {ENTRY_CACHE_CAP}"
        );
    }

    #[test]
    fn require_path_join_works() {
        let src = r#"
            const path = require('path');
            module.exports = () => path.join('/var', 'data', 'x.json');
        "#;
        let out = combust(src, json!(null)).unwrap();
        assert_eq!(out, json!("/var/data/x.json"));
    }

    #[test]
    fn require_querystring_roundtrip() {
        let src = r#"
            const qs = require('querystring');
            module.exports = () => qs.parse(qs.stringify({ a: '1', b: 'two & three' }));
        "#;
        let out = combust(src, json!(null)).unwrap();
        assert_eq!(out, json!({ "a": "1", "b": "two & three" }));
    }

    #[test]
    fn require_events_emitter_roundtrip() {
        let src = r#"
            const EventEmitter = require('events');
            module.exports = () => {
                const ee = new EventEmitter();
                let captured = null;
                ee.on('ping', (x) => { captured = x; });
                ee.emit('ping', 42);
                return captured;
            };
        "#;
        let out = combust(src, json!(null)).unwrap();
        assert_eq!(out, json!(42));
    }

    #[test]
    fn require_buffer_hex_roundtrip() {
        let src = r#"
            const { Buffer } = require('buffer');
            module.exports = () => Buffer.from('afterburner').toString('hex');
        "#;
        let out = combust(src, json!(null)).unwrap();
        assert_eq!(out, json!("61667465726275726e6572"));
    }

    #[test]
    fn require_unknown_module_throws() {
        let src = r#"
            module.exports = () => {
                try { require('no-such-module'); return 'unexpected'; }
                catch (e) { return e.message; }
            };
        "#;
        let out = combust(src, json!(null)).unwrap();
        assert_eq!(out, json!("Cannot find module 'no-such-module'"));
    }

    #[test]
    fn require_node_prefix_stripped() {
        let src = r#"
            const path = require('node:path');
            module.exports = () => path.basename('/a/b/c.js');
        "#;
        let out = combust(src, json!(null)).unwrap();
        assert_eq!(out, json!("c.js"));
    }

    #[test]
    fn eval_string_ops() {
        let out = combust(
            "module.exports = (d) => d.name.toUpperCase()",
            json!({"name": "alice"}),
        )
        .unwrap();
        assert_eq!(out, json!("ALICE"));
    }

    #[test]
    fn eval_json_roundtrip() {
        let out = combust(
            "module.exports = (d) => ({ doubled: d.n * 2, keys: Object.keys(d).length })",
            json!({"n": 21}),
        )
        .unwrap();
        assert_eq!(out, json!({"doubled": 42, "keys": 1}));
    }

    #[test]
    fn eval_array_methods() {
        let out = combust(
            "module.exports = (d) => d.xs.map(x => x * 2).reduce((a, b) => a + b, 0)",
            json!({"xs": [1, 2, 3, 4]}),
        )
        .unwrap();
        assert_eq!(out, json!(20));
    }

    #[test]
    fn eval_object_destructuring() {
        let out = combust(
            "module.exports = ({a, b}) => ({sum: a + b})",
            json!({"a": 3, "b": 4}),
        )
        .unwrap();
        assert_eq!(out, json!({"sum": 7}));
    }

    #[test]
    fn eval_es2020_optional_chain() {
        let out = combust(
            "module.exports = (d) => d?.nested?.missing ?? 'fallback'",
            json!({"nested": {}}),
        )
        .unwrap();
        assert_eq!(out, json!("fallback"));
    }

    #[test]
    fn compile_failed_on_syntax_error() {
        let c = NativeCombustor::new().unwrap();
        let err = c.ignite("module.exports = (").unwrap_err();
        match err {
            AfterburnerError::CompileFailed(_) => {}
            other => panic!("expected CompileFailed, got {other:?}"),
        }
    }

    #[test]
    fn fuel_exhaustion_returns_typed_error() {
        let c = NativeCombustor::new().unwrap();
        let id = c
            .ignite("module.exports = () => { while (true) {} }")
            .unwrap();
        let limits = FuelGauge {
            fuel: Some(1_000),
            ..FuelGauge::default()
        };
        let err = c.thrust(&id, &json!(null), &limits).unwrap_err();
        match err {
            AfterburnerError::FuelExhausted => {}
            other => panic!("expected FuelExhausted, got {other:?}"),
        }
    }

    #[test]
    fn script_not_found_after_extinguish() {
        let c = NativeCombustor::new().unwrap();
        let id = c.ignite("module.exports = () => 1").unwrap();
        c.extinguish(&id);
        let err = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap_err();
        assert!(matches!(err, AfterburnerError::ScriptNotFound));
    }

    #[test]
    fn hash_is_content_addressed() {
        let c = NativeCombustor::new().unwrap();
        let id1 = c.ignite("module.exports = () => 1").unwrap();
        let id2 = c.ignite("module.exports = () => 1").unwrap();
        assert_eq!(id1.hash, id2.hash);
    }

    #[test]
    fn cross_thread_thrust_uses_per_thread_runtime() {
        use std::thread;

        let c = Arc::new(NativeCombustor::new().unwrap());
        let id = c.ignite("module.exports = (d) => d.n * 2").unwrap();

        // Thrust from 4 different threads. Each should spin up its own
        // thread-local Runtime and compute independently.
        let mut handles = Vec::new();
        for n in 1..=4u64 {
            let c = c.clone();
            handles.push(thread::spawn(move || {
                c.thrust(&id, &json!({ "n": n }), &FuelGauge::unlimited())
                    .unwrap()
            }));
        }
        let outs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(outs, vec![json!(2), json!(4), json!(6), json!(8)]);
    }

    // -- #14/#24: cached entry-function feature safety -----------------

    #[test]
    fn cached_entry_resets_module_state_per_thrust() {
        // Pins the reset invariant: the compiled entry function is
        // reused across thrusts, but the user's top-level code (and
        // therefore `n`) must still run fresh each time. If the cache
        // ever skipped re-running the top level, this would observe
        // 1, 2, 3 instead of 1, 1, 1.
        let c = NativeCombustor::new().unwrap();
        let id = c.ignite("let n = 0; module.exports = () => ++n;").unwrap();
        for _ in 0..3 {
            let out = c
                .thrust(&id, &json!(null), &FuelGauge::unlimited())
                .unwrap();
            assert_eq!(out, json!(1));
        }
    }

    #[test]
    fn cached_entry_sees_fresh_input_each_thrust() {
        // Proves the cached function is input-independent: different
        // inputs on the same script id against the same cache entry
        // still produce different, correct outputs.
        let c = NativeCombustor::new().unwrap();
        let id = c.ignite("module.exports = (d) => d.n + 1;").unwrap();
        let out1 = c
            .thrust(&id, &json!({"n": 1}), &FuelGauge::unlimited())
            .unwrap();
        let out2 = c
            .thrust(&id, &json!({"n": 2}), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out1, json!(2));
        assert_eq!(out2, json!(3));
    }

    #[test]
    fn cached_entry_supports_async_export() {
        let out = combust("module.exports = async (x) => x.n + 1;", json!({"n": 1})).unwrap();
        assert_eq!(out, json!(2));
    }

    #[test]
    fn cached_entry_surfaces_unexpected_raw_output() {
        let c = NativeCombustor::new().unwrap();
        let id = c
            .ignite("module.exports = () => new Uint8Array([1, 2, 3]);")
            .unwrap();
        let err = c
            .thrust(&id, &json!(null), &FuelGauge::unlimited())
            .unwrap_err();
        match err {
            AfterburnerError::UnexpectedRawOutput { len } => assert_eq!(len, 3),
            other => panic!("expected UnexpectedRawOutput, got {other:?}"),
        }
    }

    #[test]
    fn reignite_after_extinguish_recompiles_and_runs() {
        // Extinguish drops this thread's cache entry; re-igniting the
        // same source (same content hash) must still compile and run
        // correctly rather than serving a stale or missing entry.
        let c = NativeCombustor::new().unwrap();
        let src = "module.exports = () => 41 + 1;";
        let id1 = c.ignite(src).unwrap();
        let out1 = c
            .thrust(&id1, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out1, json!(42));

        c.extinguish(&id1);

        let id2 = c.ignite(src).unwrap();
        assert_eq!(id1.hash, id2.hash);
        let out2 = c
            .thrust(&id2, &json!(null), &FuelGauge::unlimited())
            .unwrap();
        assert_eq!(out2, json!(42));
    }
}
