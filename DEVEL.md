
## Requirements

### Runtime

Nothing external is needed at runtime. The Javy plugin is committed as a
Wizer-preinitialized `.wasm` at
`crates/afterburner-wasi/plugin/afterburner_plugin.wasm` and pulled in via
`include_bytes!`. Consumers just depend on the afterburner crates.

### Build (default workspace)

| Tool | Version | Notes |
|:-----|:--------|:------|
| Rust | 1.99+ (2024 ed) | `rustup install stable` on most systems |
| Cargo | shipped with Rust | `cargo build` / `cargo test` work unmodified |
| libclang | any recent | required by `rquickjs-sys` bindgen |
| C compiler | any recent | required by `rquickjs-sys` / QuickJS |

### Build (plugin regeneration — required for polyfill / extern changes)

Needed when changing plugin Rust code, plugin extern decls, JS bridges,
or any file under `crates/afterburner-node-compat/polyfills/`. The committed
`.wasm` is otherwise authoritative.

| Tool | Version | How to get it |
|:-----|:--------|:--------------|
| `wasm32-wasip1` target | via rustup | `rustup target add wasm32-wasip1` |
| `javy` CLI | exactly 8.1.1 | `cargo install javy-cli` or [releases](https://github.com/bytecodealliance/javy/releases). Newer / older javy versions are not validated. |
| `wasm-opt` (Binaryen) | 119+ | Required to lower modern WASM features (bulk-memory, sign-ext, nontrapping-fptoint) that javy 8.1.1's bundled validator rejects. Install from [Binaryen releases](https://github.com/WebAssembly/binaryen/releases) or `npm install -g binaryen`. The build script falls back to a direct copy if `wasm-opt` isn't on `$PATH`, but the subsequent `javy init-plugin` will then fail with a wasm-validator error. |

The build script auto-discovers `javy` and `wasm-opt` via `$PATH` first,
then falls back to `~/.local/bin/<tool>`. Override with `JAVY=...` /
`WASM_OPT=...` env vars.

Regenerate the plugin:

```bash
# 1. Rebuild the plenum bundle from polyfills/.
AFTERBURNER_REBUILD_PLENUM=1 cargo build -p afterburner-node-compat

# 2. Compile + lower wasm features + Wizer-preinit.
#    The script:
#      a) cargo build --target wasm32-wasip1 --release
#      b) wasm-opt lowers bulk-memory / sign-ext / nontrapping-fptoint
#         to MVP-compatible ops so javy's validator accepts the module
#      c) javy init-plugin freezes the QuickJS runtime + plenum bundle
#         into the wasm so first-run startup is sub-millisecond
bash crates/afterburner-plugin/build.sh   # writes ../afterburner-wasi/plugin/afterburner_plugin.wasm
```

### Development environment summary

For local development end-to-end, install in this order:

1. **Rust stable 1.99+** with the wasm32-wasip1 target:
   ```bash
   rustup install stable
   rustup target add wasm32-wasip1
   ```
2. **System libraries** for `rquickjs-sys` bindgen:
   ```bash
   # Debian/Ubuntu
   sudo apt install build-essential clang libclang-dev pkg-config
   # macOS
   xcode-select --install
   ```
3. **Plugin regeneration toolchain** (only if you'll touch
   `crates/afterburner-plugin/` or `crates/afterburner-node-compat/polyfills/`):
   ```bash
   # javy CLI 8.1.1
   curl -L https://github.com/bytecodealliance/javy/releases/download/v8.1.1/javy-x86_64-linux-v8.1.1.gz \
     | gunzip > ~/.local/bin/javy && chmod +x ~/.local/bin/javy

   # Binaryen (wasm-opt) 119+
   curl -L https://github.com/WebAssembly/binaryen/releases/download/version_129/binaryen-version_129-x86_64-linux.tar.gz \
     | tar -xz -C /tmp && cp /tmp/binaryen-version_129/bin/wasm-opt ~/.local/bin/
   ```
4. **Build the workspace**:
   ```bash
   cargo build --workspace --exclude afterburner-plugin
   cargo test  --workspace --exclude afterburner-plugin
   ```

The plugin crate is excluded from `--workspace` builds because it
targets `wasm32-wasip1` and can't compile on the host triple — its
behavior is exercised end-to-end through the host crates' tests
that load the committed `.wasm`.

### Release builds

The default `[profile.release]` is already tuned (`opt-level=3`, fat
LTO, single codegen unit, stripped symbols, `panic="abort"`). For
shipping the `burn` CLI:

```bash
cargo build -p afterburner --features bin --release
# 21 MB single binary, statically linked to SQLite (when
# shadow-sqlite3 is on) and rustls. No runtime libsqlite3.so /
# libssl needed.
```

For shipping with **every shadow** baked in:

```bash
cargo build -p afterburner --release --features \
  bin,ts,shadow-bcrypt,shadow-argon2,shadow-jsonwebtoken,shadow-sqlite3,shadow-sharp
```

---

## Runbook

| Command | What it does |
|:--------|:-------------|
| `cargo build` | Builds the six host crates (skips the plugin). |
| `cargo test --workspace --exclude afterburner-plugin` | Runs the full 450+ test suite (set `--features bin,ts,all-shadows` to include the L3 shadow tests). |
| `cargo clippy --workspace --exclude afterburner-plugin --all-targets` | Linter check. |
| `cargo test -p afterburner-ignite --release perf_smoke` | Native throughput smoke. |
| `cargo test -p afterburner-wasi --release perf_smoke` | WASM throughput smoke. |
| `crates/afterburner-plugin/build.sh` | Rebuild + Wizer-preinit the plugin. |
| `cargo build --profile cli-release -p afterburner --bin burn --features release-cli` | Build the shippable `burn` binary locally. |
| `cargo release --execute patch` | Bump workspace version, commit, tag `vX.Y.Z`, push. The release workflow is currently set to manual-only (`workflow_dispatch`); run it from the GitHub UI with the tag as input to build + upload multi-platform binaries. See `release.toml`. |

---

## Environment Variables

| Variable | Default | Purpose |
|:---------|:--------|:--------|
| `AFTERBURNER_LOG` | `warn` | Level filter: `off` / `error` / `warn` / `info` / `debug` / `trace` |
| `AFTERBURNER_LOG_FORMAT` | `text` | Reporter format: `text` (stderr) or `json` (stdout NDJSON) |
| `AFTERBURNER_REBUILD_PLENUM` | unset | Set to `1` to regenerate `generated/plenum_bundle.js`. |

Applications opt in to logging with:

```rust
afterburner_core::log::init();  // reads AFTERBURNER_LOG + AFTERBURNER_LOG_FORMAT
```

---

## Node.js Compat Surface

Afterburner targets the **Node.js 20.x LTS API surface**. The summary
table is below; the full per-module breakdown — with status, links to
the official Node.js docs, and notes on any deliberate divergences —
lives in **[`docs/NODE_COMPAT.md`](./docs/NODE_COMPAT.md)**.

> **Drop-in promise:** code that runs under `node script.js` should
> run unchanged under `burn script.js`. Where it doesn't, that's a
> bug — file an issue with a Node.js docs link and a minimal repro.

| Group | Modules | Gate |
|:------|:--------|:-----|
| **Pure JS** | `path`, `url`, `querystring`, `events`, `assert`, `buffer`, `util`, `string_decoder`, `punycode`, `timers`, `process`, `console`, `stream` | none — always available |
| **Web globals** | `fetch`, `Request`, `Response`, `Headers`, `AbortController`, `AbortSignal`, `URL`, `URLSearchParams`, `TextEncoder`, `TextDecoder`, `btoa`/`atob`, `queueMicrotask`, `performance.now`, `structuredClone` | none |
| **Host-backed** | `fs` (incl. `createReadStream` / `createWriteStream`, `fs.promises`) | `Manifold::fs` (`None` / `ReadOnly(roots)` / `ReadWrite(roots)`) |
| | `crypto` (hash, hmac, AES-GCM/CBC, PBKDF2, scrypt, RSA & ECDSA sign/verify, randomBytes/UUID) | `Manifold::crypto` |
| | `http` / `https` | `Manifold::net` (outbound only) |
| | `dns` — `lookup` + `resolve{4,6,Mx,Txt,Cname,Ns}` + `reverse` (record-type-aware via `hickory-resolver`); `dns.Resolver` class; callback + `dns.promises.*` shapes | `Manifold::net` (any non-`None` unlocks DNS; `None` → `EACCES`) |
| | `os` | always on (non-sensitive) |
| | `zlib` (deflate/inflate/gzip/gunzip via Rust `flate2`) | always on (pure compute) |
| | `child_process` | `Manifold::child_process` — **native path only** |
| | `worker_threads` (Worker / parentPort / workerData / postMessage / terminate / threadId) | `Manifold` — children inherit the parent's manifold (never widened); `BURN_WORKER_DEPTH` ≤ 8 |
| | `net` (raw TCP) — `net.connect` / `net.createServer` / Socket / Server / `isIP{,v4,v6}`; daemon-only inbound listening; 64 KiB write HWM with `'drain'` backpressure | `Manifold::net` — outbound requires `OutboundFull` (raw TCP escapes URL-shaped policy, so `OutboundHttp` is rejected); host allow-list supports exact, `*`, and `*.suffix` |
| | `tls` (raw TLS) — `tls.connect` / `tls.createServer` / TLSSocket on `tokio-rustls`; Mozilla `webpki-roots` for client verification, `rejectUnauthorized: false` + custom `ca:` PEM, ALPN; PEM `cert` + `key` on the server side | `Manifold::net` — same posture as `net` (`OutboundFull` only) |
| **Custom** | `afterburner:state` — cross-invocation key/value store | implicit — host installs the `StateStore` |

The library default manifold is `Manifold::sealed()` — safe to hand
untrusted user scripts. The `burn` CLI defaults to `Manifold::open()`
so Node scripts drop in without flags; `--sandbox` flips it back to
sealed. See [`docs/NODE_COMPAT.md`](./docs/NODE_COMPAT.md#sandbox-model)
for the full sandbox-model section.

---

## FAQ

<details>
<summary><b>Why is <code>crates/afterburner-wasi/plugin/afterburner_plugin.wasm</code> in the repo?</b></summary>

That is the committed Wizer-preinitialized Javy plugin, pulled in at
compile time via `include_bytes!`. Storing it in the repo keeps
`cargo build` reproducible and network-free.
</details>

<details>
<summary><b>Does the runtime shell out to <code>javy</code>?</b></summary>

No. The plugin compiles JS source to bytecode in-process via
`javy_plugin_api::compile_src` and runs it via `javy_plugin_api::invoke`.
`javy` is only used during plugin regeneration (`build.sh`).
</details>

<details>
<summary><b>Can I swap in a newer Wasmtime?</b></summary>

Yes — pin the version in the workspace `Cargo.toml` and run tests. The
workspace is already on Wasmtime 36; bumping further is mostly an
import-path chore (we already live through the `p2::pipe` move).
</details>

<details>
<summary><b>What about WASI Preview 2 / components?</b></summary>

The authoritative interface is specified in `docs/wit/afterburner-host.wit`
and `docs/wit/README.md`. The runtime still uses the core-module path for
pragmatic reasons — `javy init-plugin` requires Wizer preinit, and Wizer
outputs a flattened core module even when given a component input, so
the component-model host-side linker does not meaningfully simplify
things today. The WIT file stays as source-of-truth for future
migration.
</details>

<details>
<summary><b>How do I bundle multiple JS files together?</b></summary>

`FlowEngine::load_bundle(entry, modules)` accepts an entry script plus
a list of `(name, source)` helper modules. Inside the entry,
`require('./util')` resolves to the helper registered under `"./util"`.
Helpers can `require` each other.

```rust
let id = engine.load_bundle(
    "module.exports = (i) => require('./lib').double(i.n);",
    &[("./lib".into(), "module.exports = { double: (n) => n*2 };".into())],
)?;
```
</details>

<details>
<summary><b>Cross-invocation state</b></summary>

Pass a `SharedStateStore` to the engine. The default `InMemoryStateStore`
(lock-free, in-process) ships with the workspace; embedders can plug in
their own (Redis, SQLite, …) by implementing the `StateStore` trait.

```rust
use afterburner_core::InMemoryStateStore;
use afterburner_wasi::WasmConfig;

let store = InMemoryStateStore::shared();
let combustor = WasmCombustor::new(WasmConfig {
    state_store: Some(store.clone()),
})?;
```

Inside JS:

```js
const state = require('afterburner:state');
state.setJSON('lastSeen', Date.now());
const n = state.increment('hits');
```
</details>

---

## Releasing

```bash
cargo release --execute patch    # or minor / major
```

What happens:

1. cargo-release bumps the workspace version (every member crate inherits via `version.workspace = true`).
2. Commits the bump (`chore: release X.Y.Z`).
3. Tags the commit `vX.Y.Z` and pushes commit + tag to `origin`.
4. **Manual step** — run `.github/workflows/release.yml` from the GitHub UI's "Run workflow" button with the tag as input. The release workflow is intentionally set to `workflow_dispatch` only (auto-triggers commented out); see the comment at the top of the file. Once invoked it:
   - Builds `burn` for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` with `--features release-cli` against the `cli-release` Cargo profile.
   - Bundles the binary + `README.md` + `LICENSE` + `docs/`.
   - SHA-256 sidecar per archive.
   - Creates / updates the GitHub Release named after the tag and uploads every artifact.

Manual rolls without `cargo release` are also supported — bump `version` in `[workspace.package]` by hand, push a `v*.*.*` tag, then trigger the workflow.

CI (`.github/workflows/ci.yml`) is also `workflow_dispatch`-only at the moment. When enabled it runs `fmt`, `clippy` (default + `release-cli`), workspace tests on Ubuntu + macOS, doc build, and a plugin-`.wasm` rebuild check that compares the bundled-polyfill SHA against the committed sidecar so polyfill drift can't sneak in.

---
