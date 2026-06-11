<p align="center">
  <img src="https://github.com/afterburner-sh/afterburner/raw/master/art/svg/afterburner-bg-2000x500.svg" alt="Afterburner" width="100%"/>
</p>

<p align="center">
  <strong>A sandboxed JavaScript VM for Rust. Execute untrusted scripts with memory limits, timeouts, capability-gated I/O, and threading.</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/afterburner"><img src="https://img.shields.io/crates/v/afterburner?style=flat-square&color=e6832e" alt="crates.io"/></a>
  <a href="https://docs.rs/afterburner"><img src="https://img.shields.io/docsrs/afterburner?style=flat-square&color=2a9d8f" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/rust-1.90%2B_(2024_ed)-blue?style=flat-square&logo=rust&logoColor=white" alt="MSRV"/>
  <img src="https://img.shields.io/badge/license-BUSL--1.1-orange?style=flat-square" alt="License"/>
  <a href="https://discord.gg/GfTJmZaNNn"><img src="https://img.shields.io/badge/discord-join%20chat-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"/></a>
</p>

---

Afterburner lets you load, execute, and unload JavaScript from Rust with hard resource limits and fine-grained permission controls. Node.js built-ins (`fs`, `crypto`, `http`, `zlib`, `child_process`, and more) are available but locked behind capability gates you configure per-script.

## Library usage

```toml
[dependencies]
afterburner = "0.1"
```

```rust
use afterburner::Afterburner;
use serde_json::json;

let ab = Afterburner::new()?;
let id = ab.register("module.exports = (d) => d.n + 1")?;
let out = ab.run(&id, &json!({ "n": 41 }))?;
assert_eq!(out, json!(42));
```

The default picks the best mode available (`adaptive` → native on the first call, WASM-sandboxed on the second). Use `Afterburner::builder()` for mode + limits + capabilities:

```rust
use afterburner::{Afterburner, Manifold, FsAccess};

let ab = Afterburner::builder()
    .fuel(1_000_000_000)
    .memory_bytes(64 << 20)
    .timeout_ms(30_000)
    .manifold(Manifold {
        fs: FsAccess::ReadWrite(vec!["/var/data".into()]),
        ..Manifold::sealed()
    })
    .threaded(8)
    .build()?;
```

## `burn`: the command-line runtime

### Install (prebuilt binaries)

Linux / macOS:

```sh
curl -fsSL https://afterburner.sh | sh
```

Windows (PowerShell):

```powershell
iwr -useb https://afterburner.sh | iex
```

Pin a specific version with `BURN_VERSION`:

```sh
# POSIX (put the latest version if you want, below command might be outdated)
BURN_VERSION=v0.1.2 curl -fsSL https://afterburner.sh | sh
```

```powershell
# PowerShell (put the latest version if you want, below command might be outdated)
$env:BURN_VERSION = 'v0.1.2'; iwr -useb https://afterburner.sh | iex
```

Or grab a tarball directly from the [Releases page](https://github.com/afterburner-sh/afterburner/releases). Archives are named `burn-<version>-<target>.tar.gz` (or `.zip` for Windows) and ship with a `.sha256` next to them.

Built with `--features release-cli` (every backend, every L3 shadow, TypeScript loader), so it's a single self-contained binary. No runtime libsqlite3, libssl, or libclang required. Plugin `.wasm` is `include_bytes!`-baked into the binary at build time.

### Install (build from source)

```bash
cargo install afterburner --features bin   # installs the `burn` binary
burn ./script.js                           # run a file
burn -e 'module.exports = () => 42'        # eval inline
echo '{"n":21}' | burn thrust transform.js # UDF mode (stdin → JSON)
burn bench perf.js --iters 10000 --workers 8
burn repl                                  # interactive
```

Deno-style capability grants (deny by default):

```bash
burn --allow-net=api.example.com,*.trusted.io script.js
burn --allow-listen=8080 server.js         # inbound: port list or a lo-hi range
burn --allow-fs=/tmp,/var/data etl.js
burn --allow-env=HOME,PATH launcher.js
burn -A runall.js                          # grant everything
```

See [`examples/`](./examples/) for standalone projects covering single
UDF, batched UDF, multi-worker scheduling, streaming crypto,
`HostContext` + capability grants, and rebuilding `burn` in 30 lines.
[`examples/express-app`](./examples/express-app) runs a real Express.js
app: `require('express')` resolves the actual npm package out of
`node_modules/` and serves HTTP end-to-end.

---

## Workspace Crates

| Crate | Purpose |
|:------|:--------|
| **`afterburner`**              | Facade: `Afterburner` + builder, `burn` binary, one ergonomic entry point |
| **`afterburner-core`**         | `Combustor` trait, `Manifold`, `FuelGauge`, `BurnCache`, level-gated logging |
| **`afterburner-ignite`**       | Native JS engine, thread-local runtimes |
| **`afterburner-wasi`**         | Wasmtime sandbox with host-function imports, pooling allocator + InstancePre, bytecode cache |
| **`afterburner-node-compat`**  | `plenum.js` polyfill bundle + Rust-backed host impls (incl. bounded HTTP + DNS with per-call timeouts) |
| **`afterburner-flow`**         | High-level `FlowEngine::load/execute/unload` for flow-style pipelines |
| **`afterburner-adaptive`**     | Flying Start: native → WASM tier switch |
| **`afterburner-thrust`**       | Multi-threaded scheduler: bounded per-worker queues + global injector, token-bucket admission, NUMA-aware steal-when-idle, graceful drain |
| **`afterburner-plugin`**       | WASM-side runtime plugin (`wasm32-wasip1`) |

---

## License

Afterburner is **source-available** under the [Business Source License 1.1](LICENSE)
(BSL 1.1). Each version released under the BSL automatically converts to the
[Apache License, Version 2.0](LICENSE-APACHE) **four years after that version's
release** (its per-version Change Date). Versions released *before* the relicense
(git tag `last-apache-2.0`) were never under the BSL and remain Apache-2.0.

The Apache-2.0 components shipped alongside the engine — everything under
`examples/` (see [`examples/LICENSE`](examples/LICENSE)), plus the planned
`afterburner-afb` and `burn/*` packages — are Apache-2.0 via
their own `LICENSE` / `license` metadata and **not** subject to the BSL.

**Free for non-commercial and non-production use.** Individuals on personal
projects, students on coursework, and non-commercial open-source projects (no
paid sponsorship, no monetised hosting, no enterprise SLA), plus any internal
evaluation/development/testing, are explicitly welcome — no separate agreement
needed (see the Additional Use Grant in [LICENSE](LICENSE)).

**Commercial license required to host, embed, or compete.** Offering
Afterburner as a hosted/managed service, embedding it in a commercial product
distributed to third parties (OEM), or using it to build a competing offering
requires a commercial license — including via forks, rebrands, vendored, or
embedded copies. See **[LICENSING.md](LICENSING.md)**; contact
`info@afterburner.sh`.

"Afterburner" and related marks are trademarks of vertexclique; see
[TRADEMARK.md](TRADEMARK.md). Contributions require a [CLA](CLA.md).

---

<p align="center">
  <sub>BUSL-1.1 &rarr; Apache-2.0 (per-version, 4-year change)</sub>
</p>
