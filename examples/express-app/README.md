# express-app

**Real Express.js app running inside Afterburner.**

The Rust host (nuclei) accepts HTTP requests; each request becomes a JSON envelope handed to a sandboxed JS app that does `const express = require('express')` — the actual npm package, resolved out of `./node_modules/express`.

```text
                ┌──────────────────────────────────────────────┐
HTTP   ─────►   │ nuclei (Rust)                                │
                │   ↓ envelope { method, path, query, headers, │
                │     body }                                   │
                │ Afterburner::run  →  thrust scheduler  →     │
                │   wasmtime + Javy QuickJS sandbox            │
                │      ↓                                       │
                │   app.js                                     │
                │     const express = require('express')       │
                │     app.get/post/...                         │
                │      ↓ res.end(body)                         │
                │ envelope { status, headers, body }           │
HTTP   ◄─────   │   ↑                                          │
                └──────────────────────────────────────────────┘
```

## Setup

One-time `npm install` to populate `./node_modules/express` and its transitive deps. After that the Rust binary builds and runs as a normal `cargo` project.

```bash
cd examples/express-app
npm install                # creates ./node_modules/express + deps
cargo run --release
```

```text
afterburner-example-express-app
  thrust workers: 8
  cwd:            /…/examples/express-app
  listening on http://127.0.0.1:3000
```

In another shell:

```bash
curl http://127.0.0.1:3000/
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:3000/hello/world
curl -X POST -H 'Content-Type: application/json' \
     -d '{"hello": "server"}' http://127.0.0.1:3000/echo
curl -X POST -H 'Content-Type: application/json' \
     -d '[1, 2, 3, 4]' http://127.0.0.1:3000/sum
```

## How it works

| Layer | Responsibility |
|:------|:---------------|
| `nuclei` (Rust, `src/main.rs`) | TCP + HTTP/1.1 framing + concurrent request dispatch |
| `nuclei::spawn_blocking` | Each request runs Afterburner on a blocking pool thread |
| `Afterburner` with `threaded(N)` | Hash-routes concurrent thrusts across N scheduler workers |
| Wasmtime + Javy plugin | Sandboxed QuickJS execution of `app.js` |
| `Afterburner::builder().cwd(path)` | Pins the require resolver to walk `node_modules` from the example dir, not from the host's cwd |
| `require('express')` | Resolves out of `./node_modules/express` via the CommonJS resolver in `polyfills/require.js` |
| `app.js` adapter | Builds Node-shape `IncomingMessage` / `ServerResponse` from the envelope via `http._makeIncomingMessage` / `http._makeServerResponse`, hands them to `app(req, res)`, resolves once `res.end()` fires |

## Why an adapter?

Express expects `(req, res)` where `req` is an `IncomingMessage` (an `EventEmitter` that emits `'data'` / `'end'`) and `res` is a `ServerResponse` (with `setHeader`, `statusCode`, `write`, `end`, ...).

Afterburner's HTTP polyfill (`crates/afterburner-node-compat/polyfills/http.js`) already exposes the factories that back the in-process daemon-mode HTTP server: `http._makeIncomingMessage` / `http._makeServerResponse`. The example reuses those to construct request/response objects from the host-side envelope and capture the response by intercepting `res.end`. The result is fed back to the host as a `{status, headers, body}` JSON object that the nuclei server turns back into an HTTP response.

### Body parsing

`app.use(express.json())` is **deliberately omitted**. body-parser pulls in `iconv-lite` whose encoding tables reach for Buffer internals we don't fully polyfill; rather than chase that surface, the adapter pre-parses JSON request bodies and sets `req.body` directly — the same pattern `aws-serverless-express`, Vercel's Node runtime, and other serverless adapters use. Route handlers see exactly the same `req.body` shape as if `express.json()` had run.

If you need multipart, urlencoded, or other body shapes, parse them in the Rust dispatcher (`build_envelope` in `src/main.rs`) and surface the parsed value through the envelope. Or wire the chunks through `req.on('data')` / `req.on('end')` — that path works (see the IncomingMessage tests in `crates/afterburner/tests/b2_http_server.rs`); body-parser specifically is the sticky integration.

## Sandboxing

The Manifold installed in `main.rs`:

```rust
let manifold = Manifold {
    fs: FsAccess::ReadOnly(vec![example_root.clone()]),
    crypto: true,
    ..Manifold::sealed()
};
```

grants exactly two capabilities:

* **fs read** scoped to the example root — `require('express')` reads `package.json`, `node_modules/.../*.js`. Nothing outside this directory is reachable.
* **crypto** — Express's `etag` middleware computes a SHA-1 of every response body for the `ETag` header.

Net, env, child_process, and process exit are all denied. Express runs unmodified inside that envelope. If your handler needs net or env, extend the Manifold the same way (see `examples/fetch-and-env`).

JS state is fresh per call (Afterburner invariant). Sessions or long-lived state live on the Rust side; pass them through the envelope if your handler needs them.

## How it parallelises (since v0.1.2)

The `cargo run --release` shape above embeds Afterburner directly via `Afterburner::builder()` and dispatches via the thrust scheduler — every request gets a fresh per-call sandbox. That model is unchanged.

If you instead deploy Express by running `burn server.js` directly (the `burn` CLI's daemon mode), `burn` auto-shards across all CPUs the OS exposes:

* N independent Wasmtime Stores, each its own QuickJS isolate, each on a dedicated OS thread.
* The TCP listener binds once; the dispatcher round-robins requests across shards.
* Container CPU limits become shard limits transparently — `docker run --cpus=4` produces 4 shards, k8s `cpu: "4"` the same. No flag, no env var.

**In-process JS state is per-shard.** The handler in `src/app.js` (`res.send('Hello World')`) is stateless, so it's unaffected — every shard returns the same body. But if you swap in a counter:

```js
let counter = 0;
app.get('/counter', (req, res) => {
  res.json({ value: ++counter });
});
```

`/counter` would return values from N independent counters (each shard has its own `counter` starting at 0). For shared state, use `require('afterburner:state')` — its in-memory backing is process-wide and works across shards. Same trade-off Node's `cluster` module forces; the daemon makes the trade-off explicit and gives you the multi-core throughput in return.

## Files

- `package.json` — declares the `express` dependency.
- `src/main.rs` — nuclei HTTP server, Afterburner builder (with `.cwd(...)`), request bridge.
- `src/app.js` — real Express.js app + envelope ↔ `(req, res)` adapter.
