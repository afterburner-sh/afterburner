#!/usr/bin/env bash
# Regenerate sealed_probe.wasm from sealed_probe.js - the fixture for the sealed
# precompiled-WASM path test (../sealed_precompiled.rs).
#
# It is a Javy build of the bare module wrapped with a stdin/stdout harness:
# the module reads a JSON input object on stdin and writes its JSON result on
# stdout (the WASI command pattern). The output module imports only
# wasi_snapshot_preview1 (no host imports) - the "sealed" capability profile the
# self-contained WASM flavor targets. Reproducible via -C deterministic=y.
#
#   javy 8.1.1   (override the binary with JAVY=/path/to/javy)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
JAVY="${JAVY:-javy}"

{
  echo 'const module = { exports: undefined };'
  cat sealed_probe.js
  cat <<'HARNESS'
const __fn = module.exports;
const __chunks = [];
const __buf = new Uint8Array(65536);
while (true) { const n = Javy.IO.readSync(0, __buf); if (n <= 0) break; __chunks.push(__buf.slice(0, n)); }
let __t = 0; for (const c of __chunks) __t += c.length;
const __all = new Uint8Array(__t);
let __o = 0; for (const c of __chunks) { __all.set(c, __o); __o += c.length; }
const __in = JSON.parse(new TextDecoder().decode(__all));
const __res = __fn(__in);
Javy.IO.writeSync(1, new TextEncoder().encode(JSON.stringify(__res)));
HARNESS
} > sealed_probe_wrapped.js

"$JAVY" build -J event-loop=y -J javy-stream-io=y -C deterministic=y \
  sealed_probe_wrapped.js -o sealed_probe.wasm
rm -f sealed_probe_wrapped.js
echo "built sealed_probe.wasm ($(wc -c < sealed_probe.wasm) bytes)"
