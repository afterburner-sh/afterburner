#!/usr/bin/env bash
# Build all language wasm artifacts for the polyglot demo.
# Run from the examples/languages/ directory.
#
# Prerequisites:
#   rust:   rustup target add wasm32-wasip1
#   go:     go 1.25+ (GOOS=wasip1 GOARCH=wasm)
#   js/ts:  javy 8.1.1, tsc (typescript) for TS -> JS step
#   python: CPython WASM binary at $PYTHON_WASM (default /tmp/python.wasm)
#           Not built here - it is a prebuilt binary (~25 MB) from
#           https://github.com/nicowillis/cpython-wasm or similar.
#           The binary is not committed because of its size; only the
#           source (main.py) and this build script are tracked.
#
# Every artifact is a self-contained WASI command module that exports
# _start and writes one line to stdout:
#   <lang>: sum(1..=100)=5050 fib(20)=6765
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== rust ==="
rustc --target wasm32-wasip1 -O --edition 2021 rust/main.rs -o rust/rust.wasm
wasm-opt -Os --strip-debug rust/rust.wasm -o rust/rust.wasm 2>/dev/null || true
echo "  rust/rust.wasm: $(wc -c < rust/rust.wasm) bytes"

echo "=== go ==="
GOOS=wasip1 GOARCH=wasm go build -o go/go.wasm go/main.go
echo "  go/go.wasm: $(wc -c < go/go.wasm) bytes (Go runtime ~2.5 MB; expected)"

echo "=== python ==="
echo "  python/main.py: source only; wasm binary not committed (~25 MB)"
echo "  To run: cargo run -p afterburner-wasi --example polyglot"
echo "  The runner reads \$PYTHON_WASM (default /tmp/python.wasm)."

echo "=== js ==="
javy build -J event-loop=y -J javy-stream-io=y -C deterministic=y \
    js/main.js -o js/js.wasm
echo "  js/js.wasm: $(wc -c < js/js.wasm) bytes"

echo "=== ts ==="
# Compile TS to JS first (tsc or any TS-to-JS transpiler).
TSC="${TSC:-tsc}"
"$TSC" ts/main.ts --target ES2020 --module commonjs \
    --noEmit false --skipLibCheck true --outDir ts/
javy build -J event-loop=y -J javy-stream-io=y -C deterministic=y \
    ts/main.js -o ts/ts.wasm
echo "  ts/ts.wasm: $(wc -c < ts/ts.wasm) bytes"

echo ""
echo "All artifacts built."
