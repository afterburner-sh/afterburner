#!/usr/bin/env bash
# Build the custom Javy plugin, run Wizer pre-initialization on it, and
# copy the result into `crates/afterburner-wasi/plugin/`. Run from the
# plugin dir. The output is committed to the repo and lives inside the
# wasi crate so `cargo publish` ships the plugin .wasm with no
# external-path dependencies — downstream builds never need this
# script or the `javy` CLI.

set -euo pipefail

cd "$(dirname "$0")"

# 1. Compile the plugin. Use workspace target dir so the artifact
#    lands where subsequent scripts expect it.
cargo build --target wasm32-wasip1 --release

# Workspace target is two levels up: <repo>/crates/afterburner-plugin → <repo>/target.
raw=../../target/wasm32-wasip1/release/afterburner_plugin.wasm
if [[ ! -f "$raw" ]]; then
    echo "expected $raw not produced" >&2
    exit 1
fi

# 2. Wizer-preinit so the QuickJS runtime + plenum bundle are baked
#    into the snapshot. This is a one-time build step; at runtime the
#    host never shells out to `javy`.
javy=${JAVY:-javy}
if ! command -v "$javy" >/dev/null; then
    if [[ -x "$HOME/.local/bin/javy" ]]; then
        javy="$HOME/.local/bin/javy"
    else
        echo "javy CLI not found. Set JAVY=... or install from https://github.com/bytecodealliance/javy" >&2
        exit 1
    fi
fi

tmp=$(mktemp)
lowered=$(mktemp)
trap 'rm -f "$tmp" "$lowered"' EXIT

# 2a. Lower newer WASM features that the wasm-validator bundled
#     inside `javy init-plugin` (Binaryen) doesn't accept yet.
#     Modern Rust wasi-sysroot emits `memory.copy` / `memory.fill`
#     (bulk-memory) and sign-extension ops; both are stable WASM
#     features but javy 8.1.1's embedded validator hasn't caught up.
#     We run a fresh `wasm-opt` first to either accept (if the local
#     binary is new enough) or transform the module into a form the
#     embedded validator handles. Falls back to a direct copy if
#     wasm-opt isn't installed — that path will fail loudly inside
#     javy if the plugin actually contains bulk-memory ops, which
#     is the right bisection signal.
wasm_opt=${WASM_OPT:-wasm-opt}
if ! command -v "$wasm_opt" >/dev/null; then
    if [[ -x "$HOME/.local/bin/wasm-opt" ]]; then
        wasm_opt="$HOME/.local/bin/wasm-opt"
    fi
fi

if command -v "$wasm_opt" >/dev/null; then
    # Modern wasi-sysroot emits memory.copy / memory.fill (bulk
    # memory). javy 8.1.1's bundled wasm-validator rejects them
    # because its Binaryen build pre-dates bulk-memory acceptance.
    # `--llvm-memory-copy-fill-lowering` rewrites those ops to
    # MVP-compatible loops and clears the bulk-memory feature flag,
    # so the resulting module passes javy's validator while
    # behaving identically at runtime.
    "$wasm_opt" \
        --enable-bulk-memory \
        --enable-sign-ext \
        --enable-mutable-globals \
        --enable-nontrapping-float-to-int \
        --enable-reference-types \
        --enable-multivalue \
        --llvm-memory-copy-fill-lowering \
        --llvm-nontrapping-fptoint-lowering \
        --signext-lowering \
        --strip-target-features \
        -O2 \
        "$raw" -o "$lowered"
else
    cp "$raw" "$lowered"
fi

"$javy" init-plugin "$lowered" -o "$tmp"

dest=../afterburner-wasi/plugin/afterburner_plugin.wasm
cp "$tmp" "$dest"

# Record the SHA-256 of the plenum bundle the plugin was built against
# so the host crate's build.rs can detect drift and fail cleanly.
bundle=../afterburner-node-compat/generated/plenum_bundle.js
sha=$(sha256sum "$bundle" | awk '{print $1}')
printf '%s\n' "$sha" > "$dest.bundle-sha256"

echo "wrote $(stat -c %s "$dest") bytes to $dest (Wizer-preinitialized)"
echo "recorded bundle sha256: $sha → $dest.bundle-sha256"

# The plugin ships inside the afterburner-wasi .crate (include_bytes!), and
# crates.io rejects compressed crates over 10 MiB. Warn at 8 MiB gzipped so
# growth is caught at build time, not at publish time.
gz=$(gzip -9 -c "$dest" | wc -c)
echo "plugin gzip size: $((gz / 1048576)) MiB ($gz bytes; crates.io crate limit is 10 MiB compressed)"
if [ "$gz" -gt $((8 * 1048576)) ]; then
    echo "WARNING: gzipped plugin exceeds 8 MiB — approaching the 10 MiB crates.io crate limit" >&2
fi
