# afterburner-afb

The `.afb` package format for [Afterburner](https://github.com/vertexclique/afterburner):
a reproducible, content-addressed archive that carries a JavaScript module, its
TOML manifest, and its sandbox `Manifold` together.

Apache-2.0. This crate has **no** Wasmtime/rquickjs dependency — it only packs
and unpacks bytes, and reuses `afterburner_core::Manifold` so a sealed manifest
cannot silently widen on a round trip.

## Format (v1)

A zstd-compressed tar (`ustar`, sorted entries, `mtime=0`, `uid=gid=0` →
byte-reproducible):

```
afb.toml          # package manifest (required)
manifold.json     # serialized afterburner_core::Manifold (required)
source/main.js    # entry point (required)
source/*.js       # optional secondary modules
precompiled/*     # optional, ignored by v0.1
```

## Use

```rust
use afterburner_afb::{pack, Afb};

// pack: returns (bytes, sha256 digest)
let (bytes, digest) = pack::Builder::new(manifest, manifold)
    .source("source/main.js", "module.exports = (d) => d.n + 1")
    .build()?;

// unpack: verified, bounded, sandbox-preserving
let afb = Afb::from_bytes(&bytes)?;
assert_eq!(afb.digest, digest);
assert_eq!(afb.manifold, afterburner_core::Manifold::sealed());
```

## Compatibility

`[format] version` is `"MAJOR.MINOR"`: a reader refuses a different major
loudly, accepts a greater minor additively, and honors `[format] min_reader`
as a hard floor. Unknown descriptive fields are tolerated and unknown
top-level sections are preserved; `[signature]` stays strict. The full,
binding contract is in [`FORMAT.md`](FORMAT.md); `tests/compat.rs` proves it
in both directions.

## Safety / limits

`Afb::from_bytes` is hostile-input safe: zstd window capped (≤16 MiB),
decompressed output capped at 256 MiB (zip-bomb abort), ≤1000 entries,
per-entry size cap, and path-escape / symlink / non-regular entries rejected.
Decompression streams straight into the tar reader, so peak memory is bounded
by the window, not the archive size, and is independent of the pack level.
