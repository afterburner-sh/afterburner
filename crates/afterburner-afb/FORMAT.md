# The `.afb` format & its compatibility contract

`.afb` is a zstd-compressed, `ustar` tar, content-addressed by SHA-256 of the
compressed bytes. It carries a JS module, its manifest (`afb.toml`), and its
sandbox `manifold.json`.

This document is the **binding contract**. Code enforces it
(`manifest.rs`, `tests/compat.rs`); this file is why.

## Versioning model

`afb.toml` declares `[format] version = "MAJOR.MINOR"`. The model follows
proven precedent — Python wheels (`Wheel-Version`: refuse greater major, accept
greater minor), npm/Debian (unknown descriptive fields ignored, never
hard-rejected), Cargo (`[package.metadata]` reserved namespace, `edition`
epochs).

### MAJOR — the compatibility gate

A reader supports exactly **one** major (this build: **1**). It **must refuse
any other major, loudly** (`AfbError::FormatVersion`) — a greater major (too
new) and a lesser major (a prior epoch it was not taught to migrate) are both
refused. A reader never misparses a format it does not understand.

A MAJOR bump is reserved for **breaking** changes: a field removed or
repurposed, a semantic change, or a new field that is **unsafe to ignore**.

### MINOR — additive only

A reader **accepts a greater minor** and simply does not act on what it
postdates. A MINOR bump may only:

- add an **optional** manifest field, or
- add a new **archive member** that is safe for an old reader to ignore.

A MINOR bump must **never** remove a field, change a meaning, or add a
*required* field.

### `min_reader` — the escape hatch

If an additive change is *not* safe to ignore, the package sets
`[format] min_reader = "MAJOR.MINOR"`. A reader older than that refuses with
`AfbError::ReaderTooOld`, even though the major matches. This is the only
sanctioned way to make a minor-level addition mandatory.

## Per-section strictness

| Section | Unknown keys | Why |
|---|---|---|
| `[package]`, `[runtime]`, `[format]` | **tolerated** | Descriptive/gated elsewhere. Tolerating unknowns is what lets an old reader read a newer package (npm/Debian model). |
| top-level unknown sections | **preserved** (`Manifest::extra`) | Loss-free parse → repack of a newer package. |
| `[metadata]` | **reserved, free-form** | Tools put anything here; readers never interpret it; it round-trips. |
| `[signature]` | **strict** (`deny_unknown_fields`) | Identity/security surface — an unexpected key is rejected, never tolerated. |
| `manifold.json` | governed by `afterburner-core::Manifold` | The capability set. Reused as the runtime's own type (no schema duplication). Its strictness is `afterburner-core`'s responsibility; this crate verifies a sealed manifold cannot widen on round trip. |

## Container invariants (stable, not versioned)

- zstd level 19; `ustar`; entries sorted; `mtime=0`, `uid=gid=0` → byte
  reproducible.
- Compressed cap 32 MiB; decompressed cap 256 MiB (streamed, early abort);
  ≤1000 entries; per-entry cap 64 MiB; `..`/absolute/symlink/non-regular
  entries rejected. Forward-compatibility never relaxes these.

## Required members (absence = a breaking, refused package)

`afb.toml`, `manifold.json`, and the `source/` file named by
`package.entry`. Anything else (e.g. `precompiled/*`) is optional and ignored
by v1.

## Changing this format

A change is only permitted if it is classified here first (MAJOR vs MINOR) and
`tests/compat.rs` is extended to prove the contract still holds in both
directions. The roadmap's original `[format] version = 1` integer is
superseded by this `"MAJOR.MINOR"` model.
