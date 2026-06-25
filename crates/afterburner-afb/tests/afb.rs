// SPDX-License-Identifier: Apache-2.0
//! End-to-end `.afb` pack/unpack tests.
//!
//! These read as the format spec: happy path, reproducibility, the security
//! invariant (sealed stays sealed), and every hostile-input rejection.

use afterburner_afb::{Afb, AfbError, MAX_AFB_BYTES, Manifest, digest, hex, pack::Builder};
use afterburner_core::Manifold;
use std::io::Write;
use std::path::PathBuf;

const HELLO_SOURCE: &str = "module.exports = (d) => d.n + 1\n";

/// SHA-256 of the canonical `hello.afb`. Reproducible build ⇒ this is stable
/// across machines and Rust versions; the committed fixture must match it.
const HELLO_DIGEST_HEX: &str = "395b4c15bc7cfee6b49eac5ea1697056f619d7c3b605edc0d891d6f8dc63346c";

fn hello_manifest() -> Manifest {
    Manifest::parse(
        r#"
[format]
version = "1.0"

[package]
name = "hello"
namespace = "burn"
version = "0.1.0"
language = "js"
entry = "source/main.js"
description = "Canonical afterburner-afb fixture"

[runtime]
min = "0.1.0"
"#,
    )
    .expect("canonical manifest parses")
}

/// The one canonical package every test builds from.
fn build_hello() -> (Vec<u8>, [u8; 32]) {
    Builder::new(hello_manifest(), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .build()
        .expect("hello packs")
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hello.afb")
}

// ---- happy path -----------------------------------------------------------

#[test]
fn pack_unpack_roundtrip() {
    let (bytes, d) = build_hello();
    let afb = Afb::from_bytes(&bytes).expect("unpacks");
    assert_eq!(afb.digest, d);
    assert_eq!(afb.manifest.package.name, "hello");
    assert_eq!(afb.qualified_name(), "burn/hello");
    assert_eq!(afb.entry_source().unwrap(), HELLO_SOURCE);
    assert_eq!(afb.manifold, Manifold::sealed());
}

#[test]
fn pack_is_reproducible() {
    let a = build_hello();
    let b = build_hello();
    assert_eq!(a.0, b.0, "same inputs must yield byte-identical .afb");
    assert_eq!(a.1, b.1);
}

#[test]
fn digest_stable_across_machines() {
    // Materialize the committed fixture on first run; thereafter assert the
    // committed bytes still produce the golden digest (cross-machine proof).
    let (bytes, d) = build_hello();
    let path = fixture_path();
    if !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    let on_disk = std::fs::read(&path).expect("fixture present");
    assert_eq!(on_disk, bytes, "committed hello.afb is not reproducible");
    assert_eq!(digest(&on_disk), d);
    if HELLO_DIGEST_HEX != "REPLACE_ME" {
        assert_eq!(hex(&d), HELLO_DIGEST_HEX, "golden digest drift");
    }
    eprintln!("HELLO_DIGEST_HEX = {}", hex(&d));
}

// ---- the security invariant ----------------------------------------------

#[test]
fn manifold_serde_roundtrip_preserves_sealed() {
    let (bytes, _) = Builder::new(hello_manifest(), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .build()
        .unwrap();
    let afb = Afb::from_bytes(&bytes).unwrap();
    // A sealed manifest must not widen on a pack → unpack round trip.
    assert_eq!(afb.manifold, Manifold::sealed());
}

// ---- hostile input --------------------------------------------------------

#[test]
fn runtime_min_rejects_old() {
    let mut m = hello_manifest();
    m.runtime.min = "99.0.0".into();
    let (bytes, _) = Builder::new(m, Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .build()
        .unwrap();
    assert!(matches!(
        Afb::from_bytes(&bytes),
        Err(AfbError::RuntimeTooOld { .. })
    ));
}

#[test]
fn corrupt_archive_rejected() {
    let (mut bytes, _) = build_hello();
    // Flip a byte well past the zstd magic.
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    let err = Afb::from_bytes(&bytes).unwrap_err();
    assert!(
        matches!(
            err,
            AfbError::Corrupt(_) | AfbError::DecompressedTooLarge(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn bad_manifold_rejected() {
    // Hand-build a tar whose manifold.json is not a valid Manifold.
    let mut ar = tar::Builder::new(Vec::new());
    let toml = Manifest::parse(
        "[format]\nversion=\"1.0\"\n[package]\nname=\"x\"\nnamespace=\"p\"\nversion=\"0.1.0\"\nlanguage=\"js\"\nentry=\"source/main.js\"\n[runtime]\nmin=\"0.1.0\"\n",
    )
    .unwrap()
    .to_toml_string()
    .unwrap();
    append(&mut ar, "afb.toml", toml.as_bytes());
    append(&mut ar, "manifold.json", b"{ not a manifold }");
    append(&mut ar, "source/main.js", HELLO_SOURCE.as_bytes());
    let afb = zstd::encode_all(ar.into_inner().unwrap().as_slice(), 19).unwrap();
    assert!(matches!(
        Afb::from_bytes(&afb),
        Err(AfbError::ManifoldParse(_))
    ));
}

#[test]
fn too_large_rejected() {
    let oversize = vec![0u8; MAX_AFB_BYTES + 1];
    assert!(matches!(
        Afb::from_bytes(&oversize),
        Err(AfbError::TooLarge { .. })
    ));
}

#[test]
fn oversize_uncompressed_bomb() {
    // 6 × 48 MiB = 288 MiB of zeros: each entry is under the 64 MiB
    // per-entry cap, but the total exceeds the 256 MiB decompressed cap.
    // The entries are not "wanted", so unpack never materializes them -
    // tar streams/discards them through the capped decoder, which must
    // trip *before* memory is exhausted. This exercises the streaming
    // total cap specifically (not the per-entry cap).
    let chunk = vec![0u8; 48 * 1024 * 1024];
    let mut ar = tar::Builder::new(Vec::new());
    for i in 0..6 {
        append(&mut ar, &format!("precompiled/blob{i}"), &chunk);
    }
    let afb = zstd::encode_all(ar.into_inner().unwrap().as_slice(), 19).unwrap();
    assert!(
        afb.len() < MAX_AFB_BYTES,
        "compressed bomb fits the size cap"
    );
    assert!(matches!(
        Afb::from_bytes(&afb),
        Err(AfbError::DecompressedTooLarge(_))
    ));
}

#[test]
fn incompatible_major_rejected() {
    let mut ar = tar::Builder::new(Vec::new());
    append(
        &mut ar,
        "afb.toml",
        b"[format]\nversion = \"2.0\"\n[package]\nname=\"x\"\nnamespace=\"p\"\nversion=\"0.1.0\"\nlanguage=\"js\"\nentry=\"source/main.js\"\n[runtime]\nmin=\"0.1.0\"\n",
    );
    append(&mut ar, "manifold.json", b"{}");
    append(&mut ar, "source/main.js", HELLO_SOURCE.as_bytes());
    let afb = zstd::encode_all(ar.into_inner().unwrap().as_slice(), 19).unwrap();
    assert!(matches!(
        Afb::from_bytes(&afb),
        Err(AfbError::FormatVersion { found, .. }) if found == "2.0"
    ));
}

#[test]
fn zip_slip_rejected() {
    // The `tar` *writer* refuses to emit `..`, so a real zip-slip archive
    // is hand-built at the byte level. unpack must reject the traversal.
    let afb = zstd::encode_all(
        raw_tar(&[("../../../etc/passwd", b'0', b"pwned")]).as_slice(),
        19,
    )
    .unwrap();
    assert!(matches!(
        Afb::from_bytes(&afb),
        Err(AfbError::PathEscape(_))
    ));
}

#[test]
fn symlink_entry_rejected() {
    let mut ar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_ustar();
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_size(0);
    h.set_mode(0o777);
    h.set_mtime(0);
    h.set_link_name("/etc/passwd").unwrap();
    ar.append_data(&mut h, "evil-link", std::io::empty())
        .unwrap();
    let afb = zstd::encode_all(ar.into_inner().unwrap().as_slice(), 19).unwrap();
    assert!(matches!(
        Afb::from_bytes(&afb),
        Err(AfbError::DisallowedEntryType(_))
    ));
}

#[test]
fn missing_required_members_rejected() {
    // Valid manifest, no manifold.json.
    let mut ar = tar::Builder::new(Vec::new());
    append(
        &mut ar,
        "afb.toml",
        b"[format]\nversion=\"1.0\"\n[package]\nname=\"x\"\nnamespace=\"p\"\nversion=\"0.1.0\"\nlanguage=\"js\"\nentry=\"source/main.js\"\n[runtime]\nmin=\"0.1.0\"\n",
    );
    append(&mut ar, "source/main.js", HELLO_SOURCE.as_bytes());
    let afb = zstd::encode_all(ar.into_inner().unwrap().as_slice(), 19).unwrap();
    assert!(matches!(
        Afb::from_bytes(&afb),
        Err(AfbError::MissingFile("manifold.json"))
    ));
}

#[test]
fn entry_not_in_archive_rejected() {
    // Manifest points at source/main.js but the archive ships only other.js.
    let (bytes, _) = Builder::new(hello_manifest(), Manifold::sealed())
        .source("source/other.js", HELLO_SOURCE)
        .build()
        .unwrap();
    assert!(matches!(
        Afb::from_bytes(&bytes),
        Err(AfbError::EntryMissing(e)) if e == "source/main.js"
    ));
}

// ---- precompiled/ (FORMAT_MINOR 2) ----------------------------------------

fn wasm_manifest_with_target(target: &str) -> Manifest {
    Manifest::parse(&format!(
        r#"
[format]
version = "1.0"

[package]
name = "hello"
namespace = "burn"
version = "0.1.0"
language = "js"
entry = "source/main.js"

[runtime]
min = "0.1.0"
target = "{target}"
"#,
    ))
    .expect("manifest with target parses")
}

#[test]
fn precompiled_roundtrip() {
    // Fake WASM bytes - just needs to be non-trivial binary content.
    let wasm: Vec<u8> = (0u8..=255).chain(0u8..=127).collect();
    let target = "wasm32-wasip1";
    let rel = format!("precompiled/{target}/main.wasm");

    let (bytes, _) = Builder::new(wasm_manifest_with_target(target), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .precompiled(rel.clone(), wasm.clone())
        .build()
        .expect("packs with precompiled member");

    let afb = Afb::from_bytes(&bytes).expect("unpacks");

    // The WASM bytes come back byte-identical.
    assert_eq!(
        afb.precompiled.get(&rel).map(Vec::as_slice),
        Some(wasm.as_slice()),
        "precompiled bytes must survive the round trip"
    );
    // source/ is still intact.
    assert_eq!(afb.entry_source().unwrap(), HELLO_SOURCE);
    // runtime.target survives.
    assert_eq!(afb.manifest.runtime.target.as_deref(), Some(target));
}

#[test]
fn precompiled_back_compat_old_afb() {
    // An old-style .afb (no precompiled member) must unpack to an empty map.
    let (bytes, _) = build_hello();
    let afb = Afb::from_bytes(&bytes).expect("unpacks");
    assert!(
        afb.precompiled.is_empty(),
        "no precompiled/ in a v0.1 package: map must be empty"
    );
}

#[test]
fn precompiled_reproducibility() {
    let wasm: Vec<u8> = (0u8..=255).collect();
    let rel = "precompiled/wasm32-wasip1/main.wasm";

    let build = || {
        Builder::new(
            wasm_manifest_with_target("wasm32-wasip1"),
            Manifold::sealed(),
        )
        .source("source/main.js", HELLO_SOURCE)
        .precompiled(rel, wasm.clone())
        .build()
        .expect("packs")
    };

    let (a, da) = build();
    let (b, db) = build();
    assert_eq!(
        a, b,
        "identical inputs including precompiled member must yield byte-identical .afb"
    );
    assert_eq!(da, db);
}

// ---- build_wasm_only (STEP 1) -----------------------------------------------

/// A builder with source + precompiled, built via `build_wasm_only`, must
/// produce an `.afb` that has NO `source/` members but DOES have all
/// `precompiled/` members byte-identical.
#[test]
fn build_wasm_only_drops_source_keeps_precompiled() {
    let wasm: Vec<u8> = (0u8..=255).chain(0u8..=127).collect();
    let target = "wasm32-wasip1";
    let rel = format!("precompiled/{target}/main.wasm");

    let (bytes, _) = Builder::new(wasm_manifest_with_target(target), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .precompiled(rel.clone(), wasm.clone())
        .build_wasm_only()
        .expect("build_wasm_only succeeds when a precompiled member is present");

    let afb = Afb::from_bytes(&bytes).expect("wasm-only .afb unpacks");

    // No source/ members.
    assert!(
        afb.source.is_empty(),
        "wasm-only .afb must contain no source/ members, got: {:?}",
        afb.source.keys().collect::<Vec<_>>()
    );

    // Precompiled member is present and byte-identical.
    let got = afb
        .precompiled
        .get(&rel)
        .expect("precompiled member must be present in wasm-only .afb");
    assert_eq!(got, &wasm, "precompiled bytes must survive build_wasm_only");

    // runtime.target is preserved.
    assert_eq!(afb.manifest.runtime.target.as_deref(), Some(target));
}

/// `build_wasm_only` without a precompiled member must error, never produce an
/// empty `.afb`.
#[test]
fn build_wasm_only_errors_without_precompiled_member() {
    let result = Builder::new(hello_manifest(), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .build_wasm_only();

    assert!(
        result.is_err(),
        "build_wasm_only must fail when no precompiled/ member is present"
    );
}

/// `build_wasm_only` output is reproducible - same inputs yield byte-identical `.afb`.
#[test]
fn build_wasm_only_is_reproducible() {
    let wasm: Vec<u8> = (0u8..=255).collect();
    let rel = "precompiled/wasm32-wasip1/main.wasm";
    let target = "wasm32-wasip1";

    let build = || {
        Builder::new(wasm_manifest_with_target(target), Manifold::sealed())
            .source("source/main.js", HELLO_SOURCE)
            .precompiled(rel, wasm.clone())
            .build_wasm_only()
            .expect("build_wasm_only")
    };

    let (a, da) = build();
    let (b, db) = build();
    assert_eq!(
        a, b,
        "build_wasm_only with identical inputs must produce byte-identical output"
    );
    assert_eq!(da, db);
}

/// `build()` on the same builder data still includes source - `build_wasm_only`
/// does not mutate behavior visible to `build()`.
#[test]
fn build_still_includes_source_after_omit_source_call() {
    let wasm: Vec<u8> = b"\x00asm\x01\x00\x00\x00".to_vec();
    let target = "wasm32-wasip1";

    let (bytes, _) = Builder::new(wasm_manifest_with_target(target), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .precompiled("precompiled/wasm32-wasip1/main.wasm", wasm)
        // omit_source(true) followed by build() must NOT drop source -
        // omit_source only takes effect through build_wasm_only().
        .omit_source(true)
        .build()
        .expect("build() with omit_source flag set");

    let afb = Afb::from_bytes(&bytes).expect("unpacks");
    assert!(
        afb.source.contains_key("source/main.js"),
        "build() must preserve source even when omit_source(true) was called"
    );
}

// ---- vendor/ (FORMAT_MINOR 3) -----------------------------------------------

/// A wheel filename that uses the emscripten soabi tag (sandbox-native).
const EMSCRIPTEN_WHL_MEMBER: &str = "vendor/pip/numpy-1.26.4-cpython-312-wasm32-emscripten.so";
/// A pure-Python wheel (no native code at all).
const PURE_WHL_MEMBER: &str = "vendor/pip/requests-2.31.0-py3-none-any.whl";
/// A Ruby gem member.
const GEM_MEMBER: &str = "vendor/gem/sinatra-3.1.0.gem";

/// Fake wheel bytes - non-trivial binary content so the round-trip is
/// meaningful.
fn fake_whl() -> Vec<u8> {
    (0u8..=255u8).cycle().take(512).collect()
}

#[test]
fn vendor_roundtrip_byte_identical() {
    let whl_bytes = fake_whl();
    let gem_bytes: Vec<u8> = (128u8..=255u8).collect();

    let (bytes, d) = Builder::new(hello_manifest(), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .vendor(PURE_WHL_MEMBER, whl_bytes.clone())
        .vendor(GEM_MEMBER, gem_bytes.clone())
        .build()
        .expect("packs with vendor members");

    let afb = Afb::from_bytes(&bytes).expect("unpacks");
    assert_eq!(afb.digest, d, "digest must match");

    // vendor bytes come back byte-identical.
    assert_eq!(
        afb.vendor.get(PURE_WHL_MEMBER).map(Vec::as_slice),
        Some(whl_bytes.as_slice()),
        "wheel bytes must survive the round trip"
    );
    assert_eq!(
        afb.vendor.get(GEM_MEMBER).map(Vec::as_slice),
        Some(gem_bytes.as_slice()),
        "gem bytes must survive the round trip"
    );

    // source is still intact.
    assert_eq!(afb.entry_source().unwrap(), HELLO_SOURCE);
}

#[test]
fn vendor_roundtrip_reproducible() {
    let whl_bytes = fake_whl();

    let build = || {
        Builder::new(hello_manifest(), Manifold::sealed())
            .source("source/main.js", HELLO_SOURCE)
            .vendor(PURE_WHL_MEMBER, whl_bytes.clone())
            .build()
            .expect("packs")
    };

    let (a, da) = build();
    let (b, db) = build();
    assert_eq!(
        a, b,
        "identical inputs including vendor member must yield byte-identical .afb"
    );
    assert_eq!(da, db);
}

#[test]
fn vendor_sandbox_abi_so_is_accepted() {
    // An emscripten soabi .so in vendor/pip/ passes the native-artifact gate.
    let so_bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    let (bytes, _) = Builder::new(hello_manifest(), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .vendor(EMSCRIPTEN_WHL_MEMBER, so_bytes)
        .build()
        .expect("emscripten soabi .so must be accepted");
    let afb = Afb::from_bytes(&bytes).expect("unpacks");
    assert!(afb.vendor.contains_key(EMSCRIPTEN_WHL_MEMBER));
}

#[test]
fn vendor_manylinux_so_is_refused() {
    // A manylinux .so inside a vendor/pip/ member is host-native: refused.
    let manylinux = "vendor/pip/numpy-1.26.4-cp312-cp312-manylinux_2_17_x86_64.so";
    let result = Builder::new(hello_manifest(), Manifold::sealed())
        .source("source/main.js", HELLO_SOURCE)
        .vendor(manylinux, vec![0u8; 16])
        .build();
    assert!(
        matches!(result, Err(afterburner_afb::AfbError::NativeAddon { .. })),
        "manylinux .so must be refused at pack time, got: {result:?}"
    );
}

#[test]
fn vendor_old_afb_has_empty_vendor_map() {
    // An old-style .afb (no vendor/ member) unpacks to an empty vendor map.
    let (bytes, _) = build_hello();
    let afb = Afb::from_bytes(&bytes).expect("unpacks");
    assert!(
        afb.vendor.is_empty(),
        "no vendor/ in a legacy package: map must be empty"
    );
}

#[test]
fn format_minor_3_additive_read() {
    // A package that declares version "1.3" (FORMAT_MINOR=3) with vendor/
    // members is accepted by this reader, and the vendor map is populated.
    let whl_bytes = fake_whl();

    // Use pack_members to build a raw archive at version "1.3".
    let manifest_toml = r#"[format]
version = "1.3"

[package]
name = "hello"
namespace = "burn"
version = "0.1.0"
language = "js"
entry = "source/main.js"
description = "vendor test"

[runtime]
min = "0.1.0"
"#;
    let manifold_json = serde_json::to_vec(&Manifold::sealed()).unwrap();

    let mut ar = tar::Builder::new(Vec::<u8>::new());

    // Helper to append.
    let mut append_raw = |path: &str, data: &[u8]| {
        let mut h = tar::Header::new_ustar();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        ar.append_data(&mut h, path, data).unwrap();
    };

    append_raw("afb.toml", manifest_toml.as_bytes());
    append_raw("manifold.json", &manifold_json);
    append_raw("source/main.js", HELLO_SOURCE.as_bytes());
    append_raw(PURE_WHL_MEMBER, &whl_bytes);

    let afb_bytes = zstd::encode_all(ar.into_inner().unwrap().as_slice(), 19).unwrap();
    let afb = Afb::from_bytes(&afb_bytes).expect("version 1.3 must be accepted");

    assert_eq!(afb.manifest.format.version, "1.3");
    assert_eq!(
        afb.vendor.get(PURE_WHL_MEMBER).map(Vec::as_slice),
        Some(whl_bytes.as_slice()),
        "vendor member must be materialized from a 1.3 archive"
    );
}

// ---- helpers --------------------------------------------------------------

fn append(ar: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
    let mut h = tar::Header::new_ustar();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_entry_type(tar::EntryType::Regular);
    ar.append_data(&mut h, path, data).unwrap();
}

/// Hand-roll a ustar archive, bypassing the `tar` writer's path validation
/// so hostile names (`..`, …) can be tested. `(name, typeflag, data)`.
fn raw_tar(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
    fn oct(field: &mut [u8], val: u64) {
        let n = field.len();
        let s = format!("{val:0width$o}", width = n - 1);
        field[..n - 1].copy_from_slice(s.as_bytes());
        field[n - 1] = 0;
    }
    let mut out = Vec::new();
    for &(name, typeflag, data) in entries {
        let mut h = [0u8; 512];
        let nb = name.as_bytes();
        h[..nb.len()].copy_from_slice(nb);
        oct(&mut h[100..108], 0o644); // mode
        oct(&mut h[108..116], 0); // uid
        oct(&mut h[116..124], 0); // gid
        oct(&mut h[124..136], data.len() as u64); // size
        oct(&mut h[136..148], 0); // mtime
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        // checksum: sum of all bytes with the chksum field as spaces
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let cs = format!("{sum:06o}");
        h[148..154].copy_from_slice(cs.as_bytes());
        h[154] = 0;
        h[155] = b' ';
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        if data.len() % 512 != 0 {
            out.extend(std::iter::repeat_n(0, 512 - data.len() % 512));
        }
    }
    out.extend(std::iter::repeat_n(0, 1024)); // two zero blocks = EOF
    out
}
