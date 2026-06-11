// SPDX-License-Identifier: Apache-2.0
//! Exhaustive backward/forward-compatibility matrix for the `.afb` format
//! evolution policy (see `FORMAT.md`).
//!
//! - **Forward** = a 1.0 reader (this build) consuming a *newer* package.
//! - **Backward** = this reader consuming an *older / minimal* package.
//! - **Fail-safe** = the gate must *refuse* (never misparse) across a major
//!   boundary or an unmet `min_reader`, in both directions.

use afterburner_afb::{
    Afb, AfbError, FORMAT_MAJOR, FORMAT_MINOR, Manifest, Manifold, pack::Builder,
    reader_format_version,
};

const SRC: &str = "module.exports = (d) => d.n + 1\n";

/// Minimal valid manifest body at `version`, with optional appended
/// `[format]` line, extra `[package]` keys, and extra top-level sections.
fn body(version: &str, fmt_extra: &str, pkg_extra: &str, sections: &str) -> String {
    format!(
        "[format]\nversion = \"{version}\"\n{fmt_extra}\n\
         [package]\nname = \"hello\"\nnamespace = \"burn\"\nversion = \"0.1.0\"\n\
         language = \"js\"\nentry = \"source/main.js\"\n{pkg_extra}\n\
         [runtime]\nmin = \"0.1.0\"\n{sections}"
    )
}

fn sealed_json() -> Vec<u8> {
    serde_json::to_vec(&Manifold::sealed()).unwrap()
}

/// tar (reproducible-ish) + zstd, arbitrary members - used for cases the
/// `Builder` would reject up front.
fn pack_members(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());
    for (p, d) in members {
        let mut h = tar::Header::new_ustar();
        h.set_size(d.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        ar.append_data(&mut h, p, d.as_slice()).unwrap();
    }
    zstd::encode_all(ar.into_inner().unwrap().as_slice(), 19).unwrap()
}

/// A package whose `afb.toml` is exactly `manifest_toml` (bypasses Builder's
/// up-front validation so rejected manifests can be exercised end to end).
fn raw_pkg(manifest_toml: &str) -> Vec<u8> {
    pack_members(&[
        ("afb.toml", manifest_toml.as_bytes().to_vec()),
        ("manifold.json", sealed_json()),
        ("source/main.js", SRC.as_bytes().to_vec()),
    ])
}

/// A package the Builder accepts (manifest must be valid).
fn built_pkg(manifest_toml: &str) -> Vec<u8> {
    Builder::new(
        Manifest::parse(manifest_toml).expect("manifest valid for Builder"),
        Manifold::sealed(),
    )
    .source("source/main.js", SRC)
    .build()
    .expect("packs")
    .0
}

// ============================ FORWARD ======================================
// Old (1.0) reader consuming a NEWER package: must accept additively.

#[test]
fn forward_greater_minor_is_accepted() {
    for v in ["1.1", "1.2", "1.9", "1.65535", "1.4294967295"] {
        let afb = Afb::from_bytes(&raw_pkg(&body(v, "", "", "")))
            .unwrap_or_else(|e| panic!("minor {v} must be accepted, got {e:?}"));
        assert_eq!(afb.manifest.format.version, v);
        assert_eq!(afb.entry_source().unwrap(), SRC);
    }
}

#[test]
fn forward_unknown_descriptive_keys_are_tolerated() {
    // New optional keys a 1.0 reader has never heard of, in every tolerant
    // table - must not break parsing.
    let afb = Afb::from_bytes(&raw_pkg(&body(
        "1.3",
        "future_format_hint = \"x\"",
        "keywords = [\"a\", \"b\"]\nrepository = \"https://x\"",
        "",
    )))
    .expect("unknown descriptive keys tolerated");
    assert_eq!(afb.manifest.package.name, "hello");
}

#[test]
fn forward_unknown_top_level_sections_are_preserved() {
    let afb = Afb::from_bytes(&raw_pkg(&body(
        "1.2",
        "",
        "",
        "[provenance]\nbuilt_by = \"ci\"\n\n[attestations]\nslsa = \"v1\"\n",
    )))
    .unwrap();
    assert!(afb.manifest.extra.contains_key("provenance"));
    assert!(afb.manifest.extra.contains_key("attestations"));

    // …and a tool that re-packs the newer package does not lose them.
    let repacked = Builder::new(afb.manifest.clone(), afb.manifold.clone())
        .source("source/main.js", SRC)
        .build()
        .unwrap()
        .0;
    let again = Afb::from_bytes(&repacked).unwrap();
    assert_eq!(again.manifest.extra, afb.manifest.extra);
}

#[test]
fn forward_reserved_metadata_roundtrips() {
    let afb = Afb::from_bytes(&raw_pkg(&body(
        "1.4",
        "",
        "",
        "[metadata.ci]\npipeline = \"gha\"\nattempts = 3\n",
    )))
    .unwrap();
    assert!(!afb.manifest.metadata.is_empty());
    let rt = Manifest::parse(&afb.manifest.to_toml_string().unwrap()).unwrap();
    assert_eq!(rt.metadata, afb.manifest.metadata);
}

#[test]
fn forward_unknown_archive_members_are_ignored() {
    // A future package adds members a 1.0 reader doesn't consume.
    let afb_bytes = pack_members(&[
        ("afb.toml", body("1.5", "", "", "").into_bytes()),
        ("manifold.json", sealed_json()),
        ("source/main.js", SRC.as_bytes().to_vec()),
        ("precompiled/mod.cwasm", vec![1, 2, 3, 4]),
        ("attestations/sig.ed25519", vec![9; 64]),
        ("future_dir/notes.txt", b"hello from 1.5".to_vec()),
    ]);
    let afb = Afb::from_bytes(&afb_bytes).expect("unknown members ignored");
    assert_eq!(afb.entry_source().unwrap(), SRC);
    // Only source/* is surfaced; future members are not smuggled in.
    assert_eq!(
        afb.source.keys().collect::<Vec<_>>(),
        vec!["source/main.js"]
    );
}

#[test]
fn forward_compat_does_not_weaken_safety() {
    // A bomb hidden in a future/unknown member is still caught.
    let chunk = vec![0u8; 48 * 1024 * 1024];
    let mut members = vec![
        ("afb.toml", body("1.9", "", "", "").into_bytes()),
        ("manifold.json", sealed_json()),
        ("source/main.js", SRC.as_bytes().to_vec()),
    ];
    let names: Vec<String> = (0..6).map(|i| format!("future_blobs/b{i}")).collect();
    for n in &names {
        members.push((n.as_str(), chunk.clone()));
    }
    assert!(matches!(
        Afb::from_bytes(&pack_members(&members)),
        Err(AfbError::DecompressedTooLarge(_))
    ));
}

// ============================ BACKWARD =====================================
// This reader consuming an OLDER / MINIMAL package.

#[test]
fn backward_minimal_required_only_package() {
    // Nothing optional: no description/homepage/license/target/deps/
    // signature/metadata/extra. Must still parse, pack, and unpack.
    let m = built_pkg(&body("1.0", "", "", ""));
    let afb = Afb::from_bytes(&m).unwrap();
    assert!(afb.manifest.package.description.is_none());
    assert!(afb.manifest.package.license.is_none());
    assert!(afb.manifest.runtime.target.is_none());
    assert!(afb.manifest.dependencies.is_empty());
    assert!(afb.manifest.signature.is_none());
    assert!(afb.manifest.metadata.is_empty());
    assert!(afb.manifest.extra.is_empty());
}

#[test]
fn backward_reader_baseline_is_1_0() {
    assert_eq!(FORMAT_MAJOR, 1);
    assert_eq!(FORMAT_MINOR, 0);
    assert_eq!(reader_format_version(), "1.0");
    // The exact-reader-version package is the trivial backward case.
    Afb::from_bytes(&raw_pkg(&body(&reader_format_version(), "", "", ""))).unwrap();
}

#[test]
fn backward_missing_now_required_field_is_rejected() {
    // An older package lacking a field this version requires must be
    // refused, not silently accepted with a bogus default.
    let no_entry = "[format]\nversion = \"1.0\"\n[package]\nname = \"h\"\n\
                    namespace = \"p\"\nversion = \"0.1.0\"\nlanguage = \"js\"\n\
                    [runtime]\nmin = \"0.1.0\"\n";
    assert!(matches!(
        Afb::from_bytes(&raw_pkg(no_entry)),
        Err(AfbError::ManifestParse(_))
    ));
    let no_runtime = "[format]\nversion = \"1.0\"\n[package]\nname = \"h\"\n\
                      namespace = \"p\"\nversion = \"0.1.0\"\nlanguage = \"js\"\n\
                      entry = \"source/main.js\"\n";
    assert!(matches!(
        Afb::from_bytes(&raw_pkg(no_runtime)),
        Err(AfbError::ManifestParse(_))
    ));
}

// ===================== FAIL-SAFE (the gate itself) =========================

#[test]
fn incompatible_major_is_refused_both_directions() {
    for v in ["2.0", "3.7", "255.0", "0.9", "0.1"] {
        let err = Afb::from_bytes(&raw_pkg(&body(v, "", "", ""))).unwrap_err();
        assert!(
            matches!(err, AfbError::FormatVersion { ref found, .. } if found == v),
            "major of {v} must be refused, got {err:?}"
        );
    }
}

#[test]
fn malformed_format_version_is_rejected() {
    for v in ["1", "1.", ".1", "", "1.2.3", "x.y", "1.x", " ", "v1.0"] {
        assert!(
            matches!(
                Afb::from_bytes(&raw_pkg(&body(v, "", "", ""))),
                Err(AfbError::ManifestParse(_))
            ),
            "version {v:?} must be ManifestParse"
        );
    }
}

#[test]
fn min_reader_gate_is_enforced() {
    // Newer than this reader (1.0) → hard refuse.
    for mr in ["1.1", "1.2", "2.0", "9.9"] {
        let afb = raw_pkg(&body("1.0", &format!("min_reader = \"{mr}\""), "", ""));
        assert!(
            matches!(Afb::from_bytes(&afb), Err(AfbError::ReaderTooOld { .. })),
            "min_reader {mr} must trip ReaderTooOld"
        );
    }
    // Satisfied → OK.
    for mr in ["1.0", "0.9", "0.0"] {
        let afb = raw_pkg(&body("1.0", &format!("min_reader = \"{mr}\""), "", ""));
        assert!(
            Afb::from_bytes(&afb).is_ok(),
            "min_reader {mr} should be satisfied"
        );
    }
    // Malformed min_reader → ManifestParse.
    assert!(matches!(
        Afb::from_bytes(&raw_pkg(&body("1.0", "min_reader = \"abc\"", "", ""))),
        Err(AfbError::ManifestParse(_))
    ));
}

#[test]
fn signature_surface_is_strict_even_under_forward_policy() {
    // Forward-tolerance must NOT extend to the identity block: a newer
    // package adding an unknown key inside [signature] is rejected.
    let afb = raw_pkg(&body(
        "1.6",
        "",
        "",
        "[signature]\nalgorithm = \"ed25519\"\npublic_key = \"AA\"\nrogue_field = true\n",
    ));
    assert!(matches!(
        Afb::from_bytes(&afb),
        Err(AfbError::ManifestParse(_))
    ));
}

#[test]
fn manifold_forward_tolerant_but_stays_sealed() {
    // An unknown future key in manifold.json must not break an old reader
    // (forward-compat) and must not silently widen the sandbox.
    let mut mf: serde_json::Value = serde_json::from_slice(&sealed_json()).unwrap();
    mf.as_object_mut()
        .unwrap()
        .insert("future_cap".into(), serde_json::json!(true));
    let afb = Afb::from_bytes(&pack_members(&[
        ("afb.toml", body("1.8", "", "", "").into_bytes()),
        ("manifold.json", serde_json::to_vec(&mf).unwrap()),
        ("source/main.js", SRC.as_bytes().to_vec()),
    ]))
    .expect("unknown manifold key tolerated");
    assert_eq!(
        afb.manifold,
        Manifold::sealed(),
        "an unknown key must not widen capabilities"
    );
}

// ===================== DETERMINISM ACROSS VERSIONS =========================

#[test]
fn newer_minor_packages_are_reproducible() {
    let a = built_pkg(&body("1.3", "", "", ""));
    let b = built_pkg(&body("1.3", "", "", ""));
    assert_eq!(a, b, "same newer-minor inputs must be byte-identical");
}
