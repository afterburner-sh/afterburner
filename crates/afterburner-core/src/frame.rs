// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The file-frame byte carrier (`"AFBF"` v1): the single binary-safe channel
//! reachable from every substrate (the guest filesystem - `InMemFs` bytes for
//! Python, a WASI preopen for the command languages, `fs_host` for JS).
//!
//! One length-prefixed, self-verifying, endian-fixed frame carries a typed
//! [`OutputValue`] or a raw effect payload across
//! the guest/host boundary. Because the encoder is 48 trivially-specified
//! header bytes plus the payload, it is byte-identical across every language
//! (JS / Python / Ruby / Rust / Go / C) by construction: each guest emits the
//! identical bytes, and every host decodes them through the one canonical
//! [`decode_frame`] here (DRY - no per-substrate codec).
//!
//! # Layout (fixed 48-byte header + payload)
//!
//! | Range        | Field     | Meaning                                            |
//! |--------------|-----------|----------------------------------------------------|
//! | `[0..4)`     | magic     | `b"AFBF"`                                           |
//! | `[4]`        | version   | `1`                                                |
//! | `[5]`        | kind      | `0` = Json, `1` = Bytes (the [`OutputTag`])        |
//! | `[6..8)`     | flags     | `u16` LE, reserved, `0`                             |
//! | `[8..16)`    | len       | `u64` LE payload length                            |
//! | `[16..48)`   | hash      | 32-byte BLAKE3 of the payload                      |
//! | `[48..48+len)` | payload | the carried bytes                                  |
//!
//! All multi-byte integers are little-endian - the convention the codebase
//! already uses everywhere (the iovec reads in `afterburner-wasi`'s emscripten
//! shim decode `from_le_bytes`).
//!
//! # Honesty fence
//!
//! [`decode_frame`] is **total and loud**. A wrong magic, an unknown version,
//! an unknown kind, a declared length that overruns the buffer (truncation),
//! trailing bytes past the payload, or a BLAKE3 that does not match the header
//! hash each return [`AfterburnerError::FrameDecode`].
//! There is never a silent `from_utf8_lossy`, never a truncation that reads as
//! success.

use crate::error::{AfterburnerError, Result};
use crate::types::{OutputValue, content_hash};

/// Frame magic: the four bytes every frame starts with.
pub const MAGIC: [u8; 4] = *b"AFBF";

/// Current frame version. Bumped only on an incompatible layout change.
pub const VERSION: u8 = 1;

/// Fixed header length preceding the payload.
pub const HEADER_LEN: usize = 48;

/// The guest-side mount for afterburner's OWN capture plumbing: the file-frame
/// sinks (`/.afb/output.frame`, `/.afb/stdout.bin`, `/.afb/stderr.bin`). Paths
/// under this dir are afterburner's internal machinery, not the guest program's
/// effects, so the effect seams must exclude them (they would otherwise pollute
/// the captured effect log with spurious writes the agent never made).
pub const INTERNAL_MOUNT: &str = "/.afb";

/// Whether a guest-absolute path belongs to afterburner's internal capture
/// plumbing (under [`INTERNAL_MOUNT`]) and must be excluded from the effect log.
/// Matches the mount itself and any path beneath it, but not a sibling like
/// `/.afbedded` that merely shares the prefix.
pub fn is_internal_capture_path(guest_abs_path: &str) -> bool {
    guest_abs_path == INTERNAL_MOUNT
        || guest_abs_path
            .strip_prefix(INTERNAL_MOUNT)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Which [`OutputValue`] shape a frame carries.
///
/// The `u8` discriminant is **byte-equal** to the `OutputValue` variant order
/// (`Json` = 0, `Bytes` = 1), so a value carried as a frame and the same
/// value matched on the enum agree without a translation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OutputTag {
    /// The payload is the canonical JSON text of an [`OutputValue::Json`].
    Json = 0,
    /// The payload is the raw bytes of an [`OutputValue::Bytes`].
    Bytes = 1,
}

impl OutputTag {
    /// The `u8` kind byte for this tag.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a kind byte, rejecting any value the current version does not
    /// define.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Json),
            1 => Some(Self::Bytes),
            _ => None,
        }
    }
}

/// Encode `payload` into a self-verifying frame tagged `kind`.
///
/// The output is exactly [`HEADER_LEN`] + `payload.len()` bytes. The header
/// hash is `BLAKE3(payload)` - the same content-address used for effect and
/// output payloads elsewhere, so a value carried here and the identical bytes
/// seen as a filesystem effect content-address identically.
pub fn encode_frame(kind: OutputTag, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind.as_u8());
    out.extend_from_slice(&0u16.to_le_bytes()); // flags (reserved)
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&content_hash(payload));
    out.extend_from_slice(payload);
    out
}

/// Decode a frame, returning its tag and payload bytes.
///
/// Total and loud: every malformed input is an [`AfterburnerError::FrameDecode`],
/// never a silent partial read. See the module docs for the exact failure set.
pub fn decode_frame(bytes: &[u8]) -> Result<(OutputTag, Vec<u8>)> {
    if bytes.len() < HEADER_LEN {
        return Err(frame_err(format!(
            "frame shorter than the {HEADER_LEN}-byte header ({} bytes)",
            bytes.len()
        )));
    }
    if bytes[0..4] != MAGIC {
        return Err(frame_err(format!(
            "bad magic {:02x?}, expected {:02x?}",
            &bytes[0..4],
            MAGIC
        )));
    }
    let version = bytes[4];
    if version != VERSION {
        return Err(frame_err(format!(
            "unsupported frame version {version}, this build speaks v{VERSION}"
        )));
    }
    let kind = OutputTag::from_u8(bytes[5])
        .ok_or_else(|| frame_err(format!("unknown kind byte {}", bytes[5])))?;
    // bytes[6..8] are reserved flags: read but not interpreted (forward-compat).
    let len = u64::from_le_bytes(bytes[8..16].try_into().expect("8-byte slice")) as usize;
    let header_hash = &bytes[16..HEADER_LEN];

    let end = HEADER_LEN
        .checked_add(len)
        .ok_or_else(|| frame_err(format!("declared length {len} overflows usize")))?;
    if bytes.len() < end {
        return Err(frame_err(format!(
            "truncated frame: header declares {len} payload bytes but only {} are present",
            bytes.len() - HEADER_LEN
        )));
    }
    if bytes.len() > end {
        return Err(frame_err(format!(
            "trailing bytes: header declares {len} payload bytes but the buffer holds {} more",
            bytes.len() - end
        )));
    }

    let payload = &bytes[HEADER_LEN..end];
    let actual = content_hash(payload);
    if actual != header_hash {
        return Err(frame_err(
            "payload hash mismatch: the frame is corrupt or truncated".to_string(),
        ));
    }
    Ok((kind, payload.to_vec()))
}

/// Encode an [`OutputValue`] into a frame. `Json` is carried as its canonical
/// serialized text bytes, `Bytes` verbatim. The inverse of
/// [`decode_output_value`].
pub fn encode_output_value(value: &OutputValue) -> Result<Vec<u8>> {
    match value {
        OutputValue::Json(v) => Ok(encode_frame(OutputTag::Json, &serde_json::to_vec(v)?)),
        OutputValue::Bytes(b) => Ok(encode_frame(OutputTag::Bytes, b)),
    }
}

/// Decode a frame back into an [`OutputValue`]. A `Json`-tagged payload is
/// parsed as JSON (a parse failure is loud); a `Bytes`-tagged payload is
/// returned verbatim.
pub fn decode_output_value(bytes: &[u8]) -> Result<OutputValue> {
    let (tag, payload) = decode_frame(bytes)?;
    match tag {
        OutputTag::Json => Ok(OutputValue::Json(serde_json::from_slice(&payload)?)),
        OutputTag::Bytes => Ok(OutputValue::Bytes(payload)),
    }
}

fn frame_err(msg: String) -> AfterburnerError {
    AfterburnerError::FrameDecode(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_bytes() {
        let payload = b"\x00\xff\n not utf8 \xc3\x28 preserved";
        let frame = encode_frame(OutputTag::Bytes, payload);
        assert_eq!(frame.len(), HEADER_LEN + payload.len());
        let (tag, out) = decode_frame(&frame).expect("decode");
        assert_eq!(tag, OutputTag::Bytes);
        assert_eq!(out, payload);
    }

    #[test]
    fn round_trip_empty_payload() {
        let frame = encode_frame(OutputTag::Json, b"");
        let (tag, out) = decode_frame(&frame).expect("decode");
        assert_eq!(tag, OutputTag::Json);
        assert!(out.is_empty());
    }

    #[test]
    fn round_trip_output_value() {
        let v = OutputValue::Json(json!({"a": 1, "b": [true, null]}));
        let frame = encode_output_value(&v).expect("encode");
        assert_eq!(decode_output_value(&frame).expect("decode"), v);

        let b = OutputValue::Bytes(vec![1, 2, 3, 0, 255]);
        let frame = encode_output_value(&b).expect("encode");
        assert_eq!(decode_output_value(&frame).expect("decode"), b);
    }

    #[test]
    fn header_layout_is_fixed() {
        let frame = encode_frame(OutputTag::Bytes, b"hi");
        assert_eq!(&frame[0..4], b"AFBF");
        assert_eq!(frame[4], VERSION);
        assert_eq!(frame[5], 1); // Bytes
        assert_eq!(&frame[6..8], &[0, 0]); // flags
        assert_eq!(u64::from_le_bytes(frame[8..16].try_into().unwrap()), 2);
        assert_eq!(&frame[16..48], &content_hash(b"hi"));
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(decode_frame(b"AFBF").is_err());
        assert!(decode_frame(&[]).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut frame = encode_frame(OutputTag::Json, b"x");
        frame[0] = b'X';
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut frame = encode_frame(OutputTag::Json, b"x");
        frame[4] = 2;
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut frame = encode_frame(OutputTag::Json, b"x");
        frame[5] = 9;
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn rejects_truncation() {
        let frame = encode_frame(OutputTag::Bytes, b"hello world");
        let truncated = &frame[..frame.len() - 3];
        assert!(decode_frame(truncated).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut frame = encode_frame(OutputTag::Bytes, b"hello");
        frame.push(0);
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn rejects_hash_mismatch() {
        let mut frame = encode_frame(OutputTag::Bytes, b"hello");
        let last = frame.len() - 1;
        frame[last] ^= 0xff; // corrupt the payload, header hash now stale
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn tag_byte_matches_output_value_discriminant() {
        // OutputValue::Json is variant 0, Bytes is variant 1 (types.rs).
        assert_eq!(OutputTag::Json.as_u8(), 0);
        assert_eq!(OutputTag::Bytes.as_u8(), 1);
    }

    #[test]
    fn internal_capture_paths_are_detected() {
        // The mount itself and anything beneath it are afterburner's plumbing.
        assert!(is_internal_capture_path("/.afb"));
        assert!(is_internal_capture_path("/.afb/output.frame"));
        assert!(is_internal_capture_path("/.afb/stdout.bin"));
        // Guest paths, and a sibling that merely shares the prefix, are not.
        assert!(!is_internal_capture_path("/cap_probe.bin"));
        assert!(!is_internal_capture_path("/tmp/x"));
        assert!(!is_internal_capture_path("/.afbedded"));
        assert!(!is_internal_capture_path("/home/.afb/x"));
    }
}
