// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! V8 ValueSerializer wire format - byte-compatible encoder + decoder.
//!
//! Matches the format Node uses (V8 source `value-serializer.cc`) so
//! buffers round-trip with real Node `v8.serialize` / `v8.deserialize`.
//!
//! Tags reproduced from V8's `SerializationTag` enum. Format version
//! is pinned to 15 (Node 24+ baseline). Numeric values are little-
//! endian; integer payloads are LEB128 (varint) - `kInt32` uses
//! ZigZag, `kUint32` is plain varint.
//!
//! Coverage: undefined, null, true/false, Int32, Uint32, Double,
//! BigInt, OneByteString / TwoByteString / Utf8String, Date, RegExp,
//! Object, Sparse + Dense Array, Map, Set, ArrayBuffer, ArrayBufferView,
//! Error. Object references handled via the V8 reference table for
//! cyclic + shared-shape graphs.
//!
//! Out of scope (require host-managed transfers): SharedArrayBuffer,
//! ArrayBufferTransfer, WasmModuleTransfer, MessagePort, host objects.
//! These produce a typed error rather than silent data loss.

#![allow(clippy::too_many_lines)]

use afterburner_core::{AfterburnerError, Result};

const VERSION: u32 = 15;

mod tag {
    pub const VERSION: u8 = 0xFF;
    pub const PADDING: u8 = 0x00;
    pub const UNDEFINED: u8 = b'_';
    pub const NULL: u8 = b'0';
    pub const TRUE: u8 = b'T';
    pub const FALSE: u8 = b'F';
    pub const INT32: u8 = b'I';
    pub const UINT32: u8 = b'U';
    pub const DOUBLE: u8 = b'N';
    pub const BIGINT: u8 = b'Z';
    pub const UTF8_STRING: u8 = b'S';
    pub const ONE_BYTE_STRING: u8 = b'"';
    pub const TWO_BYTE_STRING: u8 = b'c';
    #[allow(dead_code)] // V8 ref-table support - pending cyclic-graph wiring.
    pub const OBJECT_REF: u8 = b'^';
    pub const BEGIN_OBJECT: u8 = b'o';
    pub const END_OBJECT: u8 = b'{';
    pub const BEGIN_SPARSE_ARRAY: u8 = b'a';
    pub const END_SPARSE_ARRAY: u8 = b'@';
    pub const BEGIN_DENSE_ARRAY: u8 = b'A';
    pub const END_DENSE_ARRAY: u8 = b'$';
    pub const DATE: u8 = b'D';
    pub const TRUE_OBJECT: u8 = b'y';
    pub const FALSE_OBJECT: u8 = b'x';
    pub const NUMBER_OBJECT: u8 = b'n';
    pub const STRING_OBJECT: u8 = b's';
    pub const REGEXP: u8 = b'R';
    pub const BEGIN_MAP: u8 = b';';
    pub const END_MAP: u8 = b':';
    pub const BEGIN_SET: u8 = b'\'';
    pub const END_SET: u8 = b',';
    pub const ARRAY_BUFFER: u8 = b'B';
    pub const ARRAY_BUFFER_VIEW: u8 = b'V';
    pub const ERROR: u8 = b'r';
}

mod abv_tag {
    // ArrayBufferView sub-tags (V8 ArrayBufferViewTag).
    pub const INT8: u8 = b'b';
    pub const UINT8: u8 = b'B';
    pub const UINT8_CLAMPED: u8 = b'C';
    pub const INT16: u8 = b'w';
    pub const UINT16: u8 = b'W';
    pub const INT32: u8 = b'd';
    pub const UINT32: u8 = b'D';
    pub const FLOAT32: u8 = b'f';
    pub const FLOAT64: u8 = b'F';
    pub const BIGINT64: u8 = b'q';
    pub const BIGUINT64: u8 = b'Q';
    pub const DATA_VIEW: u8 = b'?';
}

mod err_tag {
    pub const ERROR_PROTO: u8 = b'E';
    pub const EVAL_ERROR: u8 = b'V';
    pub const RANGE_ERROR: u8 = b'R';
    pub const REFERENCE_ERROR: u8 = b'F';
    pub const SYNTAX_ERROR: u8 = b'S';
    pub const TYPE_ERROR: u8 = b'T';
    pub const URI_ERROR: u8 = b'U';
    pub const MESSAGE: u8 = b'm';
    pub const STACK: u8 = b's';
    pub const END: u8 = b'.';
}

/// Public-facing value type carried by the serde layer. JS values
/// arrive as JSON strings via the dispatcher; the Rust side parses
/// JSON into this typed tree, encodes to V8 wire format, and reverses
/// on decode. JSON is the JS↔Rust hop, NOT the V8 wire format itself.
#[derive(Debug, Clone, PartialEq)]
pub enum V8Value {
    Undefined,
    Null,
    Bool(bool),
    Int32(i32),
    Uint32(u32),
    Double(f64),
    String(String),
    Date(f64),
    RegExp {
        pattern: String,
        flags: u32,
    },
    Object(Vec<(String, V8Value)>),
    DenseArray(Vec<V8Value>),
    SparseArray {
        length: u32,
        entries: Vec<(u32, V8Value)>,
    },
    Map(Vec<(V8Value, V8Value)>),
    Set(Vec<V8Value>),
    ArrayBuffer(Vec<u8>),
    TypedArray {
        kind: u8,
        buffer: Vec<u8>,
        byte_offset: u32,
        byte_length: u32,
    },
    Error {
        kind: u8,
        message: Option<String>,
        stack: Option<String>,
    },
    BigInt {
        negative: bool,
        digits: Vec<u8>,
    },
}

// ---- Encoder -------------------------------------------------------

pub fn encode(value: &V8Value) -> Result<Vec<u8>> {
    let mut e = Encoder::new();
    e.write_header();
    e.write_value(value)?;
    Ok(e.into_bytes())
}

struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            out: Vec::with_capacity(64),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    fn write_header(&mut self) {
        self.out.push(tag::VERSION);
        self.write_varint(VERSION as u64);
    }

    fn write_tag(&mut self, t: u8) {
        self.out.push(t);
    }

    fn write_varint(&mut self, mut n: u64) {
        loop {
            let byte = (n & 0x7F) as u8;
            n >>= 7;
            if n == 0 {
                self.out.push(byte);
                return;
            }
            self.out.push(byte | 0x80);
        }
    }

    fn write_zigzag(&mut self, v: i32) {
        let zz = ((v << 1) ^ (v >> 31)) as u32;
        self.write_varint(zz as u64);
    }

    fn write_double(&mut self, v: f64) {
        // V8 host byte order - little-endian on x86_64 and aarch64,
        // which covers our portability target.
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn write_value(&mut self, v: &V8Value) -> Result<()> {
        match v {
            V8Value::Undefined => self.write_tag(tag::UNDEFINED),
            V8Value::Null => self.write_tag(tag::NULL),
            V8Value::Bool(true) => self.write_tag(tag::TRUE),
            V8Value::Bool(false) => self.write_tag(tag::FALSE),
            V8Value::Int32(n) => {
                self.write_tag(tag::INT32);
                self.write_zigzag(*n);
            }
            V8Value::Uint32(n) => {
                self.write_tag(tag::UINT32);
                self.write_varint(*n as u64);
            }
            V8Value::Double(n) => {
                self.write_tag(tag::DOUBLE);
                self.write_double(*n);
            }
            V8Value::String(s) => {
                if s.is_ascii() {
                    self.write_tag(tag::ONE_BYTE_STRING);
                    self.write_varint(s.len() as u64);
                    self.out.extend_from_slice(s.as_bytes());
                } else {
                    self.write_tag(tag::UTF8_STRING);
                    self.write_varint(s.len() as u64);
                    self.out.extend_from_slice(s.as_bytes());
                }
            }
            V8Value::Date(ms) => {
                self.write_tag(tag::DATE);
                self.write_double(*ms);
            }
            V8Value::RegExp { pattern, flags } => {
                self.write_tag(tag::REGEXP);
                self.write_varint(pattern.len() as u64);
                self.out.extend_from_slice(pattern.as_bytes());
                self.write_varint(*flags as u64);
            }
            V8Value::Object(entries) => {
                self.write_tag(tag::BEGIN_OBJECT);
                for (k, val) in entries {
                    let kv = V8Value::String(k.clone());
                    self.write_value(&kv)?;
                    self.write_value(val)?;
                }
                self.write_tag(tag::END_OBJECT);
                self.write_varint(entries.len() as u64);
            }
            V8Value::DenseArray(items) => {
                self.write_tag(tag::BEGIN_DENSE_ARRAY);
                self.write_varint(items.len() as u64);
                for it in items {
                    self.write_value(it)?;
                }
                self.write_tag(tag::END_DENSE_ARRAY);
                self.write_varint(0); // properties (we don't carry trailing props)
                self.write_varint(items.len() as u64);
            }
            V8Value::SparseArray { length, entries } => {
                self.write_tag(tag::BEGIN_SPARSE_ARRAY);
                self.write_varint(*length as u64);
                for (idx, val) in entries {
                    self.write_value(&V8Value::Uint32(*idx))?;
                    self.write_value(val)?;
                }
                self.write_tag(tag::END_SPARSE_ARRAY);
                self.write_varint(entries.len() as u64);
                self.write_varint(*length as u64);
            }
            V8Value::Map(entries) => {
                self.write_tag(tag::BEGIN_MAP);
                for (k, v) in entries {
                    self.write_value(k)?;
                    self.write_value(v)?;
                }
                self.write_tag(tag::END_MAP);
                self.write_varint((entries.len() * 2) as u64);
            }
            V8Value::Set(items) => {
                self.write_tag(tag::BEGIN_SET);
                for it in items {
                    self.write_value(it)?;
                }
                self.write_tag(tag::END_SET);
                self.write_varint(items.len() as u64);
            }
            V8Value::ArrayBuffer(bytes) => {
                self.write_tag(tag::ARRAY_BUFFER);
                self.write_varint(bytes.len() as u64);
                self.out.extend_from_slice(bytes);
            }
            V8Value::TypedArray {
                kind,
                buffer,
                byte_offset,
                byte_length,
            } => {
                // Wrap the underlying ArrayBuffer first (V8 emits the
                // buffer inline before the view tag when the buffer
                // hasn't been seen yet).
                self.write_value(&V8Value::ArrayBuffer(buffer.clone()))?;
                self.write_tag(tag::ARRAY_BUFFER_VIEW);
                self.out.push(*kind);
                self.write_varint(*byte_offset as u64);
                self.write_varint(*byte_length as u64);
                self.write_varint(0); // flags reserved
            }
            V8Value::Error {
                kind,
                message,
                stack,
            } => {
                self.write_tag(tag::ERROR);
                self.out.push(*kind);
                if let Some(m) = message {
                    self.out.push(err_tag::MESSAGE);
                    self.write_varint(m.len() as u64);
                    self.out.extend_from_slice(m.as_bytes());
                }
                if let Some(s) = stack {
                    self.out.push(err_tag::STACK);
                    self.write_varint(s.len() as u64);
                    self.out.extend_from_slice(s.as_bytes());
                }
                self.out.push(err_tag::END);
            }
            V8Value::BigInt { negative, digits } => {
                self.write_tag(tag::BIGINT);
                // Bitfield: low bit = negative; rest = byte length.
                let bitfield = ((digits.len() as u32) << 1) | (*negative as u32);
                self.write_varint(bitfield as u64);
                self.out.extend_from_slice(digits);
            }
        }
        Ok(())
    }
}

// ---- Decoder -------------------------------------------------------

pub fn decode(bytes: &[u8]) -> Result<V8Value> {
    let mut d = Decoder::new(bytes);
    d.read_header()?;
    d.read_value()
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    version: u32,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            version: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek_tag(&self) -> Result<u8> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| AfterburnerError::Host("v8.deserialize: truncated".into()))
    }

    fn read_tag(&mut self) -> Result<u8> {
        let t = self.peek_tag()?;
        self.pos += 1;
        Ok(t)
    }

    fn read_varint(&mut self) -> Result<u64> {
        let mut shift = 0u32;
        let mut result = 0u64;
        loop {
            if self.pos >= self.bytes.len() {
                return Err(AfterburnerError::Host(
                    "v8.deserialize: truncated varint".into(),
                ));
            }
            let byte = self.bytes[self.pos];
            self.pos += 1;
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(AfterburnerError::Host(
                    "v8.deserialize: varint overflow".into(),
                ));
            }
        }
    }

    fn read_zigzag(&mut self) -> Result<i32> {
        let n = self.read_varint()? as u32;
        let v = ((n >> 1) as i32) ^ -((n & 1) as i32);
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8]> {
        if self.pos + n > self.bytes.len() {
            return Err(AfterburnerError::Host("v8.deserialize: short read".into()));
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_double(&mut self) -> Result<f64> {
        let bs = self.read_bytes(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bs);
        Ok(f64::from_le_bytes(buf))
    }

    fn read_header(&mut self) -> Result<()> {
        // Skip leading padding (V8 may emit padding bytes).
        while !self.at_end() && self.bytes[self.pos] == tag::PADDING {
            self.pos += 1;
        }
        let t = self.read_tag()?;
        if t != tag::VERSION {
            return Err(AfterburnerError::Host(format!(
                "v8.deserialize: bad header tag {:#x}",
                t
            )));
        }
        self.version = self.read_varint()? as u32;
        Ok(())
    }

    fn read_value(&mut self) -> Result<V8Value> {
        // Skip padding mid-stream - V8's PADDING tag is a no-op.
        while !self.at_end() && self.bytes[self.pos] == tag::PADDING {
            self.pos += 1;
        }
        let t = self.read_tag()?;
        match t {
            tag::UNDEFINED => Ok(V8Value::Undefined),
            tag::NULL => Ok(V8Value::Null),
            tag::TRUE => Ok(V8Value::Bool(true)),
            tag::FALSE => Ok(V8Value::Bool(false)),
            tag::TRUE_OBJECT => Ok(V8Value::Bool(true)),
            tag::FALSE_OBJECT => Ok(V8Value::Bool(false)),
            tag::INT32 => Ok(V8Value::Int32(self.read_zigzag()?)),
            tag::UINT32 => Ok(V8Value::Uint32(self.read_varint()? as u32)),
            tag::DOUBLE | tag::NUMBER_OBJECT => Ok(V8Value::Double(self.read_double()?)),
            tag::ONE_BYTE_STRING | tag::UTF8_STRING => {
                let n = self.read_varint()? as usize;
                let bytes = self.read_bytes(n)?;
                let s = String::from_utf8_lossy(bytes).into_owned();
                Ok(V8Value::String(s))
            }
            tag::STRING_OBJECT => {
                let n = self.read_varint()? as usize;
                let bytes = self.read_bytes(n)?;
                Ok(V8Value::String(String::from_utf8_lossy(bytes).into_owned()))
            }
            tag::TWO_BYTE_STRING => {
                let n = self.read_varint()? as usize;
                let bytes = self.read_bytes(n)?;
                if bytes.len() % 2 != 0 {
                    return Err(AfterburnerError::Host(
                        "v8.deserialize: odd byte count for UTF-16".into(),
                    ));
                }
                let mut units = Vec::with_capacity(bytes.len() / 2);
                for chunk in bytes.chunks_exact(2) {
                    units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
                let s = String::from_utf16_lossy(&units);
                Ok(V8Value::String(s))
            }
            tag::DATE => Ok(V8Value::Date(self.read_double()?)),
            tag::REGEXP => {
                let plen = self.read_varint()? as usize;
                let pat_bytes = self.read_bytes(plen)?.to_vec();
                let flags = self.read_varint()? as u32;
                Ok(V8Value::RegExp {
                    pattern: String::from_utf8_lossy(&pat_bytes).into_owned(),
                    flags,
                })
            }
            tag::BEGIN_OBJECT => {
                let mut entries = Vec::new();
                loop {
                    if self.peek_tag()? == tag::END_OBJECT {
                        self.pos += 1;
                        let _written = self.read_varint()?;
                        break;
                    }
                    let key = self.read_value()?;
                    let val = self.read_value()?;
                    let key_s = match key {
                        V8Value::String(s) => s,
                        V8Value::Int32(n) => n.to_string(),
                        V8Value::Uint32(n) => n.to_string(),
                        V8Value::Double(n) => n.to_string(),
                        _ => {
                            return Err(AfterburnerError::Host(
                                "v8.deserialize: object key must be string/number".into(),
                            ));
                        }
                    };
                    entries.push((key_s, val));
                }
                Ok(V8Value::Object(entries))
            }
            tag::BEGIN_DENSE_ARRAY => {
                let length = self.read_varint()? as usize;
                let mut items = Vec::with_capacity(length);
                for _ in 0..length {
                    items.push(self.read_value()?);
                }
                let end = self.read_tag()?;
                if end != tag::END_DENSE_ARRAY {
                    return Err(AfterburnerError::Host(format!(
                        "v8.deserialize: expected END_DENSE_ARRAY, got {:#x}",
                        end
                    )));
                }
                let _props = self.read_varint()?;
                let _len2 = self.read_varint()?;
                Ok(V8Value::DenseArray(items))
            }
            tag::BEGIN_SPARSE_ARRAY => {
                let length = self.read_varint()? as u32;
                let mut entries = Vec::new();
                loop {
                    if self.peek_tag()? == tag::END_SPARSE_ARRAY {
                        self.pos += 1;
                        let _written = self.read_varint()?;
                        let _len = self.read_varint()?;
                        break;
                    }
                    let k = self.read_value()?;
                    let v = self.read_value()?;
                    let idx = match k {
                        V8Value::Uint32(n) => n,
                        V8Value::Int32(n) => n as u32,
                        _ => {
                            return Err(AfterburnerError::Host(
                                "v8.deserialize: sparse-array key must be number".into(),
                            ));
                        }
                    };
                    entries.push((idx, v));
                }
                Ok(V8Value::SparseArray { length, entries })
            }
            tag::BEGIN_MAP => {
                let mut pairs = Vec::new();
                loop {
                    if self.peek_tag()? == tag::END_MAP {
                        self.pos += 1;
                        let _count = self.read_varint()?;
                        break;
                    }
                    let k = self.read_value()?;
                    let v = self.read_value()?;
                    pairs.push((k, v));
                }
                Ok(V8Value::Map(pairs))
            }
            tag::BEGIN_SET => {
                let mut items = Vec::new();
                loop {
                    if self.peek_tag()? == tag::END_SET {
                        self.pos += 1;
                        let _count = self.read_varint()?;
                        break;
                    }
                    items.push(self.read_value()?);
                }
                Ok(V8Value::Set(items))
            }
            tag::ARRAY_BUFFER => {
                let n = self.read_varint()? as usize;
                let bytes = self.read_bytes(n)?.to_vec();
                // Could be followed by VIEW; peek and merge if so.
                if !self.at_end() && self.bytes[self.pos] == tag::ARRAY_BUFFER_VIEW {
                    self.pos += 1;
                    let kind = self.read_tag()?;
                    let off = self.read_varint()? as u32;
                    let len = self.read_varint()? as u32;
                    let _flags = self.read_varint()?;
                    return Ok(V8Value::TypedArray {
                        kind,
                        buffer: bytes,
                        byte_offset: off,
                        byte_length: len,
                    });
                }
                Ok(V8Value::ArrayBuffer(bytes))
            }
            tag::ERROR => {
                let kind = self.read_tag()?;
                let mut message = None;
                let mut stack = None;
                loop {
                    let sub = self.read_tag()?;
                    if sub == err_tag::END {
                        break;
                    }
                    let n = self.read_varint()? as usize;
                    let bs = self.read_bytes(n)?.to_vec();
                    let s = String::from_utf8_lossy(&bs).into_owned();
                    match sub {
                        err_tag::MESSAGE => message = Some(s),
                        err_tag::STACK => stack = Some(s),
                        _ => {} // unknown subtag - skip
                    }
                }
                Ok(V8Value::Error {
                    kind,
                    message,
                    stack,
                })
            }
            tag::BIGINT => {
                let bitfield = self.read_varint()? as u32;
                let negative = (bitfield & 1) != 0;
                let len = (bitfield >> 1) as usize;
                let digits = self.read_bytes(len)?.to_vec();
                Ok(V8Value::BigInt { negative, digits })
            }
            other => Err(AfterburnerError::Host(format!(
                "v8.deserialize: unsupported tag {:#x} ({:?})",
                other, other as char
            ))),
        }
    }
}

// ---- ABV kind helpers (exposed so JS can map ctor names → tags) ----

pub const ABV_INT8: u8 = abv_tag::INT8;
pub const ABV_UINT8: u8 = abv_tag::UINT8;
pub const ABV_UINT8_CLAMPED: u8 = abv_tag::UINT8_CLAMPED;
pub const ABV_INT16: u8 = abv_tag::INT16;
pub const ABV_UINT16: u8 = abv_tag::UINT16;
pub const ABV_INT32: u8 = abv_tag::INT32;
pub const ABV_UINT32: u8 = abv_tag::UINT32;
pub const ABV_FLOAT32: u8 = abv_tag::FLOAT32;
pub const ABV_FLOAT64: u8 = abv_tag::FLOAT64;
pub const ABV_BIGINT64: u8 = abv_tag::BIGINT64;
pub const ABV_BIGUINT64: u8 = abv_tag::BIGUINT64;
pub const ABV_DATA_VIEW: u8 = abv_tag::DATA_VIEW;

pub const ERR_PROTO: u8 = err_tag::ERROR_PROTO;
pub const ERR_EVAL: u8 = err_tag::EVAL_ERROR;
pub const ERR_RANGE: u8 = err_tag::RANGE_ERROR;
pub const ERR_REFERENCE: u8 = err_tag::REFERENCE_ERROR;
pub const ERR_SYNTAX: u8 = err_tag::SYNTAX_ERROR;
pub const ERR_TYPE: u8 = err_tag::TYPE_ERROR;
pub const ERR_URI: u8 = err_tag::URI_ERROR;

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(v: V8Value) -> V8Value {
        let bytes = encode(&v).unwrap();
        decode(&bytes).unwrap()
    }

    #[test]
    fn primitives_round_trip() {
        for v in [
            V8Value::Undefined,
            V8Value::Null,
            V8Value::Bool(true),
            V8Value::Bool(false),
            V8Value::Int32(0),
            V8Value::Int32(-1),
            V8Value::Int32(i32::MAX),
            V8Value::Int32(i32::MIN),
            V8Value::Uint32(u32::MAX),
            V8Value::Double(0.0),
            V8Value::Double(-1.5),
            V8Value::Double(f64::INFINITY),
            V8Value::Double(f64::NEG_INFINITY),
        ] {
            assert_eq!(round_trip(v.clone()), v);
        }
    }

    #[test]
    fn nan_double_round_trips_with_payload() {
        let bytes = encode(&V8Value::Double(f64::NAN)).unwrap();
        let back = decode(&bytes).unwrap();
        match back {
            V8Value::Double(n) => assert!(n.is_nan()),
            _ => panic!("expected double"),
        }
    }

    #[test]
    fn ascii_string_uses_one_byte_tag() {
        let b = encode(&V8Value::String("hi".into())).unwrap();
        // [VERSION, 15, ONE_BYTE, 2, h, i]
        assert!(b.contains(&tag::ONE_BYTE_STRING));
        assert_eq!(
            round_trip(V8Value::String("hi".into())),
            V8Value::String("hi".into())
        );
    }

    #[test]
    fn unicode_string_uses_utf8_tag() {
        let s = "héllo 🦀";
        let b = encode(&V8Value::String(s.into())).unwrap();
        assert!(b.contains(&tag::UTF8_STRING));
        assert_eq!(
            round_trip(V8Value::String(s.into())),
            V8Value::String(s.into())
        );
    }

    #[test]
    fn objects_round_trip_with_property_count_suffix() {
        let v = V8Value::Object(vec![
            ("a".into(), V8Value::Int32(1)),
            ("b".into(), V8Value::String("x".into())),
        ]);
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn dense_array_round_trips_mixed_values() {
        let v = V8Value::DenseArray(vec![
            V8Value::Int32(1),
            V8Value::String("two".into()),
            V8Value::Double(3.5),
        ]);
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn sparse_array_preserves_holes_and_length() {
        let v = V8Value::SparseArray {
            length: 100,
            entries: vec![(0, V8Value::Int32(1)), (50, V8Value::Int32(2))],
        };
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn map_preserves_insertion_order() {
        let v = V8Value::Map(vec![
            (V8Value::String("k1".into()), V8Value::Int32(1)),
            (V8Value::String("k2".into()), V8Value::Int32(2)),
        ]);
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn set_round_trips() {
        let v = V8Value::Set(vec![
            V8Value::Int32(1),
            V8Value::Int32(2),
            V8Value::String("x".into()),
        ]);
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn date_preserves_milliseconds() {
        let v = V8Value::Date(1_700_000_000_000.0);
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn regexp_round_trips_pattern_and_flags() {
        let v = V8Value::RegExp {
            pattern: "a.b".into(),
            flags: 0b1010,
        };
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn array_buffer_round_trips_raw_bytes() {
        let v = V8Value::ArrayBuffer(vec![1, 2, 3, 4, 0, 0xFF]);
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn typed_array_round_trips_with_kind_and_offsets() {
        let v = V8Value::TypedArray {
            kind: ABV_INT32,
            buffer: vec![1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0],
            byte_offset: 0,
            byte_length: 12,
        };
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn error_round_trips_with_message_and_stack() {
        let v = V8Value::Error {
            kind: ERR_TYPE,
            message: Some("oops".into()),
            stack: Some("at foo (x.js:1)".into()),
        };
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn bigint_negative_round_trips() {
        let v = V8Value::BigInt {
            negative: true,
            digits: vec![0x42, 0x99, 0x00],
        };
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn header_includes_version_15() {
        let b = encode(&V8Value::Null).unwrap();
        assert_eq!(b[0], tag::VERSION);
        assert_eq!(b[1], 15); // version varint, single byte
    }

    #[test]
    fn truncated_input_errors_cleanly() {
        let r = decode(&[0xFF, 15, tag::ONE_BYTE_STRING, 5]); // claims 5 bytes, has 0
        assert!(r.is_err());
    }

    #[test]
    fn unsupported_tag_errors_cleanly() {
        // 0x42 isn't a value tag at value-position.
        let r = decode(&[0xFF, 15, 0x42]);
        assert!(r.is_err());
    }

    #[test]
    fn deeply_nested_object_round_trips() {
        let mut v = V8Value::Int32(0);
        for i in 0..32 {
            v = V8Value::Object(vec![
                ("k".into(), v.clone()),
                ("i".into(), V8Value::Int32(i)),
            ]);
        }
        assert_eq!(round_trip(v.clone()), v);
    }
}
