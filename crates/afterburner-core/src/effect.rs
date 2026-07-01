// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The host-effect seam: the byte-safe record of a single side effect a guest
//! asked the host to perform (a file read, an HTTP call, a child process, an
//! env lookup, a DB statement).
//!
//! Afterburner exposes only the **seam** and the **record**, never a journal
//! schema or a persistence policy - causarum owns those. Two records exist:
//!
//! - [`HostEffect`]: the request *identity* (what the guest asked for),
//! - [`HostEffectRecord`]: the request plus its recorded *result*.
//!
//! Every field that can hold arbitrary program data is bytes ([`Vec<u8>`]),
//! never a lossy `String`: a write payload, a response body, an error message
//! all round-trip byte-exact. The one place a `String` appears is a canonical
//! *identity* ([`HostEffect::target`], [`CallSite`]) that is UTF-8 by
//! construction.
//!
//! # Content addressing (the parity crux)
//!
//! `input_hash` and `output_hash` are `BLAKE3` of the corresponding bytes -
//! the same digest the frame carrier uses. The [`HostEffect::new`] and
//! [`HostEffectRecord::new`] constructors compute those hashes so a hand-built
//! record can never disagree with its own bytes.
//!
//! # Target string forms (identical across all languages)
//!
//! The `target` is the canonical identity of the effect. If two substrates
//! spell the same effect differently, that one effect gets two content
//! addresses and replay breaks, so the spelling is fixed here and the
//! [`fs_target`] / [`process_target`] / [`http_target`] / [`socket_target`] /
//! [`env_target`] / [`db_target`] builders are the single source of truth:
//!
//! | Kind    | `target`                                             |
//! |---------|------------------------------------------------------|
//! | Fs      | `"file::"` + guest-absolute path                     |
//! | Process | `"shell::"` + argv0                                   |
//! | Net     | `"api::"` + host + path + `"#"` + method (HTTP)       |
//! | Net     | `"api::"` + host + `":"` + port (raw socket)          |
//! | Env     | `"env::"` + VARNAME                                   |
//! | Db      | `"db::"` + system                                    |
//!
//! The Fs path is the **guest**-absolute path (resolved through the
//! substrate's preopen / `InMemFs` map), never the host path.

use crate::host::HttpMethod;
use crate::types::content_hash;

/// The broad category of a side effect. `Fs` carries the concrete file
/// operation inline; the raw op only - the effect *class* (idempotent,
/// observed, mutating, ...) is causarum's concern and is deliberately not
/// pre-baked here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectKind {
    /// A filesystem operation on a guest path.
    Fs(FileOp),
    /// A network call (HTTP or raw socket; the shape is in [`EffectDetail`]).
    Net,
    /// An environment-variable read.
    Env,
    /// A wall-clock or monotonic time read.
    Clock,
    /// A source of randomness.
    Random,
    /// A child process / shell invocation.
    Process,
    /// A database statement.
    Db,
}

/// The raw filesystem operation. Raw op only - no pre-baked classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileOp {
    Read,
    Write,
    Append,
    Delete,
    Create,
    Stat,
    List,
}

/// Where in the guest source the effect was requested. Optional because not
/// every substrate can attribute a call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallSite {
    /// Guest source file (as the guest sees it).
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// Enclosing function name, or an empty string when unknown.
    pub function: String,
}

/// Op-specific detail for a [`HostEffect`]. `Fs` needs none (its [`FileOp`] is
/// already in [`EffectKind::Fs`]); the other kinds carry their shape here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EffectDetail {
    /// No extra detail (used by `Fs`, `Clock`, `Random`).
    None,
    /// HTTP request specifics.
    Http {
        method: HttpMethod,
        host: String,
        path: String,
    },
    /// Raw socket specifics.
    Socket { host: String, port: u16 },
    /// Child-process argument vector; `argv[0]` is the program.
    Process { argv: Vec<String> },
    /// Database system identifier (e.g. `"postgres"`, `"sqlite"`).
    Db { system: String },
    /// Environment-variable name.
    Env { name: String },
}

/// The seam record: the *identity* of one effect the guest requested, byte
/// safe. This is what a host inspects in [`HostContext::on_host_call`] to
/// decide record vs serve.
///
/// [`HostContext::on_host_call`]: crate::host::HostContext::on_host_call
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostEffect {
    /// The effect category (and, for `Fs`, its operation).
    pub kind: EffectKind,
    /// Canonical identity string; see the module docs for the exact forms.
    pub target: String,
    /// The request bytes: a write payload, an HTTP body, a join of argv, the
    /// statement bytes. Empty for a read-only effect that carries no input.
    pub input: Vec<u8>,
    /// `BLAKE3(input)`. Computed by [`HostEffect::new`].
    pub input_hash: [u8; 32],
    /// Op-specific detail (method + host + path, argv, db system, ...).
    pub detail: EffectDetail,
    /// Where in the guest the effect was requested, when known.
    pub call_site: Option<CallSite>,
}

impl HostEffect {
    /// Build a [`HostEffect`], computing `input_hash = BLAKE3(input)` so the
    /// hash can never disagree with the bytes.
    pub fn new(
        kind: EffectKind,
        target: String,
        input: Vec<u8>,
        detail: EffectDetail,
        call_site: Option<CallSite>,
    ) -> Self {
        let input_hash = content_hash(&input);
        Self {
            kind,
            target,
            input,
            input_hash,
            detail,
            call_site,
        }
    }
}

/// The request plus its recorded result. On the original run the substrate
/// executes the real effect and hands back one of these; on replay the host
/// returns a stored one and the substrate performs no real effect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostEffectRecord {
    /// The request identity.
    pub effect: HostEffect,
    /// The recorded result bytes: read content, a response body, child stdout.
    pub output: Vec<u8>,
    /// `BLAKE3(output)`. Computed by [`HostEffectRecord::new`].
    pub output_hash: [u8; 32],
    /// Wall-clock duration of the real effect, in milliseconds.
    pub duration_ms: u64,
    /// The terminal status of the effect.
    pub status: EffectStatus,
}

impl HostEffectRecord {
    /// Build a [`HostEffectRecord`], computing `output_hash = BLAKE3(output)`.
    pub fn new(
        effect: HostEffect,
        output: Vec<u8>,
        duration_ms: u64,
        status: EffectStatus,
    ) -> Self {
        let output_hash = content_hash(&output);
        Self {
            effect,
            output,
            output_hash,
            duration_ms,
            status,
        }
    }
}

/// The terminal status of a recorded effect. An error is carried as **bytes**,
/// never a lossy `String`, so a non-UTF-8 error payload round-trips exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EffectStatus {
    /// The effect succeeded. `code` is the effect-native status (an HTTP
    /// status, a process exit code, a DB return code); `rows` is the affected
    /// or returned row count when the effect is a DB statement.
    Ok { code: i64, rows: Option<u64> },
    /// The effect failed; the bytes are the raw error payload.
    Err(Vec<u8>),
}

/// `"file::"` + the **guest**-absolute path.
pub fn fs_target(guest_path: &str) -> String {
    format!("file::{guest_path}")
}

/// `"shell::"` + argv0.
pub fn process_target(argv0: &str) -> String {
    format!("shell::{argv0}")
}

/// `"api::"` + host + path + `"#"` + method, the canonical HTTP identity.
pub fn http_target(host: &str, path: &str, method: HttpMethod) -> String {
    format!("api::{host}{path}#{}", method.as_str())
}

/// `"api::"` + host + `":"` + port, the canonical raw-socket identity.
pub fn socket_target(host: &str, port: u16) -> String {
    format!("api::{host}:{port}")
}

/// `"env::"` + VARNAME.
pub fn env_target(var: &str) -> String {
    format!("env::{var}")
}

/// `"db::"` + system.
pub fn db_target(system: &str) -> String {
    format!("db::{system}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_computes_input_hash() {
        let e = HostEffect::new(
            EffectKind::Fs(FileOp::Write),
            fs_target("/tmp/x"),
            b"payload".to_vec(),
            EffectDetail::None,
            None,
        );
        assert_eq!(e.input_hash, content_hash(b"payload"));
        assert_eq!(e.target, "file::/tmp/x");
    }

    #[test]
    fn record_computes_output_hash() {
        let e = HostEffect::new(
            EffectKind::Net,
            http_target("example.com", "/v1", HttpMethod::Post),
            Vec::new(),
            EffectDetail::Http {
                method: HttpMethod::Post,
                host: "example.com".into(),
                path: "/v1".into(),
            },
            None,
        );
        let rec = HostEffectRecord::new(
            e,
            b"response body".to_vec(),
            12,
            EffectStatus::Ok {
                code: 200,
                rows: None,
            },
        );
        assert_eq!(rec.output_hash, content_hash(b"response body"));
        assert_eq!(rec.effect.target, "api::example.com/v1#POST");
    }

    #[test]
    fn target_forms_are_fixed() {
        assert_eq!(fs_target("/a/b"), "file::/a/b");
        assert_eq!(process_target("ls"), "shell::ls");
        assert_eq!(http_target("h", "/p", HttpMethod::Get), "api::h/p#GET");
        assert_eq!(socket_target("h", 5432), "api::h:5432");
        assert_eq!(env_target("PATH"), "env::PATH");
        assert_eq!(db_target("postgres"), "db::postgres");
    }

    #[test]
    fn error_status_is_bytes() {
        let s = EffectStatus::Err(vec![0xff, 0x00, 0xc3, 0x28]);
        match s {
            EffectStatus::Err(b) => assert_eq!(b, vec![0xff, 0x00, 0xc3, 0x28]),
            _ => panic!("expected Err"),
        }
    }
}
