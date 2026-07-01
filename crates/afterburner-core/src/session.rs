// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! A persistent session: a runtime whose filesystem root survives across
//! successive [`run`](Session::run) calls, byte-exact.
//!
//! Where [`Combustor::run_with_result`](crate::engine::Combustor::run_with_result)
//! is a single isolated run, a `Session` keeps a preopen root alive between
//! runs so a later run observes what an earlier one wrote. The filesystem
//! accessors read and write that root directly from the host, without going
//! through guest code.
//!
//! This is the substrate-agnostic contract (R4); the concrete per-language
//! implementations land in the substrate crates.

use crate::error::Result;
use crate::language::Language;
use crate::types::RunResult;

/// A stateful run session over a persistent, byte-exact filesystem root.
pub trait Session {
    /// Run `code` in `lang` against the session's live root, returning the
    /// typed [`RunResult`]. State written by this run persists for the next.
    fn run(&mut self, code: &[u8], lang: Language) -> Result<RunResult>;

    /// Read the bytes at `path` from the session root, byte-exact.
    fn fs_read(&self, path: &str) -> Result<Vec<u8>>;

    /// Write `data` to `path` in the session root, byte-exact, creating or
    /// truncating as needed.
    fn fs_write(&mut self, path: &str, data: &[u8]) -> Result<()>;

    /// Whether `path` exists in the session root.
    fn fs_exists(&self, path: &str) -> bool;
}
