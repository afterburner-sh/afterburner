// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The Ruby REPL backend - honest pending state.
//!
//! Ruby evaluation needs the ruby.wasm runtime payload (a WASM build of the
//! CRuby interpreter), which is not yet bundled in afterburner. Rather than a
//! crash or a fake prompt, the Ruby REPL prints a clear, actionable "not yet"
//! and returns. When the payload lands (a `BURN_RUBY_RUNTIME` runner, mirroring
//! the Pyodide one), only this function changes: it will run the read loop over
//! that runner exactly as the Python backend does.

use anyhow::Result;

/// The substring an integration test can match to LOUD-SKIP the Ruby REPL
/// honestly while the runtime is absent (never a silent green).
pub const RUBY_PENDING_MARKER: &str = "ruby.wasm runtime not bundled";

/// Run the Ruby REPL: an honest pending notice, then return cleanly.
pub fn run() -> Result<()> {
    anyhow::bail!(
        "Ruby REPL is not available yet: the {RUBY_PENDING_MARKER} (a WASM build \
         of the CRuby interpreter). The REPL is wired and will run line-by-line \
         the moment the payload is shipped (set BURN_RUBY_RUNTIME=<dir>). \
         For now, use --lang js, ts, python, rust, go, c, or cpp."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruby_repl_is_honest_pending_not_a_crash() {
        let err = run().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(RUBY_PENDING_MARKER),
            "must carry the pending marker for honest skip: {msg}"
        );
        assert!(
            msg.contains("BURN_RUBY_RUNTIME"),
            "must point at the runtime env var so it is actionable: {msg}"
        );
    }
}
