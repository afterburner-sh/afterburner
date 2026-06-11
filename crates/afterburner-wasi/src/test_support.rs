// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Test-only utilities. With the Javy CLI no longer in the runtime
//! path, this shrinks to a convenience constructor that callers
//! outside the crate can use without re-discovering `WasmConfig`.
//!
//! Gated behind `cfg(any(test, debug_assertions))` so it does not
//! bloat release builds used by downstream consumers.

#![cfg(any(test, debug_assertions))]

use crate::WasmConfig;

/// Build the default `WasmConfig` - no external dependencies, plugin
/// is embedded at compile time.
pub fn config_default() -> WasmConfig {
    WasmConfig::default()
}
