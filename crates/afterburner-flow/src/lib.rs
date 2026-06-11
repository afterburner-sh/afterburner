// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! Afterburner flow engine - a Rust-native runner for user-authored JS
//! modules consumed in a flow/pipeline. Construct one [`FlowEngine`] up
//! front, then `load` modules, `execute` them against a chain input, and
//! `unload` when no longer needed.

pub mod chain;
pub mod engine;

pub use engine::{FlowEngine, default_fuel_gauge};
