// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! Afterburner adaptive engine — native-first execution with background
//! WASM compilation and tier switching on hot paths (Flying Start
//! principle).

pub mod adaptive;

pub use adaptive::{AdaptiveCombustor, make_adaptive_cache};
