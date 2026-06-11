// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Common imports, re-exported as a single glob target.
//!
//! ```no_run
//! use afterburner::prelude::*;
//!
//! let ab = Afterburner::new()?;
//! # Ok::<_, AfterburnerError>(())
//! ```

pub use crate::{
    Afterburner, AfterburnerBuilder, AfterburnerError, FuelGauge, HostContext, Manifold, Mode,
    OutputValue, Result, ScriptId,
};
