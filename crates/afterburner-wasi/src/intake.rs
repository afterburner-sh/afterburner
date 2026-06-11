// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Input serializer — `serde_json::Value` → stdin bytes for the WASM
//! guest. Javy scripts expect `JSON.parse(readStdin())` to yield the data
//! they operate on, so the on-wire format is simply `serde_json::to_vec`.

use afterburner_core::{AfterburnerError, Result};
use serde_json::Value;

pub fn serialize_input(input: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(input).map_err(AfterburnerError::Serialize)
}
