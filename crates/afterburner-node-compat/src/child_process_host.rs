// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `child_process.*` host functions. Always denied when
//! `Manifold::child_process == false`. Even when enabled, only available
//! via the **native** engine path — the WASM plugin does not declare a
//! host import for `spawn`, so untrusted scripts cannot reach it.

use afterburner_core::{AfterburnerError, Manifold, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ExecResult {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn exec_sync(command: &str, args: &[&str], m: &Manifold) -> Result<ExecResult> {
    if !m.child_process {
        return Err(AfterburnerError::PermissionDenied(format!(
            "child_process.execSync({command})"
        )));
    }
    let out = Command::new(command)
        .args(args)
        .output()
        .map_err(|e| AfterburnerError::Host(format!("child_process.execSync: {e}")))?;
    Ok(ExecResult {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}
