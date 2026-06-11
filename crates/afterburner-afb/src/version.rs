// SPDX-License-Identifier: Apache-2.0
//! The `[runtime] min` gate (§3.3 / Step 37).
//!
//! A package declares the minimum engine it needs. The "running engine" is
//! the `afterburner-core` this crate is compiled against
//! ([`afterburner_core::VERSION`]) - reused directly so the gate can never
//! drift from the real runtime.

use crate::error::{AfbError, Result};

/// The engine version this build enforces against.
pub fn running_version() -> &'static str {
    afterburner_core::VERSION
}

/// Reject if `min` is newer than the running engine.
///
/// `min` and the running version are compared as semver. A non-semver `min`
/// is [`AfbError::InvalidVersion`]; `min > running` is
/// [`AfbError::RuntimeTooOld`].
pub fn check_runtime_min(min: &str) -> Result<()> {
    let required = semver::Version::parse(min.trim())
        .map_err(|e| AfbError::InvalidVersion(min.to_string(), e.to_string()))?;
    let running = semver::Version::parse(running_version()).map_err(|e| {
        // Should never happen: our own crate version is always valid semver.
        AfbError::InvalidVersion(running_version().to_string(), e.to_string())
    })?;
    if running < required {
        return Err(AfbError::RuntimeTooOld {
            required: required.to_string(),
            running: running.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_version_is_semver() {
        assert!(semver::Version::parse(running_version()).is_ok());
    }

    #[test]
    fn equal_and_older_minimums_pass() {
        check_runtime_min(running_version()).unwrap();
        check_runtime_min("0.0.1").unwrap();
        check_runtime_min(" 0.0.0 ").unwrap(); // trimmed
    }

    #[test]
    fn newer_minimum_is_rejected() {
        let err = check_runtime_min("99.0.0").unwrap_err();
        assert!(matches!(err, AfbError::RuntimeTooOld { .. }), "got {err:?}");
    }

    #[test]
    fn non_semver_minimum_is_rejected() {
        assert!(matches!(
            check_runtime_min("latest"),
            Err(AfbError::InvalidVersion(_, _))
        ));
    }
}
