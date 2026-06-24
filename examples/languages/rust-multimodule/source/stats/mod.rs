//! `stats`: a DIRECTORY module (`source/stats/mod.rs`) resolved by Cargo from
//! `mod stats;` in `main.rs`. Proves that a nested `source/` module tree
//! compiles with the `[[bin]] path = "source/main.rs"` convention.
//!
//! `mean` is exported; `sum` is private to the module - encapsulation again.

/// Arithmetic mean of `xs` (integer division). The exported API.
pub fn mean(xs: &[i64]) -> i64 {
    if xs.is_empty() {
        return 0;
    }
    // Calls the PRIVATE `sum` below; `stats::sum` is not reachable from main.
    sum(xs) / xs.len() as i64
}

/// Private sum over a slice. Not `pub`: internal to `stats`.
fn sum(xs: &[i64]) -> i64 {
    xs.iter().copied().sum()
}
