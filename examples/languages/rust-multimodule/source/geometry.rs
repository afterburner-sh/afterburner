//! `geometry`: a sibling module (`source/geometry.rs`) resolved by Cargo from
//! the crate root via `mod geometry;` in `main.rs`.
//!
//! Demonstrates encapsulation: `rectangle_area` is the only `pub` item;
//! `scale` is a PRIVATE helper that callers outside this module cannot name.

/// Area of an axis-aligned rectangle. The only exported item of this module.
pub fn rectangle_area(width: i64, height: i64) -> i64 {
    // Uses the private helper, proving an internal-only seam.
    scale(width, height)
}

/// Private helper: multiply two extents. Not `pub`, so `main` (or any other
/// module) cannot call `geometry::scale` - it is encapsulated here.
fn scale(a: i64, b: i64) -> i64 {
    a * b
}
