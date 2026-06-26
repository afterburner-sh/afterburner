// examples/rust-multimodule: a real multi-module Rust package compiled to
// wasm32-wasip1 by Cargo. It exercises module encapsulation and exports:
//   - `geometry` (source/geometry.rs): a `pub` API over a PRIVATE helper.
//   - `stats`    (source/stats/mod.rs): a directory module with an exported
//     and an unexported (private) function; main can call only the public one.
//
// main calls across both modules and prints a single deterministic line.
// Expected stdout: "area=50 mean=20"

mod geometry;
mod stats;

fn main() {
    // Cross-module call into `geometry`: the public API; the squaring helper
    // it uses is private to that module and unreachable from here.
    let area = geometry::rectangle_area(5, 10);

    // Cross-module call into the directory module `stats`: only `mean` is
    // public; `sum` is private to the module.
    let mean = stats::mean(&[10, 20, 30]);

    println!("area={area} mean={mean}");
}
