# HPACK test stories

The stories the HPACK unit tests decode and encode (`src/hpack/test/fixture.rs`), from the h2
repository at v0.4.20 (`fixtures/hpack`, which collects the http2jp hpack-test-case stories), each
gzipped. Only the stories the tests name are kept. They are test data, never published with the
crate (`include` in Cargo.toml).
