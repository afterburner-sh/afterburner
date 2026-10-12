//! Wasmtime picks one trap mechanism per process from its first engine and
//! panics on a later engine that disagrees, so this runs in its own binary.

#[test]
fn engines_start_after_a_host_engine_using_signal_traps() {
    let mut host = wasmtime::Config::new();
    #[cfg(target_os = "macos")]
    host.macos_use_mach_ports(false);
    wasmtime::Engine::new(&host).expect("host engine");

    afterburner_wasi::embedder_vm::deterministic_engine().expect("deterministic engine");
    afterburner_wasi::embedder_vm::deterministic_engine_with_epoch().expect("epoch engine");
    wasmtime::Engine::new(&afterburner_wasi::wasm_engine::base_config()).expect("base engine");
}
