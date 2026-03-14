//! Fuzz target: feed arbitrary bytes into `QuantumVaultContainer::from_bytes`.
//!
//! The property under test: `from_bytes` must **never panic** — it must always
//! return `Ok(_)` or `Err(_)` without unwinding. Any panic is a bug.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_container_parse

#![no_main]
use libfuzzer_sys::fuzz_target;
use qv_core::container::QuantumVaultContainer;

fuzz_target!(|data: &[u8]| {
    // Ignore the result — we only care that it does not panic.
    let _ = QuantumVaultContainer::from_bytes(data);
});
