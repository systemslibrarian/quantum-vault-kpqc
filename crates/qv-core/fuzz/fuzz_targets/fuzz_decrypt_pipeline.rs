//! Fuzz target: feed arbitrary bytes as a container into the full decrypt pipeline.
//!
//! Properties under test:
//!   1. `decrypt_bytes` must never panic on arbitrary input — only return Err.
//!      (A valid container with the wrong keys will Err; garbage input will Err.)
//!   2. The function must not exhibit undefined behaviour, accessible memory
//!      outside the input buffer, or stack overflows on any input.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_decrypt_pipeline

#![no_main]
use libfuzzer_sys::fuzz_target;
use qv_core::decrypt_bytes;

// A fixed pair of 32-byte keys that matches the DevKem shape.
// The fuzzer will mostly fail at JSON parsing long before reaching key material.
static FAKE_KEY: &[u8] = &[0u8; 32];
static FAKE_SIG_PUB: &[u8] = &[0u8; 32];

fuzz_target!(|data: &[u8]| {
    let keys = vec![FAKE_KEY.to_vec(), FAKE_KEY.to_vec()];
    // Must not panic — only return Ok or Err.
    let _ = decrypt_bytes(data, &keys, FAKE_SIG_PUB);
});
