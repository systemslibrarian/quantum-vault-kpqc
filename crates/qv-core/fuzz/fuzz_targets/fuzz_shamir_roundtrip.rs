//! Fuzz target: split a secret then immediately reconstruct it.
//!
//! Properties under test:
//!   1. For any valid (secret, share_count ∈ 2..=16, threshold ∈ 2..=share_count),
//!      `split` followed by `reconstruct` using all shares must return the original secret.
//!   2. Neither `split_secret` nor `reconstruct_secret` may panic.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_shamir_roundtrip

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qv_core::shamir::{reconstruct_secret, split_secret};

#[derive(Arbitrary, Debug)]
struct Input {
    secret: Vec<u8>,
    share_count: u8,
    threshold: u8,
}

fuzz_target!(|input: Input| {
    let Input { secret, share_count, threshold } = input;

    // Clamp to a sensible range so the fuzzer explores valid territory too.
    let share_count = share_count.clamp(2, 16);
    let threshold = threshold.clamp(2, share_count);

    if secret.is_empty() {
        return; // documented to return Err — skip
    }

    let shares = match split_secret(&secret, share_count, threshold) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Reconstruct using all shares — must equal the original secret.
    let recovered = match reconstruct_secret(&shares) {
        Ok(r) => r,
        Err(_) => return,
    };
    assert_eq!(recovered, secret, "round-trip failure: split then reconstruct must be identity");
});
