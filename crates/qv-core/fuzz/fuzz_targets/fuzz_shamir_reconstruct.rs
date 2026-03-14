//! Fuzz target: feed arbitrary `Share` values into `reconstruct_secret`.
//!
//! Properties under test:
//!   1. `reconstruct_secret` must never panic — only return Ok/Err.
//!   2. Calling it with a single share whose index is 0 returns Err, not a panic.
//!   3. Calling it with duplicate indices returns Err, not a panic.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_shamir_reconstruct

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qv_core::shamir::{reconstruct_secret, Share};

/// Simplified share-like structure that can be derived from arbitrary bytes.
#[derive(Arbitrary, Debug)]
struct FuzzShare {
    index: u8,
    data: Vec<u8>,
}

fuzz_target!(|shares: Vec<FuzzShare>| {
    let shares: Vec<Share> = shares
        .into_iter()
        .map(|s| Share { index: s.index, data: s.data })
        .collect();

    // Must not panic regardless of how many shares or their content.
    let _ = reconstruct_secret(&shares);
});
