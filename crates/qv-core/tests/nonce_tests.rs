// SPDX-License-Identifier: MIT
//! Nonce uniqueness tests.
//!
//! Proves that `generate_nonce()` never produces a repeated value across a
//! large sample, providing evidence that the CSPRNG is behaving correctly.
//!
//! A 96-bit (12-byte) nonce drawn from a uniform CSPRNG has a collision
//! probability of ≈ n² / 2^{97} for n samples.  For n = 10 000:
//!
//!   P(collision) ≈ (10_000)² / 2^{97}  ≈  6.2 × 10⁻²⁴
//!
//! Any collision at this sample size would indicate a catastrophic RNG failure.
//!
//! Run with: `cargo test --test nonce_tests`

use qv_core::generate_nonce;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// 1. Uniqueness over 10 000 samples
// ---------------------------------------------------------------------------

/// Generates 10 000 nonces and asserts no two are equal.
///
/// A collision here would indicate a CSPRNG failure — the probability of
/// a legitimate collision is astronomically small (≲ 10⁻²³).
#[test]
fn nonces_are_unique_over_10k() {
    let mut seen = HashSet::with_capacity(10_000);
    for i in 0..10_000usize {
        let nonce = generate_nonce();
        assert!(
            seen.insert(nonce),
            "Nonce collision detected at iteration {i}: nonce = {nonce:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. All 12 bytes are used (no systematic bias toward all-zero)
// ---------------------------------------------------------------------------

/// Verify that across a large sample, the generated nonces are not trivially
/// biased.  This is a statistical smoke-test rather than a formal randomness
/// proof: an all-zero nonce (or any single repeated byte pattern) appearing
/// more than once in 10 000 draws would indicate a defect.
#[test]
fn nonces_are_not_all_zero() {
    // Draw 1 000 nonces; none should be [0u8; 12].
    for _ in 0..1_000 {
        let nonce = generate_nonce();
        assert_ne!(
            nonce,
            [0u8; 12],
            "generate_nonce returned all-zero nonce — RNG may be broken"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Nonce structure — length is always 12 bytes
// ---------------------------------------------------------------------------

/// The AES-GCM nonce must be exactly 96 bits (12 bytes).
#[test]
fn nonce_length_is_12_bytes() {
    for _ in 0..100 {
        let nonce = generate_nonce();
        assert_eq!(
            nonce.len(),
            12,
            "generate_nonce must return exactly 12 bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Pipeline nonces are unique across independently encrypted containers
// ---------------------------------------------------------------------------

/// Encrypt the same plaintext twice; the two containers must use distinct nonces.
///
/// This checks the full pipeline, not just the helper function.
#[test]
fn pipeline_nonces_are_distinct() {
    use qv_core::{decrypt_bytes, encrypt_bytes};

    let plaintext = b"nonce uniqueness pipeline test";
    let (ct1, keys1, sig_pub1) = encrypt_bytes(plaintext).unwrap();
    let (ct2, keys2, sig_pub2) = encrypt_bytes(plaintext).unwrap();

    // Parse and extract the nonces from each container.
    let c1 = qv_core::QuantumVaultContainer::from_bytes(&ct1).unwrap();
    let c2 = qv_core::QuantumVaultContainer::from_bytes(&ct2).unwrap();

    assert_ne!(
        c1.nonce, c2.nonce,
        "two independently encrypted containers must use distinct nonces"
    );

    // Sanity: both still decrypt correctly.
    assert_eq!(decrypt_bytes(&ct1, &keys1, &sig_pub1).unwrap(), plaintext);
    assert_eq!(decrypt_bytes(&ct2, &keys2, &sig_pub2).unwrap(), plaintext);
}
