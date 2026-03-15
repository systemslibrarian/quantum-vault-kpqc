// SPDX-License-Identifier: MIT
//! Shamir Secret Sharing over GF(2^8).
//!
//! Uses the irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d).
//! This matches the TypeScript web-demo implementation (shamir.ts) so that
//! share bytes are interoperable between the two backends.
//!
//! Each byte of the secret is treated as an independent element of GF(256), so
//! an N-byte secret produces N-byte share payloads.
//!
//! # Security notes
//! * Share indices are 1-based; index 0 is the secret (never issued as a share).
//! * Polynomial coefficients other than the constant term are randomly generated;
//!   zeroized after use.
//! * Share payloads are wrapped in a [`Share`] type that implements
//!   [`zeroize::ZeroizeOnDrop`].

use anyhow::{anyhow, Result};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic
// ---------------------------------------------------------------------------

/// Add two GF(256) elements (XOR).
#[inline(always)]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiply two GF(256) elements using the Russian-peasant algorithm.
/// Reduction polynomial: x^8 + x^4 + x^3 + x^2 + 1 (carry byte: 0x1d).
/// This matches the polynomial used in the TypeScript web-demo (shamir.ts).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(256) via Fermat's little theorem: a^254.
///
/// Returns 0 for input 0 (which has no inverse in GF(2^8)). The caller is
/// responsible for ensuring this function is never called with 0 — the Lagrange
/// reconstruction loop guarantees this by checking for duplicate and zero share
/// indices before computing denominators.
fn gf_inv(a: u8) -> u8 {
    // a^(2^8 - 2) = a^254
    let mut result: u8 = 1;
    let mut base = a;
    let mut exp: u8 = 254;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Divide two GF(256) elements.
#[inline(always)]
fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

/// Evaluate a polynomial at point `x` over GF(256).
/// `coeffs[0]` is the constant term; `coeffs[k]` is the coefficient of x^k.
fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    let mut x_pow: u8 = 1;
    for &c in coeffs {
        result = gf_add(result, gf_mul(c, x_pow));
        x_pow = gf_mul(x_pow, x);
    }
    result
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single Shamir share: `(index, data)` where `data[i]` is the evaluation
/// of the i-th byte's polynomial at `x = index`.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// x-coordinate (1-based; never 0).
    pub index: u8,
    /// y-values, one per byte of the original secret.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Split `secret` into `share_count` shares with a reconstruction
/// threshold of `threshold` shares.
///
/// # Errors
/// Returns an error if `threshold < 2`, `share_count < threshold`, or
/// `secret` is empty.
#[must_use = "splitting produces shares that must be distributed"]
pub fn split_secret(secret: &[u8], share_count: u8, threshold: u8) -> Result<Vec<Share>> {
    if threshold < 2 {
        return Err(anyhow!("threshold must be at least 2"));
    }
    if share_count < threshold {
        return Err(anyhow!(
            "share_count ({share_count}) must be >= threshold ({threshold})"
        ));
    }
    if secret.is_empty() {
        return Err(anyhow!("secret must not be empty"));
    }

    let mut rng = OsRng;

    // Pre-allocate one Share per index.
    let mut shares: Vec<Share> = (1..=share_count)
        .map(|i| Share {
            index: i,
            data: Vec::with_capacity(secret.len()),
        })
        .collect();

    for &byte in secret {
        // Build a random degree-(threshold-1) polynomial whose constant term is `byte`.
        let mut coeffs = vec![0u8; threshold as usize];
        coeffs[0] = byte;
        for c in coeffs[1..].iter_mut() {
            // Rejection-sample to avoid zero coefficients where practical.
            let mut v = 0u8;
            while v == 0 {
                v = rng.next_u32() as u8;
            }
            *c = v;
        }

        for share in shares.iter_mut() {
            share.data.push(poly_eval(&coeffs, share.index));
        }

        coeffs.zeroize();
    }

    Ok(shares)
}

/// Reconstruct the secret from `shares` using Lagrange interpolation at x = 0.
///
/// Any `threshold` (or more) valid shares will yield the correct secret.
/// Providing fewer shares than the threshold will silently produce garbage —
/// the caller is responsible for supplying enough shares.
///
/// # Errors
/// Returns an error if `shares` is empty, share indices are not unique, any
/// share has index 0 (reserved for the secret), or payloads have unequal lengths.
#[must_use = "reconstruction result contains the recovered secret"]
pub fn reconstruct_secret(shares: &[Share]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(anyhow!("at least one share is required"));
    }
    let len = shares[0].data.len();
    if shares.iter().any(|s| s.data.len() != len) {
        return Err(anyhow!("shares have inconsistent payload lengths"));
    }

    // Validate indices: none may be 0 (reserved for the secret) and all must be unique.
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if s.index == 0 {
            return Err(anyhow!("share index 0 is invalid (reserved for the secret polynomial constant term)"));
        }
        if !seen.insert(s.index) {
            return Err(anyhow!("duplicate share index {}", s.index));
        }
    }

    let mut secret = vec![0u8; len];

    for (i, byte) in secret.iter_mut().enumerate() {
        // Lagrange interpolation at x = 0 over GF(256).
        let mut val: u8 = 0;
        for (j, sj) in shares.iter().enumerate() {
            let xj = sj.index;
            let yj = sj.data[i];
            let mut num: u8 = 1;
            let mut den: u8 = 1;
            for (k, sk) in shares.iter().enumerate() {
                if j != k {
                    let xk = sk.index;
                    // Numerator: product of (0 - xk) = xk  (negation is identity in GF(2^8))
                    num = gf_mul(num, xk);
                    // Denominator: product of (xj - xk) = xj XOR xk
                    den = gf_mul(den, gf_add(xj, xk));
                }
            }
            val = gf_add(val, gf_mul(yj, gf_div(num, den)));
        }
        *byte = val;
    }

    Ok(secret)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_2_of_3() {
        let secret = b"super secret key";
        let shares = split_secret(secret, 3, 2).unwrap();
        assert_eq!(shares.len(), 3);

        // Any two shares should reconstruct correctly.
        let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(reconstructed, secret);

        let reconstructed = reconstruct_secret(&shares[1..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn round_trip_3_of_5() {
        let secret: Vec<u8> = (0u8..32).collect();
        let shares = split_secret(&secret, 5, 3).unwrap();
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let reconstructed = reconstruct_secret(&subset).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn too_few_shares_produces_garbage() {
        let secret = b"test secret value";
        let shares = split_secret(secret, 3, 3).unwrap();
        // Two shares for a 3-of-3 scheme should NOT reconstruct correctly.
        let wrong = reconstruct_secret(&shares[0..2]).unwrap();
        assert_ne!(wrong, secret.as_slice());
    }

    #[test]
    fn rejects_bad_params() {
        assert!(split_secret(b"x", 3, 1).is_err()); // threshold < 2
        assert!(split_secret(b"x", 2, 3).is_err()); // share_count < threshold
        assert!(split_secret(b"", 3, 2).is_err());  // empty secret
    }

    #[test]
    fn round_trip_2_of_2() {
        let secret = b"minimum scheme";
        let shares = split_secret(secret, 2, 2).unwrap();
        assert_eq!(shares.len(), 2);
        let out = reconstruct_secret(&shares).unwrap();
        assert_eq!(out, secret);
    }

    #[test]
    fn round_trip_single_byte_secret() {
        let secret = &[0xABu8];
        let shares = split_secret(secret, 3, 2).unwrap();
        let out = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(out, secret);
    }

    #[test]
    fn round_trip_64_byte_secret() {
        // Exercises the multi-block case in xor_protect.
        let secret: Vec<u8> = (0u8..64).collect();
        let shares = split_secret(&secret, 4, 3).unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone(), shares[3].clone()];
        let out = reconstruct_secret(&subset).unwrap();
        assert_eq!(out, secret);
    }

    #[test]
    fn rejects_zero_index_share() {
        let shares = vec![Share { index: 0, data: vec![1, 2, 3] }];
        assert!(reconstruct_secret(&shares).is_err());
    }

    #[test]
    fn rejects_duplicate_share_indices() {
        let shares = vec![
            Share { index: 1, data: vec![10, 20] },
            Share { index: 1, data: vec![30, 40] },
        ];
        assert!(reconstruct_secret(&shares).is_err());
    }

    #[test]
    fn rejects_inconsistent_payload_lengths() {
        let shares = vec![
            Share { index: 1, data: vec![10, 20, 30] },
            Share { index: 2, data: vec![40, 50] },
        ];
        assert!(reconstruct_secret(&shares).is_err());
    }

    #[test]
    fn rejects_empty_share_list() {
        assert!(reconstruct_secret(&[]).is_err());
    }

    #[test]
    fn share_indices_are_one_based() {
        let shares = split_secret(b"test", 5, 3).unwrap();
        for (i, s) in shares.iter().enumerate() {
            assert_eq!(s.index, (i + 1) as u8);
        }
    }

    #[test]
    fn gf_mul_identity() {
        // a * 1 == a for all non-zero a
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, 1), a);
        }
    }

    #[test]
    fn gf_mul_commutativity() {
        assert_eq!(gf_mul(7, 13), gf_mul(13, 7));
        assert_eq!(gf_mul(200, 37), gf_mul(37, 200));
    }

    #[test]
    fn gf_inv_correctness() {
        // a * inv(a) == 1 for all non-zero a
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "failed for a={}", a);
        }
    }
}
