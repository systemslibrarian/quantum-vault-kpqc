//! FFI boundary between Rust and the SMAUG-T / HAETAE C reference
//! implementations.
//!
//! This module is only compiled when the `kpqc-native` feature is active.
//! Every symbol in the `extern "C"` block must be resolved at link time by the
//! static libraries produced by `build.rs`.
//!
//! # Safety
//!
//! All public functions in this module are safe Rust wrappers.  The unsafe
//! `extern "C"` calls are encapsulated here and nowhere else.  Callers may
//! rely on these wrappers to:
//! - correctly size output buffers (see the `SIZE` constants below),
//! - convert C integer return codes to `anyhow::Result`, and
//! - handle zero-extension of key/ciphertext byte sequences.
//!
//! # Parameter sizes
//!
//! These constants match the security-level-3 parameters from the KpqC
//! reference implementations.  If you compile with a different level you must
//! adjust them here OR use conditional compilation based on
//! `SMAUG_T_LEVEL` / `HAETAE_LEVEL` (set by `build.rs` or the environment).
//!
//! | Constant                  | Value | Notes                                |
//! |---------------------------|-------|--------------------------------------|
//! | `SMAUG_T_PK_BYTES`        | 1216  | SMAUG-T Level-3 public key           |
//! | `SMAUG_T_SK_BYTES`        | 1600  | SMAUG-T Level-3 secret key           |
//! | `SMAUG_T_CT_BYTES`        | 1216  | SMAUG-T Level-3 ciphertext           |
//! | `SMAUG_T_SS_BYTES`        | 32    | Shared secret (all levels)           |
//! | `HAETAE_PK_BYTES`         | 992   | HAETAE Level-3 public key            |
//! | `HAETAE_SK_BYTES`         | 2576  | HAETAE Level-3 secret key            |
//! | `HAETAE_SIG_BYTES`        | 2445  | HAETAE Level-3 max signature size    |

#![allow(non_snake_case, non_upper_case_globals)]

use anyhow::{anyhow, Result};

// ---------------------------------------------------------------------------
// Parameter sizes — SMAUG-T Level 3
// ---------------------------------------------------------------------------

pub const SMAUG_T_PK_BYTES: usize = 1216;
pub const SMAUG_T_SK_BYTES: usize = 1600;
pub const SMAUG_T_CT_BYTES: usize = 1216;
pub const SMAUG_T_SS_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Parameter sizes — HAETAE Level 3
// ---------------------------------------------------------------------------

pub const HAETAE_PK_BYTES: usize = 992;
pub const HAETAE_SK_BYTES: usize = 2576;
/// Maximum signature size (the actual signature may be shorter).
pub const HAETAE_SIG_BYTES: usize = 2445;

// ---------------------------------------------------------------------------
// Raw extern "C" declarations
// ---------------------------------------------------------------------------
//
// These function names match the symbols exported by the SMAUG-T and HAETAE
// reference implementations at security level 3.  Other levels use the same
// API surface with different symbol names (e.g. `smaug1_keypair`,
// `haetae2_keypair`).  Adjust the names if you build a different level.

extern "C" {
    // ── SMAUG-T ──────────────────────────────────────────────────────────

    /// Generate a SMAUG-T keypair.
    ///
    /// `pk` must be at least `SMAUG_T_PK_BYTES` bytes; `sk` at least
    /// `SMAUG_T_SK_BYTES` bytes.
    ///
    /// Returns 0 on success.
    fn smaug3_keypair(pk: *mut u8, sk: *mut u8) -> std::os::raw::c_int;

    /// Encapsulate: produce ciphertext `ct` and shared secret `ss` from
    /// recipient public key `pk`.
    ///
    /// `ct` must be at least `SMAUG_T_CT_BYTES`; `ss` at least
    /// `SMAUG_T_SS_BYTES`.
    ///
    /// Returns 0 on success.
    fn smaug3_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> std::os::raw::c_int;

    /// Decapsulate: recover shared secret `ss` from `ct` using secret key
    /// `sk`.
    ///
    /// `ss` must be at least `SMAUG_T_SS_BYTES`.
    ///
    /// Returns 0 on success.
    fn smaug3_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> std::os::raw::c_int;

    // ── HAETAE ───────────────────────────────────────────────────────────

    /// Generate a HAETAE keypair.
    ///
    /// `pk` must be at least `HAETAE_PK_BYTES`; `sk` at least
    /// `HAETAE_SK_BYTES`.
    ///
    /// Returns 0 on success.
    fn haetae3_keypair(pk: *mut u8, sk: *mut u8) -> std::os::raw::c_int;

    /// Sign `mlen` bytes at `m` with secret key `sk`.
    ///
    /// `sig` must be at least `HAETAE_SIG_BYTES` bytes.  The actual number of
    /// bytes written is placed in `*siglen`.
    ///
    /// Returns 0 on success.
    fn haetae3_sign(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> std::os::raw::c_int;

    /// Verify a signature.
    ///
    /// Returns 0 when the signature is valid.
    fn haetae3_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> std::os::raw::c_int;
}

// ---------------------------------------------------------------------------
// Safe Rust wrappers — SMAUG-T
// ---------------------------------------------------------------------------

/// Generate a SMAUG-T Level-3 keypair.
///
/// Returns `(public_key, secret_key)`.
pub fn smaug_t_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; SMAUG_T_PK_BYTES];
    let mut sk = vec![0u8; SMAUG_T_SK_BYTES];
    let rc = unsafe { smaug3_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err(anyhow!("smaug3_keypair failed with code {}", rc));
    }
    Ok((pk, sk))
}

/// Encapsulate using a SMAUG-T Level-3 public key.
///
/// Returns `(ciphertext, shared_secret)`.
pub fn smaug_t_enc(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if pk.len() != SMAUG_T_PK_BYTES {
        return Err(anyhow!(
            "SMAUG-T public key must be {} bytes, got {}",
            SMAUG_T_PK_BYTES,
            pk.len()
        ));
    }
    let mut ct = vec![0u8; SMAUG_T_CT_BYTES];
    let mut ss = vec![0u8; SMAUG_T_SS_BYTES];
    let rc = unsafe {
        smaug3_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr())
    };
    if rc != 0 {
        return Err(anyhow!("smaug3_enc failed with code {}", rc));
    }
    Ok((ct, ss))
}

/// Decapsulate using a SMAUG-T Level-3 secret key + ciphertext.
///
/// Returns the shared secret.
pub fn smaug_t_dec(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != SMAUG_T_SK_BYTES {
        return Err(anyhow!(
            "SMAUG-T secret key must be {} bytes, got {}",
            SMAUG_T_SK_BYTES,
            sk.len()
        ));
    }
    if ct.len() != SMAUG_T_CT_BYTES {
        return Err(anyhow!(
            "SMAUG-T ciphertext must be {} bytes, got {}",
            SMAUG_T_CT_BYTES,
            ct.len()
        ));
    }
    let mut ss = vec![0u8; SMAUG_T_SS_BYTES];
    let rc = unsafe { smaug3_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    if rc != 0 {
        return Err(anyhow!("smaug3_dec failed with code {}", rc));
    }
    Ok(ss)
}

// ---------------------------------------------------------------------------
// Safe Rust wrappers — HAETAE
// ---------------------------------------------------------------------------

/// Generate a HAETAE Level-3 keypair.
///
/// Returns `(public_key, secret_key)`.
pub fn haetae_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; HAETAE_PK_BYTES];
    let mut sk = vec![0u8; HAETAE_SK_BYTES];
    let rc = unsafe { haetae3_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err(anyhow!("haetae3_keypair failed with code {}", rc));
    }
    Ok((pk, sk))
}

/// Sign `message` with a HAETAE Level-3 secret key.
///
/// Returns the signature bytes (length ≤ `HAETAE_SIG_BYTES`).
pub fn haetae_sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != HAETAE_SK_BYTES {
        return Err(anyhow!(
            "HAETAE secret key must be {} bytes, got {}",
            HAETAE_SK_BYTES,
            sk.len()
        ));
    }
    let mut sig = vec![0u8; HAETAE_SIG_BYTES];
    let mut siglen: usize = HAETAE_SIG_BYTES;
    let rc = unsafe {
        haetae3_sign(
            sig.as_mut_ptr(),
            &mut siglen as *mut usize,
            message.as_ptr(),
            message.len(),
            sk.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(anyhow!("haetae3_sign failed with code {}", rc));
    }
    sig.truncate(siglen);
    Ok(sig)
}

/// Verify a HAETAE Level-3 signature.
///
/// Returns `Ok(true)` when valid, `Ok(false)` when invalid.
pub fn haetae_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    if pk.len() != HAETAE_PK_BYTES {
        return Err(anyhow!(
            "HAETAE public key must be {} bytes, got {}",
            HAETAE_PK_BYTES,
            pk.len()
        ));
    }
    let rc = unsafe {
        haetae3_verify(
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
            pk.as_ptr(),
        )
    };
    Ok(rc == 0)
}
