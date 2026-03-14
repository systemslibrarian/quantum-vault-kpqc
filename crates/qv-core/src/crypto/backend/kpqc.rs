//! KPQC backend scaffold — SMAUG-T (KEM) + HAETAE (signature).
//!
//! # Status: NOT IMPLEMENTED
//!
//! This module is a documented scaffold.  It defines the integration strategy
//! and expected FFI surface for the Korean Post-Quantum Cryptography competition
//! finalists.  No real cryptography is wired up yet.
//!
//! ## Algorithms
//!
//! | Role      | Algorithm  | Security level | Reference |
//! |-----------|-----------|----------------|-----------|
//! | KEM       | SMAUG-T   | Level 1/3/5    | <https://kpqc.or.kr/competition.html> |
//! | Signature | HAETAE    | Level 2/3/5    | <https://kpqc.or.kr/competition.html> |
//!
//! ## Integration strategy
//!
//! ### Native (CLI / server)
//! 1. Vendor the reference C implementations under `vendor/smaug-t/` and
//!    `vendor/haetae/`.
//! 2. Write a `build.rs` in this crate that compiles them via `cc` crate.
//! 3. Declare `extern "C"` bindings in this file mirroring the C API below.
//! 4. Wrap them in safe Rust structs that implement [`Kem`] and [`Signature`].
//!
//! ### WASM (web-demo)
//! 1. The reference implementations must be compiled with `emcc` or `wasm-pack`.
//! 2. Alternatively, maintain a pure-Rust port of the algorithms.
//! 3. Feature-gate native vs. WASM builds:
//!    ```toml
//!    [features]
//!    kpqc-native = []   # links C libraries
//!    kpqc-wasm   = []   # uses pure-Rust / emcc output
//!    ```
//!
//! ## Expected C API — SMAUG-T
//!
//! ```c
//! // Key generation
//! int smaug_keypair(uint8_t *pk, uint8_t *sk);
//!
//! // Encapsulation: produces ciphertext ct and shared secret ss
//! int smaug_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
//!
//! // Decapsulation: recovers shared secret ss from ct + sk
//! int smaug_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
//! ```
//!
//! ## Expected C API — HAETAE
//!
//! ```c
//! // Key generation
//! int haetae_keypair(uint8_t *pk, uint8_t *sk);
//!
//! // Signing
//! int haetae_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t mlen,
//!                 const uint8_t *sk);
//!
//! // Verification (returns 0 on success)
//! int haetae_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
//!                   size_t mlen, const uint8_t *pk);
//! ```

use crate::crypto::{kem::Kem, signature::Signature};
use anyhow::{anyhow, Result};

// ---------------------------------------------------------------------------
// KpqcKem
// ---------------------------------------------------------------------------

/// Post-quantum KEM using SMAUG-T.
///
/// # Status
/// **Not yet implemented.**  Calling any method returns an informative error.
/// Replace the bodies with FFI calls once the native library is vendored.
pub struct KpqcKem;

impl Kem for KpqcKem {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(anyhow!(
            "SMAUG-T is not yet integrated. \
             See crates/qv-core/src/crypto/backend/kpqc.rs for the integration roadmap."
        ))
    }

    fn encapsulate(&self, _pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(anyhow!(
            "SMAUG-T is not yet integrated. \
             See crates/qv-core/src/crypto/backend/kpqc.rs for the integration roadmap."
        ))
    }

    fn decapsulate(&self, _privkey: &[u8], _kem_ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(
            "SMAUG-T is not yet integrated. \
             See crates/qv-core/src/crypto/backend/kpqc.rs for the integration roadmap."
        ))
    }

    fn algorithm_id(&self) -> &'static str {
        "SMAUG-T (scaffold)"
    }
}

// ---------------------------------------------------------------------------
// KpqcSignature
// ---------------------------------------------------------------------------

/// Post-quantum signature using HAETAE.
///
/// # Status
/// **Not yet implemented.**  Calling any method returns an informative error.
/// Replace the bodies with FFI calls once the native library is vendored.
pub struct KpqcSignature;

impl Signature for KpqcSignature {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(anyhow!(
            "HAETAE is not yet integrated. \
             See crates/qv-core/src/crypto/backend/kpqc.rs for the integration roadmap."
        ))
    }

    fn sign(&self, _privkey: &[u8], _message: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!(
            "HAETAE is not yet integrated. \
             See crates/qv-core/src/crypto/backend/kpqc.rs for the integration roadmap."
        ))
    }

    fn verify(&self, _pubkey: &[u8], _message: &[u8], _signature: &[u8]) -> Result<bool> {
        Err(anyhow!(
            "HAETAE is not yet integrated. \
             See crates/qv-core/src/crypto/backend/kpqc.rs for the integration roadmap."
        ))
    }

    fn algorithm_id(&self) -> &'static str {
        "HAETAE (scaffold)"
    }
}
