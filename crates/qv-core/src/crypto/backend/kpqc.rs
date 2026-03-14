//! KPQC backend — SMAUG-T (KEM) + HAETAE (signature).
//!
//! This module is **feature-gated**:
//!
//! | Feature flag     | What is compiled                                         |
//! |------------------|----------------------------------------------------------|
//! | `kpqc-native`    | Real FFI calls to compiled C libraries (requires `build.rs` + vendored source) |
//! | `kpqc-wasm`      | Browser-side WASM stub (placeholder — pure-Rust port TBD) |
//! | *(neither)*      | No-op stubs that return `NotAvailable` errors with hints |
//!
//! ## Algorithms
//!
//! | Role      | Algorithm  | Security level | Reference |
//! |-----------|-----------|----------------|-----------|
//! | KEM       | SMAUG-T   | Level 3        | <https://kpqc.or.kr/competition.html> |
//! | Signature | HAETAE    | Level 3        | <https://kpqc.or.kr/competition.html> |
//!
//! ## Vendoring the C reference implementations
//!
//! The SMAUG-T and HAETAE reference implementations are available from the
//! KpqC competition at <https://kpqc.or.kr/competition.html>.  There is no
//! official public GitHub mirror.  Download the submission packages, extract
//! them, and place the source trees at:
//!
//! ```text
//! vendor/smaug-t/   ← extracted SMAUG-T reference implementation
//! vendor/haetae/    ← extracted HAETAE reference implementation
//! ```
//!
//! Then build with:
//! ```sh
//! cargo build -p qv-core --features kpqc-native
//! ```

use crate::crypto::{kem::Kem, signature::Signature};
use anyhow::{anyhow, Result};

// ===========================================================================
// ── NATIVE path (kpqc-native) ──────────────────────────────────────────────
// ===========================================================================

#[cfg(feature = "kpqc-native")]
mod native {
    use super::*;
    use crate::crypto::backend::kpqc_ffi as ffi;

    // ── KpqcKem (native) ────────────────────────────────────────────────────

    /// Post-quantum KEM using SMAUG-T Level-3 via FFI.
    pub struct KpqcKem;

    impl Kem for KpqcKem {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            ffi::smaug_t_keypair()
        }

        fn encapsulate(&self, pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            ffi::smaug_t_enc(pubkey)
        }

        fn decapsulate(&self, privkey: &[u8], kem_ciphertext: &[u8]) -> Result<Vec<u8>> {
            ffi::smaug_t_dec(privkey, kem_ciphertext)
        }

        fn algorithm_id(&self) -> &'static str {
            "SMAUG-T-3"
        }
    }

    // ── KpqcSignature (native) ───────────────────────────────────────────────

    /// Post-quantum signature using HAETAE Level-3 via FFI.
    pub struct KpqcSignature;

    impl Signature for KpqcSignature {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            ffi::haetae_keypair()
        }

        fn sign(&self, privkey: &[u8], message: &[u8]) -> Result<Vec<u8>> {
            ffi::haetae_sign(privkey, message)
        }

        fn verify(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
            ffi::haetae_verify(pubkey, message, signature)
        }

        fn algorithm_id(&self) -> &'static str {
            "HAETAE-3"
        }
    }
}

// ===========================================================================
// ── WASM path (kpqc-wasm, !kpqc-native) ────────────────────────────────────
// ===========================================================================

#[cfg(all(feature = "kpqc-wasm", not(feature = "kpqc-native")))]
mod wasm_backend {
    use super::*;

    // TODO: replace this stub with a proper pure-Rust port or emcc-compiled
    // WASM bindings once available.

    /// Post-quantum KEM using SMAUG-T (WASM stub — not yet implemented).
    pub struct KpqcKem;

    impl Kem for KpqcKem {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(anyhow!(
                "SMAUG-T WASM backend is not yet implemented. \
                 A pure-Rust port or emcc-compiled binding is required."
            ))
        }
        fn encapsulate(&self, _pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(anyhow!("SMAUG-T WASM backend is not yet implemented."))
        }
        fn decapsulate(&self, _privkey: &[u8], _ct: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("SMAUG-T WASM backend is not yet implemented."))
        }
        fn algorithm_id(&self) -> &'static str {
            "SMAUG-T-3"
        }
    }

    /// Post-quantum signature using HAETAE (WASM stub — not yet implemented).
    pub struct KpqcSignature;

    impl Signature for KpqcSignature {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(anyhow!(
                "HAETAE WASM backend is not yet implemented. \
                 A pure-Rust port or emcc-compiled binding is required."
            ))
        }
        fn sign(&self, _privkey: &[u8], _message: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("HAETAE WASM backend is not yet implemented."))
        }
        fn verify(&self, _pubkey: &[u8], _message: &[u8], _sig: &[u8]) -> Result<bool> {
            Err(anyhow!("HAETAE WASM backend is not yet implemented."))
        }
        fn algorithm_id(&self) -> &'static str {
            "HAETAE-3"
        }
    }
}

// ===========================================================================
// ── Stub path (neither kpqc-native nor kpqc-wasm) ──────────────────────────
// ===========================================================================

#[cfg(not(any(feature = "kpqc-native", feature = "kpqc-wasm")))]
mod stub {
    use super::*;

    /// Post-quantum KEM using SMAUG-T.
    ///
    /// This stub is compiled when neither `kpqc-native` nor `kpqc-wasm`
    /// features are active.  Activate one of those features to enable real
    /// cryptography.
    pub struct KpqcKem;

    impl Kem for KpqcKem {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(not_available("SMAUG-T (KEM)"))
        }
        fn encapsulate(&self, _pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(not_available("SMAUG-T (KEM)"))
        }
        fn decapsulate(&self, _privkey: &[u8], _ct: &[u8]) -> Result<Vec<u8>> {
            Err(not_available("SMAUG-T (KEM)"))
        }
        fn algorithm_id(&self) -> &'static str {
            "SMAUG-T-3"
        }
    }

    /// Post-quantum signature using HAETAE.
    ///
    /// This stub is compiled when neither `kpqc-native` nor `kpqc-wasm`
    /// features are active.
    pub struct KpqcSignature;

    impl Signature for KpqcSignature {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            Err(not_available("HAETAE (signature)"))
        }
        fn sign(&self, _privkey: &[u8], _message: &[u8]) -> Result<Vec<u8>> {
            Err(not_available("HAETAE (signature)"))
        }
        fn verify(&self, _pubkey: &[u8], _message: &[u8], _sig: &[u8]) -> Result<bool> {
            Err(not_available("HAETAE (signature)"))
        }
        fn algorithm_id(&self) -> &'static str {
            "HAETAE-3"
        }
    }

    fn not_available(algo: &str) -> anyhow::Error {
        anyhow!(
            "{algo} is not available in this build. \
             Compile with `--features kpqc-native` (requires vendored C source) \
             or `--features kpqc-wasm` for the browser backend."
        )
    }
}

// ===========================================================================
// ── Public re-exports — pick the right impl ─────────────────────────────────
// ===========================================================================

#[cfg(feature = "kpqc-native")]
pub use native::{KpqcKem, KpqcSignature};

#[cfg(all(feature = "kpqc-wasm", not(feature = "kpqc-native")))]
pub use wasm_backend::{KpqcKem, KpqcSignature};

#[cfg(not(any(feature = "kpqc-native", feature = "kpqc-wasm")))]
pub use stub::{KpqcKem, KpqcSignature};
