//! Key Encapsulation Mechanism (KEM) trait.
//!
//! A KEM is used to protect each Shamir key share so that only the holder of
//! the corresponding private key can recover it.
//!
//! # Interface contract
//! * [`Kem::encapsulate`] takes a public key, generates a fresh shared secret,
//!   and returns `(ciphertext, shared_secret)`.
//! * [`Kem::decapsulate`] takes a private key and the KEM ciphertext and returns
//!   the same shared secret.
//! * The shared secret bytes are used directly as a one-time pad for the Shamir
//!   share via SHA-256 counter-mode expansion (see [`crate::encrypt::xor_protect`]).

use anyhow::Result;

/// Trait for Key Encapsulation Mechanisms.
///
/// Implementations must be `Send + Sync` so they can be passed across thread
/// boundaries in async CLI scenarios.
pub trait Kem: Send + Sync {
    /// Encapsulate a shared secret for `pubkey`.
    ///
    /// Returns `(kem_ciphertext, shared_secret)`.  The shared secret **must
    /// not** be stored by the implementation after this call — the caller
    /// is responsible for zeroizing it when done.
    fn encapsulate(&self, pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate `kem_ciphertext` using `privkey` to recover the shared secret.
    ///
    /// The returned bytes are the same shared secret produced during encapsulation.
    fn decapsulate(&self, privkey: &[u8], kem_ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Generate a fresh KEM keypair.
    ///
    /// Returns `(public_key, private_key)`.
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// A short human-readable algorithm identifier, e.g. `"dev-stub"` or `"SMAUG-T"`.
    fn algorithm_id(&self) -> &'static str;
}
