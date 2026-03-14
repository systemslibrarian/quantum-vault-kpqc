//! Digital signature scheme trait.
//!
//! A signature is used to authenticate the [`crate::container::QuantumVaultContainer`]
//! as a whole.  The signer holds a long-lived key pair; the verifier only needs
//! the public key.

use anyhow::Result;

/// Trait for digital signature schemes.
///
/// Implementations must be `Send + Sync` so they can be passed across thread
/// boundaries in async CLI scenarios.
pub trait Signature: Send + Sync {
    /// Sign `message` with `privkey`.
    ///
    /// Returns the raw signature bytes.  The implementation must not leak
    /// `privkey` through logs or error messages.
    fn sign(&self, privkey: &[u8], message: &[u8]) -> Result<Vec<u8>>;

    /// Verify `signature` over `message` using `pubkey`.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
    /// invalid (wrong key or tampered message), or `Err` only on a hard
    /// operational failure.
    fn verify(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<bool>;

    /// Generate a fresh signature keypair.
    ///
    /// Returns `(public_key, private_key)`.
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// A short human-readable algorithm identifier, e.g. `"dev-stub"` or `"HAETAE"`.
    fn algorithm_id(&self) -> &'static str;
}
