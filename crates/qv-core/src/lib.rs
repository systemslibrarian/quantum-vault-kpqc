//! Quantum Vault core cryptography library.
//!
//! This crate provides the foundational pipeline for Quantum Vault:
//! AES-256-GCM file encryption, threshold key splitting with Shamir Secret Sharing,
//! container serialization, and pluggable post-quantum crypto interfaces.
//!
//! # Quick start
//!
//! ```no_run
//! use qv_core::{encrypt_bytes, decrypt_bytes};
//!
//! let (ct, keys, sig_pub) = encrypt_bytes(b"hello world").unwrap();
//! let plain  = decrypt_bytes(&ct, &keys, &sig_pub).unwrap();
//! assert_eq!(plain, b"hello world");
//! ```

pub mod container;
pub mod crypto;
pub mod decrypt;
pub mod encrypt;
pub mod shamir;

/// WebAssembly bindings — compiled only with the `wasm` feature.
///
/// Build with:
/// ```sh
/// wasm-pack build crates/qv-core --target bundler --features wasm \
///   --out-dir web-demo/src/lib/wasm-pkg
/// ```
#[cfg(feature = "wasm")]
pub mod wasm;

pub use container::{EncryptedKeyShare, QuantumVaultContainer};
pub use shamir::{reconstruct_secret, split_secret, Share as KeyShare};

use anyhow::Result;
use crypto::backend::dev::{DevKem, DevSignature};
use crypto::kem::Kem as _;
use crypto::signature::Signature as _;

/// Container format version used by the current implementation.
pub const CONTAINER_VERSION: u8 = 1;

/// Input options controlling key splitting and metadata during encryption.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// Minimum number of shares required to reconstruct the file key.
    pub threshold: u8,
    /// Total shares to create from the file key.
    pub share_count: u8,
    /// Recipient KEM public keys, one for each share to protect.
    pub recipient_public_keys: Vec<Vec<u8>>,
    /// Signature private key used to sign the serialized container.
    pub signer_private_key: Vec<u8>,
}

/// Input options for decrypting and validating a container.
#[derive(Debug, Clone)]
pub struct DecryptOptions {
    /// Recipient KEM private keys used to recover protected key shares.
    pub recipient_private_keys: Vec<Vec<u8>>,
    /// Signature public key used to verify container authenticity.
    pub signer_public_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Low-level pipeline API (accepts explicit backend objects)
// ---------------------------------------------------------------------------

/// Encrypts plaintext bytes into a versioned Quantum Vault container.
pub fn encrypt_file(
    plaintext: &[u8],
    options: &EncryptOptions,
    kem: &dyn crypto::kem::Kem,
    signature: &dyn crypto::signature::Signature,
) -> Result<QuantumVaultContainer> {
    encrypt::encrypt_file(plaintext, options, kem, signature)
}

/// Decrypts a Quantum Vault container back into plaintext bytes.
pub fn decrypt_file(
    container: &QuantumVaultContainer,
    options: &DecryptOptions,
    kem: &dyn crypto::kem::Kem,
    signature: &dyn crypto::signature::Signature,
) -> Result<Vec<u8>> {
    decrypt::decrypt_file(container, options, kem, signature)
}

/// Splits a symmetric key into threshold shares.
pub fn split_key(secret: &[u8], share_count: u8, threshold: u8) -> Result<Vec<KeyShare>> {
    split_secret(secret, share_count, threshold)
}

/// Reconstructs a symmetric key from threshold shares.
pub fn reconstruct_key(shares: &[KeyShare]) -> Result<Vec<u8>> {
    reconstruct_secret(shares)
}

// ---------------------------------------------------------------------------
// High-level convenience API (uses dev backend, manages keypairs internally)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` using the dev backend with a 2-of-2 threshold scheme.
///
/// Returns `(container_json, kem_privkeys, sig_pubkey)`.
/// Both `kem_privkeys` are required for decryption — pass them to [`decrypt_bytes`].
///
/// For a custom share count or threshold use [`encrypt_with_threshold`].
///
/// # ⚠ Dev backend only
/// Key material is produced by the development stub (SHA-256/XOR).  Do **not**
/// use this to protect real data.
pub fn encrypt_bytes(plaintext: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)> {
    encrypt_with_threshold(plaintext, 2, 2)
}

/// Decrypt a container produced by [`encrypt_bytes`].
///
/// `kem_privkeys` must be the slice returned by the matching `encrypt_bytes` call.
pub fn decrypt_bytes(
    container_json: &[u8],
    kem_privkeys: &[Vec<u8>],
    sig_pubkey: &[u8],
) -> Result<Vec<u8>> {
    decrypt_with_threshold(container_json, kem_privkeys, sig_pubkey)
}

/// Encrypt `plaintext` with a configurable threshold scheme using the dev backend.
///
/// Generates one KEM keypair per share and one signature keypair.
///
/// Returns `(container_json, kem_privkeys, sig_pubkey)`.
/// `kem_privkeys[i]` unlocks share `i`.  Any `threshold` of them suffice for
/// decryption.
///
/// # ⚠ Dev backend only
pub fn encrypt_with_threshold(
    plaintext: &[u8],
    share_count: u8,
    threshold: u8,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)> {
    let kem = DevKem;
    let sig = DevSignature;

    let (sig_pub, sig_priv) = sig.generate_keypair()?;

    let mut kem_pubkeys: Vec<Vec<u8>> = Vec::with_capacity(share_count as usize);
    let mut kem_privkeys: Vec<Vec<u8>> = Vec::with_capacity(share_count as usize);
    for _ in 0..share_count {
        let (pk, sk) = kem.generate_keypair()?;
        kem_pubkeys.push(pk);
        kem_privkeys.push(sk);
    }

    let options = EncryptOptions {
        threshold,
        share_count,
        recipient_public_keys: kem_pubkeys,
        signer_private_key: sig_priv,
    };

    let container = encrypt::encrypt_file(plaintext, &options, &kem, &sig)?;
    Ok((container.to_bytes()?, kem_privkeys, sig_pub))
}

/// Decrypt a container produced by [`encrypt_with_threshold`].
///
/// Supply at least `threshold` private keys from the list returned during encryption.
/// Keys must correspond to the first N encrypted shares in the container
/// (i.e. pass keys in the same order they were generated).
pub fn decrypt_with_threshold(
    container_json: &[u8],
    kem_privkeys: &[Vec<u8>],
    sig_pubkey: &[u8],
) -> Result<Vec<u8>> {
    let kem = DevKem;
    let sig = DevSignature;
    let container = QuantumVaultContainer::from_bytes(container_json)?;
    let options = DecryptOptions {
        recipient_private_keys: kem_privkeys.to_vec(),
        signer_public_key: sig_pubkey.to_vec(),
    };
    decrypt::decrypt_file(&container, &options, &kem, &sig)
}

// ---------------------------------------------------------------------------
// Integration tests for the high-level API
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_bytes_roundtrip() {
        let plaintext = b"quantum vault high-level roundtrip test";
        let (ct, keys, sig_pub) = encrypt_bytes(plaintext).unwrap();
        let recovered = decrypt_bytes(&ct, &keys, &sig_pub).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_decrypt_with_threshold_3_of_5() {
        let plaintext = b"threshold roundtrip: 3 of 5";
        let (ct, keys, sig_pub) = encrypt_with_threshold(plaintext, 5, 3).unwrap();
        // Use only the first 3 keys.
        let recovered = decrypt_with_threshold(&ct, &keys[..3], &sig_pub).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_with_too_few_keys_fails() {
        let plaintext = b"must fail with insufficient keys";
        let (ct, keys, sig_pub) = encrypt_with_threshold(plaintext, 3, 3).unwrap();
        // Only 2 of 3 required keys — should fail threshold check in decrypt_file.
        let result = decrypt_with_threshold(&ct, &keys[..2], &sig_pub);
        assert!(result.is_err());
    }
}
