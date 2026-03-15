// SPDX-License-Identifier: MIT
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
pub mod error;
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
pub use error::{QvError, QvResult};
pub use encrypt::generate_nonce;
pub use shamir::{reconstruct_secret, split_secret, Share as KeyShare};

use crypto::backend::dev::{DevKem, DevSignature};
use crypto::kem::Kem as _;
use crypto::signature::Signature as _;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result of encrypting plaintext: (container_json, kem_privkeys, sig_pubkey).
///
/// - `container_json`: serialized container for storage/transmission
/// - `kem_privkeys`: one private key per share; any `threshold` keys suffice for decryption
/// - `sig_pubkey`: public key for verifying the container signature
pub type EncryptResult = (Vec<u8>, Vec<Vec<u8>>, Vec<u8>);

// [L-002] Prevent dev-backend from shipping in release builds.
// Add feature `allow_dev_backend_in_release` to explicitly opt-in if needed
// (e.g. for benchmarking), but it must never be the default.
#[cfg(all(
    not(debug_assertions),
    feature = "dev-backend",
    not(feature = "allow_dev_backend_in_release")
))]
compile_error!(
    "dev-backend is active in a release build. \
     Compile with --features kpqc-native for a production build, or add \
     feature `allow_dev_backend_in_release` to acknowledge the insecurity."
);

/// Container format version used by the current implementation.
pub const CONTAINER_VERSION: u8 = 2;

/// Input options controlling key splitting and metadata during encryption.
///
/// Implements [`ZeroizeOnDrop`]: `signer_private_key` is wiped from memory
/// when this struct is dropped so private key material does not linger on
/// the heap after the encrypt operation completes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
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

/// Redacted Debug implementation — never prints private key material (H-004).
impl fmt::Debug for EncryptOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptOptions")
            .field("threshold", &self.threshold)
            .field("share_count", &self.share_count)
            .field("recipient_public_keys_count", &self.recipient_public_keys.len())
            .field("signer_private_key", &"[redacted]")
            .finish()
    }
}

/// Input options for decrypting and validating a container.
///
/// Implements [`ZeroizeOnDrop`]: `recipient_private_keys` are wiped from
/// memory when this struct is dropped so private key material does not
/// linger on the heap after the decrypt operation completes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecryptOptions {
    /// Recipient KEM private keys used to recover protected key shares.
    /// Element `i` decrypts the share with index `share_indices[i]`.
    pub recipient_private_keys: Vec<Vec<u8>>,
    /// Share indices parallel to `recipient_private_keys`.
    /// `share_indices[i]` is the 1-based share index that `recipient_private_keys[i]` unlocks.
    pub share_indices: Vec<u8>,
    /// Signature public key used to verify container authenticity.
    pub signer_public_key: Vec<u8>,
}

/// Redacted Debug implementation — never prints private key material (H-004).
impl fmt::Debug for DecryptOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptOptions")
            .field("recipient_private_keys_count", &self.recipient_private_keys.len())
            .field("share_indices", &self.share_indices)
            .field("signer_public_key_len", &self.signer_public_key.len())
            .finish()
    }
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
) -> QvResult<QuantumVaultContainer> {
    encrypt::encrypt_file(plaintext, options, kem, signature)
}

/// Decrypts a Quantum Vault container back into plaintext bytes.
pub fn decrypt_file(
    container: &QuantumVaultContainer,
    options: &DecryptOptions,
    kem: &dyn crypto::kem::Kem,
    signature: &dyn crypto::signature::Signature,
) -> QvResult<Vec<u8>> {
    decrypt::decrypt_file(container, options, kem, signature)
}

/// Splits a symmetric key into threshold shares.
pub fn split_key(secret: &[u8], share_count: u8, threshold: u8) -> QvResult<Vec<KeyShare>> {
    split_secret(secret, share_count, threshold).map_err(|_| QvError::InvalidInput("invalid shamir parameters"))
}

/// Reconstructs a symmetric key from threshold shares.
pub fn reconstruct_key(shares: &[KeyShare]) -> QvResult<Vec<u8>> {
    reconstruct_secret(shares).map_err(|_| QvError::InvalidInput("invalid shamir shares"))
}

// ---------------------------------------------------------------------------
// High-level convenience API (uses dev backend, manages keypairs internally)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` using the dev backend with a 2-of-2 threshold scheme.
///
/// Returns `(container_json, kem_privkeys, sig_pubkey)` — see [`EncryptResult`].
/// Both `kem_privkeys` are required for decryption — pass them to [`decrypt_bytes`].
///
/// For a custom share count or threshold use [`encrypt_with_threshold`].
///
/// # ⚠ Dev backend only
/// Key material is produced by the development stub (SHA-256/XOR).  Do **not**
/// use this to protect real data.
#[must_use = "encryption result contains keys required for decryption"]
pub fn encrypt_bytes(plaintext: &[u8]) -> QvResult<EncryptResult> {
    encrypt_with_threshold(plaintext, 2, 2)
}

/// Decrypt a container produced by [`encrypt_bytes`].
///
/// `kem_privkeys` must be the slice returned by the matching `encrypt_bytes` call.
#[must_use = "decryption result contains the recovered plaintext"]
pub fn decrypt_bytes(
    container_json: &[u8],
    kem_privkeys: &[Vec<u8>],
    sig_pubkey: &[u8],
) -> QvResult<Vec<u8>> {
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
) -> QvResult<EncryptResult> {
    let kem = DevKem;
    let sig = DevSignature;

    let (sig_pub, sig_priv) = sig.generate_keypair().map_err(|_| QvError::EncryptionFailed)?;

    let mut kem_pubkeys: Vec<Vec<u8>> = Vec::with_capacity(share_count as usize);
    let mut kem_privkeys: Vec<Vec<u8>> = Vec::with_capacity(share_count as usize);
    for _ in 0..share_count {
        let (pk, sk) = kem.generate_keypair().map_err(|_| QvError::EncryptionFailed)?;
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
) -> QvResult<Vec<u8>> {
    let kem = DevKem;
    let sig = DevSignature;
    let container = QuantumVaultContainer::from_bytes(container_json).map_err(|_| QvError::DecryptionFailed)?;
    // Derive share indices from the container's shares in order (positional match).
    let share_indices: Vec<u8> = container
        .shares
        .iter()
        .take(kem_privkeys.len())
        .map(|s| s.index)
        .collect();
    let options = DecryptOptions {
        recipient_private_keys: kem_privkeys.to_vec(),
        share_indices,
        signer_public_key: sig_pubkey.to_vec(),
    };
    decrypt::decrypt_file(&container, &options, &kem, &sig).map_err(|_| QvError::DecryptionFailed)
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

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        // Empty plaintext is a valid AES-GCM input — should round-trip cleanly.
        let (ct, keys, sig_pub) = encrypt_bytes(b"").unwrap();
        let recovered = decrypt_bytes(&ct, &keys, &sig_pub).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn encrypt_decrypt_large_plaintext() {
        let plaintext = vec![0xABu8; 1_000_000]; // 1 MB
        let (ct, keys, sig_pub) = encrypt_bytes(&plaintext).unwrap();
        let recovered = decrypt_bytes(&ct, &keys, &sig_pub).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_rejects_corrupted_json() {
        let (ct, keys, sig_pub) = encrypt_bytes(b"some data").unwrap();
        let mut bad = ct.clone();
        // Corrupt a byte near the start to break JSON parsing.
        bad[5] ^= 0xff;
        assert!(decrypt_bytes(&bad, &keys, &sig_pub).is_err());
    }

    #[test]
    fn decrypt_rejects_wrong_sig_pubkey() {
        let plaintext = b"wrong key test";
        let (ct, keys, _sig_pub) = encrypt_bytes(plaintext).unwrap();
        // Generate a fresh, unrelated sig keypair and use its public key.
        use crypto::backend::dev::DevSignature;
        use crypto::signature::Signature;
        let (wrong_pub, _) = DevSignature.generate_keypair().unwrap();
        let result = decrypt_bytes(&ct, &keys, &wrong_pub);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_binary_plaintext() {
        // Full 0x00–0xFF byte range.
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let (ct, keys, sig_pub) = encrypt_bytes(&plaintext).unwrap();
        let recovered = decrypt_bytes(&ct, &keys, &sig_pub).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn threshold_1_of_n_is_rejected() {
        // threshold must be >= 2 — enforce at the library boundary.
        assert!(encrypt_with_threshold(b"x", 3, 1).is_err());
    }

    #[test]
    fn encrypt_produces_different_ciphertexts_each_call() {
        let plaintext = b"determinism check";
        let (ct1, _, _) = encrypt_bytes(plaintext).unwrap();
        let (ct2, _, _) = encrypt_bytes(plaintext).unwrap();
        assert_ne!(ct1, ct2, "two encryptions of the same plaintext must differ (random nonce)");
    }
}
