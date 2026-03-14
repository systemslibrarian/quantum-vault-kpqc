//! Quantum Vault core cryptography library.
//!
//! This crate provides the foundational pipeline for Quantum Vault:
//! AES-256-GCM file encryption, threshold key splitting with Shamir Secret Sharing,
//! container serialization, and pluggable post-quantum crypto interfaces.

pub mod container;
pub mod crypto;
pub mod decrypt;
pub mod encrypt;
pub mod shamir;

pub use container::{EncryptedKeyShare, QuantumVaultContainer};
pub use shamir::{reconstruct_secret, split_secret, Share as KeyShare};

use anyhow::Result;

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
