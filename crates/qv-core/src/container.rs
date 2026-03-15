// SPDX-License-Identifier: MIT
//! Quantum Vault container format.
//!
//! A `.qvault` file is a JSON-serialized [`QuantumVaultContainer`].  The magic
//! string and version field allow future format migrations without breaking
//! older parsers.

use crate::{error::{QvError, QvResult}, CONTAINER_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Magic string embedded at the start of every container to identify the format.
pub const MAGIC: &str = "QVKP";

pub const MAX_CONTAINER_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SHARE_COUNT: u8 = 16;
pub const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 4096;
pub const MAX_KEM_CIPHERTEXT_BYTES: usize = 2048;
pub const MAX_ENCRYPTED_SHARE_BYTES: usize = 128;
pub const MAX_ALGORITHM_ID_BYTES: usize = 32;
pub const CONTAINER_ID_BYTES: usize = 16;

fn is_supported_kem_algorithm(value: &str) -> bool {
    matches!(value, "dev-kem" | "SMAUG-T-3")
}

fn is_supported_sig_algorithm(value: &str) -> bool {
    matches!(value, "dev-sig" | "HAETAE-3")
}

/// Symmetric cipher used to encrypt the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256 in Galois/Counter Mode with a 96-bit nonce and 128-bit tag.
    Aes256Gcm,
}

/// A single Shamir key-share after KEM protection.
///
/// The raw share bytes are AES-256-GCM encrypted under the KEM shared secret
/// so that only the holder of the corresponding KEM private key can recover them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedKeyShare {
    /// Shamir share index (x-coordinate, 1-based).
    pub index: u8,
    /// KEM ciphertext produced by `Kem::encapsulate`.  The recipient uses their
    /// private key to run `Kem::decapsulate` and recover the shared secret.
    pub kem_ciphertext: Vec<u8>,
    /// Raw share bytes AES-256-GCM encrypted under the KEM shared secret
    /// (nonce prepended; 16-byte authentication tag appended by the AEAD).
    pub encrypted_share: Vec<u8>,
}

/// The top-level Quantum Vault container.
///
/// Fields are ordered so they can be deterministically serialized for
/// signature coverage (see [`crate::encrypt::container_signing_bytes`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantumVaultContainer {
    /// Format identifier — must equal [`MAGIC`].
    pub magic: String,
    /// Format version — currently `2`.
    pub version: u8,
    /// Symmetric cipher used to encrypt `ciphertext`.
    pub cipher: CipherSuite,
    /// KEM algorithm identifier (e.g. `"DevKem"`, `"SMAUG-T-3"`).
    ///
    /// Stored in the container so that future readers can validate they are
    /// using the correct algorithm to decapsulate the key shares.
    pub kem_algorithm: String,
    /// Signature algorithm identifier (e.g. `"DevSignature"`, `"HAETAE-3"`).
    ///
    /// Stored so that future readers can validate the signature with the
    /// correct algorithm.
    pub sig_algorithm: String,
    /// Minimum number of shares required to reconstruct the file key.
    pub threshold: u8,
    /// Total number of shares that were created.
    pub share_count: u8,
    /// Creation timestamp (Unix seconds) used for replay and swap resistance.
    pub created_at: u64,
    /// Random per-container identifier used to derive the outer AEAD nonce.
    pub container_id: Vec<u8>,
    /// AES-GCM nonce (12 bytes, base64-encoded in JSON).
    pub nonce: Vec<u8>,
    /// AES-256-GCM ciphertext (includes the 16-byte authentication tag).
    pub ciphertext: Vec<u8>,
    /// KEM-protected Shamir key shares.
    pub shares: Vec<EncryptedKeyShare>,
    /// Signature over the canonical serialization of all fields above.
    pub signature: Vec<u8>,
}

impl QuantumVaultContainer {
    /// Serialize the container to compact JSON bytes.
    pub fn to_bytes(&self) -> QvResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| QvError::Serialization)
    }

    /// Deserialize a container from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> QvResult<Self> {
        if data.len() > MAX_CONTAINER_BYTES {
            return Err(QvError::OversizedInput);
        }

        let c: Self = serde_json::from_slice(data)
            .map_err(|_| QvError::InvalidContainer("malformed json"))?;
        if c.magic != MAGIC {
            return Err(QvError::InvalidContainer("invalid magic"));
        }
        match c.version {
            CONTAINER_VERSION => {}
            other => return Err(QvError::UnsupportedVersion(other)),
        }

        if c.kem_algorithm.len() > MAX_ALGORITHM_ID_BYTES || c.sig_algorithm.len() > MAX_ALGORITHM_ID_BYTES {
            return Err(QvError::InvalidContainer("algorithm identifier too long"));
        }
        if !is_supported_kem_algorithm(&c.kem_algorithm) {
            return Err(QvError::UnsupportedAlgorithm("kem"));
        }
        if !is_supported_sig_algorithm(&c.sig_algorithm) {
            return Err(QvError::UnsupportedAlgorithm("signature"));
        }
        if c.threshold < 2 {
            return Err(QvError::InvalidContainer("threshold must be >= 2"));
        }
        if c.share_count > MAX_SHARE_COUNT {
            return Err(QvError::InvalidContainer("share_count exceeds limit"));
        }
        if c.share_count < c.threshold {
            return Err(QvError::InvalidContainer("share_count must be >= threshold"));
        }
        if c.shares.len() != c.share_count as usize {
            return Err(QvError::InvalidContainer("shares length mismatch"));
        }
        if c.container_id.len() != CONTAINER_ID_BYTES {
            return Err(QvError::InvalidContainer("container_id must be 16 bytes"));
        }
        if c.nonce.len() != 12 {
            return Err(QvError::InvalidContainer("nonce must be 12 bytes"));
        }
        if c.ciphertext.is_empty() || c.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(QvError::InvalidContainer("ciphertext length out of bounds"));
        }
        if c.signature.is_empty() || c.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(QvError::InvalidContainer("signature length out of bounds"));
        }

        let mut seen = HashSet::with_capacity(c.shares.len());
        for share in &c.shares {
            if share.index == 0 || share.index > c.share_count {
                return Err(QvError::InvalidContainer("share index out of bounds"));
            }
            if !seen.insert(share.index) {
                return Err(QvError::InvalidContainer("duplicate share index"));
            }
            if share.kem_ciphertext.is_empty() || share.kem_ciphertext.len() > MAX_KEM_CIPHERTEXT_BYTES {
                return Err(QvError::InvalidContainer("kem ciphertext length out of bounds"));
            }
            if share.encrypted_share.len() < 28 || share.encrypted_share.len() > MAX_ENCRYPTED_SHARE_BYTES {
                return Err(QvError::InvalidContainer("encrypted share length out of bounds"));
            }
        }

        Ok(c)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::backend::dev::{DevKem, DevSignature},
        crypto::kem::Kem,
        crypto::signature::Signature,
        encrypt::encrypt_file,
        EncryptOptions, CONTAINER_VERSION,
    };

    /// Build a minimal valid container for use by multiple tests.
    fn make_valid_container() -> QuantumVaultContainer {
        let kem = DevKem;
        let sig = DevSignature;
        let (pk, _sk) = kem.generate_keypair().unwrap();
        let (sig_pub_key, sig_priv_key) = sig.generate_keypair().unwrap();
        let opts = EncryptOptions {
            threshold: 2,
            share_count: 2,
            recipient_public_keys: vec![pk.clone(), pk],
            signer_private_key: sig_priv_key,
        };
        let _ = sig_pub_key; // used in decrypt, not here
        encrypt_file(b"unit test payload", &opts, &kem, &sig).unwrap()
    }

    #[test]
    fn round_trip_to_and_from_bytes() {
        let c = make_valid_container();
        let bytes = c.to_bytes().unwrap();
        let c2 = QuantumVaultContainer::from_bytes(&bytes).unwrap();
        assert_eq!(c.magic, c2.magic);
        assert_eq!(c.version, c2.version);
        assert_eq!(c.threshold, c2.threshold);
        assert_eq!(c.share_count, c2.share_count);
        assert_eq!(c.created_at, c2.created_at);
        assert_eq!(c.container_id, c2.container_id);
        assert_eq!(c.nonce, c2.nonce);
        assert_eq!(c.ciphertext, c2.ciphertext);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut c = make_valid_container();
        c.magic = "WRONG".to_string();
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut c = make_valid_container();
        c.version = CONTAINER_VERSION + 1;
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_threshold_below_two() {
        let mut c = make_valid_container();
        c.threshold = 1;
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_share_count_below_threshold() {
        let mut c = make_valid_container();
        c.share_count = c.threshold - 1; // share_count < threshold
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_nonce_length() {
        let mut c = make_valid_container();
        c.nonce = vec![0u8; 8]; // should be 12
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_container_id_length() {
        let mut c = make_valid_container();
        c.container_id = vec![0u8; 8];
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let mut c = make_valid_container();
        c.kem_algorithm = "unknown-kem".to_string();
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_shares_len_mismatch() {
        let mut c = make_valid_container();
        c.shares.pop(); // one fewer share than share_count
        let bytes = c.to_bytes().unwrap();
        assert!(QuantumVaultContainer::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_oversized_container() {
        // 65 MiB — above the 64 MiB cap in from_bytes.
        let big = vec![0u8; 65 * 1024 * 1024];
        assert!(QuantumVaultContainer::from_bytes(&big).is_err());
    }

    #[test]
    fn rejects_invalid_utf8_json() {
        assert!(QuantumVaultContainer::from_bytes(&[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn rejects_empty_input() {
        assert!(QuantumVaultContainer::from_bytes(b"").is_err());
    }
}
