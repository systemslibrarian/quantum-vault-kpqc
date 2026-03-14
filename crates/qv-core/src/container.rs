//! Quantum Vault container format.
//!
//! A `.qvault` file is a JSON-serialized [`QuantumVaultContainer`].  The magic
//! string and version field allow future format migrations without breaking
//! older parsers.

use serde::{Deserialize, Serialize};

/// Magic string embedded at the start of every container to identify the format.
pub const MAGIC: &str = "QVLT1";

/// Symmetric cipher used to encrypt the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// AES-256 in Galois/Counter Mode with a 96-bit nonce and 128-bit tag.
    Aes256Gcm,
}

/// A single Shamir key-share after KEM protection.
///
/// The raw share bytes are XOR-encrypted with the KEM shared secret so that
/// only the holder of the corresponding KEM private key can recover them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyShare {
    /// Shamir share index (x-coordinate, 1-based).
    pub index: u8,
    /// KEM ciphertext produced by `Kem::encapsulate`.  The recipient uses their
    /// private key to run `Kem::decapsulate` and recover the shared secret.
    pub kem_ciphertext: Vec<u8>,
    /// Raw share bytes XOR'd with a keystream derived from the KEM shared secret.
    pub encrypted_share: Vec<u8>,
}

/// The top-level Quantum Vault container.
///
/// Fields are ordered so they can be deterministically serialized for
/// signature coverage (see [`crate::encrypt::container_signing_bytes`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumVaultContainer {
    /// Format identifier — must equal [`MAGIC`].
    pub magic: String,
    /// Format version — currently `1`.
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
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize a container from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        // Guard against memory exhaustion via oversized containers (M-002).
        const MAX_CONTAINER_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
        if data.len() > MAX_CONTAINER_BYTES {
            return Err(anyhow::anyhow!(
                "container exceeds maximum allowed size ({} bytes)",
                MAX_CONTAINER_BYTES,
            ));
        }

        let c: Self = serde_json::from_slice(data)?;
        if c.magic != MAGIC {
            return Err(anyhow::anyhow!(
                "invalid magic: expected {:?}, got {:?}",
                MAGIC,
                c.magic
            ));
        }
        if c.version != crate::CONTAINER_VERSION {
            return Err(anyhow::anyhow!(
                "unsupported container version {}",
                c.version
            ));
        }
        // Structural validation (M-003 / H-002).
        if c.threshold < 2 {
            return Err(anyhow::anyhow!(
                "container threshold must be >= 2, got {}",
                c.threshold
            ));
        }
        if c.share_count < c.threshold {
            return Err(anyhow::anyhow!(
                "share_count ({}) must be >= threshold ({})",
                c.share_count,
                c.threshold
            ));
        }
        if c.shares.len() != c.share_count as usize {
            return Err(anyhow::anyhow!(
                "shares.len() ({}) != share_count ({})",
                c.shares.len(),
                c.share_count
            ));
        }
        if c.nonce.len() != 12 {
            return Err(anyhow::anyhow!(
                "nonce must be 12 bytes, got {}",
                c.nonce.len()
            ));
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
