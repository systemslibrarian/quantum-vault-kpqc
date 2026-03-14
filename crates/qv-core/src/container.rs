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
        Ok(c)
    }
}
