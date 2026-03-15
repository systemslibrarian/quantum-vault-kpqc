// SPDX-License-Identifier: MIT
//! Encryption pipeline: plaintext → AES-256-GCM → Shamir split → KEM protect → container.

use crate::{
    container::{
        CipherSuite, EncryptedKeyShare, QuantumVaultContainer, CONTAINER_ID_BYTES,
        MAGIC, MAX_CIPHERTEXT_BYTES, MAX_ENCRYPTED_SHARE_BYTES, MAX_SHARE_COUNT,
    },
    crypto::{kem::Kem, signature::Signature},
    error::{QvError, QvResult},
    shamir::split_secret,
    EncryptOptions, CONTAINER_VERSION,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Generate a fresh random 96-bit (12-byte) AES-GCM nonce.
///
/// Exposed so that external tests can verify nonce uniqueness properties
/// without having to go through the full encryption pipeline.
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

struct AadContext<'a> {
    version: u8,
    cipher: &'a CipherSuite,
    created_at: u64,
    container_id: &'a [u8],
    nonce: &'a [u8],
    threshold: u8,
    share_count: u8,
    kem_alg: &'a str,
    sig_alg: &'a str,
}

fn derive_labeled_bytes<const N: usize>(ikm: &[u8], label: &[u8]) -> QvResult<[u8; N]> {
    let hk = Hkdf::<Sha256>::new(Some(b"qvault-v2"), ikm);
    let mut out = [0u8; N];
    hk.expand(label, &mut out)
        .map_err(|_| QvError::EncryptionFailed)?;
    Ok(out)
}

fn derive_container_id() -> [u8; CONTAINER_ID_BYTES] {
    let mut container_id = [0u8; CONTAINER_ID_BYTES];
    OsRng.fill_bytes(&mut container_id);
    container_id
}

fn derive_container_nonce(container_id: &[u8]) -> QvResult<[u8; 12]> {
    derive_labeled_bytes(container_id, b"qvault-container-nonce")
}

fn derive_share_key(shared_secret: &[u8]) -> QvResult<[u8; 32]> {
    derive_labeled_bytes(shared_secret, b"qvault-share-key")
}

fn derive_share_nonce(shared_secret: &[u8]) -> QvResult<[u8; 12]> {
    derive_labeled_bytes(shared_secret, b"qvault-share-nonce")
}

/// Encrypts `plaintext` and returns a signed [`QuantumVaultContainer`].
///
/// Steps:
/// 1. Generate a random 256-bit file key.
/// 2. Encrypt `plaintext` with AES-256-GCM.
/// 3. Shamir-split the file key into `options.share_count` shares.
/// 4. KEM-protect each share for the corresponding recipient public key.
/// 5. Serialize fields for signing; attach signature.
pub fn encrypt_file(
    plaintext: &[u8],
    options: &EncryptOptions,
    kem: &dyn Kem,
    signer: &dyn Signature,
) -> QvResult<QuantumVaultContainer> {
    if options.share_count > MAX_SHARE_COUNT {
        return Err(QvError::InvalidInput("share_count exceeds parser limit"));
    }
    if options.recipient_public_keys.len() != options.share_count as usize {
        return Err(QvError::InvalidInput("recipient key count must match share_count"));
    }
    if plaintext.len() + 16 > MAX_CIPHERTEXT_BYTES {
        return Err(QvError::InvalidInput("plaintext too large"));
    }

    // 1. Random 256-bit file key.
    let mut file_key = vec![0u8; 32];
    OsRng.fill_bytes(&mut file_key);

    // 2. Replay-resistant metadata and deterministic outer AEAD nonce.
    let container_id = derive_container_id();
    let nonce_bytes = derive_container_nonce(&container_id)?;
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| QvError::EncryptionFailed)?
        .as_secs();

    // 3. AES-256-GCM encryption with AAD covering security-relevant context.
    let aad = aad_bytes(&AadContext {
        version: CONTAINER_VERSION,
        cipher: &CipherSuite::Aes256Gcm,
        created_at,
        container_id: &container_id,
        nonce: &nonce_bytes,
        threshold: options.threshold,
        share_count: options.share_count,
        kem_alg: kem.algorithm_id(),
        sig_alg: signer.algorithm_id(),
    });
    let aes_key = Key::<Aes256Gcm>::from_slice(&file_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|_| QvError::EncryptionFailed)?;

    // 4. Shamir split.
    let raw_shares = split_secret(&file_key, options.share_count, options.threshold)
        .map_err(|_| QvError::EncryptionFailed)?;
    file_key.zeroize();

    // 5. Protect each share with the recipient's KEM public key.
    let mut encrypted_shares: Vec<EncryptedKeyShare> = Vec::with_capacity(raw_shares.len());
    for (share, pubkey) in raw_shares.iter().zip(options.recipient_public_keys.iter()) {
        let (kem_ct, mut ss) = kem.encapsulate(pubkey).map_err(|_| QvError::EncryptionFailed)?;
        let protected = aead_protect(&share.data, &ss)?;
        ss.zeroize();
        if protected.len() > MAX_ENCRYPTED_SHARE_BYTES {
            return Err(QvError::EncryptionFailed);
        }
        encrypted_shares.push(EncryptedKeyShare {
            index: share.index,
            kem_ciphertext: kem_ct,
            encrypted_share: protected,
        });
    }

    // 6. Build container (signature field empty until we sign it).
    let mut container = QuantumVaultContainer {
        magic: MAGIC.to_string(),
        version: CONTAINER_VERSION,
        cipher: CipherSuite::Aes256Gcm,
        kem_algorithm: kem.algorithm_id().to_string(),
        sig_algorithm: signer.algorithm_id().to_string(),
        threshold: options.threshold,
        share_count: options.share_count,
        created_at,
        container_id: container_id.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        shares: encrypted_shares,
        signature: vec![],
    };

    // 7. Sign the canonical byte representation of the non-signature fields.
    let to_sign = container_signing_bytes(&container)?;
    container.signature = signer
        .sign(&options.signer_private_key, &to_sign)
        .map_err(|_| QvError::EncryptionFailed)?;

    Ok(container)
}

/// Compute the AES-GCM Additional Authenticated Data (AAD).
///
/// Binds the ciphertext to its security-relevant context: algorithm choice,
/// threshold, and container version.  Both encrypt and decrypt must supply
/// the same bytes for the GCM authentication tag to verify.
///
/// Key ordering is stable: `serde_json` serialises object fields via an internal
/// `BTreeMap`, which sorts keys alphabetically, making the output deterministic
/// across platforms regardless of the order the fields appear in the `json!()`
/// macro call.
fn aad_bytes(ctx: &AadContext<'_>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "cipher":        ctx.cipher,
        "container_id":  ctx.container_id,
        "created_at":    ctx.created_at,
        "kem_algorithm": ctx.kem_alg,
        "nonce":         ctx.nonce,
        "share_count":   ctx.share_count,
        "sig_algorithm": ctx.sig_alg,
        "threshold":     ctx.threshold,
        "version":       ctx.version,
    }))
    .expect("AAD serialisation is infallible")
}

pub(crate) fn aes_aad(c: &QuantumVaultContainer) -> Vec<u8> {
    aad_bytes(&AadContext {
        version: c.version,
        cipher: &c.cipher,
        created_at: c.created_at,
        container_id: &c.container_id,
        nonce: &c.nonce,
        threshold: c.threshold,
        share_count: c.share_count,
        kem_alg: &c.kem_algorithm,
        sig_alg: &c.sig_algorithm,
    })
}

/// Returns the canonical byte string covered by the container signature.
///
/// The signature field itself is excluded. Fields are serialized in a stable
/// JSON object so the byte string is deterministic across platforms.
pub(crate) fn container_signing_bytes(c: &QuantumVaultContainer) -> QvResult<Vec<u8>> {
    let repr = serde_json::to_vec(&serde_json::json!({
        "magic":         &c.magic,
        "version":       c.version,
        "cipher":        &c.cipher,
        "kem_algorithm": &c.kem_algorithm,
        "sig_algorithm": &c.sig_algorithm,
        "threshold":     c.threshold,
        "share_count":   c.share_count,
        "created_at":    c.created_at,
        "container_id":  &c.container_id,
        "nonce":         &c.nonce,
        "ciphertext":    &c.ciphertext,
        "shares":        &c.shares,
    }))
    .map_err(|_| QvError::Serialization)?;
    Ok(repr)
}

/// Wrap `data` under AES-256-GCM using `key` (32 bytes), replacing the
/// unauthenticated SHA-256 counter-mode XOR previously used.
///
/// Output layout: `nonce (12 B) || AES-GCM ciphertext+tag (data.len() + 16 B)`.
/// The derived nonce is prepended so callers store only a single opaque blob.
pub(crate) fn aead_protect(data: &[u8], ikm: &[u8]) -> QvResult<Vec<u8>> {
    let key = derive_share_key(ikm)?;
    let nonce_bytes = derive_share_nonce(ikm)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, data)
        .map_err(|_| QvError::EncryptionFailed)?;
    let mut result = Vec::with_capacity(12 + ct.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ct);
    Ok(result)
}

/// Authenticate and decrypt data produced by [`aead_protect`].
/// Returns an error immediately if the authentication tag does not verify,
/// pinpointing corruption to this specific share without consulting the outer AES-GCM tag.
pub(crate) fn aead_unprotect(data: &[u8], ikm: &[u8]) -> QvResult<Vec<u8>> {
    if data.len() < 12 {
        return Err(QvError::DecryptionFailed);
    }
    let derived_nonce = derive_share_nonce(ikm)?;
    if !bool::from(data[..12].ct_eq(&derived_nonce)) {
        return Err(QvError::DecryptionFailed);
    }
    let nonce = Nonce::from_slice(&derived_nonce);
    let key = derive_share_key(ikm)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(aes_key);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|_| QvError::DecryptionFailed)
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
        decrypt::decrypt_file,
        DecryptOptions, EncryptOptions,
    };

    #[test]
    fn aes_encrypt_decrypt_roundtrip() {
        let kem = DevKem;
        let sig = DevSignature;

        let (pk1, sk1) = kem.generate_keypair().unwrap();
        let (pk2, sk2) = kem.generate_keypair().unwrap();
        let (sig_pub, sig_priv) = sig.generate_keypair().unwrap();

        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let opts = EncryptOptions {
            threshold: 2,
            share_count: 2,
            recipient_public_keys: vec![pk1, pk2],
            signer_private_key: sig_priv,
        };

        let container = encrypt_file(plaintext, &opts, &kem, &sig).unwrap();

        let dec_opts = DecryptOptions {
            recipient_private_keys: vec![sk1, sk2],
            share_indices: vec![1, 2],
            signer_public_key: sig_pub,
        };

        let recovered = decrypt_file(&container, &dec_opts, &kem, &sig).unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let kem = DevKem;
        let sig = DevSignature;

        let (pk1, _sk1) = kem.generate_keypair().unwrap();
        let (pk2, _sk2) = kem.generate_keypair().unwrap();
        let (_sig_pub, sig_priv) = sig.generate_keypair().unwrap();

        let opts = EncryptOptions {
            threshold: 2,
            share_count: 2,
            recipient_public_keys: vec![pk1, pk2],
            signer_private_key: sig_priv,
        };

        let mut container = encrypt_file(b"sensitive data", &opts, &kem, &sig).unwrap();

        // Flip a bit in the ciphertext.
        if let Some(b) = container.ciphertext.first_mut() {
            *b ^= 0xff;
        }

        // Signature covers the ciphertext, so this must fail at verification.
        let dec_opts = DecryptOptions {
            recipient_private_keys: vec![_sk1, _sk2],
            share_indices: vec![1, 2],
            signer_public_key: _sig_pub,
        };
        let result = crate::decrypt::decrypt_file(&container, &dec_opts, &kem, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn aead_protect_round_trip() {
        // aead_protect produces an authenticated ciphertext; aead_unprotect must recover the input.
        let data: Vec<u8> = (0u8..80).collect();
        let key = b"test-key-material-32-bytes-long!";
        let protected = aead_protect(&data, key).unwrap();
        let restored = aead_unprotect(&protected, key).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn aead_protect_empty_data() {
        let key = b"test-key-material-32-bytes-long!";
        let protected = aead_protect(&[], key).unwrap();
        let restored = aead_unprotect(&protected, key).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn aead_unprotect_rejects_tampered_tag() {
        let data = b"secret share bytes";
        let key = b"test-key-material-32-bytes-long!";
        let mut protected = aead_protect(data, key).unwrap();
        // Flip the last byte (part of the GCM auth tag) — must fail.
        let last = protected.len() - 1;
        protected[last] ^= 0x01;
        assert!(aead_unprotect(&protected, key).is_err());
    }

    #[test]
    fn aes_aad_is_deterministic() {
        let ctx = AadContext {
            version: 2,
            cipher: &CipherSuite::Aes256Gcm,
            created_at: 1,
            container_id: &[7u8; 16],
            nonce: &[9u8; 12],
            threshold: 2,
            share_count: 2,
            kem_alg: "dev-kem",
            sig_alg: "dev-sig",
        };
        let a = aad_bytes(&ctx);
        let b = aad_bytes(&ctx);
        assert_eq!(a, b);
    }

    #[test]
    fn aes_aad_differs_on_algorithm_change() {
        let a = aad_bytes(&AadContext {
            version: 2,
            cipher: &CipherSuite::Aes256Gcm,
            created_at: 1,
            container_id: &[7u8; 16],
            nonce: &[9u8; 12],
            threshold: 2,
            share_count: 2,
            kem_alg: "dev-kem",
            sig_alg: "dev-sig",
        });
        let b = aad_bytes(&AadContext {
            version: 2,
            cipher: &CipherSuite::Aes256Gcm,
            created_at: 1,
            container_id: &[7u8; 16],
            nonce: &[9u8; 12],
            threshold: 2,
            share_count: 2,
            kem_alg: "SMAUG-T-3",
            sig_alg: "dev-sig",
        });
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_mismatched_recipient_key_count() {
        let kem = DevKem;
        let sig = DevSignature;
        let (pk, _sk) = kem.generate_keypair().unwrap();
        let (_sig_pub, sig_priv) = sig.generate_keypair().unwrap();
        // share_count=2 but only one public key supplied
        let opts = EncryptOptions {
            threshold: 2,
            share_count: 2,
            recipient_public_keys: vec![pk],
            signer_private_key: sig_priv,
        };
        assert!(encrypt_file(b"hello", &opts, &kem, &sig).is_err());
    }
}
