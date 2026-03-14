//! Encryption pipeline: plaintext → AES-256-GCM → Shamir split → KEM protect → container.

use crate::{
    container::{CipherSuite, EncryptedKeyShare, QuantumVaultContainer, MAGIC},
    crypto::{kem::Kem, signature::Signature},
    shamir::split_secret,
    EncryptOptions, CONTAINER_VERSION,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use rand::RngCore;
use zeroize::Zeroize;

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
) -> Result<QuantumVaultContainer> {
    if options.recipient_public_keys.len() != options.share_count as usize {
        return Err(anyhow!(
            "recipient_public_keys length ({}) must equal share_count ({})",
            options.recipient_public_keys.len(),
            options.share_count,
        ));
    }

    let mut rng = rand::thread_rng();

    // 1. Random 256-bit file key.
    let mut file_key = vec![0u8; 32];
    rng.fill_bytes(&mut file_key);

    // 2. Random 96-bit AES-GCM nonce.
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    // 3. AES-256-GCM encryption.
    let aes_key = Key::<Aes256Gcm>::from_slice(&file_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("AES-256-GCM encryption failed"))?;

    // 4. Shamir split.
    let raw_shares = split_secret(&file_key, options.share_count, options.threshold)?;
    file_key.zeroize();

    // 5. Protect each share with the recipient's KEM public key.
    let mut encrypted_shares: Vec<EncryptedKeyShare> = Vec::with_capacity(raw_shares.len());
    for (share, pubkey) in raw_shares.iter().zip(options.recipient_public_keys.iter()) {
        let (kem_ct, mut ss) = kem.encapsulate(pubkey)?;
        let protected = xor_protect(&share.data, &ss)?;
        ss.zeroize();
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
        threshold: options.threshold,
        share_count: options.share_count,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        shares: encrypted_shares,
        signature: vec![],
    };

    // 7. Sign the canonical byte representation of the non-signature fields.
    let to_sign = container_signing_bytes(&container)?;
    container.signature = signer.sign(&options.signer_private_key, &to_sign)?;

    Ok(container)
}

/// Returns the canonical byte string covered by the container signature.
///
/// The signature field itself is excluded. Fields are serialized in a stable
/// JSON object so the byte string is deterministic across platforms.
pub(crate) fn container_signing_bytes(c: &QuantumVaultContainer) -> Result<Vec<u8>> {
    let repr = serde_json::to_vec(&serde_json::json!({
        "magic":       &c.magic,
        "version":     c.version,
        "cipher":      &c.cipher,
        "threshold":   c.threshold,
        "share_count": c.share_count,
        "nonce":       &c.nonce,
        "ciphertext":  &c.ciphertext,
        "shares":      &c.shares,
    }))?;
    Ok(repr)
}

/// XOR `data` with a keystream produced from `key` via SHA-256 counter mode.
///
/// Supports share data that is longer than one SHA-256 block (unlikely in
/// practice, but handled correctly).
pub(crate) fn xor_protect(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let mut result = Vec::with_capacity(data.len());
    let mut keystream: Vec<u8> = Vec::new();
    let mut block: u32 = 0;

    for (i, &byte) in data.iter().enumerate() {
        // Extend keystream in 32-byte (SHA-256 output) blocks as needed.
        while keystream.len() <= i {
            let mut h = Sha256::new();
            h.update(key);
            h.update(block.to_le_bytes());
            keystream.extend_from_slice(&h.finalize());
            block += 1;
        }
        result.push(byte ^ keystream[i]);
    }

    Ok(result)
}
