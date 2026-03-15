// SPDX-License-Identifier: MIT
//! Decryption pipeline: container → verify → KEM recover → Shamir reconstruct → AES decrypt.

use crate::{
    container::QuantumVaultContainer,
    crypto::{kem::Kem, signature::Signature},
    encrypt::{aead_unprotect, aes_aad, container_signing_bytes},
    error::{QvError, QvResult},
    shamir::{reconstruct_secret, Share},
    DecryptOptions,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use zeroize::Zeroize;

/// Decrypts a [`QuantumVaultContainer`] back to plaintext bytes.
///
/// Steps:
/// 1. Verify the container signature.
/// 2. Recover Shamir shares by matching each private key to its share index.
/// 3. Reconstruct the file key.
/// 4. AES-256-GCM decrypt the ciphertext (with AAD).
pub fn decrypt_file(
    container: &QuantumVaultContainer,
    options: &DecryptOptions,
    kem: &dyn Kem,
    signer: &dyn Signature,
) -> QvResult<Vec<u8>> {
    // Validate that key list and index list are paired.
    if options.recipient_private_keys.len() != options.share_indices.len() {
        return Err(QvError::InvalidInput("private key count must match share index count"));
    }
    if options.share_indices.len() < container.threshold as usize {
        return Err(QvError::InvalidInput("insufficient shares supplied"));
    }

    // 1. Verify the signature before touching any ciphertext material.
    let to_sign = container_signing_bytes(container)?;
    let valid = signer
        .verify(&options.signer_public_key, &to_sign, &container.signature)
        .map_err(|_| QvError::DecryptionFailed)?;
    if !valid {
        return Err(QvError::DecryptionFailed);
    }

    // 2. Recover each share by matching the supplied private key to its share index (H-005).
    let mut shares: Vec<Share> = Vec::with_capacity(options.share_indices.len());
    for (privkey, &share_idx) in options
        .recipient_private_keys
        .iter()
        .zip(options.share_indices.iter())
    {
        let enc_share = container
            .shares
            .iter()
            .find(|s| s.index == share_idx)
            .ok_or(QvError::DecryptionFailed)?;

        let mut ss = kem
            .decapsulate(privkey, &enc_share.kem_ciphertext)
            .map_err(|_| QvError::DecryptionFailed)?;
        let share_data = aead_unprotect(&enc_share.encrypted_share, &ss)?;
        ss.zeroize();
        shares.push(Share {
            index: enc_share.index,
            data: share_data,
        });
    }

    // 3. Reconstruct the file key from the recovered shares.
    let mut file_key = reconstruct_secret(&shares).map_err(|_| QvError::DecryptionFailed)?;

    // Zeroize share data before the early-return path.
    for s in shares.iter_mut() {
        s.data.zeroize();
    }

    // Defensive nonce length check (container.rs::from_bytes already validates this,
    // but protect against containers constructed programmatically without going
    // through from_bytes).
    if container.nonce.len() != 12 {
        file_key.zeroize(); // must not survive an early return
        return Err(QvError::DecryptionFailed);
    }

    // 4. AES-256-GCM decryption with the same AAD used during encryption (M-001).
    let aad = aes_aad(container);
    let aes_key = Key::<Aes256Gcm>::from_slice(&file_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&container.nonce);
    // Capture the result first so file_key is zeroized unconditionally before
    // any error is propagated — the key must not survive an auth failure.
    let decrypt_result = cipher
        .decrypt(nonce, Payload { msg: container.ciphertext.as_slice(), aad: &aad });
    file_key.zeroize();
    let plaintext = decrypt_result.map_err(|_| QvError::DecryptionFailed)?;

    Ok(plaintext)
}
