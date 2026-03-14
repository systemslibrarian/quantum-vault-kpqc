//! Decryption pipeline: container → verify → KEM recover → Shamir reconstruct → AES decrypt.

use crate::{
    container::QuantumVaultContainer,
    crypto::{kem::Kem, signature::Signature},
    encrypt::{container_signing_bytes, xor_protect},
    shamir::{reconstruct_secret, Share},
    DecryptOptions,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use zeroize::Zeroize;

/// Decrypts a [`QuantumVaultContainer`] back to plaintext bytes.
///
/// Steps:
/// 1. Verify the container signature.
/// 2. Recover as many Shamir shares as private keys are available.
/// 3. Reconstruct the file key.
/// 4. AES-256-GCM decrypt the ciphertext.
pub fn decrypt_file(
    container: &QuantumVaultContainer,
    options: &DecryptOptions,
    kem: &dyn Kem,
    signer: &dyn Signature,
) -> Result<Vec<u8>> {
    // 1. Verify the signature before touching any ciphertext material.
    let to_sign = container_signing_bytes(container)?;
    let valid = signer.verify(&options.signer_public_key, &to_sign, &container.signature)?;
    if !valid {
        return Err(anyhow!("container signature verification failed"));
    }

    // 2. Recover the share for each supplied private key.
    //    Callers provide one private key per share they hold; they do not need
    //    all shares, only `threshold` of them.
    if options.recipient_private_keys.len() < container.threshold as usize {
        return Err(anyhow!(
            "only {} private key(s) supplied; need at least {} for the threshold",
            options.recipient_private_keys.len(),
            container.threshold,
        ));
    }

    let mut shares: Vec<Share> = Vec::with_capacity(options.recipient_private_keys.len());
    for (privkey, enc_share) in options
        .recipient_private_keys
        .iter()
        .zip(container.shares.iter())
    {
        let mut ss = kem.decapsulate(privkey, &enc_share.kem_ciphertext)?;
        let share_data = xor_protect(&enc_share.encrypted_share, &ss)?;
        ss.zeroize();
        shares.push(Share {
            index: enc_share.index,
            data: share_data,
        });
    }

    // 3. Reconstruct the file key from the recovered shares.
    let mut file_key = reconstruct_secret(&shares)?;

    // Zeroize share data before the early-return path.
    for s in shares.iter_mut() {
        s.data.zeroize();
    }

    // 4. AES-256-GCM decryption.
    let aes_key = Key::<Aes256Gcm>::from_slice(&file_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&container.nonce);
    let plaintext = cipher
        .decrypt(nonce, container.ciphertext.as_slice())
        .map_err(|_| anyhow!("AES-256-GCM decryption failed — wrong key or tampered data"))?;

    file_key.zeroize();

    Ok(plaintext)
}
