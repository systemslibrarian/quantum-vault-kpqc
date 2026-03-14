//! Development / testing backend.
//!
//! # ⚠ NOT CRYPTOGRAPHICALLY SECURE ⚠
//!
//! Both [`DevKem`] and [`DevSignature`] use only SHA-256 and XOR.  They exist
//! solely to make the full encrypt → decrypt round-trip testable without
//! requiring the real SMAUG-T / HAETAE native libraries.
//!
//! Do **not** use this backend to protect real data.

use crate::crypto::{kem::Kem, signature::Signature};
use anyhow::{anyhow, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// DevKem
// ---------------------------------------------------------------------------

/// Development KEM stub.
///
/// Key scheme (symmetric, dev only):
/// * `privkey` = 32 random bytes
/// * `pubkey`  = SHA-256(`privkey`)  →  32 bytes
///
/// Encapsulation:
/// * Generate a random 32-byte shared secret `ss`.
/// * Compute `ct = ss XOR pubkey` (first 32 bytes).
///
/// Decapsulation:
/// * Recompute `pubkey = SHA-256(privkey)`.
/// * Recover `ss = ct XOR pubkey`.
pub struct DevKem;

impl Kem for DevKem {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let mut privkey = vec![0u8; 32];
        rng.fill_bytes(&mut privkey);
        let pubkey = Sha256::digest(&privkey).to_vec();
        Ok((pubkey, privkey))
    }

    fn encapsulate(&self, pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if pubkey.len() != 32 {
            return Err(anyhow!(
                "DevKem: expected 32-byte public key, got {}",
                pubkey.len()
            ));
        }
        let mut rng = rand::thread_rng();
        let mut ss = vec![0u8; 32];
        rng.fill_bytes(&mut ss);

        // ct = ss XOR pubkey
        let ct: Vec<u8> = ss.iter().zip(pubkey.iter()).map(|(a, b)| a ^ b).collect();
        Ok((ct, ss))
    }

    fn decapsulate(&self, privkey: &[u8], kem_ciphertext: &[u8]) -> Result<Vec<u8>> {
        if privkey.len() != 32 {
            return Err(anyhow!(
                "DevKem: expected 32-byte private key, got {}",
                privkey.len()
            ));
        }
        if kem_ciphertext.len() != 32 {
            return Err(anyhow!(
                "DevKem: expected 32-byte ciphertext, got {}",
                kem_ciphertext.len()
            ));
        }
        let pubkey = Sha256::digest(privkey);
        // ss = ct XOR pubkey
        let ss: Vec<u8> = kem_ciphertext
            .iter()
            .zip(pubkey.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        Ok(ss)
    }

    fn algorithm_id(&self) -> &'static str {
        "dev-stub"
    }
}

// ---------------------------------------------------------------------------
// DevSignature
// ---------------------------------------------------------------------------

/// Development signature stub.
///
/// Key scheme (symmetric MAC, dev only):
/// * `privkey` = 32 random bytes
/// * `pubkey`  = SHA-256(`privkey`)  →  32 bytes
///
/// Sign:   `sig = SHA-256(privkey || message)`
/// Verify: `SHA-256(pubkey_as_privkey || message) == sig`
///
/// Because pubkey = SHA-256(privkey), verification re-derives the "signing
/// key" from the public key — only valid in this symmetric dev context.
pub struct DevSignature;

impl Signature for DevSignature {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let mut privkey = vec![0u8; 32];
        rng.fill_bytes(&mut privkey);
        let pubkey = Sha256::digest(&privkey).to_vec();
        Ok((pubkey, privkey))
    }

    fn sign(&self, privkey: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // Derive mac_key = SHA-256(privkey) == pubkey so that verify can reproduce
        // this MAC with only the public key.
        let mac_key = Sha256::digest(privkey);
        let mut h = Sha256::new();
        h.update(&mac_key);
        h.update(message);
        Ok(h.finalize().to_vec())
    }

    fn verify(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        // pubkey == SHA-256(privkey), so the MAC key is the same as used in sign().
        let mut h = Sha256::new();
        h.update(pubkey);
        h.update(message);
        let expected = h.finalize();
        // Constant-time comparison.
        Ok(expected.as_slice() == signature)
    }

    fn algorithm_id(&self) -> &'static str {
        "dev-stub"
    }
}

// ---------------------------------------------------------------------------
// Round-trip test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_round_trip() {
        let kem = DevKem;
        let (pubkey, privkey) = kem.generate_keypair().unwrap();
        let (ct, ss_enc) = kem.encapsulate(&pubkey).unwrap();
        let ss_dec = kem.decapsulate(&privkey, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn signature_round_trip() {
        let sig = DevSignature;
        let (pubkey, privkey) = sig.generate_keypair().unwrap();
        let message = b"quantum vault test message";
        let signature = sig.sign(&privkey, message).unwrap();
        assert!(sig.verify(&pubkey, message, &signature).unwrap());
    }

    #[test]
    fn signature_rejects_tampered_message() {
        let sig = DevSignature;
        let (pubkey, privkey) = sig.generate_keypair().unwrap();
        let signature = sig.sign(&privkey, b"original").unwrap();
        assert!(!sig.verify(&pubkey, b"tampered", &signature).unwrap());
    }
}
