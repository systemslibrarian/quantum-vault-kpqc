// SPDX-License-Identifier: MIT
//! WebAssembly interface for qv-core.
//!
//! Compiled only when the `wasm` feature is active.
//!
//! # Build
//!
//! From the repo root:
//! ```sh
//! wasm-pack build crates/qv-core --target bundler --features wasm \
//!   --out-dir web-demo/src/lib/wasm-pkg
//! ```
//!
//! The output lands in `web-demo/src/lib/wasm-pkg/` and is imported by the
//! Next.js app via the WASM bridge (`web-demo/src/lib/wasm-bridge.ts`).
//!
//! # ⚠ Dev backend only
//!
//! All operations use [`DevKem`] + [`DevSignature`] (SHA-256 / XOR stubs).
//! This is **not cryptographically secure** — it exists to prove the full
//! pipeline works in the browser without requiring native PQ library bindings.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::{
    container::QuantumVaultContainer,
    crypto::backend::dev::{DevKem, DevSignature},
    crypto::kem::Kem,
    crypto::signature::Signature,
    encrypt::{aead_unprotect, aes_aad, container_signing_bytes, encrypt_file},
    shamir::{reconstruct_secret, Share},
    EncryptOptions,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};

// ── Keypair helpers ───────────────────────────────────────────────────────────

/// Generate a KEM keypair using the dev backend.
///
/// Returns a JSON string `{"pub":"<base64>","priv":"<base64>"}`.
#[wasm_bindgen]
pub fn qv_kem_generate_keypair() -> Result<String, JsError> {
    let kem = DevKem;
    let (pk, sk) = kem.generate_keypair().map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "pub": B64.encode(&pk), "priv": B64.encode(&sk) }).to_string())
}

/// Generate a signature keypair using the dev backend.
///
/// Returns a JSON string `{"pub":"<base64>","priv":"<base64>"}`.
#[wasm_bindgen]
pub fn qv_sig_generate_keypair() -> Result<String, JsError> {
    let sig = DevSignature;
    let (pk, sk) = sig.generate_keypair().map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "pub": B64.encode(&pk), "priv": B64.encode(&sk) }).to_string())
}

// ── Encryption ────────────────────────────────────────────────────────────────

/// Encrypt a byte payload through the full qv-core pipeline.
///
/// # Parameters
/// * `plaintext`        — raw bytes (e.g. a 52-byte deck permutation)
/// * `kem_pubkeys_json` — JSON array of base64-encoded KEM public keys, one per share
/// * `threshold`        — minimum shares required for decryption
/// * `sig_priv_b64`     — base64-encoded signing private key
///
/// # Returns
/// A serialised [`QuantumVaultContainer`] as a JSON string.
/// Pass this to [`qv_decrypt`] to reverse the operation.
#[wasm_bindgen]
pub fn qv_encrypt(
    plaintext: &[u8],
    kem_pubkeys_json: &str,
    threshold: u8,
    sig_priv_b64: &str,
) -> Result<String, JsError> {
    let kem = DevKem;
    let sig = DevSignature;

    let pubkey_b64s: Vec<String> = serde_json::from_str(kem_pubkeys_json)
        .map_err(|e| JsError::new(&format!("kem_pubkeys_json parse error: {e}")))?;

    let recipient_public_keys: Vec<Vec<u8>> = pubkey_b64s
        .iter()
        .map(|s| B64.decode(s).map_err(|e| JsError::new(&format!("invalid base64 pubkey: {e}"))))
        .collect::<Result<_, _>>()?;

    let signer_private_key = B64
        .decode(sig_priv_b64)
        .map_err(|e| JsError::new(&format!("invalid sig_priv_b64: {e}")))?;

    let share_count = recipient_public_keys.len() as u8;
    if threshold > share_count {
        return Err(JsError::new(&format!(
            "threshold ({threshold}) exceeds share_count ({share_count})"
        )));
    }

    let options = EncryptOptions {
        threshold,
        share_count,
        recipient_public_keys,
        signer_private_key,
    };

    let container = encrypt_file(plaintext, &options, &kem, &sig)
        .map_err(|_| JsError::new("encryption failed"))?;

    let json_bytes = container.to_bytes().map_err(|_| JsError::new("encryption failed"))?;
    String::from_utf8(json_bytes).map_err(|e| JsError::new(&e.to_string()))
}

// ── Decryption ────────────────────────────────────────────────────────────────

/// Decrypt a [`QuantumVaultContainer`] produced by [`qv_encrypt`].
///
/// This variant accepts selected share indices so participants can be chosen
/// non-consecutively (e.g. participants 0 and 2 from a 3-share container).
///
/// # Parameters
/// * `container_json`      — JSON string returned by [`qv_encrypt`]
/// * `selected_pairs_json` — JSON array of `{"shareIndex":N,"privKey":"<base64>"}`.
///   Supply at least `threshold` entries.
/// * `sig_pub_b64`         — base64-encoded signature verification public key
///
/// # Returns
/// The decrypted plaintext bytes (e.g. a 52-byte deck permutation).
#[wasm_bindgen]
pub fn qv_decrypt(
    container_json: &str,
    selected_pairs_json: &str,
    sig_pub_b64: &str,
) -> Result<Vec<u8>, JsError> {
    let kem = DevKem;
    let sig = DevSignature;

    let container = QuantumVaultContainer::from_bytes(container_json.as_bytes())
        .map_err(|_| JsError::new("decryption failed"))?;

    // Deserialise the selected (shareIndex, privKey) pairs.
    #[derive(serde::Deserialize)]
    struct Pair {
        #[serde(rename = "shareIndex")]
        share_index: u8,
        #[serde(rename = "privKey")]
        priv_key: String,
    }

    let pairs: Vec<Pair> = serde_json::from_str(selected_pairs_json)
        .map_err(|e| JsError::new(&format!("selected_pairs_json parse error: {e}")))?;

    if pairs.len() < container.threshold as usize {
        return Err(JsError::new(&format!(
            "need at least {} shares, got {}",
            container.threshold,
            pairs.len()
        )));
    }

    // 1. Verify the signature on the full original container before touching any
    //    ciphertext material.
    let signer_public_key = B64
        .decode(sig_pub_b64)
        .map_err(|e| JsError::new(&format!("invalid sig_pub_b64: {e}")))?;

    let to_verify =
        container_signing_bytes(&container).map_err(|_| JsError::new("decryption failed"))?;

    let valid = sig
        .verify(&signer_public_key, &to_verify, &container.signature)
        .map_err(|_| JsError::new("decryption failed"))?;

    if !valid {
        return Err(JsError::new("decryption failed"));
    }

    // 2. Recover one Shamir share per (shareIndex, privKey) pair.
    //    Pairs are matched by share index so non-consecutive participant
    //    subsets work correctly.
    let mut shares: Vec<Share> = Vec::with_capacity(pairs.len());
    for pair in &pairs {
        let privkey = B64
            .decode(&pair.priv_key)
            .map_err(|e| JsError::new(&format!("invalid privKey base64: {e}")))?;

        let enc_share = container
            .shares
            .iter()
            .find(|s| s.index == pair.share_index)
            .ok_or_else(|| JsError::new("decryption failed"))?;

        let mut ss = kem
            .decapsulate(&privkey, &enc_share.kem_ciphertext)
            .map_err(|_| JsError::new("decryption failed"))?;

        let share_data = aead_unprotect(&enc_share.encrypted_share, &ss)
            .map_err(|_| JsError::new("decryption failed"))?;

        ss.zeroize();
        shares.push(Share { index: pair.share_index, data: share_data });
    }

    // 3. Reconstruct the file key from the recovered shares.
    let mut file_key =
        reconstruct_secret(&shares).map_err(|_| JsError::new("decryption failed"))?;

    // 4. AES-256-GCM decrypt with the same AAD used during encryption (M-001).
    let aad = aes_aad(&container);
    let aes_key = Key::<Aes256Gcm>::from_slice(&file_key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&container.nonce);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: container.ciphertext.as_slice(), aad: &aad })
        .map_err(|_| JsError::new("decryption failed"))?;

    file_key.zeroize();
    Ok(plaintext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the WASM-exposed encrypt/decrypt roundtrip without a real browser.
    /// The JSON serialisation and base64 encoding are exercised end-to-end.
    #[test]
    fn wasm_api_roundtrip() {
        // Generate two KEM keypairs and one signing keypair.
        let kem_kp1: serde_json::Value =
            serde_json::from_str(&qv_kem_generate_keypair().unwrap()).unwrap();
        let kem_kp2: serde_json::Value =
            serde_json::from_str(&qv_kem_generate_keypair().unwrap()).unwrap();
        let sig_kp: serde_json::Value =
            serde_json::from_str(&qv_sig_generate_keypair().unwrap()).unwrap();

        let kem_pub1 = kem_kp1["pub"].as_str().unwrap();
        let kem_pub2 = kem_kp2["pub"].as_str().unwrap();
        let kem_priv1 = kem_kp1["priv"].as_str().unwrap();
        let kem_priv2 = kem_kp2["priv"].as_str().unwrap();
        let sig_pub = sig_kp["pub"].as_str().unwrap();
        let sig_priv = sig_kp["priv"].as_str().unwrap();

        // Encrypt a fake 52-byte deck permutation.
        let permutation: Vec<u8> = (0u8..52).collect();
        let kem_pubkeys_json =
            serde_json::json!([kem_pub1, kem_pub2]).to_string();

        let container_json =
            qv_encrypt(&permutation, &kem_pubkeys_json, 2, sig_priv).unwrap();

        // Parse container to get share indices.
        let c: serde_json::Value = serde_json::from_str(&container_json).unwrap();
        let idx1 = c["shares"][0]["index"].as_u64().unwrap() as u8;
        let idx2 = c["shares"][1]["index"].as_u64().unwrap() as u8;

        // Decrypt using both keys.
        let selected_pairs = serde_json::json!([
            { "shareIndex": idx1, "privKey": kem_priv1 },
            { "shareIndex": idx2, "privKey": kem_priv2 },
        ])
        .to_string();

        let recovered = qv_decrypt(&container_json, &selected_pairs, sig_pub).unwrap();
        assert_eq!(recovered, permutation);
    }

    #[test]
    fn wasm_api_threshold_2_of_3() {
        // Only first 2 of 3 shares needed.
        let kps: Vec<serde_json::Value> = (0..3)
            .map(|_| {
                serde_json::from_str::<serde_json::Value>(&qv_kem_generate_keypair().unwrap())
                    .unwrap()
            })
            .collect();
        let sig_kp: serde_json::Value =
            serde_json::from_str(&qv_sig_generate_keypair().unwrap()).unwrap();

        let pubs: Vec<&str> = kps.iter().map(|k| k["pub"].as_str().unwrap()).collect();
        let kem_pubkeys_json = serde_json::to_string(&pubs).unwrap();

        let plaintext = b"threshold test payload";
        let container_json =
            qv_encrypt(plaintext, &kem_pubkeys_json, 2, sig_kp["priv"].as_str().unwrap())
                .unwrap();

        let c: serde_json::Value = serde_json::from_str(&container_json).unwrap();
        let idx0 = c["shares"][0]["index"].as_u64().unwrap() as u8;
        let idx1 = c["shares"][1]["index"].as_u64().unwrap() as u8;

        // Use only shares 0 and 1 (threshold = 2).
        let selected = serde_json::json!([
            { "shareIndex": idx0, "privKey": kps[0]["priv"].as_str().unwrap() },
            { "shareIndex": idx1, "privKey": kps[1]["priv"].as_str().unwrap() },
        ])
        .to_string();

        let recovered = qv_decrypt(
            &container_json,
            &selected,
            sig_kp["pub"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    // JsError::new calls js_sys::Error::new which is a WASM import and panics
    // on native targets.  This test is only meaningful in an actual WASM runtime.
    #[cfg(target_arch = "wasm32")]
    #[test]
    fn wasm_api_wrong_sig_key_fails() {
        let kem_kp: serde_json::Value =
            serde_json::from_str(&qv_kem_generate_keypair().unwrap()).unwrap();
        let sig_kp: serde_json::Value =
            serde_json::from_str(&qv_sig_generate_keypair().unwrap()).unwrap();
        let wrong_sig_kp: serde_json::Value =
            serde_json::from_str(&qv_sig_generate_keypair().unwrap()).unwrap();

        let kem_pubkeys_json =
            serde_json::json!([kem_kp["pub"].as_str().unwrap()]).to_string();
        let container_json =
            qv_encrypt(b"data", &kem_pubkeys_json, 1, sig_kp["priv"].as_str().unwrap())
                .unwrap();

        let c: serde_json::Value = serde_json::from_str(&container_json).unwrap();
        let idx = c["shares"][0]["index"].as_u64().unwrap() as u8;
        let selected = serde_json::json!([
            { "shareIndex": idx, "privKey": kem_kp["priv"].as_str().unwrap() }
        ])
        .to_string();

        // Use the WRONG verification key → should fail.
        let result = qv_decrypt(
            &container_json,
            &selected,
            wrong_sig_kp["pub"].as_str().unwrap(),
        );
        assert!(result.is_err());
    }
}
