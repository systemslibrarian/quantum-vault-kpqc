//! Known-Answer Tests (KAT) and Deterministic Test Vectors
//!
//! This file provides:
//!
//! 1. **AES-256-GCM NIST vector** — verifies the `aes-gcm` crate produces the
//!    correct tag for an empty message with all-zero key/nonce (NIST SP 800-38D).
//!
//! 2. **GF(2⁸) arithmetic vectors** — exercises `gf_mul`/`gf_inv` via the
//!    public Shamir API, using hand-verifiable inputs.
//!
//! 3. **Shamir deterministic reconstruction vector** — verifies that
//!    `reconstruct_secret` returns the known secret for pre-computed shares
//!    derived from a specific polynomial over GF(2⁸).
//!
//! 4. **Container round-trip** — verifies `to_bytes` / `from_bytes` identity.
//!
//! 5. **Pipeline property tests** — nonce freshness, round-trip for edge cases.
//!
//! 6. **Generator** (`#[ignore]`) — run with `-- --ignored --nocapture` to
//!    print all computed hex values for independent verification.
//!
//! See `docs/test-vectors.md` for the full vector documentation.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use qv_core::{
    decrypt_bytes, decrypt_with_threshold, encrypt_bytes, encrypt_with_threshold,
    container::QuantumVaultContainer,
    KeyShare, reconstruct_secret,
};

// ── AES-256-GCM NIST Test Vectors ────────────────────────────────────────────

/// NIST SP 800-38D: AES-256-GCM with all-zero 256-bit key, all-zero 96-bit IV,
/// empty plaintext, empty AAD.
///
/// Expected auth tag: 530f8afbc74536b9a963b4f1c4cb738b
///
/// Source: NIST Cryptographic Algorithm Validation Program (CAVP) GCM vectors.
#[test]
fn aes256_gcm_nist_empty_message() {
    let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let cipher = Aes256Gcm::new(key);

    // For an empty message, the output is purely the 16-byte auth tag.
    let expected_tag: [u8; 16] = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
        0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
    ];

    let ct = cipher
        .encrypt(nonce, Payload { msg: &[], aad: &[] })
        .expect("AES-256-GCM encryption failed");

    assert_eq!(
        ct.as_slice(), &expected_tag,
        "NIST AES-256-GCM vector (empty PT) tag mismatch — \
         expected: {}, got: {}",
        hex_str(&expected_tag),
        hex_str(&ct),
    );
}

/// NIST AES-256-GCM — encrypt then decrypt with the same key/nonce returns the
/// original plaintext. (Sanity check for the AEAD crate itself.)
#[test]
fn aes256_gcm_round_trip() {
    let key_bytes = [0xABu8; 32];
    let nonce_bytes = [0xCDu8; 12];
    let plaintext = b"Quantum Vault test vector plaintext";
    let aad = b"test-aad";

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .unwrap();
    let recovered = cipher
        .decrypt(nonce, Payload { msg: &ct, aad })
        .expect("AES-256-GCM decryption failed");

    assert_eq!(recovered.as_slice(), plaintext);
}

/// AES-256-GCM must fail authentication if the AAD is changed after encryption.
#[test]
fn aes256_gcm_aad_mismatch_fails() {
    let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let cipher = Aes256Gcm::new(key);

    let ct = cipher
        .encrypt(nonce, Payload { msg: b"secret", aad: b"correct-aad" })
        .unwrap();
    let result = cipher.decrypt(nonce, Payload { msg: &ct, aad: b"tampered-aad" });
    assert!(result.is_err(), "modified AAD must cause authentication failure");
}

// ── Shamir GF(2⁸) Deterministic Reconstruction Vector ───────────────────────

/// ## Vector SSS-01
///
/// Polynomial: f(x) = 0x42 + 0x53·x  over GF(2⁸) with poly 0x11b
///
/// f(1) = 0x42 XOR gf_mul(0x53, 1) = 0x42 XOR 0x53 = 0x11
/// f(2) = 0x42 XOR gf_mul(0x53, 2) = 0x42 XOR 0xA6 = 0xE4
///        (0x53 = 0101 0011, MSB=0, left-shift = 1010 0110 = 0xA6)
///
/// Reconstruct from both shares must yield 0x42.
#[test]
fn shamir_deterministic_reconstruction_sss01() {
    // Pre-computed shares from polynomial f(x) = 0x42 + 0x53·x
    let shares = vec![
        KeyShare { index: 1, data: vec![0x11] },
        KeyShare { index: 2, data: vec![0xE4] },
    ];

    let secret = reconstruct_secret(&shares).expect("reconstruction failed");
    assert_eq!(
        secret, vec![0x42u8],
        "SSS-01: reconstruction from known shares failed; \
         got: {}, expected: 0x42",
        hex_str(&secret),
    );
}

/// SSS-01 extended: multi-byte secret using the same polynomial applied per byte.
///
/// Secret = [0x42, 0x00, 0xFF]:
/// - Byte 0: polynomial f_0(x) = 0x42 + 0x53·x  →  f_0(1)=0x11, f_0(2)=0xE4
/// - Byte 1: polynomial f_1(x) = 0x00 + 0x53·x  →  f_1(1)=0x53, f_1(2)=0xA6
/// - Byte 2: polynomial f_2(x) = 0xFF + 0x53·x  →  f_2(1)=0xFF^0x53=0xAC, f_2(2)=0xFF^0xA6=0x59
#[test]
fn shamir_deterministic_multi_byte_sss01_ext() {
    let shares = vec![
        KeyShare { index: 1, data: vec![0x11, 0x53, 0xAC] },
        KeyShare { index: 2, data: vec![0xE4, 0xA6, 0x59] },
    ];

    let secret = reconstruct_secret(&shares).expect("multi-byte reconstruction failed");
    assert_eq!(
        secret, vec![0x42u8, 0x00, 0xFF],
        "SSS-01 extended: multi-byte reconstruction mismatch; got: {}",
        hex_str(&secret),
    );
}

/// Supplying only one share of a 2-share scheme must not produce the correct secret.
#[test]
fn shamir_single_share_of_two_is_not_secret() {
    let shares = vec![KeyShare { index: 1, data: vec![0x11] }];
    let recovered = reconstruct_secret(&shares).unwrap();
    // With only 1 share of a 2-of-2, the result is the share value itself
    // (Lagrange at (1, 0x11) with a single point), not 0x42.
    assert_ne!(recovered, vec![0x42u8],
        "single share must not reconstruct the 2-of-2 secret");
}

// ── Container Format Vectors ─────────────────────────────────────────────────

/// Container produced by encrypt_bytes must survive a to_bytes/from_bytes round-trip
/// and preserve all structural fields.
#[test]
fn container_serialise_deserialise_identity() {
    let (ct_bytes, _keys, _sig_pub) =
        encrypt_bytes(b"container format vector").unwrap();

    let c = QuantumVaultContainer::from_bytes(&ct_bytes).unwrap();

    // Re-serialise and re-parse — fields must be identical.
    let ct_bytes_2 = c.to_bytes().unwrap();
    let c2 = QuantumVaultContainer::from_bytes(&ct_bytes_2).unwrap();

    assert_eq!(c.magic, c2.magic);
    assert_eq!(c.version, c2.version);
    assert_eq!(c.threshold, c2.threshold);
    assert_eq!(c.share_count, c2.share_count);
    assert_eq!(c.nonce, c2.nonce);
    assert_eq!(c.ciphertext, c2.ciphertext);
    assert_eq!(c.shares.len(), c2.shares.len());
}

/// The container's `magic` field must equal the defined constant.
#[test]
fn container_magic_field_is_qvkp() {
    let (ct_bytes, _, _) = encrypt_bytes(b"magic check").unwrap();
    let c = QuantumVaultContainer::from_bytes(&ct_bytes).unwrap();
    assert_eq!(c.magic, "QVKP");
    assert_eq!(c.version, 2);
}

// ── Full Pipeline Property Vectors ───────────────────────────────────────────

/// Two calls to encrypt_bytes with identical plaintext must produce different
/// ciphertexts (random nonce ensures this with overwhelming probability).
#[test]
fn pipeline_nonce_freshness() {
    let plain = b"nonce freshness test vector";
    let (ct1, _, _) = encrypt_bytes(plain).unwrap();
    let (ct2, _, _) = encrypt_bytes(plain).unwrap();
    assert_ne!(ct1, ct2, "identical plaintext must produce different containers");
}

/// Round-trip for the minimum threshold (2-of-2).
#[test]
fn pipeline_2_of_2_roundtrip() {
    let plain = b"2-of-2 pipeline test";
    let (ct, keys, sig_pub) = encrypt_with_threshold(plain, 2, 2).unwrap();
    let recovered = decrypt_with_threshold(&ct, &keys, &sig_pub).unwrap();
    assert_eq!(recovered, plain);
}

/// Round-trip for a 3-of-5 scheme using the minimum 3 keys.
#[test]
fn pipeline_3_of_5_minimum_keys() {
    let plain = b"3-of-5 minimum subset test vector";
    let (ct, keys, sig_pub) = encrypt_with_threshold(plain, 5, 3).unwrap();
    // The high-level API matches private keys positionally to container shares,
    // so we supply the first 3 keys (any 3 consecutive from the front work).
    let recovered = decrypt_with_threshold(&ct, &keys[..3], &sig_pub).unwrap();
    assert_eq!(recovered, plain);
}

/// Round-trip with the full binary range (0x00 through 0xFF).
#[test]
fn pipeline_full_byte_range() {
    let plain: Vec<u8> = (0u8..=255).collect();
    let (ct, keys, sig_pub) = encrypt_bytes(&plain).unwrap();
    let recovered = decrypt_bytes(&ct, &keys, &sig_pub).unwrap();
    assert_eq!(recovered, plain);
}

/// Decryption with a modified signature byte must fail.
#[test]
fn pipeline_signature_tamper_detected() {
    let (ct_bytes, keys, sig_pub) = encrypt_bytes(b"tamper me").unwrap();
    let mut c = QuantumVaultContainer::from_bytes(&ct_bytes).unwrap();
    // Flip the first byte of the signature.
    if let Some(b) = c.signature.first_mut() {
        *b ^= 0xFF;
    }
    let tampered_bytes = c.to_bytes().unwrap();
    let result = decrypt_bytes(&tampered_bytes, &keys, &sig_pub);
    assert!(result.is_err(), "tampered signature must be rejected");
}

/// Decryption with a modified ciphertext byte must fail.
#[test]
fn pipeline_ciphertext_tamper_detected() {
    let (ct_bytes, keys, sig_pub) = encrypt_bytes(b"tamper the ct").unwrap();
    let mut c = QuantumVaultContainer::from_bytes(&ct_bytes).unwrap();
    if let Some(b) = c.ciphertext.first_mut() {
        *b ^= 0xFF;
    }
    let tampered_bytes = c.to_bytes().unwrap();
    let result = decrypt_bytes(&tampered_bytes, &keys, &sig_pub);
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

// ── Vector Generator (run with --ignored --nocapture) ────────────────────────

/// Generator: prints all computed vectors as hex for independent verification.
///
/// Run with:
/// ```sh
/// cargo test -p qv-core generate_test_vectors -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn generate_test_vectors() {
    // AES-256-GCM: empty PT, all-zero key/nonce
    let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let cipher = Aes256Gcm::new(key);
    let tag = cipher.encrypt(nonce, Payload { msg: &[], aad: &[] }).unwrap();
    println!("=== AES-01 ===");
    println!("Key:   {}", hex_str(&[0u8; 32]));
    println!("Nonce: {}", hex_str(&[0u8; 12]));
    println!("Tag:   {}", hex_str(&tag));

    // Shamir SSS-01
    println!("\n=== SSS-01 ===");
    let shares = vec![
        KeyShare { index: 1, data: vec![0x11] },
        KeyShare { index: 2, data: vec![0xE4] },
    ];
    let secret = reconstruct_secret(&shares).unwrap();
    println!("Share 1 (x=1): {}", hex_str(&[0x11]));
    println!("Share 2 (x=2): {}", hex_str(&[0xE4]));
    println!("Secret:        {}", hex_str(&secret));

    // Full pipeline
    println!("\n=== Pipeline (2-of-2) ===");
    let plain = b"quantum vault 2-of-2";
    let (ct, _keys, _sig_pub) = encrypt_with_threshold(plain, 2, 2).unwrap();
    let c = QuantumVaultContainer::from_bytes(&ct).unwrap();
    println!("Plaintext:    {:?}", std::str::from_utf8(plain).unwrap());
    println!("Magic:        {}", c.magic);
    println!("Version:      {}", c.version);
    println!("Threshold:    {}", c.threshold);
    println!("Share count:  {}", c.share_count);
    println!("Nonce:        {}", hex_str(&c.nonce));
    println!("CT len:       {} bytes", c.ciphertext.len());
    println!("Sig len:      {} bytes", c.signature.len());
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}
