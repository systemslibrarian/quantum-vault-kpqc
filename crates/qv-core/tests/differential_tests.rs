// SPDX-License-Identifier: MIT
//! Differential and Known-Answer Tests (KAT) for PQ algorithm backends.
//!
//! These tests verify that the Rust implementations of the cryptographic
//! primitives (DevKem, DevSignature) produce byte-for-byte correct outputs
//! when measured against independently-computed reference values.
//!
//! ## Strategy
//!
//! Since the development-backend algorithms (`dev-kem`, `dev-sig`) are fully
//! specified by their documentation comments (pure SHA-256 + XOR), we compute
//! the expected outputs using the `sha2` crate directly — an independent code
//! path from the backend implementations.  Any implementation divergence is
//! detected as a test failure.
//!
//! For the production KpqC backend (SMAUG-T / HAETAE), KAT vectors would be
//! compared against official NIST/KpqC submission test vectors stored as JSON
//! fixtures.  Those tests are scaffolded below and marked `#[ignore]`; they
//! require the `kpqc-native` feature and vendor C libraries.
//!
//! ## Dev-backend algorithm specification (from `dev.rs` comments)
//!
//! **DevKem:**
//! - `generate_keypair()`:  privkey = 32 random bytes; pubkey = SHA-256(privkey)
//! - `encapsulate(pubkey)`: ss = 32 random bytes; ct = ss XOR pubkey
//! - `decapsulate(privkey, ct)`: pubkey = SHA-256(privkey); ss = ct XOR pubkey
//!
//! **DevSignature:**
//! - `generate_keypair()`: privkey = 32 random bytes; pubkey = SHA-256(privkey)
//! - `sign(privkey, msg)`: SHA-256(SHA-256(privkey) || msg)
//! - `verify(pubkey, msg, sig)`: constant-time compare(SHA-256(pubkey || msg), sig)
//!
//! Run with: `cargo test --test differential_tests`

use qv_core::crypto::{
    backend::dev::{DevKem, DevSignature},
    kem::Kem,
    signature::Signature,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Helper: independently compute SHA-256 using the sha2 crate
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn sha256_concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().to_vec()
}

// ============================================================================
// DevKem — differential tests
// ============================================================================

/// DevKem key derivation: pubkey must equal SHA-256(privkey).
///
/// Differential: the expected pubkey is computed by the `sha2` crate
/// independently of the `DevKem` implementation.
#[test]
fn dev_kem_pubkey_matches_sha256_of_privkey() {
    let kem = DevKem;
    let privkey = [0x42u8; 32];

    // Independent reference: pubkey = SHA-256(privkey)
    let expected_pubkey = sha256(&privkey);

    // Compute pubkey via DevKem's internal derivation (bypass generate_keypair
    // randomness by deriving pubkey through encapsulate's length/validation path,
    // then using the known privkey directly with decapsulate).
    //
    // DevKem::decapsulate: pubkey_internal = SHA-256(privkey); ss = ct XOR pubkey_internal
    // We construct ct = ss_known XOR expected_pubkey so that decapsulate returns ss_known.
    let known_ss = [0xAAu8; 32];
    let ct: Vec<u8> = known_ss
        .iter()
        .zip(expected_pubkey.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let recovered_ss = kem.decapsulate(&privkey, &ct).unwrap();
    assert_eq!(
        recovered_ss, known_ss,
        "DevKem decapsulate must recover the shared secret encoded with SHA-256(privkey)"
    );
}

/// DevKem decapsulation KAT: given fixed (privkey, ct), the recovered shared
/// secret must be exactly ct XOR SHA-256(privkey).
#[test]
fn dev_kem_decapsulate_kat() {
    let kem = DevKem;

    // Fixed test vectors.
    let privkey = [0x11u8; 32];
    let desired_ss = [0x55u8; 32];

    // Build reference values independently.
    let pubkey_ref = sha256(&privkey);
    let ct: Vec<u8> = desired_ss
        .iter()
        .zip(pubkey_ref.iter())
        .map(|(ss_byte, pk_byte)| ss_byte ^ pk_byte)
        .collect();

    // Assert: decapsulate(privkey, ct) == desired_ss
    let ss = kem.decapsulate(&privkey, &ct).unwrap();
    assert_eq!(
        ss, desired_ss,
        "DevKem decapsulate KAT failed: expected {desired_ss:?}, got {ss:?}"
    );
}

/// DevKem round-trip: encapsulate then decapsulate with a fixed keypair always
/// recovers the same shared secret regardless of which ss was generated.
#[test]
fn dev_kem_encap_decap_roundtrip_with_fixed_keypair() {
    let kem = DevKem;

    // Fixed private key; derive pubkey via decapsulation math.
    let privkey = [0x99u8; 32];
    let pubkey = sha256(&privkey);

    // Encapsulate using the derived pubkey.
    let (ct, ss_enc) = kem.encapsulate(&pubkey).unwrap();
    let ss_dec = kem.decapsulate(&privkey, &ct).unwrap();

    assert_eq!(
        ss_enc, ss_dec,
        "DevKem encap/decap roundtrip must recover the same shared secret"
    );
}

/// DevKem rejects a privkey that is the wrong length.
#[test]
fn dev_kem_rejects_wrong_length_privkey() {
    let kem = DevKem;
    let ct = vec![0u8; 32];
    assert!(kem.decapsulate(&[0u8; 16], &ct).is_err());
}

/// DevKem rejects a ciphertext that is the wrong length.
#[test]
fn dev_kem_rejects_wrong_length_ciphertext() {
    let kem = DevKem;
    assert!(kem.decapsulate(&[0u8; 32], &[0u8; 16]).is_err());
}

// ============================================================================
// DevSignature — differential tests
// ============================================================================

/// DevSignature key derivation: pubkey must equal SHA-256(privkey).
#[test]
fn dev_signature_pubkey_is_sha256_of_privkey() {
    let sig = DevSignature;
    let privkey = [0x77u8; 32];
    let expected_pubkey = sha256(&privkey);

    // Derive parity: sign a message with privkey, verify with expected_pubkey.
    // If verify passes, then the implementation derives pubkey = SHA-256(privkey).
    let message = b"pubkey derivation check";
    let signature = sig.sign(&privkey, message).unwrap();
    let valid = sig.verify(&expected_pubkey, message, &signature).unwrap();
    assert!(
        valid,
        "DevSignature pubkey must equal SHA-256(privkey) for verify to pass"
    );
}

/// DevSignature sign KAT: signature must equal SHA-256(SHA-256(privkey) || message).
#[test]
fn dev_signature_sign_kat() {
    let sig = DevSignature;

    let privkey = [0x33u8; 32];
    let message = b"quantum vault differential test message";

    // Independent reference computation:
    // pubkey = SHA-256(privkey)
    // expected_sig = SHA-256(pubkey || message)
    let pubkey = sha256(&privkey);
    let expected_sig = sha256_concat(&pubkey, message);

    let actual_sig = sig.sign(&privkey, message).unwrap();

    assert_eq!(
        actual_sig, expected_sig,
        "DevSignature::sign must produce SHA-256(SHA-256(privkey) || message)"
    );
}

/// DevSignature verify KAT: the reference signature verifies correctly.
#[test]
fn dev_signature_verify_kat() {
    let sig = DevSignature;

    let privkey = [0x33u8; 32];
    let message = b"quantum vault differential test message";

    // Compute reference values.
    let pubkey = sha256(&privkey);
    let expected_sig = sha256_concat(&pubkey, message);

    // Verify using the implementation.
    let ok = sig.verify(&pubkey, message, &expected_sig).unwrap();
    assert!(ok, "DevSignature::verify must accept a correct KAT signature");
}

/// DevSignature must reject a signature over a different message.
#[test]
fn dev_signature_rejects_wrong_message() {
    let sig = DevSignature;

    let privkey = [0x33u8; 32];
    let message = b"original message";
    let tampered = b"tampered message";

    let pubkey = sha256(&privkey);
    let signature = sha256_concat(&pubkey, message);

    let ok = sig.verify(&pubkey, tampered, &signature).unwrap();
    assert!(!ok, "DevSignature::verify must reject a signature over a different message");
}

/// DevSignature must reject a signature with a flipped bit.
#[test]
fn dev_signature_rejects_flipped_sig_bit() {
    let sig = DevSignature;

    let privkey = [0x44u8; 32];
    let message = b"bit flip test";
    let pubkey = sha256(&privkey);
    let mut signature = sha256_concat(&pubkey, message);

    // Flip one bit.
    signature[0] ^= 0x01;

    let ok = sig.verify(&pubkey, message, &signature).unwrap();
    assert!(
        !ok,
        "DevSignature::verify must reject a signature with a single flipped bit"
    );
}

/// DevSignature must reject an all-zero signature.
#[test]
fn dev_signature_rejects_zero_signature() {
    let sig = DevSignature;
    let pubkey = sha256(&[0x55u8; 32]);
    let message = b"zero signature test";
    let zero_sig = vec![0u8; 32];

    let ok = sig.verify(&pubkey, message, &zero_sig).unwrap();
    assert!(!ok, "DevSignature::verify must reject an all-zero signature");
}

// ============================================================================
// Algorithm ID consistency
// ============================================================================

/// Algorithm ID strings must be stable across invocations.
#[test]
fn dev_kem_algorithm_id_is_stable() {
    let kem = DevKem;
    assert_eq!(kem.algorithm_id(), "dev-kem");
    // Call twice — must be identical.
    assert_eq!(kem.algorithm_id(), DevKem.algorithm_id());
}

#[test]
fn dev_signature_algorithm_id_is_stable() {
    let sig = DevSignature;
    assert_eq!(sig.algorithm_id(), "dev-sig");
    assert_eq!(sig.algorithm_id(), DevSignature.algorithm_id());
}

// ============================================================================
// Full pipeline differential: encrypt → decrypt with fixed algorithm choices
// ============================================================================

/// End-to-end KAT: the same plaintext encrypted twice with the dev backend
/// must always decrypt to the original plaintext (regression guard).
///
/// This does not pin exact ciphertext bytes (because the nonce and key are
/// random), but it confirms the encrypt → decrypt pipeline is algebraically
/// consistent under the dev backend's SHA-256 + XOR math.
#[test]
fn full_pipeline_encrypt_decrypt_consistent() {
    use qv_core::{decrypt_bytes, encrypt_bytes};

    let plaintext = b"differential test: full pipeline round-trip";
    let (ct, keys, sig_pub) = encrypt_bytes(plaintext).unwrap();
    let recovered = decrypt_bytes(&ct, &keys, &sig_pub).unwrap();
    assert_eq!(
        recovered, plaintext,
        "full pipeline round-trip must recover the original plaintext"
    );
}

// ============================================================================
// Scaffold: KpqC KAT tests (require kpqc-native feature + vendor C libraries)
// ============================================================================

/// SMAUG-T keygen KAT against the KpqC reference implementation.
///
/// # Prerequisites
/// - `kpqc-native` feature enabled
/// - `vendor/smaug-t/` C source present
/// - KAT vector file `tests/kat/smaug_t_kat.json` present
///
/// Run with: `cargo test --test differential_tests --features kpqc-native -- --ignored smaug_keygen_matches_reference`
#[test]
#[ignore = "requires kpqc-native feature and SMAUG-T KAT vectors; run with --ignored"]
fn smaug_keygen_matches_reference() {
    // When the kpqc-native feature is enabled, this test would:
    //   1. Load KAT vectors from tests/kat/smaug_t_kat.json
    //   2. For each vector: run SmaugTKemBackend::generate_keypair_seeded(seed)
    //   3. Assert pk == pk_ref and sk == sk_ref
    //
    // Stub assertion to confirm the test scaffolding compiles.
    eprintln!(
        "SMAUG-T KAT test skipped: enable kpqc-native feature and provide KAT vectors"
    );
}

/// HAETAE sign/verify KAT against the KpqC reference implementation.
///
/// Run with: `cargo test --test differential_tests --features kpqc-native -- --ignored haetae_sign_matches_reference`
#[test]
#[ignore = "requires kpqc-native feature and HAETAE KAT vectors; run with --ignored"]
fn haetae_sign_matches_reference() {
    // When the kpqc-native feature is enabled, this test would:
    //   1. Load KAT vectors from tests/kat/haetae_kat.json
    //   2. For each vector: run HaetaeSignatureBackend::sign_seeded(privkey, msg, seed)
    //   3. Assert signature == sig_ref
    //   4. Run verify(pubkey, msg, sig_ref) → assert true
    eprintln!(
        "HAETAE KAT test skipped: enable kpqc-native feature and provide KAT vectors"
    );
}
