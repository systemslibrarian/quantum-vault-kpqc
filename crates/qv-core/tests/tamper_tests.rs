// SPDX-License-Identifier: MIT
//! Tamper-resistance tests.
//!
//! Prove that **any** single-field mutation of a valid encrypted container causes
//! `decrypt_file` to return `Err`.  Every path through the container is protected
//! by at least two independent mechanisms:
//!
//! 1. **Outer signature** — covers all non-signature fields; verified first.
//! 2. **AES-256-GCM AEAD tag** — additionally covers ciphertext integrity and AAD.
//! 3. **Per-share AEAD** — each encrypted key-share has its own GCM tag.
//!
//! Run with: `cargo test --test tamper_tests`

use qv_core::{
    container::QuantumVaultContainer,
    crypto::{backend::dev::{DevKem, DevSignature}, kem::Kem, signature::Signature},
    decrypt_file, encrypt_file, DecryptOptions, EncryptOptions,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Build a valid 2-of-2 container together with the keys needed to decrypt it.
fn make_valid_container() -> (QuantumVaultContainer, DecryptOptions) {
    let kem = DevKem;
    let sig = DevSignature;

    let (pk1, sk1) = kem.generate_keypair().unwrap();
    let (pk2, sk2) = kem.generate_keypair().unwrap();
    let (sig_pub, sig_priv) = sig.generate_keypair().unwrap();

    let opts = EncryptOptions {
        threshold: 2,
        share_count: 2,
        recipient_public_keys: vec![pk1, pk2],
        signer_private_key: sig_priv,
    };

    let container = encrypt_file(b"tamper-resistance test payload", &opts, &kem, &sig).unwrap();

    let share_indices: Vec<u8> = container.shares.iter().map(|s| s.index).collect();
    let dec_opts = DecryptOptions {
        recipient_private_keys: vec![sk1, sk2],
        share_indices,
        signer_public_key: sig_pub,
    };
    (container, dec_opts)
}

/// Assert that decryption succeeds with an unmodified container (sanity check).
fn assert_roundtrip_ok(container: &QuantumVaultContainer, dec_opts: &DecryptOptions) {
    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(container, dec_opts, &kem, &sig).is_ok(),
        "unmodified container should decrypt successfully"
    );
}

// ---------------------------------------------------------------------------
// 1. Ciphertext — flip one bit in the payload bytes
// ---------------------------------------------------------------------------

#[test]
fn tamper_ciphertext_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    container.ciphertext[0] ^= 0x01;

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "flipped ciphertext byte should cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// 2. Authentication tag — flip one bit in the last 16 bytes (GCM tag)
// ---------------------------------------------------------------------------

#[test]
fn tamper_auth_tag_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // The GCM auth tag is the last 16 bytes of the ciphertext blob.
    let len = container.ciphertext.len();
    assert!(len >= 16, "ciphertext must contain at least the 16-byte tag");
    container.ciphertext[len - 1] ^= 0x01;

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "flipped auth-tag byte should cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// 3. Header version — mutate the version field
// ---------------------------------------------------------------------------

#[test]
fn tamper_header_version_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // Changing the version alters the signing-bytes representation, so the
    // signature check fails immediately before any ciphertext is touched.
    container.version = container.version.wrapping_add(1);

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "mutated header version should cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// 4. Algorithm ID — mutate the KEM algorithm identifier
// ---------------------------------------------------------------------------

#[test]
fn tamper_kem_algorithm_id_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // Changing the algorithm ID changes both signing bytes (→ sig fails) and
    // the AAD (→ GCM tag fails), so two independent checks catch this.
    container.kem_algorithm = "tampered-kem".to_string();

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "mutated kem_algorithm should cause decryption failure"
    );
}

#[test]
fn tamper_sig_algorithm_id_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    container.sig_algorithm = "tampered-sig".to_string();

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "mutated sig_algorithm should cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// 5. KEM payload — corrupt the KEM encapsulation ciphertext
// ---------------------------------------------------------------------------

#[test]
fn tamper_kem_ciphertext_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // Corrupting the KEM ciphertext also changes the signing bytes,
    // so the outer signature check fires first.
    container.shares[0].kem_ciphertext[0] ^= 0xFF;

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "corrupted KEM ciphertext should cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// 6. Signature — corrupt the container signature bytes
// ---------------------------------------------------------------------------

#[test]
fn tamper_signature_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    container.signature[0] ^= 0xFF;

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "corrupted signature should cause decryption failure"
    );
}

#[test]
fn tamper_signature_cleared_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // Completely clear the signature to verify all-zero is not accepted.
    for byte in container.signature.iter_mut() {
        *byte = 0;
    }

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "zeroed-out signature should cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// 7. Shamir share — corrupt the encrypted share blob
// ---------------------------------------------------------------------------

#[test]
fn tamper_shamir_share_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // The encrypted_share field is the per-share AES-GCM blob (nonce + ct + tag).
    // Corrupting it also changes the signing bytes → signature fails first,
    // and even if that check were bypassed the per-share AEAD would catch it.
    container.shares[0].encrypted_share[0] ^= 0xFF;

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "corrupted Shamir share blob should cause decryption failure"
    );
}

#[test]
fn tamper_shamir_share_tag_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // Flip the last byte of the first share (inside the per-share AES-GCM tag).
    let share_len = container.shares[0].encrypted_share.len();
    assert!(share_len >= 16, "encrypted_share must be at least nonce(12) + tag(16)");
    container.shares[0].encrypted_share[share_len - 1] ^= 0x01;

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "corrupted per-share auth tag should cause decryption failure"
    );
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn tamper_nonce_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // The nonce is part of the signing bytes; changing it also changes the GCM
    // decryption context, so both signature and AEAD checks catch this.
    container.nonce[0] ^= 0x01;

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "mutated nonce should cause decryption failure"
    );
}

#[test]
fn tamper_threshold_should_fail() {
    let (mut container, dec_opts) = make_valid_container();
    assert_roundtrip_ok(&container, &dec_opts);

    // Threshold is in the AAD and signing bytes.
    container.threshold = container.threshold.saturating_add(1);
    // Adjust share_count to keep structural check happy (threshold <= share_count).
    if container.threshold > container.share_count {
        container.share_count = container.threshold;
        // Add a dummy share entry to match the count (it won't matter — sig fails first).
        let dummy = container.shares[0].clone();
        container.shares.push(dummy);
    }

    let kem = DevKem;
    let sig = DevSignature;
    assert!(
        decrypt_file(&container, &dec_opts, &kem, &sig).is_err(),
        "mutated threshold should cause decryption failure"
    );
}
