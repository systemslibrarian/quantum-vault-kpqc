// SPDX-License-Identifier: MIT
//! Malformed container corpus tests.
//!
//! Each file in `tests/corpus/` must be rejected by
//! `QuantumVaultContainer::from_bytes`.  This guards the parser against
//! a range of structural and semantic violations.
//!
//! ## Corpus file manifest
//!
//! | File | Injected fault |
//! |------|---------------|
//! | `invalid_magic.bin` | `magic` field ≠ `"QVLT1"` |
//! | `truncated_container.bin` | JSON cut short mid-field |
//! | `duplicate_fields.bin` | Repeated header field (serde rejects as `duplicate field`) |
//! | `oversized_metadata.bin` | `threshold` = 1 (below minimum of 2) |
//! | `bad_kem_payload.bin` | `kem_ciphertext` element = 999 (out of `u8` range) |
//! | `invalid_tag.bin` | `nonce` length = 8 (must be exactly 12) |
//! | `bad_signature.bin` | `signature` field is JSON `null` (cannot decode as `Vec<u8>`) |
//!
//! ## Regenerating corpus files
//!
//! Run the ignored helper test to (re)write all corpus files from the in-code
//! definitions:
//!
//! ```sh
//! cargo test --test corpus_tests -- --ignored --nocapture regenerate_corpus
//! ```
//!
//! Corpus files are committed to the repository so `cargo test` works offline
//! without needing to run the generator first.

use qv_core::container::QuantumVaultContainer;

// ---------------------------------------------------------------------------
// Corpus contents — defined once here so the loader test and generator share
// exactly the same bytes.
// ---------------------------------------------------------------------------

/// All corpus entries: `(filename, content_bytes)`.
fn corpus_entries() -> Vec<(&'static str, &'static [u8])> {
    vec![
        // 1. Wrong magic string.
        (
            "invalid_magic.bin",
            br#"{"magic":"NOT_QVLT1","version":1,"cipher":"Aes256Gcm","kem_algorithm":"dev-kem","sig_algorithm":"dev-sig","threshold":2,"share_count":2,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[1,2,3],"shares":[{"index":1,"kem_ciphertext":[1],"encrypted_share":[1]},{"index":2,"kem_ciphertext":[1],"encrypted_share":[1]}],"signature":[1,2,3]}"#,
        ),
        // 2. JSON truncated mid-field — JSON parse error.
        (
            "truncated_container.bin",
            br#"{"magic":"QVLT1","version":1,"cipher":"Aes2"#,
        ),
        // 3. Duplicate `magic` field — serde returns "duplicate field `magic`".
        (
            "duplicate_fields.bin",
            br#"{"magic":"QVLT1","magic":"QVLT1","version":1,"cipher":"Aes256Gcm","kem_algorithm":"dev-kem","sig_algorithm":"dev-sig","threshold":2,"share_count":2,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[1],"shares":[{"index":1,"kem_ciphertext":[1],"encrypted_share":[1]},{"index":2,"kem_ciphertext":[1],"encrypted_share":[1]}],"signature":[1]}"#,
        ),
        // 4. `threshold` = 1 — below minimum of 2.
        (
            "oversized_metadata.bin",
            br#"{"magic":"QVLT1","version":1,"cipher":"Aes256Gcm","kem_algorithm":"dev-kem","sig_algorithm":"dev-sig","threshold":1,"share_count":2,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[1],"shares":[{"index":1,"kem_ciphertext":[1],"encrypted_share":[1]},{"index":2,"kem_ciphertext":[1],"encrypted_share":[1]}],"signature":[1]}"#,
        ),
        // 5. `kem_ciphertext` element 999 is out of u8 range — deserialization error.
        (
            "bad_kem_payload.bin",
            br#"{"magic":"QVLT1","version":1,"cipher":"Aes256Gcm","kem_algorithm":"dev-kem","sig_algorithm":"dev-sig","threshold":2,"share_count":2,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[1],"shares":[{"index":1,"kem_ciphertext":[999],"encrypted_share":[1]},{"index":2,"kem_ciphertext":[1],"encrypted_share":[1]}],"signature":[1]}"#,
        ),
        // 6. `nonce` has 8 bytes — must be exactly 12.
        (
            "invalid_tag.bin",
            br#"{"magic":"QVLT1","version":1,"cipher":"Aes256Gcm","kem_algorithm":"dev-kem","sig_algorithm":"dev-sig","threshold":2,"share_count":2,"nonce":[0,0,0,0,0,0,0,0],"ciphertext":[1],"shares":[{"index":1,"kem_ciphertext":[1],"encrypted_share":[1]},{"index":2,"kem_ciphertext":[1],"encrypted_share":[1]}],"signature":[1]}"#,
        ),
        // 7. `signature` is JSON null — cannot decode as Vec<u8>.
        (
            "bad_signature.bin",
            br#"{"magic":"QVLT1","version":1,"cipher":"Aes256Gcm","kem_algorithm":"dev-kem","sig_algorithm":"dev-sig","threshold":2,"share_count":2,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[1],"shares":[{"index":1,"kem_ciphertext":[1],"encrypted_share":[1]},{"index":2,"kem_ciphertext":[1],"encrypted_share":[1]}],"signature":null}"#,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Loader test — every corpus file must be rejected by the parser
// ---------------------------------------------------------------------------

/// Verify that every file in `tests/corpus/` is rejected by
/// `QuantumVaultContainer::from_bytes`.
///
/// This test runs automatically as part of `cargo test`.
#[test]
fn malformed_containers_all_fail() {
    let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus");

    let entries: Vec<_> = std::fs::read_dir(&corpus_dir)
        .unwrap_or_else(|e| panic!("failed to open corpus directory {}: {e}", corpus_dir.display()))
        .filter_map(|r| r.ok())
        .collect();

    assert!(
        !entries.is_empty(),
        "corpus directory is empty — run `cargo test -- --ignored regenerate_corpus` first"
    );

    let mut tested = 0usize;
    for entry in entries {
        let path = entry.path();
        // Skip directories and non-.bin files.
        if !path.extension().map_or(false, |e| e == "bin") {
            continue;
        }
        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read corpus file {}: {e}", path.display()));

        assert!(
            QuantumVaultContainer::from_bytes(&data).is_err(),
            "corpus file SHOULD have been rejected but was accepted: {}",
            path.display()
        );
        tested += 1;
    }

    assert!(
        tested >= 7,
        "expected at least 7 corpus files, only tested {tested}; \
         run `cargo test -- --ignored regenerate_corpus` to regenerate"
    );
}

// ---------------------------------------------------------------------------
// Corpus file integrity — each in-code definition must also fail parsing
// ---------------------------------------------------------------------------

/// Verify the in-code corpus definitions are all rejected (fast sanity check
/// that does not require files on disk).
#[test]
fn corpus_definitions_all_fail() {
    for (name, data) in corpus_entries() {
        assert!(
            QuantumVaultContainer::from_bytes(data).is_err(),
            "in-code corpus entry '{name}' should be rejected but was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Corpus generator — write files to disk
// ---------------------------------------------------------------------------

/// Regenerate all corpus files in `tests/corpus/` from the in-code definitions.
///
/// Run with:
/// ```sh
/// cargo test --test corpus_tests -- --ignored --nocapture regenerate_corpus
/// ```
///
/// The generator is marked `#[ignore]` so it is not executed during normal
/// `cargo test` runs (the committed files serve that purpose).
#[test]
#[ignore = "run explicitly to regenerate corpus files"]
fn regenerate_corpus() {
    let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus");

    std::fs::create_dir_all(&corpus_dir)
        .unwrap_or_else(|e| panic!("failed to create corpus directory: {e}"));

    for (filename, content) in corpus_entries() {
        let path = corpus_dir.join(filename);
        std::fs::write(&path, content)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
        println!("wrote {} ({} bytes)", path.display(), content.len());
    }

    println!("corpus regenerated at {}", corpus_dir.display());
}
