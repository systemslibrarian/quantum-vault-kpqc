# Quantum Vault Container Format

Version: **1**  
Magic: `QVLT1`

---

## Overview

A `.qvault` file is a JSON document produced by `qv-core`.  It stores the
AES-256-GCM ciphertext of the original file together with the threshold key
shares needed to recover the file key.  Every container is signed so that
tampering is detected before any decryption is attempted.

---

## Top-level structure

```json
{
  "magic":         "QVLT1",
  "version":       1,
  "cipher":        "Aes256Gcm",
  "kem_algorithm": "SMAUG-T-3",
  "sig_algorithm": "HAETAE-3",
  "threshold":     2,
  "share_count":   3,
  "nonce":         [/* 12 bytes, JSON array of u8 */],
  "ciphertext":    [/* N + 16 bytes (payload + GCM auth tag) */],
  "shares":        [ /* array of EncryptedKeyShare */ ],
  "signature":     [/* variable bytes */]
}
```

### Field reference

| Field | Type | Notes |
|-------|------|-------|
| `magic` | string | Must equal `"QVLT1"` |
| `version` | u8 | Format version; currently `1` |
| `cipher` | enum | `"Aes256Gcm"` only in v1 |
| `kem_algorithm` | string | Algorithm used for key encapsulation, e.g. `"DevKem"`, `"SMAUG-T-3"` |
| `sig_algorithm` | string | Algorithm used for the container signature, e.g. `"DevSignature"`, `"HAETAE-3"` |
| `threshold` | u8 | Minimum shares needed to decrypt |
| `share_count` | u8 | Total shares created |
| `nonce` | `[u8]` | 12-byte AES-GCM nonce |
| `ciphertext` | `[u8]` | AES-256-GCM output including 16-byte auth tag |
| `shares` | array | One `EncryptedKeyShare` per recipient |
| `signature` | `[u8]` | Signature over all fields above |

---

## EncryptedKeyShare

```json
{
  "index":           1,
  "kem_ciphertext":  [/* KEM ciphertext bytes */],
  "encrypted_share": [/* share bytes XOR'd with KEM shared secret */]
}
```

| Field | Notes |
|-------|-------|
| `index` | x-coordinate in the Shamir scheme (1-based) |
| `kem_ciphertext` | Output of `Kem::encapsulate(pubkey)` |
| `encrypted_share` | `share_data XOR keystream(kem_shared_secret)` |

The keystream is derived from the KEM shared secret using SHA-256 in counter
mode as implemented in `qv-core::encrypt::xor_protect`.

---

## Signature coverage

The signature covers the canonical JSON serialization of the following fields
in this exact key order:

```
magic, version, cipher, kem_algorithm, sig_algorithm, threshold, share_count, nonce, ciphertext, shares
```

The `signature` field itself is excluded.  The signing implementation is in
`qv-core::encrypt::container_signing_bytes`.

In version 1 the signature is produced by whatever backend is active.  The
dev backend uses `SHA-256(SHA-256(privkey) || canonical_json)` so that
verification only requires the public key.  Production containers will use HAETAE.

---

## Encryption pipeline

```
plaintext
    │
    ▼  AES-256-GCM (random 256-bit key, random 96-bit nonce)
ciphertext + auth_tag
    │
    │  [key material path]
    ▼
random 256-bit file_key
    │
    ▼  Shamir split (threshold / share_count)
share_1 … share_n
    │
    ▼  KEM encapsulate per recipient
encrypted_share_1 … encrypted_share_n
    │
    ▼  Serialize + sign
.qvault container
```

---

## Decryption pipeline

```
.qvault container
    │
    ▼  Verify signature
OK
    │
    ▼  KEM decapsulate (≥ threshold private keys)
raw_share_1 … raw_share_k
    │
    ▼  Shamir reconstruct
256-bit file_key
    │
    ▼  AES-256-GCM decrypt
plaintext
```

---

## Security notes

* The file key is zeroized in memory immediately after Shamir splitting.
* The KEM shared secret is zeroized after each share is protected.
* The `nonce` must never be reused with the same file key (guaranteed by
  randomness; the probability of collision is negligible for 96-bit uniform
  nonces).
* Container integrity is protected end-to-end by the signature; an attacker
  cannot silently substitute nonce or ciphertext bytes.

---

## Additional Authenticated Data (AAD)

The AES-256-GCM AAD binds the ciphertext to its policy and algorithm context.
It is **recomputed** at decryption time (not stored) from the container fields:

```json
{
  "kem_algorithm": "<value>",
  "sig_algorithm": "<value>",
  "threshold":     <uint8>,
  "version":       <uint8>
}
```

Keys appear in **alphabetical order** in the serialised form.  Any mismatch in these
fields causes AES-GCM authentication to fail.

---

## Size estimates (SMAUG-T-3 / HAETAE-3, n=5 shares)

| Plaintext | Container size (approx) | Overhead |
|-----------|------------------------|---------|
| 1 KB | 9.8 KB | ×9.8 |
| 1 MB | 1 057 KB | +0.8% |
| 100 MB | 100.9 MB | +0.9% |

Fixed overhead ≈ 8 192 B (5 × 992 B KEM cts + 5 × 32 B shares + 2 349 B sig + JSON).

---

## Parser validation checklist

Parsers MUST enforce these checks **in order** before any cryptographic operation:

1. `len(data) ≤ 64 MiB` — memory exhaustion guard
2. Valid UTF-8 JSON
3. `magic == "QVLT1"`
4. `version == 1`
5. `threshold >= 2`
6. `share_count >= threshold`
7. `shares.len() == share_count`
8. `nonce.len() == 12`
9. All `shares[i].index` unique and non-zero
10. Signature verification (before any KEM / AES operation)
11. AES-GCM decrypt with recomputed AAD

---

## Versioning policy

Backward-incompatible changes increment `version`.  Old parsers are expected
to reject unknown versions with a clear error.

Future planned versions:

| Version | Change |
|---------|--------|
| 2 | Optional: base64url byte arrays instead of JSON integer arrays |
| 3 | HAETAE signature over binary-encoded fields (smaller containers) |
