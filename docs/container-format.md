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
dev backend uses `SHA-256(privkey || canonical_json)`.  Production containers
will use HAETAE.

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

## Versioning policy

Backward-incompatible changes increment `version`.  Old parsers are expected
to reject unknown versions with a clear error.

Future planned versions:

| Version | Change |
|---------|--------|
| 2 | SMAUG-T KEM ciphertext format |
| 3 | HAETAE signature over binary encoding |
