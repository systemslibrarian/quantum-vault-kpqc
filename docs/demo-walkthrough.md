# Quantum Vault — Demo Walkthrough

**Version:** 1.0  
**Date:** 2026-03  
**Applies to:** Web demo v5.0 (real KpqC WASM)

---

## Overview

The web demo is a single-page application that presents a 4×3 grid of twelve
numbered safety deposit boxes (01–12).  Three of them (03, 08, 10) are
pre-sealed on first load using **real** SMAUG-T Level 1 KEM and HAETAE Mode 2
signatures — the same algorithms from the KpqC competition.  The remaining nine
boxes are empty and can be filled with your own secrets.

Every cryptographic operation runs inside Emscripten-compiled WebAssembly; there
are no mock implementations, HMAC substitutes, or pre-computed values.

---

## 1. The Vault Wall

On first visit the application calls `generateDemoBoxes()`, which runs three full
`sealMessage()` pipelines (one per demo box) before rendering the wall.  Because
fresh random keys and nonces are derived each time, the ciphertext stored in
session state is always unique — but the documented passwords always unlock it.

Box appearance:

| Class | Meaning |
|-------|---------|
| `empty` | No secret stored |
| `occupied` | A sealed secret is present |
| `selected` | The box is currently active in the side panel |

Clicking a box (or pressing Enter / Space on it) opens the side panel.  An
occupied box shows the **Retrieve** form; an empty box shows the **Deposit**
form.

---

## 2. Pre-Loaded Demo Boxes

These three boxes are available on every fresh page load:

| Box | Secret | Alice's key | Bob's key | Carol's key |
|-----|--------|-------------|-----------|-------------|
| 03 | `The treasure map is under the old oak tree` | `ruby` | `emerald` | `diamond` |
| 08 | `Launch code: ALPHA-7749-ZULU` | `fortress` | `bastion` | `citadel` |
| 10 | `The meeting is moved to Friday at noon` | `monday` | `tuesday` | `wednesday` |

Any two of the three listed passwords unlock each box.  Entering only one is
not enough, even with the correct password — this demonstrates the 2-of-3
threshold property.

---

## 3. Deposit Flow (Sealing a New Secret)

Click an **empty** box to open the Deposit panel.

### 3.1 Input Validation

| Field | Rule |
|-------|------|
| Secret message | Must not be empty |
| Alice / Bob / Carol key | Minimum 4 characters; all three must be distinct |

Validation is client-side only; it runs before any cryptographic work starts.

### 3.2 Pipeline Animation

When "Seal deposit box" is pressed, four steps light up sequentially — each
representing a real cryptographic operation:

```
AES-256-GCM  →  Shamir split  →  SMAUG-T wrap  →  HAETAE sign
```

**What each step actually does:**

**AES-256-GCM**  
`crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 })` generates a 256-
bit file key K.  The UTF-8–encoded message is encrypted to produce a ciphertext
C and a 96-bit random nonce IV.

**Shamir split**  
The 32 raw bytes of K are split into 3 shares over GF(2⁸) with polynomial
`0x11d`, threshold t = 2.  Each share is an (index, 32-byte data) pair.
Reconstructing any 2 of the 3 shares recovers K exactly; 1 share reveals
nothing.

**SMAUG-T wrap** (runs three times in parallel, one per keyholder)  
For each participant:
1. `smaug_keypair()` (WASM) generates a fresh 672-byte public key and 832-byte
   secret key.
2. `smaug_encapsulate()` encapsulates a 32-byte shared secret SS using the
   public key, producing a 672-byte KEM ciphertext.
3. The 32-byte share is AES-256-GCM encrypted using SS as the key.
4. The SMAUG-T secret key itself is encrypted with a key derived by
   PBKDF2-SHA-256 (100 000 iterations) from the participant's password.

All four SMAUG-T outputs (salt, KEM ciphertext, wrapped share, wrapped SK) plus
their nonces are stored as a `WrappedShare` record.

**HAETAE sign**  
A one-time HAETAE Mode 2 keypair (992-byte VK, 1408-byte SK) is generated.
The hash input is the concatenation of all persistent container fields:

```
nonce ‖ ciphertext ‖ [salt ‖ kemCT ‖ wrappedShare ‖ shareNonce ‖ pk ‖ wrappedSK ‖ skNonce] × 3
```

`haetae_sign()` produces a signature of up to 1474 bytes.  The verification
key VK is stored in `sigPublicKey` alongside the container.  The signing key SK
is discarded.

### 3.3 Result

The box turns to `occupied` state.  "Secret sealed in box XX. ✓" appears in the
panel.

---

## 4. Retrieve Flow (Opening a Sealed Box)

Click an **occupied** box to open the Retrieve panel.

### 4.1 Password Entry

Enter any combination of Alice, Bob, and Carol passwords.  Leave a field blank
to skip that participant.  Input fields are `type="password"` (masked).

At least two correct passwords are required; the entry form does not enforce a
minimum, so the threshold failure path can be explored deliberately.

### 4.2 Pipeline Animation

```
HAETAE verify  →  SMAUG-T unlock  →  Shamir reconstruct  →  AES-256-GCM
```

**What each step actually does:**

**HAETAE verify**  
Before any decryption is attempted, `haetae_verify()` (WASM) checks the
container signature over the same byte-concatenation used at seal time.  A
return value of zero means the container is intact; non-zero stops the pipeline
immediately and returns a failure result without touching the ciphertext.

This step catches bit-flips, truncation, reordering of shares, or any other
tampering with the stored container bytes.

**SMAUG-T unlock** (per non-empty password)  
For each field that was filled in:
1. PBKDF2-SHA-256 (100 000 iterations) over the participant's password and the
   stored 16-byte salt re-derives the AES key.
2. AES-256-GCM decrypts the wrapped SMAUG-T SK.  A wrong password causes an
   AES-GCM auth-tag mismatch → `DOMException`; the share is silently skipped.
3. `smaug_decapsulate()` (WASM) uses the recovered SK to derive the same SS from
   the stored KEM ciphertext.
4. AES-256-GCM decrypts the wrapped share using SS.

**Shamir reconstruct**  
`reconstructSecret()` runs Lagrange interpolation over GF(2⁸) with however many
valid shares were recovered.  If validShares < 2, the output is mathematically
wrong but the function does not throw — the error is caught in the next step.

If the threshold is not met, the pipeline indicator marks `Shamir reconstruct`
as `failed` (red) and stops.  The step indicator for AES-256-GCM is never
activated.

**AES-256-GCM**  
`crypto.subtle.decrypt` attempts to decrypt the ciphertext with the reconstructed
key.  If exactly 1 valid share was recovered, the key is incorrect and the
16-byte GCM auth tag will not match → another `DOMException`; the failure path
is taken.  If 2 or 3 valid shares were recovered, decryption succeeds.

### 4.3 Success Path

The revealed message appears letter-by-letter with a brief scramble animation
before each character settles.  Spaces appear instantly.  The character source
is genuine decryption output, not pre-stored plaintext.

### 4.4 Failure Paths

**Wrong password(s) — threshold not met:**  
The pipeline reaches `Shamir reconstruct`, marks it `failed`, and stops.  The
Lagrange output (wrong key bytes) is displayed as rapidly cycling gibberish for
~480 ms before the ACCESS DENIED message.  The gibberish bytes are the real
incorrect Lagrange output XOR'd against cycling constants — they are not
generated randomly; they are the genuine wrong-key bytes.

**HAETAE verify fails (tampered container):**  
The pipeline halts before SMAUG-T unlock.  Random bytes replace the gibberish
display (there is no Lagrange output to show since decryption was not attempted).
No decryption of any sort is performed.

**Wrong key exact threshold (1 valid share only):**  
SMAUG-T unlock succeeds for one share; Shamir reconstruct runs with 1 share and
produces a wrong key; AES-GCM auth tag mismatch.  The failure-path gibberish
bytes in this case are derived from `reconstructedKey[i % 32] XOR (i * 7 + 31)`.

---

## 5. What Is Real vs. What Is Visualisation

| Element | Real cryptography? |
|---------|-------------------|
| SMAUG-T keypair / encapsulate / decapsulate | Yes — WASM from KpqC reference C |
| HAETAE keypair / sign / verify | Yes — WASM from KpqC reference C |
| AES-256-GCM encrypt / decrypt | Yes — `window.crypto.subtle` |
| PBKDF2-SHA-256 key derivation | Yes — `window.crypto.subtle` |
| Shamir GF(2⁸) split / reconstruct | Yes — TypeScript implementation |
| Pipeline step animation timing | Visual only (500 ms `sleep()` per step) |
| Letter-by-letter reveal | Visual only (the decrypted string is known before animation starts) |
| Gibberish animation cycles | Derived from real wrong-key bytes, displayed with cycling XOR masks |

---

## 6. Parameter Summary

| Parameter | Value |
|-----------|-------|
| Shares (n) | 3 |
| Threshold (t) | 2 |
| AES key size | 256 bits |
| GCM nonce | 96 bits (random per seal) |
| PBKDF2 iterations | 100 000 |
| PBKDF2 salt | 16 bytes (random per participant per seal) |
| SMAUG-T level | Level 1 (128-bit PQC security) |
| HAETAE mode | Mode 2 (128-bit PQC security) |
| GF(2⁸) polynomial | 0x11d (generator 2 has order 255) |
