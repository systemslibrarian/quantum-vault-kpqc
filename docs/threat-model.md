# Quantum Vault — Threat Model

**Version:** 1.0  
**Status:** Stable

---

## 1. Overview

This document enumerates the assets Quantum Vault protects, the threat actors
it considers, the security properties it guarantees, and the threats that are
*out of scope* for the current design.

---

## 2. Protected Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Plaintext file $F$ | Critical | The content to be encrypted |
| File key $K$ | Critical | 256-bit AES key; exists only for the duration of encrypt/decrypt |
| KEM private keys $sk_i$ | High | Each recipient's secret; compromise of $t$ enables decryption |
| Signature private key $\text{sig\_sk}$ | High | Used to authenticate the container |
| KEM public keys $pk_i$ | Low | Public but integrity-critical (substitution enables MITM) |
| Signature public key $\text{sig\_pk}$ | Low | Needed for verification; must be distributed authentically |
| Container ciphertext | Medium | Exposure reveals algorithm choices and share count but not $F$ |

---

## 3. Threat Actors

### 3.1 Passive Network Attacker (Classical)

**Capabilities:**  
- Observes all transmitted data (containers, public keys)
- Cannot modify data in transit

**Threat:**  
Recovers $F$ from the container without possessing private keys.

**Mitigation:**  
Under IND-CPA security of SMAUG-T, the probability of recovering a share's
$\text{ss}_i$ from $\text{kem\_ct}_i$ and $pk_i$ is negligible.  
Under perfect threshold security of Shamir SSS, fewer than $t$ shares reveal
zero bits of $K$.  
AES-256-GCM provides 256-bit (128-bit post-quantum) symmetric security.

**Verdict: Defended.**

---

### 3.2 Insider / Colluding Participants (Classical)

**Capabilities:**  
- Controls up to $t-1$ recipients (holds their private keys)
- Can share their partial decryptions

**Threat:**  
Reconstruct $K$ and decrypt $F$ with fewer than $t$ shares.

**Mitigation:**  
Any $t-1$ or fewer shares are information-theoretically independent of $K$.
The colluding participants learn *nothing* about $K$ beyond what they already
know.

**Verdict: Defended (unconditionally — assumes correct Shamir SSS).**

---

### 3.3 Storage / Backup Compromise (Classical)

**Capabilities:**  
- Read access to the container file on disk or in storage
- May have access to up to $t-1$ KEM private keys

**Threat:**  
Recover $F$ from a stolen backup.

**Mitigation:**  
As above — fewer than $t$ shares provide no information about $K$.
The container's HAETAE signature prevents silent modification before a
compromised $t$-share attack.

**Verdict: Defended against passive access; $t$-share active attack is out of scope (see §5).**

---

### 3.4 Active Container Tampering

**Capabilities:**  
- Can modify the container in transit or at rest
- Does not hold any private keys

**Threat:**  
- Replace the KEM ciphertext for one share with one for a different recipient,
  redirecting a partial decryption.
- Truncate or corrupt the ciphertext.
- Modify the `threshold` field to weaken the policy.

**Mitigation:**  
HAETAE signs *all* container fields (nonce, ciphertext, all KEM ciphertexts,
threshold, algorithm IDs). Any modification invalidates the signature.
Decryption aborts on signature failure *before* any KEM or AES operation.

The AAD in AES-256-GCM additionally binds the threshold and algorithm choice to
the ciphertext, providing a second layer of defense.

**Verdict: Defended.**

---

### 3.5 Quantum Attacker (Harvest Now, Decrypt Later)

**Capabilities:**  
- Stores containers today; executes large quantum computers in the future
- Can break RSA, ECC, and Diffie-Hellman

**Threat:**  
Use Shor's algorithm to break the KEM and recover $K$; use Grover's algorithm
to brute-force AES.

**Mitigation:**  
SMAUG-T and HAETAE are based on module lattice problems (MLWE, MLWR, MSIS),
believed to resist known quantum algorithms at Level 3 (≈128 bits
post-quantum security). AES-256 provides ≥128 bits even under Grover's
algorithm.

**Verdict: Defended (assuming lattice assumptions hold against quantum adversaries).**

---

### 3.6 Algorithm-Substitution / Downgrade

**Capabilities:**  
- Can intercept and modify the container's `kem_algorithm` or `sig_algorithm`
  field before a recipient processes it.

**Threat:**  
Convince a recipient to use the weak `dev-backend` or a future weaker
algorithm.

**Mitigation:**  
- The `kem_algorithm` and `sig_algorithm` fields are covered by the HAETAE
  signature; modification is detectable.
- The AAD includes both algorithm IDs and the container version; a downgraded
  algorithm produces a different AAD, causing AES-GCM decryption to fail.
- The `dev-backend` compile-error guard prevents it from shipping in release
  builds (`cfg!(not(debug_assertions))`).

**Verdict: Defended.**

---

## 4. Security Properties Summary

| Property | Guarantee | Assumption |
|----------|-----------|------------|
| Confidentiality ($< t$ shares) | Information-theoretic (perfect secrecy) | Correct Shamir SSS |
| Confidentiality (KEM layer) | Computational | MLWE / MLWR (SMAUG-T IND-CCA2) |
| Integrity | Computational | MSIS (HAETAE EUF-CMA) |
| Authenticity | Computational | HAETAE EUF-CMA |
| Quantum resistance | Computational | Lattice hard problems resist quantum |
| Post-quantum symmetric | 128-bit under Grover | AES-256 security |

---

## 5. Out of Scope / Explicitly Not Defended

The following are **not** in Quantum Vault's current threat model:

| Threat | Reason |
|--------|--------|
| **Compromise of ≥ t recipients** | Shamir provides no protection if $t$ shares are obtained legitimately or through coercion |
| **Side-channel attacks** (timing, power, EM) | The dev backend and reference C libraries have not been hardened against timing; xor_protect is not constant-time in general |
| **Memory forensics** | Key material is zeroized but OS page swapping or hibernation may persist it before zeroization |
| **Malicious encryptor** | The encryptor can embed arbitrary plaintext; Quantum Vault makes no claims about what is encrypted |
| **Signature key distribution** | The authenticity of `sig_pk` is out of scope — a TOFU or PKI layer is required |
| **Deniability** | The HAETAE signature creates a non-repudiable binding between the signer and the container |
| **Key revocation** | There is no mechanism to revoke a recipient's key share |
| **Quantum attacks on GF(2⁸)** | Quantum algorithms provide a small speedup for Gaussian elimination over finite fields but do not threaten SSS at current parameters |

---

## 6. Implementation Security Requirements

All implementations MUST:

1. Verify the container signature **before** any decryption operation.
2. Zeroize the file key $K$ and all intermediate shared secrets from memory.
3. Use a cryptographically secure random number generator for $K$, $\text{nonce}$, and SSS polynomial coefficients.
4. Reject containers exceeding 64 MiB to prevent memory exhaustion.
5. Validate all structural constraints (threshold ≥ 2, nonce length = 12, shares count matches `share_count`) before processing.
6. Never enable `dev-backend` in production builds.
