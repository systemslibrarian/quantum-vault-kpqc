# Quantum Vault — v5.0

**A threshold secret-storage demo running real post-quantum cryptography in the browser.**

Quantum Vault encrypts short secrets with **AES-256-GCM**, splits the key using **Shamir Secret Sharing (GF(2⁸))**, wraps each share with **SMAUG-T Level 1 KEM** (key encapsulation), and seals the container with a **HAETAE Mode 2 signature**.

Every cryptographic primitive executes inside the browser as WebAssembly — compiled from the official C reference implementations of the KpqC competition finalists. **There are no mocks, no HMAC substitutes, no polyfills.**

---

## Live Demo

👉 **[systemslibrarian.github.io/quantum-vault-kpqc](https://systemslibrarian.github.io/quantum-vault-kpqc/)**

Three demo boxes are pre-sealed on first visit. Each requires two correct passwords (2-of-3 threshold).

| Box | Secret | Alice | Bob | Carol |
|-----|--------|-------|-----|-------|
| 03 | *The treasure map is under the old oak tree* | `ruby` | `emerald` | `diamond` |
| 08 | *Launch code: ALPHA-7749-ZULU* | `fortress` | `bastion` | `citadel` |
| 10 | *The meeting is moved to Friday at noon* | `monday` | `tuesday` | `wednesday` |

Unlock any box by entering **any two** of its three passwords.

---

## Cryptographic Stack

| Layer | Algorithm | Notes |
|-------|-----------|-------|
| Symmetric encryption | **AES-256-GCM** | Web Crypto API |
| Key splitting | **Shamir Secret Sharing** | GF(2⁸), evaluation polynomial over 256-byte shares |
| Post-quantum KEM | **SMAUG-T Level 1** | KpqC standard — PK 672 B, SK 832 B, CT 672 B, SS 32 B |
| Post-quantum signature | **HAETAE Mode 2** | KpqC standard — PK 992 B, SK 1408 B, max-sig 1474 B |

### Why KpqC rather than NIST PQC?

The NIST PQC process selected ML-KEM (Kyber) and ML-DSA (Dilithium). This project deliberately chooses the KpqC finalists (SMAUG-T + HAETAE) as an exercise in exploring alternative algorithm families — lattice-based designs with different parameter choices and design tradeoffs. A hybrid mode combining both families is a future goal.

---

## Seal / Open Pipeline

### Sealing a secret (deposit)

```
1. AES-256-GCM
   random 256-bit key → encrypt plaintext → (ciphertext, nonce)

2. Shamir split
   32-byte AES key → 3 shares, threshold = 2  (GF(2⁸) polynomial)

3. SMAUG-T wrap  (repeated 3× — once per participant)
   a. SMAUG-T keygen()         → (publicKey PK, secretKey SK)
   b. SMAUG-T encapsulate(PK)  → (kemCiphertext, sharedSecret)
   c. AES-GCM(sharedSecret)    → wrappedShare
   d. PBKDF2(password, salt)   → passwordKey
   e. AES-GCM(passwordKey, SK) → wrappedSecretKey

4. HAETAE sign
   haetaeKeypair()                  → (sigPK, sigSK)
   haetaeSign(containerBytes, sigSK) → signature
   store sigPK alongside the container
```

### Opening a secret (retrieve)

```
1. HAETAE verify
   haetaeVerify(signature, containerBytes, sigPK) → reject if invalid

2. SMAUG-T unlock  (for each submitted password)
   PBKDF2(password, salt) → passwordKey
   AES-GCM decrypt wrappedSecretKey → SK      (throws if wrong password)
   smaugDecapsulate(kemCiphertext, SK) → sharedSecret
   AES-GCM(sharedSecret) decrypt wrappedShare → Shamir share

3. Shamir reconstruct
   ≥ 2 shares → AES key   (wrong if < 2 shares)

4. AES-256-GCM decrypt
   AES-GCM(reconstructedKey) → plaintext      (throws if key wrong)
```

---

## Project Layout

```
quantum-vault-kpqc/
│
├─ crates/
│   ├─ qv-core/       ← Rust crypto library (AES-GCM + Shamir + 45 unit tests)
│   └─ qv-cli/        ← CLI binary
│
├─ wasm/
│   ├─ build.sh                ← Emscripten build script (read-only; run locally)
│   ├─ src/
│   │   ├─ randombytes_wasm.c  ← routes to crypto.getRandomValues
│   │   ├─ smaug_exports.c     ← SMAUG-T exported entry points
│   │   └─ haetae_exports.c    ← HAETAE exported entry points
│   ├─ dist/                   ← (gitignored) compiled JS+WASM
│   └─ vendor/                 ← (gitignored) C reference implementations
│
├─ web-demo/
│   ├─ index.html
│   ├─ src/
│   │   ├─ main.ts             ← entry point; calls initCrypto() before vault init
│   │   ├─ crypto/
│   │   │   ├─ init.ts         ← parallel WASM module initialization
│   │   │   ├─ smaug.ts        ← SMAUG-T WASM wrapper
│   │   │   ├─ haetae.ts       ← HAETAE WASM wrapper
│   │   │   ├─ keywrap.ts      ← SMAUG-T KEM + PBKDF2 share wrapping
│   │   │   ├─ pipeline.ts     ← seal/open orchestration
│   │   │   ├─ aes.ts          ← AES-256-GCM helpers
│   │   │   ├─ shamir.ts       ← Shamir SSS over GF(2⁸)
│   │   │   └─ wasm/           ← Emscripten JS loaders (committed)
│   │   ├─ vault/
│   │   │   ├─ demo.ts         ← generates the three pre-sealed demo boxes
│   │   │   └─ state.ts        ← localStorage persistence / serialization
│   │   └─ ui/
│   │       ├─ wall.ts         ← vault-wall rendering
│   │       ├─ panel.ts        ← deposit / retrieve panel
│   │       ├─ pipeline-ui.ts  ← animated pipeline steps
│   │       ├─ reveal.ts       ← message reveal / gibberish animation
│   │       └─ styles/vault.css
│   └─ public/
│       ├─ smaug.wasm          ← compiled SMAUG-T Level 1 binary (committed)
│       └─ haetae.wasm         ← compiled HAETAE Mode 2 binary (committed)
│
├─ docs/
│   ├─ ARCHITECTURE.md            ← full stack: C → WASM → TypeScript, Rust FFI
│   ├─ specification.md           ← normative cryptographic specification
│   ├─ container-format.md        ← .qvault binary format
│   ├─ threat-model.md            ← threat actors and security properties
│   ├─ test-vectors.md            ← known-answer tests for Shamir + KEM
│   ├─ security-audit-checklist.md ← reviewer checklist
│   ├─ demo-walkthrough.md        ← UI steps mapped to cryptographic operations
│   └─ implementation-notes.md   ← Emscripten build, JS↔WASM interface, limits
│
├─ .github/workflows/deploy-pages.yml
└─ README.md
```

---

## Running the Web Demo Locally

```bash
cd web-demo
npm install
npm run dev          # Vite dev server → http://localhost:5173
```

**Build for production:**

```bash
npm run build        # outputs to web-demo/dist/
```

The Vite config sets `base: '/quantum-vault-kpqc/'` to match the GitHub Pages subdirectory.

---

## Rebuilding the WASM Modules

The compiled `.wasm` + Emscripten loader `.js` files are committed to the repo so the web demo deploys without a C toolchain. To rebuild from source:

```bash
# 1. Install and activate Emscripten (one-time)
git clone https://github.com/emscripten-core/emsdk ~/emsdk
cd ~/emsdk && ./emsdk install 5.0.3 && ./emsdk activate 5.0.3
source ~/emsdk/emsdk_env.sh

# 2. Restore vendor sources (gitignored)
#    SMAUG-T:
git clone https://github.com/hmchoe0528/SMAUG-T_public \
  wasm/vendor/smaug-t
#    HAETAE — download HAETAE-1.1.2.zip from the KpqC submission page and:
unzip HAETAE-1.1.2.zip -d wasm/vendor/haetae

# 3. Build
bash wasm/build.sh

# 4. Copy outputs
cp wasm/dist/smaug.js  web-demo/src/crypto/wasm/smaug.js
cp wasm/dist/haetae.js web-demo/src/crypto/wasm/haetae.js
cp wasm/dist/smaug.wasm  web-demo/public/smaug.wasm
cp wasm/dist/haetae.wasm web-demo/public/haetae.wasm
```

### Verified WASM sizes (Emscripten 5.0.3, -O2)

| Module | PK | SK | CT/maxSig | SS |
|--------|----|----|-----------|-----|
| SMAUG-T Level 1 | 672 B | 832 B | 672 B | 32 B |
| HAETAE Mode 2 | 992 B | 1408 B | 1474 B (max) | — |

Round-trip tests confirmed:
- SMAUG-T: encapsulate → decapsulate → shared secrets match ✓
- HAETAE: sign → verify → returns 0 (valid) ✓

---

## Rust CLI

The `qv-core` crate provides the same cryptographic stack in Rust (AES-256-GCM + Shamir SSS, with a pluggable backend interface designed for KpqC FFI).

```bash
cargo build --release
cargo test           # 45 unit tests
cargo bench          # criterion benchmarks
```

---

## Security Notes

- All secrets and keys stay in the browser — nothing is transmitted to a server.
- PBKDF2 with 100,000 SHA-256 iterations is used to derive a password-wrapping key for the SMAUG-T secret key. This means brute-forcing a weak password is possible; use strong passwords for real secrets.
- SMAUG-T does not support deterministic keygen from a seed, so a fresh random keypair is generated per deposit. The secret key is encrypted with the password-derived key; the ciphertext and public key are stored in the container.
- The HAETAE signing keypair is ephemeral (generated at seal time) and the public key is stored in the container. This provides authentication but not attribution — anyone who reads the public key can verify the seal but cannot determine who created it.
- The WASM binaries are the official KpqC reference implementations, not production-hardened code. They have not been audited for side-channel resistance.

---

## License

MIT — see [LICENSE](LICENSE).
