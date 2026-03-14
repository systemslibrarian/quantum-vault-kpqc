# Quantum Vault

**A threshold file encryption tool combining Shamir Secret Sharing with Post-Quantum Cryptography (SMAUG-T + HAETAE).**

Quantum Vault is an experimental cryptography project exploring how **threshold cryptography** and **post-quantum cryptography** can be combined to protect encrypted files.

The system encrypts files with **AES-256-GCM**, splits the encryption key using **Shamir Secret Sharing**, and protects those shares using **post-quantum cryptographic primitives**.

---

## Interactive Cryptography Demo

Quantum Vault includes an interactive web demo that visualizes threshold cryptography using a deck of playing cards.

Instead of encrypting a file, the demo encrypts the ordering of a shuffled deck. Each cryptographic step becomes visible:

- Encryption flips the cards face-down (AES-256-GCM)
- The key splits into share cards dealt to participants (Shamir Secret Sharing)
- Each share is locked with post-quantum encryption (SMAUG-T)
- A cryptographic seal stamps across the container (HAETAE)

The user selects which participants contribute their shares. If the threshold is met, the cards flip face-up and the original order is restored. If not, the cards stay dark.

### Demo Preview

![Quantum Vault Demo](docs/demo-preview.png)

---

## Design Goals

Quantum Vault explores a security model where **no single person can decrypt a file alone**.

A threshold number of authorized participants must cooperate to reconstruct the encryption key.

Example:
```
Shares: 5  Threshold: 3
```

Any **3 of the 5 participants** can recover the key and decrypt the file.

---

## Cryptographic Stack

Quantum Vault uses the following algorithms:

| Layer | Algorithm | Purpose |
|------|-----------|---------|
| Symmetric Encryption | AES-256-GCM | Encrypt file contents |
| Secret Sharing | Shamir Secret Sharing | Split encryption key into shares |
| Post-Quantum KEM | SMAUG-T | Protect each share with PQ encryption |
| Post-Quantum Signature | HAETAE | Sign and verify encrypted containers |

This architecture allows the system to remain secure even in a **future with quantum computers**.

### A Note on Algorithm Choice

SMAUG-T and HAETAE are candidates from the **KpqC (Korean Post-Quantum Cryptography)** competition — not the NIST PQC standardization process, which selected ML-KEM (Kyber) and ML-DSA (Dilithium).

This is a deliberate choice. The KpqC candidates represent active research with different design tradeoffs, and part of the purpose of Quantum Vault is to explore algorithms outside the NIST selections.

That said, NIST-standardized algorithms carry more ecosystem support, more reference implementations, and broader third-party scrutiny. A planned **hybrid mode** will allow combining KpqC and NIST algorithms together, giving users the option to layer both.

---

## High-Level Encryption Flow

```
File
  ↓
AES-256-GCM encryption
  ↓
Random 256-bit file key
  ↓
Shamir Secret Sharing
  ↓
Multiple key shares created
  ↓
Each share protected using SMAUG-T
  ↓
Container signed with HAETAE
  ↓
.qvault encrypted file
```

## Decryption Flow

```
Load container
  ↓
Verify HAETAE signature
  ↓
Decrypt shares using SMAUG-T
  ↓
Reconstruct AES key using Shamir Secret Sharing
  ↓
Decrypt file with AES-256-GCM
```

---

## Web Demo — Encrypt a Deck of Cards

A deck of cards is small, visual, and universally understood — making it an ideal way to demonstrate threshold encryption. Every layer of the cryptographic stack maps to something the user can see.

### What Gets Encrypted

The demo encrypts the **permutation** of a shuffled deck — not the card names or images. A shuffled deck is represented as an array of integers:

```
[12, 3, 44, 9, 27, 51, ...]
```

This keeps the encrypted payload extremely small, the demo fast, and the cryptography real.

### Encryption

1. 52 cards appear face-up on screen — the user can shuffle them
2. The user hits **Encrypt** — the cards flip face-down (AES-256-GCM)
3. The encryption key shatters into share cards dealt to participants (Shamir Secret Sharing)
4. Each share card is locked with a PQ padlock icon (SMAUG-T encapsulation)
5. A cryptographic seal stamps across the container (HAETAE signature)

### Decryption

1. Participants sit at a virtual table — the user selects which ones contribute
2. HAETAE verifies the container seal
3. SMAUG-T unlocks each selected share
4. Shamir reconstructs the AES key (only if the threshold is met)
5. The cards flip face-up — the user can verify the original order is intact

### Threshold Failure

If fewer shares than the threshold are selected, reconstruction fails and the cards stay face-down. This makes the threshold concept immediately tangible.

### Visual Mapping

| Cryptographic Layer | Visual Representation |
|------|-----------|
| AES-256-GCM encryption | Cards flip face-down |
| Shamir Secret Sharing | Key splits into share cards dealt to participants |
| SMAUG-T encapsulation | Lock icon on each share card |
| HAETAE signature | Seal stamped across the container |
| Threshold failure | Cards stay dark when too few shares are contributed |

---

## Web Demo Architecture

The browser demo runs the cryptographic pipeline client-side using **WebAssembly**. No files or keys ever leave the browser.

### Phased Implementation

The demo runs the real cryptographic pipeline in the browser.

The initial version uses real AES-256-GCM encryption and real Shamir Secret Sharing compiled from Rust to WebAssembly.

Later versions integrate the SMAUG-T and HAETAE reference implementations compiled to WebAssembly from their KpqC C reference code.

### Rust to WASM

The Quantum Vault core library compiles to WASM via `wasm-pack`. The AES-256-GCM and Shamir Secret Sharing layers run as compiled Rust in the browser.

### SMAUG-T and HAETAE in the Browser

Both algorithms have C reference implementations from the KpqC competition. These compile to WASM using **Emscripten**, and the Rust core library calls them through FFI bindings — which is exactly what the `kpqc.rs` backend in the existing architecture is designed for.

Considerations for the WASM compilation:
- Platform-specific randomness calls are routed to the browser's `crypto.getRandomValues`
- Memory footprint is managed for browser constraints
- KpqC reference code is portable C, which is favorable for Emscripten targets

### Hosting

The demo is a static Next.js export with a WASM bundle — no server-side processing required. Suitable for GitHub Pages, Render, or any static hosting.

---

## Project Structure

The project uses a Cargo workspace to separate the library (WASM-compilable) from the CLI binary, with the web demo as a standalone frontend application:

```
quantum-vault/
├─ Cargo.toml              ← workspace root
│
├─ crates/
│   ├─ qv-core/            ← core crypto library (compiles to WASM)
│   │   ├─ Cargo.toml      ← features: dev-backend (default), kpqc-native, kpqc-wasm, wasm
│   │   ├─ build.rs        ← compiles SMAUG-T + HAETAE C libs (kpqc-native only)
│   │   └─ src/
│   │       ├─ lib.rs
│   │       ├─ encrypt.rs
│   │       ├─ decrypt.rs
│   │       ├─ container.rs
│   │       ├─ shamir.rs
│   │       ├─ wasm.rs     ← wasm-bindgen exports (--features wasm)
│   │       └─ crypto/
│   │           ├─ mod.rs
│   │           ├─ kem.rs
│   │           ├─ signature.rs
│   │           └─ backend/
│   │               ├─ mod.rs
│   │               ├─ dev.rs
│   │               ├─ kpqc.rs      ← feature-gated: native / wasm / stub
│   │               └─ kpqc_ffi.rs ← extern "C" wrappers (kpqc-native only)
│   │
│   └─ qv-cli/             ← CLI binary
│       ├─ Cargo.toml
│       └─ src/
│           └─ main.rs     ← --backend dev|kpqc flag
│
├─ vendor/                  ← (gitignored) C reference implementations
│   ├─ smaug-t/             ←   extracted SMAUG-T reference implementation
│   └─ haetae/              ←   extracted HAETAE reference implementation
│
├─ web-demo/                ← Next.js interactive demo
│   ├─ package.json
│   ├─ src/
│   └─ public/
│
├─ docs/
│   ├─ architecture.md
│   ├─ container-format.md
│   └─ demo-preview.png
│
├─ LICENSE
└─ .gitignore
```

---

## CLI Usage

Generate a KEM + signature keypair with the dev backend:
```sh
qv keygen --out-dir ./keys --name alice
```

Encrypt a file for 3 recipients with a 2-of-3 threshold:
```sh
# First generate a key per recipient:
qv keygen --out-dir ./keys --name alice
qv keygen --out-dir ./keys --name bob
qv keygen --out-dir ./keys --name carol

# Then encrypt (comma-separated KEM public key files, read as base64):
qv encrypt \
  --in secret.pdf \
  --out secret.qvault \
  --pubkeys "$(cat keys/alice.kem.pub),$(cat keys/bob.kem.pub),$(cat keys/carol.kem.pub)" \
  --threshold 2 \
  --sign-key keys/alice.sig.priv
```

Decrypt with any 2 of the 3 private keys:
```sh
qv decrypt \
  --in secret.qvault \
  --out recovered.pdf \
  --privkeys "$(cat keys/alice.kem.priv),$(cat keys/bob.kem.priv)" \
  --verify-key keys/alice.sig.pub
```

The `--backend` flag selects the crypto backend (`dev` by default; `kpqc`
requires the `kpqc-native` or `kpqc-wasm` feature to be compiled in):
```sh
# Show which backend is active:
qv keygen --backend dev
```

---

## Architecture

The cryptographic implementation uses a **pluggable backend architecture**.

The application calls stable Rust trait interfaces (`encapsulate`/`decapsulate`, `sign`/`verify`) rather than binding directly to a single implementation. This allows:

- Easier testing with a development backend
- Cleaner separation of application logic and cryptographic primitives
- Future integration with real KpqC and NIST implementations
- Safer evolution of the codebase as algorithms mature

### Container Format

The `.qvault` container format is documented in `docs/container-format.md`. Getting this right is critical — versioning, authenticated metadata, and forward compatibility are where most real-world crypto tools encounter problems. The container design prioritizes:

- Explicit version fields for format evolution
- Authenticated metadata so tampering is detectable before decryption
- Clean separation of encrypted payload, protected shares, and signature data

### Shamir Secret Sharing

The Shamir implementation requires particular care around:

- Side-channel resistance during polynomial evaluation
- Share validation to detect corrupted or malicious shares before reconstruction
- Proper use of a finite field (GF(256) or a prime field) with no information leakage from partial share sets

---

## Current Development Status

Completed:

- AES-256-GCM file encryption
- Shamir Secret Sharing over GF(2^8)
- Container serialization with `kem_algorithm` + `sig_algorithm` metadata fields
- Pluggable backend architecture (`dev-backend`, `kpqc-native`, `kpqc-wasm` feature flags)
- CLI (`qv keygen / encrypt / decrypt`) with `--backend dev|kpqc` flag
- WASM bridge for the browser demo (TypeScript fallback included)
- `build.rs` for SMAUG-T + HAETAE C compilation (activated by `kpqc-native`)
- `kpqc_ffi.rs` — safe Rust wrappers over the `smaug3_*` / `haetae3_*` C API
- Feature-gated `kpqc.rs` — native FFI / WASM stub / no-op stub automatically selected

In progress / remaining:

- Vendor the KpqC reference C implementations (`vendor/smaug-t/`, `vendor/haetae/`)
- SMAUG-T WASM path (Emscripten / pure-Rust port)
- Hybrid mode (KpqC + NIST algorithm support)
- Interactive web demo with card deck visualization
- Formal test vectors

---

## Security Notice

Quantum Vault is currently an **experimental research project** and should not be considered production-ready.

Before production use the project would require:

- Formal cryptographic review
- Constant-time verification where relevant
- Test vectors for all cryptographic operations
- Container format validation and fuzzing
- Secure key lifecycle handling
- Interoperability testing for PQ backends

---

## License

MIT
