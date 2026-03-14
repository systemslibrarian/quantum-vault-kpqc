# Quantum Vault — Architecture

## Overview

Quantum Vault is organized as a Cargo workspace containing two Rust crates and a Next.js web demo.

```
quantum-vault/
├─ Cargo.toml              workspace root
├─ crates/
│   ├─ qv-core/            core crypto library — WASM-compilable
│   └─ qv-cli/             command-line binary
└─ web-demo/               Next.js interactive demo
```

---

## qv-core

The central library. It compiles to both native code (for the CLI) and WebAssembly (for the browser demo).

### Module map

```
src/
├─ lib.rs          public API surface: encrypt_file, decrypt_file, split_key, reconstruct_key
├─ container.rs    .qvault container type + JSON serialization
├─ encrypt.rs      AES-256-GCM + Shamir + KEM protect + sign pipeline
├─ decrypt.rs      verify + KEM recover + Shamir reconstruct + AES decrypt pipeline
├─ shamir.rs       Shamir Secret Sharing over GF(2^8)
└─ crypto/
    ├─ mod.rs          re-exports backends
    ├─ kem.rs          Kem trait
    ├─ signature.rs    Signature trait
    └─ backend/
        ├─ mod.rs      re-exports dev + kpqc
        ├─ dev.rs      development stub (SHA-256 + XOR) — no real security
        └─ kpqc.rs     SMAUG-T + HAETAE scaffold (not yet integrated)
```

### Encryption pipeline

```
plaintext bytes
      │
      ▼  rand::thread_rng() → 256-bit file_key + 96-bit nonce
      │
      ▼  AES-256-GCM encrypt(file_key, nonce, plaintext)
      │
ciphertext (includes 128-bit auth tag)
      │
      ▼  shamir::split_secret(file_key, share_count, threshold)
      │
raw_share_1 … raw_share_n    ← zeroize file_key
      │
      ▼  Kem::encapsulate(recipient_pubkey) per share
      │     → (kem_ciphertext, shared_secret)
      │     → encrypted_share = share_data XOR keystream(shared_secret)
      │     → zeroize shared_secret
      │
EncryptedKeyShare list
      │
      ▼  build QuantumVaultContainer (signature = [])
      │
      ▼  container_signing_bytes() → canonical JSON of non-signature fields
      │
      ▼  Signature::sign(signer_privkey, canonical_bytes)
      │
.qvault JSON container
```

### Decryption pipeline

```
.qvault JSON container
      │
      ▼  QuantumVaultContainer::from_bytes() — validates magic + version
      │
      ▼  container_signing_bytes() → canonical JSON
      │
      ▼  Signature::verify(signer_pubkey, canonical_bytes, signature)
      │     error if invalid
      │
      ▼  for each supplied recipient_privkey:
      │     Kem::decapsulate(privkey, kem_ciphertext) → shared_secret
      │     share_data = encrypted_share XOR keystream(shared_secret)
      │     zeroize shared_secret
      │
raw_share list (≥ threshold)
      │
      ▼  shamir::reconstruct_secret(shares) → file_key
      │
      ▼  AES-256-GCM decrypt(file_key, nonce, ciphertext)
      │
plaintext bytes
```

---

## Shamir Secret Sharing

Implemented from scratch in `shamir.rs` over GF(2^8) with irreducible polynomial
x^8 + x^4 + x^3 + x + 1 (0x11b — the AES field polynomial).

Each byte of the secret is treated as an independent GF(256) element.  An N-byte
secret produces N-byte share payloads.  Reconstruction uses Lagrange interpolation
at x = 0.

Share indices are 1-based u8 values.  Index 0 is never issued (it would reveal the
secret directly).

---

## Crypto backend abstraction

Two traits define the interface all backends must implement:

```rust
trait Kem {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    fn encapsulate(&self, pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    fn decapsulate(&self, privkey: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn algorithm_id(&self) -> &'static str;
}

trait Signature {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    fn sign(&self, privkey: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<bool>;
    fn algorithm_id(&self) -> &'static str;
}
```

### Development backend (`dev.rs`)

Used for all current testing.  Not cryptographically secure.

| Operation | Implementation |
|-----------|----------------|
| KEM keypair | privkey = 32 rand bytes; pubkey = SHA-256(privkey) |
| Encapsulate | ss = 32 rand bytes; ct = ss XOR pubkey |
| Decapsulate | pubkey = SHA-256(privkey); ss = ct XOR pubkey |
| Sign | SHA-256(privkey \|\| message) |
| Verify | SHA-256(pubkey \|\| message) == signature |

### KPQC backend scaffold (`kpqc.rs`)

Placeholder for SMAUG-T (KEM) and HAETAE (signature).  All methods return a
descriptive error with an integration roadmap pointer.

**Integration plan:**
1. Vendor KpqC C reference implementations under `vendor/smaug-t/` and `vendor/haetae/`.
2. Write `build.rs` to compile them with the `cc` crate.
3. Declare `extern "C"` bindings in `kpqc.rs`.
4. Feature-gate: `kpqc-native` for CLI, `kpqc-wasm` for browser (Emscripten build).

---

## qv-cli

A `clap`-based binary exposing three subcommands:

| Command | Purpose |
|---------|---------|
| `qv keygen` | Generate KEM + signature keypairs (dev backend) |
| `qv encrypt` | Encrypt a file → `.qvault` container |
| `qv decrypt` | Decrypt a `.qvault` container → plaintext file |

Keys are stored as base64-encoded text files.  The CLI accepts comma-separated lists of base64 public/private keys for multi-recipient threshold setups.

---

## Container format

See [container-format.md](container-format.md) for the full field reference.

Summary:
- JSON-encoded with magic `QVLT1` and version `1`
- Nonce and ciphertext stored as `[u8]` arrays
- Each share is independently KEM-protected
- Signature covers all fields except itself

---

## Web demo

A Next.js static export that runs the full crypto pipeline in the browser.

### Technology

| Layer | Choice |
|-------|--------|
| Framework | Next.js 14 (App Router, static export) |
| Styling | Tailwind CSS |
| AES-256-GCM | Web Crypto API (`SubtleCrypto`) |
| Shamir SSS | TypeScript port of `shamir.rs` (GF(256)) |
| KEM / signature | Dev stub in TypeScript (mirrors `dev.rs`) |
| Future WASM | `qv-core` compiled with `wasm-pack` |

### Visual pipeline

```
52 cards face-up (shuffled permutation)
      │
[Encrypt button]
      │
      ▼  AES-256-GCM → cards flip face-down
      │
      ▼  Shamir split → key shatters into share cards dealt to participants
      │
      ▼  KEM protect → padlock icon on each share card
      │
      ▼  Sign → wax seal overlay on container
      │
[Select participants ≥ threshold]
      │
      ▼  Verify seal
      ▼  KEM recover shares
      ▼  Shamir reconstruct
      ▼  AES decrypt → cards flip face-up
```

### Hosting

Static export (`next build` + `next export`) — no server required.
Suitable for GitHub Pages, Cloudflare Pages, or any CDN.

---

## Security properties

| Property | Status |
|----------|--------|
| AES-256-GCM confidentiality | Implemented (real) |
| GCM authentication tag | Implemented (real) |
| Shamir threshold secrecy | Implemented (real GF(256)) |
| KEM share protection | Dev stub — real with SMAUG-T |
| Container authentication | Dev stub — real with HAETAE |
| Key zeroization | Implemented (`zeroize` crate) |
| No key material in logs | Enforced by design |

---

## Roadmap

- [ ] Vendor SMAUG-T C reference implementation
- [ ] Vendor HAETAE C reference implementation
- [ ] Write FFI bindings in `kpqc.rs`
- [ ] Compile `qv-core` to WASM with `wasm-pack`
- [ ] Wire WASM into the web demo
- [ ] Add hybrid mode (KpqC + NIST ML-KEM / ML-DSA)
- [ ] Publish demo to GitHub Pages
