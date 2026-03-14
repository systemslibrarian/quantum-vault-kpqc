# Quantum Vault — Web Demo

An interactive browser demo that visualises every layer of the Quantum Vault cryptographic stack using a bank vault of 9 safety deposit boxes (3×3 grid).

> **v5.0 — real KpqC cryptography.** All cryptographic operations run as genuine WebAssembly compiled from the official KpqC C reference implementations. SMAUG-T Level 1 handles key encapsulation; HAETAE Mode 2 handles container signing. No mocks, no HMAC substitutes.

---

## Quick Start

```bash
# from the web-demo/ directory
npm install
npm run dev
# open http://localhost:5173
```

Requires Node ≥ 18.

---

## Demo Box Passwords

Three boxes are pre-sealed on first visit. Any two of the three passwords unlock each box.

| Box | Password 1 | Password 2 | Password 3 |
|-----|-----------|-----------|-----------|
| 03 | `ruby` | `emerald` | `diamond` |
| 06 | `fortress` | `bastion` | `citadel` |
| 09 | `monday` | `tuesday` | `wednesday` |

The passwords are also shown in the **"How This Demo Works"** panel on the demo page itself.

---

## Running Tests

```bash
npm run test          # run all tests once (Vitest)
npm run test:watch    # watch mode
```

Test coverage:
- `src/crypto/__tests__/utils.test.ts` — base64 codec, byte helpers, text encode/decode
- `src/crypto/__tests__/shamir.test.ts` — GF(2⁸) Shamir split/reconstruct, threshold behaviour
- `src/crypto/__tests__/pipeline.test.ts` — full seal/open pipeline with mocked WASM modules

---

## Project Structure

```
web-demo/
├── index.html
├── vite.config.ts
├── vitest.config.ts
├── tsconfig.json
├── package.json
├── public/
│   ├── smaug.wasm          ← compiled SMAUG-T Level 1 (committed)
│   └── haetae.wasm         ← compiled HAETAE Mode 2 (committed)
└── src/
    ├── main.ts             ← entry point; awaits initCrypto() before vault init
    ├── crypto/
    │   ├── init.ts         ← parallel WASM module initialisation
    │   ├── smaug.ts        ← SMAUG-T Level 1 WASM wrapper
    │   ├── haetae.ts       ← HAETAE Mode 2 WASM wrapper
    │   ├── keywrap.ts      ← SMAUG-T KEM + PBKDF2 share wrapping
    │   ├── pipeline.ts     ← sealMessage / openBox orchestration
    │   ├── aes.ts          ← AES-256-GCM via Web Crypto API
    │   ├── shamir.ts       ← Shamir SSS over GF(2⁸)
    │   ├── utils.ts        ← base64, text codecs, byte helpers
    │   ├── signature.ts    ← re-export shim for haetae.ts
    │   └── wasm/
    │       ├── smaug.js    ← Emscripten JS loader (committed)
    │       ├── smaug.d.ts
    │       ├── haetae.js   ← Emscripten JS loader (committed)
    │       └── haetae.d.ts
    ├── vault/
    │   ├── demo.ts         ← generates demo boxes on first visit
    │   └── state.ts        ← localStorage persistence / serialisation
    └── ui/
        ├── wall.ts
        ├── panel.ts
        ├── pipeline-ui.ts
        ├── reveal.ts
        └── styles/vault.css
```

---

## Cryptographic Pipeline

### Seal (deposit)

```
AES-256-GCM  →  Shamir split  →  SMAUG-T wrap  →  HAETAE sign
```

1. **AES-256-GCM** — encrypt plaintext with a random 256-bit key
2. **Shamir split** — split the 32-byte AES key into 3 shares, threshold = 2
3. **SMAUG-T wrap** (×3) — fresh SMAUG-T keypair per participant; encapsulate share; seal SK with PBKDF2(password)
4. **HAETAE sign** — fresh signing keypair; sign the entire container serialisation

### Open (retrieve)

```
HAETAE verify  →  SMAUG-T unlock  →  Shamir reconstruct  →  AES-256-GCM
```

1. **HAETAE verify** — reject tampered containers immediately
2. **SMAUG-T unlock** (for each password) — PBKDF2 → decrypt SK → decapsulate → recover Shamir share
3. **Shamir reconstruct** — requires ≥ 2 valid shares; fewer → wrong bytes → AES auth fails
4. **AES-256-GCM** — decrypt ciphertext; wrong key → DOMException

---

## Building for Production

```bash
npm run build   # TypeScript type-check + Vite production build → dist/
```

Deployed to GitHub Pages via `.github/workflows/deploy-pages.yml`.

---

## WASM Modules

The `.wasm` binaries and Emscripten JS loaders are committed to the repository so that CI/CD does not require a C toolchain. To rebuild from the KpqC C reference sources:

```bash
# From the repository root:
bash wasm/build.sh
cp wasm/dist/smaug.js  web-demo/src/crypto/wasm/smaug.js
cp wasm/dist/haetae.js web-demo/src/crypto/wasm/haetae.js
cp wasm/dist/smaug.wasm  web-demo/public/smaug.wasm
cp wasm/dist/haetae.wasm web-demo/public/haetae.wasm
```

See `wasm/build.sh` for required Emscripten version and flags.

---

## License

MIT — see root [`LICENSE`](../LICENSE).
