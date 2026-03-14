# Quantum Vault — Web Demo

An interactive browser demo that visualises every layer of the Quantum Vault cryptographic stack using a shuffled deck of 52 playing cards as the payload.

> **Experimental.** This demo uses a mock backend for KEM and signature operations. It is not production-ready and should not be used to protect real data.

---

## Quick Start

```bash
# from the web-demo/ directory
npm install
npm run dev
# open http://localhost:3000
```

Tested with Node ≥ 18. All dependencies are installed locally — no global tooling required.

---

## Running Tests

```bash
npm run test          # run all tests once
npm run test:watch    # watch mode
```

The test suite uses **Vitest** + **@testing-library/react** + **jsdom**.

```
Test Files  2 passed (2)
     Tests  18 passed (18)
```

- `src/crypto/__tests__/mock-backend.test.ts` — 12 tests covering every crypto primitive (AES-GCM round-trip, GF(256) Shamir split/reconstruct, KEM, signatures)
- `src/components/__tests__/DeckOfCards.test.tsx` — 6 integration tests for the main UI component

---

## Project Structure

```
web-demo/
├── src/
│   ├── app/
│   │   ├── layout.tsx          Next.js root layout (dark theme, meta tags)
│   │   ├── page.tsx            Main demo page
│   │   └── globals.css         Tailwind + CSS custom properties
│   ├── components/
│   │   ├── DeckOfCards.tsx     Main interactive component — orchestrates the full pipeline
│   │   ├── PlayingCard.tsx     Single card with face-up/face-down flip animation
│   │   ├── ShareCard.tsx       Shamir share card with lock/unlock and selection state
│   │   ├── ContainerSeal.tsx   HAETAE signature seal (stamp animation, pass/fail glow)
│   │   ├── StepIndicator.tsx   Pipeline progress indicator
│   │   └── CryptoZoo.tsx       Algorithm showcase carousel
│   ├── crypto/
│   │   ├── types.ts            Shared TypeScript interfaces (CryptoBackend, Share, …)
│   │   ├── mock-backend.ts     Browser-native mock backend (real AES-GCM, real GF(256) Shamir)
│   │   └── index.ts            Active backend export — swap point for future WASM backend
│   ├── hooks/
│   │   └── useVault.ts         React hook encapsulating the vault state machine
│   ├── lib/
│   │   ├── cards.ts            Deck utilities: buildDeck, shuffleDeck, encode/decodePermutation
│   │   ├── shamir.ts           GF(256) Shamir Secret Sharing (legacy — superseded by mock-backend)
│   │   ├── types.ts            Container and vault types (legacy lib layer)
│   │   ├── vault.ts            TypeScript vault pipeline (encrypt/decrypt with real SubtleCrypto)
│   │   └── wasm-bridge.ts      Bridge between Rust WASM output and TypeScript types
│   └── test/
│       └── setup.ts            Vitest setup file (@testing-library/jest-dom matchers)
├── vitest.config.ts
├── package.json
└── README.md                   (this file)
```

---

## Architecture: Mock Backend → WASM Backend

The demo uses a **two-tier architecture** so the UI can be developed and tested independently of the Rust WASM build:

```
┌─────────────────────────────────────────────────────────┐
│                    Browser / Next.js                    │
│                                                         │
│  DeckOfCards.tsx ──► useVault hook ──► CryptoBackend    │
│                                              │          │
│                              ┌───────────────┤          │
│                              ▼               ▼          │
│                       MockBackend      WasmBackend      │
│                      (current)        (future swap)     │
│                              │               │          │
│                              ▼               ▼          │
│                   Web Crypto API      qv-core.wasm      │
│                   (real AES-GCM)      (SMAUG-T+HAETAE)  │
└─────────────────────────────────────────────────────────┘
```

### What the mock backend does for real

| Operation | Implementation |
|-----------|---------------|
| AES-256-GCM encrypt / decrypt | Real `SubtleCrypto.encrypt` / `decrypt` — no mocking |
| Shamir split / reconstruct | Real GF(256) polynomial arithmetic (Lagrange interpolation) |
| Key generation | `crypto.getRandomValues(new Uint8Array(32))` |

### What the mock backend simulates

| Operation | Simulation |
|-----------|-----------|
| KEM keypair | Random bytes of realistic size (PK=1088 B, SK=1312 B = SMAUG-T Level 3) |
| KEM encapsulate | Returns random CT (992 B) + SS (32 B); stores SS keyed by CT prefix |
| KEM decapsulate | Looks up the stored SS for the given CT |
| Signature keypair | Random bytes (VK=1472 B, SK=2112 B = HAETAE Level 3) |
| Sign | SHA-256(SK ‖ message) as a deterministic 64-byte mock signature |
| Verify | Re-derives SHA-256(SK ‖ message) and compares — round-trips correctly |

### Swapping in the WASM backend

1. Build the WASM package: `npm run wasm:build`
2. In [src/crypto/index.ts](src/crypto/index.ts), change the one import line:

```typescript
// Before (mock):
export { mockBackend as backend } from './mock-backend';

// After (WASM):
export { wasmBackend as backend } from './wasm-backend';
```

No other code changes are needed.

---

## Easter Egg

Type **`meow`** anywhere on the page to toggle cat mode — step labels get cat puns and share cards get cat names.

---

## Building for Production

```bash
npm run build    # Next.js production build
npm run start    # serve the production build
```

---

## WASM Build (optional)

Requires `wasm-pack` and the Rust toolchain:

```bash
# install wasm-pack if not present
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# build (from web-demo/ or workspace root)
npm run wasm:build        # release
npm run wasm:build:dev    # debug
```

The WASM package is output to `public/wasm-pkg/`.

---

## License

See root [`LICENSE`](../LICENSE). Experimental — not for production use.
