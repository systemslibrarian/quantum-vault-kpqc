'use client';

/**
 * WASM bridge for qv-core.
 *
 * Exports the same API as `vault.ts`.  When the compiled WASM package is
 * present in `public/wasm-pkg/` (built with wasm-pack) it is loaded
 * dynamically and used for all crypto operations.  If the package is missing
 * the module falls back to the pure-TypeScript implementation in `vault.ts`
 * transparently — no changes required in `useVault.ts` or anywhere else.
 *
 * ## Build the WASM module
 *
 * From the repo root:
 * ```sh
 * wasm-pack build crates/qv-core --target web --features wasm \
 *   --out-dir web-demo/public/wasm-pkg
 * ```
 *
 * Or use the helper script:
 * ```sh
 * cd web-demo && npm run wasm:build
 * ```
 *
 * ## Architecture
 *
 *   useVault.ts  →  wasm-bridge.ts  ──(WASM loaded)──▶  Rust qv-core WASM
 *                                   └─(WASM missing)─▶  vault.ts (TS fallback)
 */

import {
  encryptPayload as encryptPayloadTs,
  decryptPayload as decryptPayloadTs,
  kemGenerateKeypair as kemGenerateKeypairTs,
  sigGenerateKeypair as sigGenerateKeypairTs,
} from './vault';
import type { VaultContainer, Participant } from './types';

export type { KemKeyPair, SigKeyPair } from './vault';

// ── WASM module shape (mirrors exports from wasm.rs via wasm-bindgen) ─────────

interface QvWasm {
  qv_kem_generate_keypair: () => string;
  qv_sig_generate_keypair: () => string;
  /** Returns serialised QuantumVaultContainer JSON. */
  qv_encrypt: (
    plaintext: Uint8Array,
    kemPubkeysJson: string,
    threshold: number,
    sigPrivB64: string,
  ) => string;
  /** Returns decrypted plaintext bytes. */
  qv_decrypt: (
    containerJson: string,
    selectedPairsJson: string,
    sigPubB64: string,
  ) => Uint8Array;
}

// ── Singleton WASM loader ─────────────────────────────────────────────────────

let wasmMod: QvWasm | null = null;
let loadPromise: Promise<void> | null = null;

async function loadWasm(): Promise<void> {
  try {
    // Use a Function constructor so webpack cannot statically resolve the
    // specifier at build time.  The WASM package is served as a public
    // static asset (built with `npm run wasm:build` → web-demo/public/wasm-pkg/).
    // If the file does not exist the catch block fires silently and every
    // call falls back to the TypeScript implementation.
    const dynImport = new Function('s', 'return import(s)') as
      (s: string) => Promise<Record<string, unknown>>;
    const mod = await dynImport('/wasm-pkg/qv_core.js');
    // wasm-pack --target web generates an init() default export that fetches
    // and compiles the .wasm binary before any exported functions can be used.
    if (typeof mod.default === 'function') {
      await (mod.default as () => Promise<void>)();
    }
    wasmMod = mod as unknown as QvWasm;
    console.info('[qv] Rust WASM backend loaded');
  } catch {
    // Not a fatal error – the TS fallback handles everything.
    console.info('[qv] WASM module not found – using TypeScript fallback');
  }
}

// Kick off loading when the module is first imported (browser only).
if (typeof window !== 'undefined') {
  loadPromise = loadWasm();
}

/** Returns the WASM module after awaiting the initial load attempt. */
async function getWasm(): Promise<QvWasm | null> {
  if (loadPromise) await loadPromise;
  return wasmMod;
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

function toB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/**
 * Convert a Rust `QuantumVaultContainer` JSON string to the TypeScript
 * `VaultContainer` type.
 *
 * Differences handled here:
 * - Rust uses `share_count`, TS uses `shareCount`
 * - Rust share fields: `kem_ciphertext` / `encrypted_share`; TS: `kemCiphertext` / `encryptedData`
 * - Rust serialises `Vec<u8>` as a JSON array of numbers; TS uses `Uint8Array`
 * - `_wasmJson` is stored to allow lossless roundtrip back to `qv_decrypt`
 */
function rustContainerToTs(containerJson: string): VaultContainer {
  const p = JSON.parse(containerJson) as {
    version: number;
    threshold: number;
    share_count: number;
    nonce: number[];
    ciphertext: number[];
    shares: Array<{
      index: number;
      kem_ciphertext: number[];
      encrypted_share: number[];
    }>;
    signature: number[];
  };

  return {
    version: p.version,
    threshold: p.threshold,
    shareCount: p.share_count,
    nonce: new Uint8Array(p.nonce),
    ciphertext: new Uint8Array(p.ciphertext),
    shares: p.shares.map((s) => ({
      index: s.index,
      kemCiphertext: new Uint8Array(s.kem_ciphertext),
      encryptedData: new Uint8Array(s.encrypted_share),
    })),
    signature: new Uint8Array(p.signature),
    _wasmJson: containerJson,
  };
}

// ── Public API (identical signatures to vault.ts) ─────────────────────────────

export async function kemGenerateKeypair() {
  const w = await getWasm();
  if (w) {
    const kp = JSON.parse(w.qv_kem_generate_keypair()) as { pub: string; priv: string };
    return { publicKey: fromB64(kp.pub), privateKey: fromB64(kp.priv) };
  }
  return kemGenerateKeypairTs();
}

export async function sigGenerateKeypair() {
  const w = await getWasm();
  if (w) {
    const kp = JSON.parse(w.qv_sig_generate_keypair()) as { pub: string; priv: string };
    return { publicKey: fromB64(kp.pub), privateKey: fromB64(kp.priv) };
  }
  return sigGenerateKeypairTs();
}

export async function encryptPayload(
  plaintext: Uint8Array,
  participants: Participant[],
  threshold: number,
  signerPrivKey: Uint8Array,
): Promise<VaultContainer> {
  const w = await getWasm();
  if (w) {
    const kemPubKeysJson = JSON.stringify(participants.map((p) => toB64(p.publicKey)));
    const containerJson = w.qv_encrypt(plaintext, kemPubKeysJson, threshold, toB64(signerPrivKey));
    return rustContainerToTs(containerJson);
  }
  return encryptPayloadTs(plaintext, participants, threshold, signerPrivKey);
}

export async function decryptPayload(
  container: VaultContainer,
  selectedParticipants: Participant[],
  signerPubKey: Uint8Array,
): Promise<Uint8Array> {
  const w = await getWasm();
  const wasmJson = (container as VaultContainer & { _wasmJson?: string })._wasmJson;

  // Only delegate to WASM when the container was encrypted by the Rust backend
  // (identified by the _wasmJson field).  Mixed-backend roundtrips are not
  // supported; always fall back to the TS implementation otherwise.
  if (w && wasmJson) {
    const selectedPairs = selectedParticipants.map((p) => ({
      shareIndex: p.shareIndex,
      privKey: toB64(p.privateKey),
    }));
    return w.qv_decrypt(wasmJson, JSON.stringify(selectedPairs), toB64(signerPubKey));
  }

  return decryptPayloadTs(container, selectedParticipants, signerPubKey);
}
