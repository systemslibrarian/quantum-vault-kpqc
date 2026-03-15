// SPDX-License-Identifier: MIT
// TypeScript wrapper for HAETAE Mode 2 digital signatures compiled to WebAssembly.
// All WASM memory management is contained here — callers receive plain Uint8Arrays.

import type { HaetaeModule, EmscriptenModuleFactory } from './wasm-types';

let haetaeModule: HaetaeModule | null = null;

export async function initHaetae(): Promise<void> {
  const createModule = (await import('./wasm/haetae.js')).default as EmscriptenModuleFactory<HaetaeModule>;
  haetaeModule = await createModule({
    locateFile: (path: string) => {
      const base = import.meta.env.BASE_URL ?? '/';
      return base.replace(/\/$/, '') + '/' + path;
    },
  });
}

/** Get the initialized module or throw. Returns narrowed type for TypeScript. */
function getModule(): HaetaeModule {
  if (!haetaeModule) throw new Error('HAETAE WASM not initialized — call initHaetae() first');
  return haetaeModule;
}

/** Generate a HAETAE Mode 2 signing keypair (PK: 992 B, SK: 1408 B). */
export function haetaeKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const m = getModule();
  const pkSize = m._haetae_publickeybytes();
  const skSize = m._haetae_secretkeybytes();
  const pkPtr = m._malloc(pkSize);
  const skPtr = m._malloc(skSize);
  try {
    const ret = m._haetae_keypair(pkPtr, skPtr);
    if (ret !== 0) throw new Error(`HAETAE keygen failed (ret=${ret})`);
    return {
      publicKey: new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, pkPtr, pkSize).slice(),
      secretKey: new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, skPtr, skSize).slice(),
    };
  } finally {
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    m._haetae_secure_zeroize(pkPtr, pkSize);
    m._free(pkPtr);
    m._haetae_secure_zeroize(skPtr, skSize);
    m._free(skPtr);
  }
}

/**
 * Sign a message with HAETAE Mode 2.
 * Returns the actual signature bytes (up to 1474 B).
 */
export function haetaeSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const m = getModule();
  const maxSigSize = m._haetae_sigbytes();
  const msgPtr = m._malloc(message.length);
  const skPtr = m._malloc(secretKey.length);
  const sigPtr = m._malloc(maxSigSize);
  // size_t (4 bytes in wasm32) to hold the actual signature length
  const siglenPtr = m._malloc(8);
  try {
    m.HEAPU8.set(message, msgPtr);
    m.HEAPU8.set(secretKey, skPtr);
    const ret = m._haetae_sign(sigPtr, siglenPtr, msgPtr, message.length, skPtr);
    if (ret !== 0) throw new Error(`HAETAE sign failed (ret=${ret})`);
    // Read actual length as a 32-bit value (wasm32 size_t)
    const siglen = m.HEAPU32[siglenPtr >> 2];
    if (siglen === 0 || siglen > maxSigSize) {
      throw new Error(`HAETAE sign returned invalid signature length: ${siglen} (max ${maxSigSize})`);
    }
    return new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, sigPtr, siglen).slice();
  } finally {
    m._free(msgPtr);
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    m._haetae_secure_zeroize(skPtr, secretKey.length);
    m._free(skPtr);
    m._free(sigPtr);
    m._free(siglenPtr);
  }
}

/**
 * Verify a HAETAE Mode 2 signature.
 * Returns true if valid, false if invalid or tampered.
 */
export function haetaeVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  const m = getModule();
  const sigPtr = m._malloc(signature.length);
  const msgPtr = m._malloc(message.length);
  const pkPtr = m._malloc(publicKey.length);
  try {
    m.HEAPU8.set(signature, sigPtr);
    m.HEAPU8.set(message, msgPtr);
    m.HEAPU8.set(publicKey, pkPtr);
    const ret = m._haetae_verify(sigPtr, signature.length, msgPtr, message.length, pkPtr);
    return ret === 0;
  } finally {
    m._free(sigPtr);
    m._free(msgPtr);
    m._free(pkPtr);
  }
}
