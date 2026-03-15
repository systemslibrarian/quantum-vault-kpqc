// SPDX-License-Identifier: MIT
// TypeScript wrapper for SMAUG-T Level 1 KEM compiled to WebAssembly.
// All WASM memory management is contained here — callers receive plain Uint8Arrays.

import type { SmaugModule, EmscriptenModuleFactory } from './wasm-types';

let smaugModule: SmaugModule | null = null;

export async function initSmaug(): Promise<void> {
  // Dynamic import of the Emscripten-generated JS loader.
  // Vite copies the .wasm file to public/ and the loader fetches it from there.
  const createModule = (await import('./wasm/smaug.js')).default as EmscriptenModuleFactory<SmaugModule>;
  smaugModule = await createModule({
    // Tell Emscripten where the .wasm file lives at runtime.
    locateFile: (path: string) => {
      const base = import.meta.env.BASE_URL ?? '/';
      return base.replace(/\/$/, '') + '/' + path;
    },
  });
}

/** Get the initialized module or throw. Returns narrowed type for TypeScript. */
function getModule(): SmaugModule {
  if (!smaugModule) throw new Error('SMAUG-T WASM not initialized — call initSmaug() first');
  return smaugModule;
}

/** Generate a SMAUG-T Level 1 keypair (PK: 672 B, SK: 832 B). */
export function smaugKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const m = getModule();
  const pkSize = m._smaug_publickeybytes();
  const skSize = m._smaug_secretkeybytes();
  const pkPtr = m._malloc(pkSize);
  const skPtr = m._malloc(skSize);
  try {
    const ret = m._smaug_keypair(pkPtr, skPtr);
    if (ret !== 0) throw new Error(`SMAUG-T keygen failed (ret=${ret})`);
    const publicKey = new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, pkPtr, pkSize).slice();
    const secretKey = new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, skPtr, skSize).slice();
    return { publicKey, secretKey };
  } finally {
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    m._smaug_secure_zeroize(pkPtr, pkSize);
    m._free(pkPtr);
    m._smaug_secure_zeroize(skPtr, skSize);
    m._free(skPtr);
  }
}

/**
 * Encapsulate: generate a shared secret and its ciphertext from a public key.
 * Returns: ciphertext (672 B) + sharedSecret (32 B).
 */
export function smaugEncapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  const m = getModule();
  const ctSize = m._smaug_ciphertextbytes();
  const ssSize = m._smaug_sharedsecretbytes();
  const pkSize = m._smaug_publickeybytes();
  if (publicKey.length !== pkSize) {
    throw new Error(`Invalid SMAUG-T public key length: ${publicKey.length} (expected ${pkSize})`);
  }
  const pkPtr = m._malloc(pkSize);
  const ctPtr = m._malloc(ctSize);
  const ssPtr = m._malloc(ssSize);
  try {
    m.HEAPU8.set(publicKey, pkPtr);
    const ret = m._smaug_encapsulate(ctPtr, ssPtr, pkPtr);
    if (ret !== 0) throw new Error(`SMAUG-T encapsulate failed (ret=${ret})`);
    return {
      ciphertext: new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, ctPtr, ctSize).slice(),
      sharedSecret: new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, ssPtr, ssSize).slice(),
    };
  } finally {
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    m._smaug_secure_zeroize(pkPtr, pkSize);
    m._free(pkPtr);
    m._free(ctPtr);
    m._smaug_secure_zeroize(ssPtr, ssSize);
    m._free(ssPtr);
  }
}

/**
 * Decapsulate: recover the shared secret from a KEM ciphertext and secret key.
 * Returns: sharedSecret (32 B). Different SK → different (wrong) shared secret.
 */
export function smaugDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const m = getModule();
  const ctExpected = m._smaug_ciphertextbytes();
  const skExpected = m._smaug_secretkeybytes();
  const ssSize = m._smaug_sharedsecretbytes();
  if (ciphertext.length !== ctExpected) {
    throw new Error(`Invalid SMAUG-T ciphertext length: ${ciphertext.length} (expected ${ctExpected})`);
  }
  if (secretKey.length !== skExpected) {
    throw new Error(`Invalid SMAUG-T secret key length: ${secretKey.length} (expected ${skExpected})`);
  }
  const ctPtr = m._malloc(ciphertext.length);
  const skPtr = m._malloc(secretKey.length);
  const ssPtr = m._malloc(ssSize);
  try {
    m.HEAPU8.set(ciphertext, ctPtr);
    m.HEAPU8.set(secretKey, skPtr);
    const ret = m._smaug_decapsulate(ssPtr, ctPtr, skPtr);
    if (ret !== 0) throw new Error(`SMAUG-T decapsulate failed (ret=${ret})`);
    return new Uint8Array(m.HEAPU8.buffer as ArrayBuffer, ssPtr, ssSize).slice();
  } finally {
    m._free(ctPtr);
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    m._smaug_secure_zeroize(skPtr, secretKey.length);
    m._free(skPtr);
    m._smaug_secure_zeroize(ssPtr, ssSize);
    m._free(ssPtr);
  }
}
