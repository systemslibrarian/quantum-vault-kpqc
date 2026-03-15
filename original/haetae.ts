// TypeScript wrapper for HAETAE Mode 2 digital signatures compiled to WebAssembly.
// All WASM memory management is contained here — callers receive plain Uint8Arrays.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let haetaeModule: any = null;

export async function initHaetae(): Promise<void> {
  const createModule = (await import('./wasm/haetae.js')).default;
  haetaeModule = await createModule({
    locateFile: (path: string) => {
      const base = import.meta.env.BASE_URL ?? '/';
      return base.replace(/\/$/, '') + '/' + path;
    },
  });
}

function assertReady(): void {
  if (!haetaeModule) throw new Error('HAETAE WASM not initialized — call initHaetae() first');
}

/** Generate a HAETAE Mode 2 signing keypair (PK: 992 B, SK: 1408 B). */
export function haetaeKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  assertReady();
  const pkSize = haetaeModule._haetae_publickeybytes() as number;
  const skSize = haetaeModule._haetae_secretkeybytes() as number;
  const pkPtr = haetaeModule._malloc(pkSize) as number;
  const skPtr = haetaeModule._malloc(skSize) as number;
  try {
    const ret = haetaeModule._haetae_keypair(pkPtr, skPtr) as number;
    if (ret !== 0) throw new Error(`HAETAE keygen failed (ret=${ret})`);
    return {
      publicKey: new Uint8Array(haetaeModule.HEAPU8.buffer as ArrayBuffer, pkPtr, pkSize).slice(),
      secretKey: new Uint8Array(haetaeModule.HEAPU8.buffer as ArrayBuffer, skPtr, skSize).slice(),
    };
  } finally {
    haetaeModule._free(pkPtr);
    haetaeModule._free(skPtr);
  }
}

/**
 * Sign a message with HAETAE Mode 2.
 * Returns the actual signature bytes (up to 1474 B).
 */
export function haetaeSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  assertReady();
  const maxSigSize = haetaeModule._haetae_sigbytes() as number;
  const msgPtr = haetaeModule._malloc(message.length) as number;
  const skPtr = haetaeModule._malloc(secretKey.length) as number;
  const sigPtr = haetaeModule._malloc(maxSigSize) as number;
  // size_t (4 bytes in wasm32) to hold the actual signature length
  const siglenPtr = haetaeModule._malloc(8) as number;
  try {
    haetaeModule.HEAPU8.set(message, msgPtr);
    haetaeModule.HEAPU8.set(secretKey, skPtr);
    const ret = haetaeModule._haetae_sign(sigPtr, siglenPtr, msgPtr, message.length, skPtr) as number;
    if (ret !== 0) throw new Error(`HAETAE sign failed (ret=${ret})`);
    // Read actual length as a 32-bit value (wasm32 size_t)
    const siglen = haetaeModule.HEAPU32[siglenPtr >> 2] as number;
    return new Uint8Array(haetaeModule.HEAPU8.buffer as ArrayBuffer, sigPtr, siglen).slice();
  } finally {
    haetaeModule._free(msgPtr);
    haetaeModule._free(skPtr);
    haetaeModule._free(sigPtr);
    haetaeModule._free(siglenPtr);
  }
}

/**
 * Verify a HAETAE Mode 2 signature.
 * Returns true if valid, false if invalid or tampered.
 */
export function haetaeVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  assertReady();
  const sigPtr = haetaeModule._malloc(signature.length) as number;
  const msgPtr = haetaeModule._malloc(message.length) as number;
  const pkPtr = haetaeModule._malloc(publicKey.length) as number;
  try {
    haetaeModule.HEAPU8.set(signature, sigPtr);
    haetaeModule.HEAPU8.set(message, msgPtr);
    haetaeModule.HEAPU8.set(publicKey, pkPtr);
    const ret = haetaeModule._haetae_verify(sigPtr, signature.length, msgPtr, message.length, pkPtr) as number;
    return ret === 0;
  } finally {
    haetaeModule._free(sigPtr);
    haetaeModule._free(msgPtr);
    haetaeModule._free(pkPtr);
  }
}
