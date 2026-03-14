// Utility helpers: base64 encoding, text encoding, sleep

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export const encode = (str: string): Uint8Array => new TextEncoder().encode(str);

export const decode = (bytes: ArrayBuffer | Uint8Array): string =>
  new TextDecoder().decode(bytes);

export const sleep = (ms: number): Promise<void> =>
  new Promise(r => setTimeout(r, ms));

// Type assertion helper: casts a Uint8Array to the concrete ArrayBuffer-backed
// variant required by the WebCrypto API (TypeScript 5.5+ made Uint8Array generic;
// all arrays in this codebase are backed by plain ArrayBuffer, not SharedArrayBuffer).
export function buf(arr: Uint8Array): Uint8Array<ArrayBuffer> {
  return arr as unknown as Uint8Array<ArrayBuffer>;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
