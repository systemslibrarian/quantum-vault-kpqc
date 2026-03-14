// HMAC-SHA-256 container signing (simulates HAETAE lattice signature)
import { buf } from './utils';
//
// The signing key is derived from the AES key bytes via SHA-256 with a
// domain separator, so it is bound to the specific encrypted container.

export async function signContainer(
  data: Uint8Array,
  keyMaterial: Uint8Array,
): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    buf(keyMaterial),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', hmacKey, buf(data));
  return new Uint8Array(sig);
}

export async function verifyContainer(
  data: Uint8Array,
  signature: Uint8Array,
  keyMaterial: Uint8Array,
): Promise<boolean> {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    buf(keyMaterial),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  return crypto.subtle.verify('HMAC', hmacKey, buf(signature), buf(data));
}
