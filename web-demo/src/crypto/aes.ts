// AES-256-GCM encrypt/decrypt via Web Crypto API
import { buf } from './utils';

export interface AesEncryptResult {
  ciphertext: Uint8Array;
  nonce: Uint8Array; // 12-byte IV
}

export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,               // extractable (needed for Shamir splitting)
    ['encrypt', 'decrypt'],
  );
}

export async function exportRawKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
}

export async function importRawKey(rawBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    buf(rawBytes),
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
}

export async function aesEncrypt(
  plaintext: Uint8Array,
  key: CryptoKey,
): Promise<AesEncryptResult> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: buf(nonce) },
    key,
    buf(plaintext),
  );
  return { ciphertext: new Uint8Array(ciphertextBuffer), nonce };
}

export async function aesDecrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: CryptoKey,
): Promise<Uint8Array> {
  // Throws DOMException if key is wrong or data is tampered — this is intentional.
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf(nonce) },
    key,
    buf(ciphertext),
  );
  return new Uint8Array(plaintextBuffer);
}
