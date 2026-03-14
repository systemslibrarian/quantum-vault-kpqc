// PBKDF2 key derivation + AES-GCM share wrapping (simulates SMAUG-T key encapsulation)
//
// Each Shamir share is wrapped with a password-derived key:
//   password  →  PBKDF2(SHA-256, 100 000 iter, random 16-byte salt)  →  AES-256-GCM key
//   AES-256-GCM key  →  encrypt(share bytes)  →  wrappedShare
//
// A wrong password derives a wrong key, which causes decrypt to throw DOMException.
// That throw is the mechanism by which incorrect passwords are rejected.

import { aesEncrypt, aesDecrypt } from './aes';
import { buf } from './utils';

export interface WrappedShare {
  salt: Uint8Array;       // 16-byte PBKDF2 salt (random per share)
  nonce: Uint8Array;      // 12-byte AES-GCM nonce
  ciphertext: Uint8Array; // encrypted share bytes + 16-byte auth tag
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: buf(salt),
      iterations: 100_000,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function wrapShare(
  shareData: Uint8Array,
  password: string,
): Promise<WrappedShare> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);
  const { ciphertext, nonce } = await aesEncrypt(shareData, key);
  return { salt, nonce, ciphertext };
}

export async function unwrapShare(
  wrapped: WrappedShare,
  password: string,
): Promise<Uint8Array> {
  // deriveKey uses the stored salt, so the same password always gives the same key.
  // A different password → different derived key → decrypt throws DOMException.
  const key = await deriveKey(password, wrapped.salt);
  return aesDecrypt(wrapped.ciphertext, wrapped.nonce, key);
}
