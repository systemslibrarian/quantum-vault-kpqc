// Quantum Vault browser crypto pipeline.
//
// Uses:
//   - Web Crypto API (SubtleCrypto) for AES-256-GCM
//   - TypeScript Shamir SSS (shamir.ts) over GF(256)
//   - Dev KEM + signature stubs (mirrors Rust dev.rs backend)
//
// NOTE: The dev KEM/signature stubs are NOT cryptographically secure.
// They exist to make the full round-trip demonstrable in the browser
// until the WASM build of qv-core is integrated.

import { splitSecret, reconstructSecret, Share } from './shamir';
import type { VaultContainer, EncryptedShare, Participant } from './types';

// ── Utility: copy Uint8Array into a fresh ArrayBuffer for SubtleCrypto ────────
// TypeScript 5.8 tightened BufferSource to require ArrayBuffer (not ArrayBufferLike).

function toAB(u8: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(u8.byteLength);
  new Uint8Array(ab).set(u8);
  return ab;
}

// ── SHA-256 helper ────────────────────────────────────────────────────────────

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', toAB(data));
  return new Uint8Array(buf);
}

// ── Keystream (SHA-256 counter mode) — mirrors encrypt.rs xor_protect ────────

async function keystream(key: Uint8Array, length: number): Promise<Uint8Array> {
  const out = new Uint8Array(length);
  let offset = 0;
  let block = 0;
  while (offset < length) {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, block, true);
    const combined = new Uint8Array(key.length + 4);
    combined.set(key);
    combined.set(counter, key.length);
    const hash = await sha256(combined);
    const toCopy = Math.min(hash.length, length - offset);
    out.set(hash.subarray(0, toCopy), offset);
    offset += toCopy;
    block++;
  }
  return out;
}

async function xorProtect(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const ks = await keystream(key, data.length);
  return data.map((b, i) => b ^ ks[i]);
}

// ── Dev KEM stub (mirrors dev.rs) ────────────────────────────────────────────

export interface KemKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function kemGenerateKeypair(): Promise<KemKeyPair> {
  const privKey = crypto.getRandomValues(new Uint8Array(32));
  const pubKey = await sha256(privKey);
  return { publicKey: pubKey, privateKey: privKey };
}

async function kemEncapsulate(
  pubKey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
  const ss = crypto.getRandomValues(new Uint8Array(32));
  const ct = ss.map((b, i) => b ^ pubKey[i]);
  return { ciphertext: ct, sharedSecret: ss };
}

async function kemDecapsulate(
  privKey: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const pubKey = await sha256(privKey);
  return ciphertext.map((b, i) => b ^ pubKey[i]);
}

// ── Dev Signature stub (mirrors dev.rs) ──────────────────────────────────────

export interface SigKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function sigGenerateKeypair(): Promise<SigKeyPair> {
  const privKey = crypto.getRandomValues(new Uint8Array(32));
  const pubKey = await sha256(privKey);
  return { publicKey: pubKey, privateKey: privKey };
}

async function sign(privKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(privKey.length + message.length);
  combined.set(privKey);
  combined.set(message, privKey.length);
  return sha256(combined);
}

async function verify(
  pubKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const combined = new Uint8Array(pubKey.length + message.length);
  combined.set(pubKey);
  combined.set(message, pubKey.length);
  const expected = await sha256(combined);
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ signature[i];
  return diff === 0;
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

async function aesEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toAB(key), 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toAB(nonce) }, cryptoKey, toAB(plaintext));
  return new Uint8Array(ct);
}

async function aesDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toAB(key), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toAB(nonce) }, cryptoKey, toAB(ciphertext));
  return new Uint8Array(pt);
}

// ── Signing bytes (canonical representation, mirrors container_signing_bytes) ─

function canonicalBytes(c: Omit<VaultContainer, 'signature'>): Uint8Array {
  const obj = {
    version: c.version,
    threshold: c.threshold,
    shareCount: c.shareCount,
    nonce: Array.from(c.nonce),
    ciphertext: Array.from(c.ciphertext),
    shares: c.shares.map((s) => ({
      index: s.index,
      kemCiphertext: Array.from(s.kemCiphertext),
      encryptedData: Array.from(s.encryptedData),
    })),
  };
  return new TextEncoder().encode(JSON.stringify(obj));
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function encryptPayload(
  plaintext: Uint8Array,
  participants: Participant[],
  threshold: number,
  signerPrivKey: Uint8Array,
): Promise<VaultContainer> {
  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const nonce   = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await aesEncrypt(fileKey, nonce, plaintext);
  const rawShares  = splitSecret(fileKey, participants.length, threshold);

  const encShares: EncryptedShare[] = await Promise.all(
    rawShares.map(async (share, i) => {
      const { ciphertext: kemCt, sharedSecret } = await kemEncapsulate(
        participants[i].publicKey,
      );
      const encData = await xorProtect(share.data, sharedSecret);
      return { index: share.index, kemCiphertext: kemCt, encryptedData: encData };
    }),
  );

  const partial: Omit<VaultContainer, 'signature'> = {
    version: 1,
    threshold,
    shareCount: participants.length,
    nonce,
    ciphertext,
    shares: encShares,
  };

  const toSign = canonicalBytes(partial);
  const signature = await sign(signerPrivKey, toSign);

  return { ...partial, signature };
}

export async function decryptPayload(
  container: VaultContainer,
  selectedParticipants: Participant[],
  signerPubKey: Uint8Array,
): Promise<Uint8Array> {
  // Verify signature.
  const toSign = canonicalBytes(container);
  const valid = await verify(signerPubKey, toSign, container.signature);
  if (!valid) throw new Error('Container signature verification failed.');

  if (selectedParticipants.length < container.threshold) {
    throw new Error(
      `Need at least ${container.threshold} shares; only ${selectedParticipants.length} selected.`,
    );
  }

  // Recover shares.
  const shares: Share[] = await Promise.all(
    selectedParticipants.map(async (p) => {
      const encShare = container.shares.find((s) => s.index === p.shareIndex);
      if (!encShare) throw new Error(`No share found for participant ${p.name}`);
      const ss = await kemDecapsulate(p.privateKey, encShare.kemCiphertext);
      const data = await xorProtect(encShare.encryptedData, ss);
      return { index: encShare.index, data };
    }),
  );

  const fileKey = reconstructSecret(shares);
  return aesDecrypt(fileKey, container.nonce, container.ciphertext);
}
