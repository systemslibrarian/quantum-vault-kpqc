// Vault state: types, localStorage persistence, serialization helpers

import { toBase64, fromBase64 } from '../crypto/utils';
import type { SealedBox, WrappedShare } from '../crypto/pipeline';

export interface WrappedShareSerialized {
  salt: string;       // base64 (16 bytes)
  nonce: string;      // base64 (12 bytes)
  ciphertext: string; // base64
}

export interface VaultBox {
  ciphertext: string;                       // base64
  nonce: string;                            // base64 (12 bytes)
  wrappedShares: WrappedShareSerialized[];  // always 3 elements
  signature: string;                        // base64
  createdAt: string;                        // ISO timestamp
}

export interface VaultState {
  boxes: Record<string, VaultBox>; // keys: "01" – "12"
  version: number;                 // format version, currently 1
}

const STORAGE_KEY = 'quantum-vault-data';

export function loadVaultState(): VaultState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'boxes' in parsed &&
      'version' in parsed &&
      (parsed as VaultState).version === 1
    ) {
      return parsed as VaultState;
    }
    return null;
  } catch {
    return null;
  }
}

export function saveVaultState(state: VaultState): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

export function clearVaultState(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function emptyVaultState(): VaultState {
  return { boxes: {}, version: 1 };
}

export function serializeSealedBox(box: SealedBox): VaultBox {
  return {
    ciphertext: toBase64(box.ciphertext),
    nonce: toBase64(box.nonce),
    wrappedShares: box.wrappedShares.map((ws: WrappedShare) => ({
      salt: toBase64(ws.salt),
      nonce: toBase64(ws.nonce),
      ciphertext: toBase64(ws.ciphertext),
    })),
    signature: toBase64(box.signature),
    createdAt: box.createdAt,
  };
}

export function deserializeSealedBox(vb: VaultBox): SealedBox {
  return {
    ciphertext: fromBase64(vb.ciphertext),
    nonce: fromBase64(vb.nonce),
    wrappedShares: vb.wrappedShares.map(ws => ({
      salt: fromBase64(ws.salt),
      nonce: fromBase64(ws.nonce),
      ciphertext: fromBase64(ws.ciphertext),
    })),
    signature: fromBase64(vb.signature),
    createdAt: vb.createdAt,
  };
}
