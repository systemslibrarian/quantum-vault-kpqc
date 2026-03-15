// SPDX-License-Identifier: MIT
// .qvault file serialization, export, and import with HAETAE verification.
//
// The .qvault format is JSON with base64-encoded binary fields, matching
// the VaultBox structure from state.ts for localStorage compatibility.

import { toBase64, fromBase64, encode } from '../crypto/utils';
import { haetaeVerify } from '../crypto/haetae';
import type { SealedBox, WrappedShare } from '../crypto/pipeline';
import type { VaultBox, VaultState, WrappedShareSerialized } from './state';

// Version identifier for the file format
const QVAULT_VERSION = 'qvault-v1';

// Algorithm identifiers for verification
const ALGORITHMS = {
  kem: 'smaug-t-level1',
  sig: 'haetae-mode2',
  symmetric: 'aes-256-gcm',
  kdf: 'pbkdf2-sha256',
} as const;

// Expected byte lengths for validation
const EXPECTED = {
  nonce: 12,
  salt: 16,
  kemCiphertext: 672,
  shareNonce: 12,
  publicKey: 672,
  skNonce: 12,
  sigPublicKey: 992,
  maxSignature: 1474,
  maxCiphertext: 64 * 1024 * 1024, // 64 MiB
} as const;

/**
 * File format for .qvault files.
 * This is a superset of VaultBox with version and algorithm metadata.
 */
export interface QvaultFile {
  version: string;
  algorithm: {
    kem: string;
    sig: string;
    symmetric: string;
    kdf: string;
  };
  ciphertext: string;
  nonce: string;
  participants: Array<{
    label: string;
    kemCiphertext: string;
    wrappedSecretKey: string;
    wrappedShare: string;
    pbkdf2Salt: string;
    kemPublicKey: string;
    shareNonce: string;
    skNonce: string;
    iterations: number;
  }>;
  signature: string;
  signaturePublicKey: string;
  createdAt: string;
}

const PARTICIPANT_LABELS = ['Alice', 'Bob', 'Carol'] as const;

/**
 * Serialize a SealedBox to a .qvault JSON string.
 * Uses a human-readable format with labeled participants.
 */
export function serializeToQvault(box: SealedBox): string {
  const file: QvaultFile = {
    version: QVAULT_VERSION,
    algorithm: { ...ALGORITHMS },
    ciphertext: toBase64(box.ciphertext),
    nonce: toBase64(box.nonce),
    participants: box.wrappedShares.map((ws, i) => ({
      label: PARTICIPANT_LABELS[i],
      kemCiphertext: toBase64(ws.kemCiphertext),
      wrappedSecretKey: toBase64(ws.wrappedSecretKey),
      wrappedShare: toBase64(ws.wrappedShare),
      pbkdf2Salt: toBase64(ws.salt),
      kemPublicKey: toBase64(ws.publicKey),
      shareNonce: toBase64(ws.shareNonce),
      skNonce: toBase64(ws.skNonce),
      iterations: ws.iterations,
    })),
    signature: toBase64(box.signature),
    signaturePublicKey: toBase64(box.sigPublicKey),
    createdAt: box.createdAt,
  };
  return JSON.stringify(file, null, 2);
}

/**
 * Error class for import validation failures.
 */
export class QvaultImportError extends Error {
  constructor(
    message: string,
    public readonly code:
      | 'INVALID_JSON'
      | 'UNSUPPORTED_VERSION'
      | 'MISSING_FIELD'
      | 'INVALID_PARTICIPANTS'
      | 'CORRUPTED_DATA'
      | 'UNSUPPORTED_ALGORITHM'
      | 'SIGNATURE_INVALID',
  ) {
    super(message);
    this.name = 'QvaultImportError';
  }
}

function assertField(obj: Record<string, unknown>, field: string): void {
  if (!(field in obj) || obj[field] === undefined || obj[field] === null) {
    throw new QvaultImportError(
      `Incomplete container — missing ${field}`,
      'MISSING_FIELD',
    );
  }
}

function decodeBase64Field(value: string, field: string): Uint8Array {
  try {
    return fromBase64(value);
  } catch {
    throw new QvaultImportError(
      `Corrupted data in ${field}`,
      'CORRUPTED_DATA',
    );
  }
}

function assertLen(arr: Uint8Array, expected: number, field: string): void {
  if (arr.length !== expected) {
    throw new QvaultImportError(
      `Corrupted data in ${field}: expected ${expected} bytes, got ${arr.length}`,
      'CORRUPTED_DATA',
    );
  }
}

function assertMaxLen(arr: Uint8Array, max: number, field: string): void {
  if (arr.length === 0 || arr.length > max) {
    throw new QvaultImportError(
      `Corrupted data in ${field}: length ${arr.length} out of range [1, ${max}]`,
      'CORRUPTED_DATA',
    );
  }
}

/**
 * Deserialize a .qvault JSON string to a SealedBox.
 * Performs comprehensive validation but does NOT verify the HAETAE signature.
 * Call verifyQvaultSignature() separately after deserialization.
 */
export function deserializeFromQvault(json: string): SealedBox {
  // 1. Parse JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new QvaultImportError('Invalid file format', 'INVALID_JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new QvaultImportError('Invalid file format', 'INVALID_JSON');
  }
  const obj = parsed as Record<string, unknown>;

  // 2. Check version
  assertField(obj, 'version');
  if (obj.version !== QVAULT_VERSION) {
    throw new QvaultImportError(
      `Unsupported vault format: ${obj.version}`,
      'UNSUPPORTED_VERSION',
    );
  }

  // 3. Check required fields
  assertField(obj, 'ciphertext');
  assertField(obj, 'nonce');
  assertField(obj, 'participants');
  assertField(obj, 'signature');
  assertField(obj, 'signaturePublicKey');
  assertField(obj, 'createdAt');

  // 4. Check participants array
  if (!Array.isArray(obj.participants) || obj.participants.length !== 3) {
    throw new QvaultImportError(
      'Invalid participant count',
      'INVALID_PARTICIPANTS',
    );
  }

  // 5. Check algorithm fields if present
  if (obj.algorithm && typeof obj.algorithm === 'object') {
    const alg = obj.algorithm as Record<string, unknown>;
    if (alg.kem && alg.kem !== ALGORITHMS.kem) {
      throw new QvaultImportError(
        `Unsupported algorithm: kem=${alg.kem}`,
        'UNSUPPORTED_ALGORITHM',
      );
    }
    if (alg.sig && alg.sig !== ALGORITHMS.sig) {
      throw new QvaultImportError(
        `Unsupported algorithm: sig=${alg.sig}`,
        'UNSUPPORTED_ALGORITHM',
      );
    }
  }

  // 6. Decode and validate binary fields
  const ciphertext = decodeBase64Field(obj.ciphertext as string, 'ciphertext');
  const nonce = decodeBase64Field(obj.nonce as string, 'nonce');
  const signature = decodeBase64Field(obj.signature as string, 'signature');
  const sigPublicKey = decodeBase64Field(
    obj.signaturePublicKey as string,
    'signaturePublicKey',
  );

  assertMaxLen(ciphertext, EXPECTED.maxCiphertext, 'ciphertext');
  assertLen(nonce, EXPECTED.nonce, 'nonce');
  assertLen(sigPublicKey, EXPECTED.sigPublicKey, 'signaturePublicKey');
  assertMaxLen(signature, EXPECTED.maxSignature, 'signature');

  // 7. Decode and validate participants
  const wrappedShares: WrappedShare[] = (
    obj.participants as Array<Record<string, unknown>>
  ).map((p, i) => {
    const prefix = `participants[${i}]`;

    assertField(p, 'kemCiphertext');
    assertField(p, 'wrappedSecretKey');
    assertField(p, 'wrappedShare');
    assertField(p, 'pbkdf2Salt');
    assertField(p, 'kemPublicKey');
    assertField(p, 'shareNonce');
    assertField(p, 'skNonce');

    const kemCiphertext = decodeBase64Field(
      p.kemCiphertext as string,
      `${prefix}.kemCiphertext`,
    );
    const wrappedSecretKey = decodeBase64Field(
      p.wrappedSecretKey as string,
      `${prefix}.wrappedSecretKey`,
    );
    const wrappedShare = decodeBase64Field(
      p.wrappedShare as string,
      `${prefix}.wrappedShare`,
    );
    const salt = decodeBase64Field(
      p.pbkdf2Salt as string,
      `${prefix}.pbkdf2Salt`,
    );
    const publicKey = decodeBase64Field(
      p.kemPublicKey as string,
      `${prefix}.kemPublicKey`,
    );
    const shareNonce = decodeBase64Field(
      p.shareNonce as string,
      `${prefix}.shareNonce`,
    );
    const skNonce = decodeBase64Field(p.skNonce as string, `${prefix}.skNonce`);

    assertLen(kemCiphertext, EXPECTED.kemCiphertext, `${prefix}.kemCiphertext`);
    assertLen(salt, EXPECTED.salt, `${prefix}.pbkdf2Salt`);
    assertLen(publicKey, EXPECTED.publicKey, `${prefix}.kemPublicKey`);
    assertLen(shareNonce, EXPECTED.shareNonce, `${prefix}.shareNonce`);
    assertLen(skNonce, EXPECTED.skNonce, `${prefix}.skNonce`);

    const iterations =
      typeof p.iterations === 'number' ? p.iterations : 100_000;

    return {
      salt,
      kemCiphertext,
      wrappedShare,
      shareNonce,
      publicKey,
      wrappedSecretKey,
      skNonce,
      iterations,
    };
  });

  return {
    ciphertext,
    nonce,
    wrappedShares,
    signature,
    sigPublicKey,
    createdAt: obj.createdAt as string,
  };
}

/**
 * Build the container data corpus for HAETAE signature verification.
 * Must match buildContainerData() in pipeline.ts exactly.
 */
function buildContainerData(box: SealedBox): Uint8Array {
  const corpus = {
    ciphertext: toBase64(box.ciphertext),
    createdAt: box.createdAt,
    nonce: toBase64(box.nonce),
    sigPublicKey: toBase64(box.sigPublicKey),
    wrappedShares: box.wrappedShares.map(ws => ({
      iterations: ws.iterations,
      kemCiphertext: toBase64(ws.kemCiphertext),
      publicKey: toBase64(ws.publicKey),
      salt: toBase64(ws.salt),
      shareNonce: toBase64(ws.shareNonce),
      skNonce: toBase64(ws.skNonce),
      wrappedSecretKey: toBase64(ws.wrappedSecretKey),
      wrappedShare: toBase64(ws.wrappedShare),
    })),
  };
  return encode(JSON.stringify(corpus));
}

/**
 * Verify the HAETAE signature on a deserialized container.
 * Returns true if valid, false if tampered.
 */
export function verifyQvaultSignature(box: SealedBox): boolean {
  const containerData = buildContainerData(box);
  return haetaeVerify(box.signature, containerData, box.sigPublicKey);
}

/**
 * Trigger a file download of the container as a .qvault file.
 */
export function exportQvault(box: SealedBox, boxNumber: string): void {
  const json = serializeToQvault(box);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vault-box-${boxNumber}.qvault`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Read and parse a .qvault file, with full validation and signature verification.
 * Throws QvaultImportError on any validation failure.
 */
export async function importQvault(file: File): Promise<SealedBox> {
  const text = await file.text();

  // Deserialize with structure validation
  const box = deserializeFromQvault(text);

  // Verify HAETAE signature — this is the critical tamper check
  const valid = verifyQvaultSignature(box);
  if (!valid) {
    throw new QvaultImportError(
      'Container signature invalid — file may be tampered',
      'SIGNATURE_INVALID',
    );
  }

  return box;
}

/**
 * Convert a VaultBox (localStorage format) to SealedBox for export.
 */
export function vaultBoxToSealedBox(vb: VaultBox): SealedBox {
  const wrappedShares: WrappedShare[] = vb.wrappedShares.map(
    (ws: WrappedShareSerialized) => ({
      salt: fromBase64(ws.salt),
      kemCiphertext: fromBase64(ws.kemCiphertext),
      wrappedShare: fromBase64(ws.wrappedShare),
      shareNonce: fromBase64(ws.shareNonce),
      publicKey: fromBase64(ws.publicKey),
      wrappedSecretKey: fromBase64(ws.wrappedSecretKey),
      skNonce: fromBase64(ws.skNonce),
      iterations: ws.iterations ?? 100_000,
    }),
  );

  return {
    ciphertext: fromBase64(vb.ciphertext),
    nonce: fromBase64(vb.nonce),
    wrappedShares,
    signature: fromBase64(vb.signature),
    sigPublicKey: fromBase64(vb.sigPublicKey),
    createdAt: vb.createdAt,
  };
}

// ---- Full vault export / import ----

const FULL_VAULT_VERSION = 'quantum-vault-v1';

interface FullVaultFile {
  version: string;
  exportedAt: string;
  boxes: Record<string, VaultBox>;
}

/**
 * Export the entire vault state as a downloadable .quantum-vault file.
 */
export function exportFullVault(state: VaultState): void {
  const file: FullVaultFile = {
    version: FULL_VAULT_VERSION,
    exportedAt: new Date().toISOString(),
    boxes: state.boxes,
  };
  const json = JSON.stringify(file, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `quantum-vault-${new Date().toISOString().slice(0, 10)}.quantum-vault`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Import a full vault from a .quantum-vault file.
 * Validates structure and verifies HAETAE signatures on all boxes.
 * Returns a new VaultState on success.
 */
export async function importFullVault(file: File): Promise<VaultState> {
  const text = await file.text();

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new QvaultImportError('Invalid file format', 'INVALID_JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new QvaultImportError('Invalid file format', 'INVALID_JSON');
  }
  const obj = parsed as Record<string, unknown>;

  if (obj.version !== FULL_VAULT_VERSION) {
    throw new QvaultImportError(
      `Unsupported vault format: ${String(obj.version)}`,
      'UNSUPPORTED_VERSION',
    );
  }

  if (typeof obj.boxes !== 'object' || obj.boxes === null) {
    throw new QvaultImportError('Missing boxes', 'MISSING_FIELD');
  }

  const rawBoxes = obj.boxes as Record<string, unknown>;
  const validatedBoxes: Record<string, VaultBox> = {};

  for (const [key, rawBox] of Object.entries(rawBoxes)) {
    // Validate box key is a two-digit string "01"-"09"
    if (!/^0[1-9]$/.test(key)) {
      throw new QvaultImportError(
        `Invalid box key: ${key}`,
        'CORRUPTED_DATA',
      );
    }

    const box = rawBox as VaultBox;

    // Basic structure check
    if (
      !box.ciphertext || !box.nonce || !box.signature ||
      !box.sigPublicKey || !box.createdAt ||
      !Array.isArray(box.wrappedShares) || box.wrappedShares.length !== 3
    ) {
      throw new QvaultImportError(
        `Incomplete container in box ${key}`,
        'MISSING_FIELD',
      );
    }

    // Verify HAETAE signature
    const sealedBox = vaultBoxToSealedBox(box);
    const containerData = buildContainerData(sealedBox);
    const valid = haetaeVerify(sealedBox.signature, containerData, sealedBox.sigPublicKey);
    if (!valid) {
      throw new QvaultImportError(
        `Signature invalid on box ${key} — file may be tampered`,
        'SIGNATURE_INVALID',
      );
    }

    validatedBoxes[key] = box;
  }

  return { boxes: validatedBoxes, version: 2 };
}
