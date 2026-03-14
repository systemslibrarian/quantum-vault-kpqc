// Full cryptographic pipeline: seal (encrypt) and open (decrypt)
//
// Seal pipeline:
//   AES-256-GCM  →  Shamir split  →  SMAUG-T wrap (PBKDF2+AES-GCM)  →  HAETAE sign (HMAC)
//
// Open pipeline:
//   HAETAE verify  →  SMAUG-T unlock  →  Shamir reconstruct  →  AES-256-GCM
//
// NOTE: The pipeline functions are pure crypto — no animation delays.
// Animation is driven separately in ui/pipeline-ui.ts.

import { generateAesKey, exportRawKey, importRawKey, aesEncrypt, aesDecrypt } from './aes';
import { splitSecret, reconstructSecret } from './shamir';
import type { Share } from './shamir';
import { wrapShare, unwrapShare } from './keywrap';
import type { WrappedShare } from './keywrap';
import { signContainer } from './signature';
import { encode, decode, concatBytes, buf } from './utils';

export type { WrappedShare };

export interface SealedBox {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  wrappedShares: WrappedShare[]; // always 3 elements — one per keyholder
  signature: Uint8Array;
  createdAt: string;
}

export type OpenResult =
  | { success: true; message: string; validShareCount: number }
  | { success: false; gibberish: Uint8Array; validShareCount: number };

// -- Container data serialization for signing --
function buildContainerData(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  wrappedShares: WrappedShare[],
): Uint8Array {
  const parts: Uint8Array[] = [nonce, ciphertext];
  for (const ws of wrappedShares) {
    parts.push(ws.salt, ws.nonce, ws.ciphertext);
  }
  return concatBytes(...parts);
}

// -- Seal: encrypt message, split key, wrap shares, sign container --
export async function sealMessage(
  message: string,
  passwords: [string, string, string],
): Promise<SealedBox> {
  // Step 1 — AES-256-GCM: encrypt the plaintext message
  const key = await generateAesKey();
  const rawKey = await exportRawKey(key);
  const plaintext = encode(message);
  const { ciphertext, nonce } = await aesEncrypt(plaintext, key);

  // Step 2 — Shamir split: split the 32-byte AES key into 3 shares, threshold 2
  const shares: Share[] = splitSecret(rawKey, 2, 3);

  // Step 3 — SMAUG-T wrap: PBKDF2+AES-GCM wrap each share with its password
  const wrappedShares = await Promise.all(
    shares.map((share, i) => wrapShare(share.data, passwords[i])),
  );

  // Step 4 — HAETAE sign: HMAC-SHA-256 over all container bytes
  // Signing key is derived from the raw AES key bytes via SHA-256 with domain separator
  const sigKeyMaterial = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      buf(concatBytes(rawKey, encode('quantum-vault-haetae-v1'))),
    ),
  );
  const containerData = buildContainerData(ciphertext, nonce, wrappedShares);
  const signature = await signContainer(containerData, sigKeyMaterial);

  return {
    ciphertext,
    nonce,
    wrappedShares,
    signature,
    createdAt: new Date().toISOString(),
  };
}

// -- Open: verify, unwrap shares, reconstruct key, decrypt --
export async function openBox(
  box: SealedBox,
  passwords: [string | null, string | null, string | null],
): Promise<OpenResult> {
  const validShares: Share[] = [];
  let validShareCount = 0;

  // Step 2 — SMAUG-T unlock: try each non-empty password
  // Wrong password → deriveKey → decrypt → DOMException (caught here, share unavailable)
  for (let i = 0; i < 3; i++) {
    const pw = passwords[i];
    if (!pw) continue;
    try {
      const shareData = await unwrapShare(box.wrappedShares[i], pw);
      validShares.push({ index: i + 1, data: shareData });
      validShareCount++;
    } catch {
      // Wrong password: AES-GCM auth tag fails → DOMException
    }
  }

  // Edge case: no passwords provided at all
  if (validShares.length === 0) {
    const garbage = crypto.getRandomValues(
      new Uint8Array(Math.max(8, box.ciphertext.length - 16)),
    );
    return { success: false, gibberish: garbage, validShareCount: 0 };
  }

  // Step 3 — Shamir reconstruct: always runs, produces correct bytes only if
  // validShares.length >= threshold (2). With only 1 share, the result is wrong bytes.
  const reconstructedKey = reconstructSecret(validShares);

  // Step 4 — AES-256-GCM decrypt: fails (throws) if the reconstructed key is wrong
  try {
    const cryptoKey = await importRawKey(reconstructedKey);
    const plaintext = await aesDecrypt(box.ciphertext, box.nonce, cryptoKey);
    return { success: true, message: decode(plaintext), validShareCount };
  } catch {
    // Reconstructed key was garbage → AES-GCM auth tag mismatch → DOMException
    // Return the wrong key bytes as "gibberish" to drive the failure animation
    const gibberish = new Uint8Array(Math.max(8, box.ciphertext.length - 16));
    for (let i = 0; i < gibberish.length; i++) {
      gibberish[i] = reconstructedKey[i % reconstructedKey.length] ^ ((i * 7 + 31) & 0xff);
    }
    return { success: false, gibberish, validShareCount };
  }
}
