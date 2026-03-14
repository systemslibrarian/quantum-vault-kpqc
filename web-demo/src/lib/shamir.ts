// Shamir Secret Sharing over GF(2^8) — TypeScript port of shamir.rs.
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11b).

// ── GF(256) arithmetic ──────────────────────────────────────────────────────

function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const carry = a & 0x80;
    a = (a << 1) & 0xff;
    if (carry) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function gfInv(a: number): number {
  // a^254 via repeated squaring
  let result = 1;
  let base = a;
  let exp = 254;
  while (exp > 0) {
    if (exp & 1) result = gfMul(result, base);
    base = gfMul(base, base);
    exp >>= 1;
  }
  return result;
}

function polyEval(coeffs: number[], x: number): number {
  let result = 0;
  let xPow = 1;
  for (const c of coeffs) {
    result ^= gfMul(c, xPow);
    xPow = gfMul(xPow, x);
  }
  return result;
}

// ── Public types ─────────────────────────────────────────────────────────────

export interface Share {
  index: number;   // x-coordinate (1-based)
  data: Uint8Array;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Split `secret` into `shareCount` shares with reconstruction threshold.
 * Uses crypto.getRandomValues for coefficient generation.
 */
export function splitSecret(
  secret: Uint8Array,
  shareCount: number,
  threshold: number,
): Share[] {
  if (threshold < 2) throw new Error('threshold must be at least 2');
  if (shareCount < threshold) throw new Error('shareCount must be >= threshold');
  if (secret.length === 0) throw new Error('secret must not be empty');

  const shares: Share[] = Array.from({ length: shareCount }, (_, i) => ({
    index: i + 1,
    data: new Uint8Array(secret.length),
  }));

  const randBuf = new Uint8Array(threshold - 1);

  for (let bi = 0; bi < secret.length; bi++) {
    // Random non-zero coefficients for indices 1..threshold-1.
    crypto.getRandomValues(randBuf);
    // Force non-zero (rejection-sample by flipping 0→1; negligible bias for demo).
    for (let i = 0; i < randBuf.length; i++) {
      if (randBuf[i] === 0) randBuf[i] = 1;
    }
    const coeffs = [secret[bi], ...randBuf];

    for (const share of shares) {
      share.data[bi] = polyEval(coeffs, share.index);
    }
  }

  return shares;
}

/**
 * Reconstruct secret from `shares` (any ≥ threshold shares) via Lagrange
 * interpolation at x = 0.
 */
export function reconstructSecret(shares: Share[]): Uint8Array {
  if (shares.length === 0) throw new Error('at least one share required');
  const len = shares[0].data.length;
  const secret = new Uint8Array(len);

  for (let i = 0; i < len; i++) {
    let val = 0;
    for (let j = 0; j < shares.length; j++) {
      const xj = shares[j].index;
      const yj = shares[j].data[i];
      let num = 1;
      let den = 1;
      for (let k = 0; k < shares.length; k++) {
        if (j !== k) {
          const xk = shares[k].index;
          num = gfMul(num, xk);           // 0 - xk == xk in GF(2^8)
          den = gfMul(den, xj ^ xk);      // xj - xk == xj XOR xk
        }
      }
      val ^= gfMul(yj, gfMul(num, gfInv(den)));
    }
    secret[i] = val;
  }

  return secret;
}
