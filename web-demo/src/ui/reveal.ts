// Letter-by-letter message reveal and failure gibberish animation

import { sleep } from '../crypto/utils';

const SCRAMBLE_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&';

function randomChar(): string {
  return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
}

// Reveal `message` one character at a time with a brief scramble before each char.
// Spaces appear instantly; other characters flash 2 random frames (25 + 20 ms)
// before the real character settles (45 ms hold time per character).
export async function revealMessage(
  container: HTMLElement,
  message: string,
): Promise<void> {
  let revealed = '';
  for (let i = 0; i < message.length; i++) {
    if (message[i] === ' ') {
      revealed += ' ';
      container.textContent = revealed;
      continue;
    }
    container.textContent = revealed + randomChar();
    await sleep(25);
    container.textContent = revealed + randomChar();
    await sleep(20);
    revealed += message[i];
    container.textContent = revealed;
    await sleep(45);
  }
}

// Display rapidly cycling gibberish (from the actual wrong Shamir reconstruction
// bytes) before settling on the ACCESS DENIED message.
// wrongBytes come from pipeline.ts — they are the real incorrect bytes from
// Lagrange interpolation with insufficient shares, so they are genuinely random.
export async function showGibberish(
  container: HTMLElement,
  wrongBytes: Uint8Array,
): Promise<void> {
  const maxLen = Math.min(wrongBytes.length, 32);

  for (let cycle = 0; cycle < 4; cycle++) {
    const display = new Uint8Array(maxLen);
    for (let i = 0; i < maxLen; i++) {
      display[i] = (wrongBytes[i] ^ (cycle * 37 + i)) & 0xff;
    }
    container.textContent = Array.from(display)
      .map(b => SCRAMBLE_CHARS[b % SCRAMBLE_CHARS.length])
      .join('');
    await sleep(120);
  }
}
