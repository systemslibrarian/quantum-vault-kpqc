// Generate the three pre-loaded demo boxes using real crypto on first load.
// These are regenerated fresh each time (new random keys/nonces/salts),
// so the stored ciphertext is always different — but the passwords always work.

import { sealMessage } from '../crypto/pipeline';
import { serializeSealedBox } from './state';
import type { VaultState } from './state';

interface DemoBox {
  number: string;
  secret: string;
  passwords: [string, string, string];
}

const DEMO_BOXES: DemoBox[] = [
  {
    number: '03',
    secret: 'The treasure map is under the old oak tree',
    passwords: ['ruby', 'emerald', 'diamond'],
  },
  {
    number: '06',
    secret: 'Launch code: ALPHA-7749-ZULU',
    passwords: ['fortress', 'bastion', 'citadel'],
  },
  {
    number: '09',
    secret: 'The meeting is moved to Friday at noon',
    passwords: ['monday', 'tuesday', 'wednesday'],
  },
];

// Populates DEMO_BOXES entries that are not already in state.
// Runs real crypto (PBKDF2 × 3 per box), so the returned state contains
// genuinely encrypted data — not hard-coded or mocked values.
export async function generateDemoBoxes(state: VaultState): Promise<VaultState> {
  const newState: VaultState = { ...state, boxes: { ...state.boxes } };
  for (const demo of DEMO_BOXES) {
    if (!newState.boxes[demo.number]) {
      const sealed = await sealMessage(demo.secret, demo.passwords);
      newState.boxes[demo.number] = serializeSealedBox(sealed);
    }
  }
  return newState;
}
