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
  // English demo boxes
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
  // Korean demo boxes (한국어 데모 보관함)
  {
    number: '01',
    secret: '보물 지도는 오래된 참나무 아래에 있다',
    passwords: ['무궁화', '태극기', '한라산'],
  },
  {
    number: '04',
    secret: '발사 코드: 가나다-7749-라마바',
    passwords: ['거북선', '첨성대', '석굴암'],
  },
  {
    number: '07',
    secret: '회의가 금요일 정오로 변경되었습니다',
    passwords: ['봄바람', '여름비', '가을달'],
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
