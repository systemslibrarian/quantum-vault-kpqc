// Generate the three pre-loaded demo boxes using real crypto on first load.
// These are regenerated fresh each time (new random keys/nonces/salts),
// so the stored ciphertext is always different — but the passwords always work.
//
// Only 3 boxes are created per language (EN → 03/06/09, KO → 03/06/09).
// When the user switches language, the old demo boxes are swapped out for new ones.

import { sealMessage } from '../crypto/pipeline';
import { serializeSealedBox } from './state';
import type { VaultState } from './state';

interface DemoBox {
  number: string;
  secret: string;
  passwords: [string, string, string];
}

const EN_BOXES: DemoBox[] = [
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

const KO_BOXES: DemoBox[] = [
  {
    number: '03',
    secret: '보물 지도는 오래된 참나무 아래에 있다',
    passwords: ['무궁화', '태극기', '한라산'],
  },
  {
    number: '06',
    secret: '발사 코드: 가나다-7749-라마바',
    passwords: ['거북선', '첨성대', '석굴암'],
  },
  {
    number: '09',
    secret: '회의가 금요일 정오로 변경되었습니다',
    passwords: ['봄바람', '여름비', '가을달'],
  },
];

/** Box numbers used by each language's demo set. */
export const EN_DEMO_NUMBERS = EN_BOXES.map(b => b.number);
export const KO_DEMO_NUMBERS = KO_BOXES.map(b => b.number);

function boxesForLang(lang: 'en' | 'ko'): DemoBox[] {
  return lang === 'ko' ? KO_BOXES : EN_BOXES;
}

/** Return the demo box numbers for a given language. */
export function demoNumbersForLang(lang: 'en' | 'ko'): string[] {
  return lang === 'ko' ? KO_DEMO_NUMBERS : EN_DEMO_NUMBERS;
}

// ---- Demo-box tracker (localStorage) ----
// Tracks which boxes are currently demo-generated so we can safely remove
// them on language switch without accidentally deleting user data.
const DEMO_TRACKER_KEY = 'qv-demo-boxes';

export function getDemoTracker(): string[] {
  try {
    const raw = localStorage.getItem(DEMO_TRACKER_KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

export function setDemoTracker(numbers: string[]): void {
  try {
    localStorage.setItem(DEMO_TRACKER_KEY, JSON.stringify(numbers));
  } catch { /* ignore */ }
}

export function clearDemoTracker(): void {
  try {
    localStorage.removeItem(DEMO_TRACKER_KEY);
  } catch { /* ignore */ }
}

// Populates demo boxes for the given language that are not already in state.
// Runs real crypto (PBKDF2 × 3 per box), so the returned state contains
// genuinely encrypted data — not hard-coded or mocked values.
export async function generateDemoBoxes(
  state: VaultState,
  lang: 'en' | 'ko',
): Promise<VaultState> {
  const demos = boxesForLang(lang);
  const newState: VaultState = { ...state, boxes: { ...state.boxes } };
  const generated: string[] = [];
  for (const demo of demos) {
    if (!newState.boxes[demo.number]) {
      const sealed = await sealMessage(demo.secret, demo.passwords);
      newState.boxes[demo.number] = serializeSealedBox(sealed);
      generated.push(demo.number);
    }
  }
  // Merge with any previously tracked demo boxes that are still in state
  const prev = getDemoTracker().filter(n => !!newState.boxes[n]);
  setDemoTracker([...new Set([...prev, ...generated])]);
  return newState;
}

// Remove tracked demo boxes from state and return the cleaned state.
export function removeDemoBoxes(state: VaultState): VaultState {
  const tracked = getDemoTracker();
  if (tracked.length === 0) return state;
  const newState: VaultState = { ...state, boxes: { ...state.boxes } };
  for (const num of tracked) {
    delete newState.boxes[num];
  }
  setDemoTracker([]);
  return newState;
}
