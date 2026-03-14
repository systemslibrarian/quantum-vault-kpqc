// Lightweight i18n — English (default) and Korean UI strings.
// Call setLang('ko') to switch language globally.
// Use t(key) anywhere in TypeScript for the current language.
// Static HTML elements use data-en / data-ko attributes, toggled by main.ts.

const strings: Record<string, { en: string; ko: string }> = {
  storeSecret:       { en: 'store a secret',           ko: '비밀 저장' },
  enterPasswords:    { en: 'enter passwords to open',  ko: '비밀번호로 열기' },
  secretMessage:     { en: 'Secret message',           ko: '비밀 메시지' },
  secretPlaceholder: { en: 'Type your secret…',        ko: '비밀을 입력하세요…' },
  aliceKey:          { en: "Alice's key",              ko: '앨리스 키' },
  bobKey:            { en: "Bob's key",                ko: '밥의 키' },
  carolKey:          { en: "Carol's key",              ko: '캐롤 키' },
  alicePh:           { en: "alice's password",         ko: '앨리스 비밀번호' },
  bobPh:             { en: "bob's password",           ko: '밥 비밀번호' },
  carolPh:           { en: "carol's password",         ko: '캐롤 비밀번호' },
  thresholdNote:     { en: 'Any 2 of these 3 passwords will unlock this box.',
                       ko: '이 3개 비밀번호 중 2개로 보관함을 열 수 있습니다.' },
  thresholdOpen:     { en: 'Enter at least 2 of the 3 passwords to unlock this box.',
                       ko: '3개 비밀번호 중 최소 2개를 입력하세요.' },
  sealBtn:           { en: 'Seal deposit box',         ko: '봉인하기' },
  openBtn:           { en: 'Open box',                 ko: '열기' },
  cancelBtn:         { en: 'Cancel',                   ko: '취소' },
  sealing:           { en: 'Sealing…',                 ko: '봉인 중…' },
  opening:           { en: 'Opening…',                 ko: '열기 중…' },
  msgEmpty:          { en: 'Message cannot be empty.', ko: '메시지를 입력하세요.' },
  minChars:          { en: 'Min 4 characters.',        ko: '최소 4자 이상.' },
  required:          { en: 'Required.',                ko: '필수 항목.' },
  allDiff:           { en: 'All 3 passwords must be different.',
                       ko: '3개의 비밀번호는 모두 달라야 합니다.' },
  sealedIn:          { en: 'Secret sealed in box',     ko: '봉인 완료 —보관함' },
  sealedCheck:       { en: '✓',                        ko: '✓' },
  decrypted:         { en: 'decrypted',                ko: '복호화 완료' },
  accessDenied:      { en: 'access denied',            ko: '접근 거부' },
  thresholdMet:      { en: 'of 3 passwords correct — threshold met — secret recovered',
                       ko: '/ 3개 중 임계값 충족 — 비밀 복원 완료' },
  accessDeniedMsg:   { en: 'ACCESS DENIED',            ko: '접근 거부' },
  needPasswords:     { en: 'need 2 of 3 passwords, only',
                       ko: '필요: 2개, 현재 유효:' },
  correct:           { en: 'correct',                  ko: '개' },
};

let _lang: 'en' | 'ko' = 'en';

export function setLang(lang: 'en' | 'ko'): void {
  _lang = lang;
}

export function getLang(): 'en' | 'ko' {
  return _lang;
}

export function t(key: string): string {
  return strings[key]?.[_lang] ?? strings[key]?.en ?? key;
}
