// SPDX-License-Identifier: MIT
// Lightweight i18n — English (default) and Korean UI strings.
// Call setLang('ko') to switch language globally.
// Use t(key) anywhere in TypeScript for the current language.
// Static HTML elements use data-en / data-ko attributes, toggled by main.ts.

const LOCALE_KEY = 'qv-locale';

const strings: Record<string, { en: string; ko: string }> = {
  storeSecret:       { en: 'store a secret',           ko: '비밀 저장' },
  enterPasswords:    { en: 'enter passwords to open',  ko: '비밀번호로 열기' },
  secretMessage:     { en: 'Secret message',           ko: '비밀 메시지' },
  secretPlaceholder: { en: 'Type your secret…',        ko: '비밀을 입력하세요…' },
  aliceKey:          { en: "Alice's key",              ko: 'Alice 키' },
  bobKey:            { en: "Bob's key",                ko: 'Bob 키' },
  carolKey:          { en: "Carol's key",              ko: 'Carol 키' },
  alicePh:           { en: "alice's password",         ko: 'Alice 비밀번호' },
  bobPh:             { en: "bob's password",           ko: 'Bob 비밀번호' },
  carolPh:           { en: "carol's password",         ko: 'Carol 비밀번호' },
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
  sealedIn:          { en: 'Secret sealed in box',     ko: '봉인 완료 — 보관함' },
  sealedCheck:       { en: '✓',                        ko: '✓' },
  decrypted:         { en: 'decrypted',                ko: '복호화 완료' },
  accessDenied:      { en: 'access denied',            ko: '접근 거부' },
  thresholdMet:      { en: 'of 3 passwords correct — threshold met — secret recovered',
                       ko: '/ 3개 중 임계값 충족 — 비밀 복원 완료' },
  accessDeniedMsg:   { en: 'ACCESS DENIED',            ko: '접근 거부' },
  needPasswords:     { en: 'need 2 of 3 passwords, only',
                       ko: '필요: 2개, 현재 유효:' },
  correct:           { en: 'correct',                  ko: '개' },
  occupied:          { en: 'occupied',                 ko: '사용 중' },
  empty:             { en: 'empty',                    ko: '비어 있음' },
  boxLabel:          { en: 'Box',                      ko: '보관함' },
  selectedLabel:     { en: 'selected',                 ko: '선택됨' },
  // Pipeline step labels
  pipeAes:           { en: 'AES-256-GCM',              ko: 'AES-256-GCM' },
  pipeShamirSplit:   { en: 'Shamir split',             ko: '샤미르 분할' },
  pipeSmaugWrap:     { en: 'SMAUG-T wrap',             ko: '스마우그-T 래핑' },
  pipeHaetaeSign:    { en: 'HAETAE sign',              ko: '해태 서명' },
  pipeHaetaeVerify:  { en: 'HAETAE verify',            ko: '해태 검증' },
  pipeSmaugUnlock:   { en: 'SMAUG-T unlock',           ko: '스마우그-T 해제' },
  pipeShamirRecon:   { en: 'Shamir reconstruct',       ko: '샤미르 복원' },
  // Footer
  footerCopyright:   { en: '© 2026 Paul Clark',        ko: '© 2026 Paul Clark' },
  footerLicense:     { en: 'MIT License',              ko: 'MIT 라이선스' },
  // Algorithm names (order swaps per locale)
  algoSmaug:         { en: 'SMAUG-T (스마우그-T)',     ko: '스마우그-T (SMAUG-T)' },
  algoHaetae:        { en: 'HAETAE (해태)',            ko: '해태 (HAETAE)' },
  // Tooltips
  haetaeTooltip:     { en: '해태 — mythical Korean guardian', ko: '해태 — 한국의 수호 신수' },
  // Toggle aria
  switchToKorean:    { en: 'Switch to Korean',         ko: '영어로 전환' },
  switchToEnglish:   { en: 'Switch to English',        ko: '영어로 전환' },
  // Export / Import
  exportBtn:         { en: 'Export .qvault',           ko: '.qvault 내보내기' },
  exportSuccess:     { en: 'File downloaded',          ko: '파일 다운로드 완료' },
  importBtn:         { en: 'Import .qvault',           ko: '.qvault 가져오기' },
  importOrCreate:    { en: 'or import an existing file',
                       ko: '또는 기존 파일 가져오기' },
  importing:         { en: 'Verifying…',               ko: '검증 중…' },
  importSuccess:     { en: 'Container loaded and verified',
                       ko: '컨테이너 로드 및 검증 완료' },
  importErrorJson:   { en: 'Invalid file format',      ko: '잘못된 파일 형식' },
  importErrorVer:    { en: 'Unsupported vault format', ko: '지원하지 않는 볼트 형식' },
  importErrorField:  { en: 'Incomplete container',     ko: '불완전한 컨테이너' },
  importErrorPart:   { en: 'Invalid participant count', ko: '잘못된 참여자 수' },
  importErrorData:   { en: 'Corrupted data',           ko: '손상된 데이터' },
  importErrorAlgo:   { en: 'Unsupported algorithm',    ko: '지원하지 않는 알고리즘' },
  importErrorSig:    { en: 'Container signature invalid — file may be tampered',
                       ko: '컨테이너 서명이 유효하지 않습니다 — 파일이 변조되었을 수 있습니다' },
  chooseFile:        { en: 'Choose .qvault file',      ko: '.qvault 파일 선택' },
};

let _lang: 'en' | 'ko' = 'en';

// Detect initial locale from localStorage or navigator.language
function detectInitialLocale(): 'en' | 'ko' {
  try {
    const stored = localStorage.getItem(LOCALE_KEY);
    if (stored === 'ko' || stored === 'en') return stored;
  } catch {
    // localStorage may be unavailable (private browsing, etc.)
  }
  // Auto-detect from browser language
  if (typeof navigator !== 'undefined' && navigator.language?.startsWith('ko')) {
    return 'ko';
  }
  return 'en';
}

// Initialize on module load
_lang = detectInitialLocale();

/**
 * Set the active UI language and persist to localStorage.
 * @param lang - The language code ('en' or 'ko')
 */
export function setLang(lang: 'en' | 'ko'): void {
  _lang = lang;
  try {
    localStorage.setItem(LOCALE_KEY, lang);
  } catch {
    // Ignore storage errors
  }
}

/**
 * Get the current UI language.
 * @returns The active language code
 */
export function getLang(): 'en' | 'ko' {
  return _lang;
}

/**
 * Translate a key to the current language.
 * Falls back to English, then to the key itself if not found.
 * @param key - The translation key (e.g., 'sealBtn', 'openBtn')
 * @returns The translated string
 */
export function t(key: string): string {
  return strings[key]?.[_lang] ?? strings[key]?.en ?? key;
}
