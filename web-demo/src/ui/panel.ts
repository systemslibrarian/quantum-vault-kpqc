// Deposit and retrieval panel forms with inline validation

import { t } from '../i18n';
import { importQvault, QvaultImportError } from '../vault/file';
import type { SealedBox } from '../crypto/pipeline';

export interface DepositFormData {
  message: string;
  passwords: [string, string, string];
}

export interface RetrieveFormData {
  passwords: [string | null, string | null, string | null];
}

export function showDepositPanel(
  panel: HTMLElement,
  boxNumber: string,
  onSubmit: (data: DepositFormData) => Promise<void>,
  onImport: (box: SealedBox) => Promise<void>,
  onCancel: () => void,
): void {
  panel.innerHTML = `
    <div class="panel-inner">
      <div class="panel-header">
        <h2 class="panel-title">Box ${boxNumber} — ${t('storeSecret')}</h2>
        <button class="btn-cancel-x" aria-label="${t('cancelBtn')}">✕</button>
      </div>
      <div class="form-group">
        <label for="deposit-message">${t('secretMessage')}</label>
        <textarea id="deposit-message"
                  placeholder="${t('secretPlaceholder')}"
                  rows="3"
                  aria-required="true"
                  aria-describedby="err-message"
                  autocomplete="off"></textarea>
        <div class="field-error" id="err-message" role="alert" aria-live="assertive"></div>
      </div>
      <div class="password-row">
        <div class="form-group">
          <label for="pw-alice">${t('aliceKey')}</label>
          <input type="password" id="pw-alice"
                 autocomplete="new-password"
                 placeholder="${t('alicePh')}"
                 aria-required="true"
                 aria-describedby="err-alice" />
          <div class="field-error" id="err-alice" role="alert" aria-live="assertive"></div>
        </div>
        <div class="form-group">
          <label for="pw-bob">${t('bobKey')}</label>
          <input type="password" id="pw-bob"
                 autocomplete="new-password"
                 placeholder="${t('bobPh')}"
                 aria-required="true"
                 aria-describedby="err-bob" />
          <div class="field-error" id="err-bob" role="alert" aria-live="assertive"></div>
        </div>
        <div class="form-group">
          <label for="pw-carol">${t('carolKey')}</label>
          <input type="password" id="pw-carol"
                 autocomplete="new-password"
                 placeholder="${t('carolPh')}"
                 aria-required="true"
                 aria-describedby="err-carol" />
          <div class="field-error" id="err-carol" role="alert" aria-live="assertive"></div>
        </div>
      </div>
      <div class="show-password-toggle">
        <label>
          <input type="checkbox" id="show-pw-toggle" />
          ${t('showPasswords')}
        </label>
      </div>
      <p class="panel-note">${t('thresholdNote')}</p>
      <div id="pipeline-area"></div>
      <div class="form-actions">
        <button class="btn-primary" id="btn-seal">${t('sealBtn')}</button>
        <button class="btn-outline" id="btn-cancel-deposit">${t('cancelBtn')}</button>
      </div>
      <div id="deposit-result" aria-live="polite" aria-atomic="true"></div>
      <div class="import-section">
        <p class="import-divider">${t('importOrCreate')}</p>
        <label class="btn-outline btn-import" for="import-file">
          <input type="file" id="import-file" accept=".qvault,.json" hidden />
          ${t('importBtn')}
        </label>
        <div class="import-status" id="import-status" role="status" aria-live="polite"></div>
      </div>
    </div>
  `;

  openPanel(panel);

  // Password visibility toggle
  const pwToggle = panel.querySelector<HTMLInputElement>('#show-pw-toggle')!;
  pwToggle.addEventListener('change', () => {
    const type = pwToggle.checked ? 'text' : 'password';
    (['pw-alice', 'pw-bob', 'pw-carol']).forEach(id => {
      panel.querySelector<HTMLInputElement>(`#${id}`)!.type = type;
    });
  });

  // Import file handling
  const fileInput = panel.querySelector<HTMLInputElement>('#import-file')!;
  const importStatus = panel.querySelector<HTMLElement>('#import-status')!;
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file) return;

    importStatus.className = 'import-status';
    importStatus.textContent = t('importing');

    try {
      const box = await importQvault(file);
      importStatus.textContent = t('importSuccess');
      importStatus.classList.add('success');
      await onImport(box);
    } catch (err) {
      importStatus.classList.add('error');
      if (err instanceof QvaultImportError) {
        switch (err.code) {
          case 'INVALID_JSON':
            importStatus.textContent = t('importErrorJson');
            break;
          case 'UNSUPPORTED_VERSION':
            importStatus.textContent = t('importErrorVer');
            break;
          case 'MISSING_FIELD':
            importStatus.textContent = `${t('importErrorField')}: ${err.message}`;
            break;
          case 'INVALID_PARTICIPANTS':
            importStatus.textContent = t('importErrorPart');
            break;
          case 'CORRUPTED_DATA':
            importStatus.textContent = `${t('importErrorData')}: ${err.message}`;
            break;
          case 'UNSUPPORTED_ALGORITHM':
            importStatus.textContent = `${t('importErrorAlgo')}: ${err.message}`;
            break;
          case 'SIGNATURE_INVALID':
            importStatus.textContent = t('importErrorSig');
            break;
        }
      } else {
        importStatus.textContent = `${t('importErrorJson')}: ${String(err)}`;
      }
    }
    // Reset file input for re-selection
    fileInput.value = '';
  });
  // Move focus into the panel so keyboard/screen-reader users land on the first field
  setTimeout(() => {
    const first = panel.querySelector<HTMLElement>('textarea, input');
    first?.focus();
  }, 50);

  panel.querySelector('.btn-cancel-x')!.addEventListener('click', onCancel);
  panel.querySelector('#btn-cancel-deposit')!.addEventListener('click', onCancel);

  panel.querySelector('#btn-seal')!.addEventListener('click', async () => {
    const messageEl = panel.querySelector<HTMLTextAreaElement>('#deposit-message')!;
    const aliceEl = panel.querySelector<HTMLInputElement>('#pw-alice')!;
    const bobEl = panel.querySelector<HTMLInputElement>('#pw-bob')!;
    const carolEl = panel.querySelector<HTMLInputElement>('#pw-carol')!;

    const message = messageEl.value.trim();
    const alice = aliceEl.value.trim();
    const bob = bobEl.value.trim();
    const carol = carolEl.value.trim();

    // Clear previous errors
    (['err-message', 'err-alice', 'err-bob', 'err-carol'] as const).forEach(id => {
      (panel.querySelector(`#${id}`) as HTMLElement).textContent = '';
    });

    let valid = true;
    if (!message) {
      (panel.querySelector('#err-message') as HTMLElement).textContent = t('msgEmpty');
      valid = false;
    }
    if (!alice || alice.length < 4) {
      (panel.querySelector('#err-alice') as HTMLElement).textContent = alice
        ? t('minChars')
        : t('required');
      valid = false;
    }
    if (!bob || bob.length < 4) {
      (panel.querySelector('#err-bob') as HTMLElement).textContent = bob
        ? t('minChars')
        : t('required');
      valid = false;
    }
    if (!carol || carol.length < 4) {
      (panel.querySelector('#err-carol') as HTMLElement).textContent = carol
        ? t('minChars')
        : t('required');
      valid = false;
    }
    if (valid && (alice === bob || bob === carol || alice === carol)) {
      (panel.querySelector('#err-alice') as HTMLElement).textContent = t('allDiff');
      valid = false;
    }

    // Set aria-invalid on fields with errors
    (['message', 'alice', 'bob', 'carol'] as const).forEach(field => {
      const errId = `err-${field}`;
      const inputId = field === 'message' ? 'deposit-message' : `pw-${field}`;
      const hasError = !!(panel.querySelector(`#${errId}`) as HTMLElement).textContent;
      const inputEl = panel.querySelector<HTMLElement>(`#${inputId}`);
      if (inputEl) inputEl.setAttribute('aria-invalid', hasError ? 'true' : 'false');
    });

    if (!valid) return;

    const btn = panel.querySelector<HTMLButtonElement>('#btn-seal')!;
    btn.disabled = true;
    btn.textContent = t('sealing');
    (panel.querySelector<HTMLButtonElement>('#btn-cancel-deposit')!).disabled = true;

    await onSubmit({ message, passwords: [alice, bob, carol] });
  });
}

export function showRetrievePanel(
  panel: HTMLElement,
  boxNumber: string,
  onSubmit: (data: RetrieveFormData) => Promise<void>,
  onExport: () => void,
  onCancel: () => void,
): void {
  panel.innerHTML = `
    <div class="panel-inner">
      <div class="panel-header">
        <h2 class="panel-title" id="retrieve-title">Box ${boxNumber} — ${t('enterPasswords')}</h2>
        <button class="btn-cancel-x" aria-label="${t('cancelBtn')}">✕</button>
      </div>
      <div class="panel-actions-row">
        <button class="btn-outline btn-export" id="btn-export" type="button">
          <span class="export-icon">↓</span> ${t('exportBtn')}
        </button>
      </div>
      <p class="panel-note">${t('thresholdOpen')}</p>
      <div class="password-row">
        <div class="form-group">
          <label for="rpw-alice">${t('aliceKey')}</label>
          <input type="password" id="rpw-alice"
                 autocomplete="current-password"
                 placeholder="${t('alicePh')}" />
        </div>
        <div class="form-group">
          <label for="rpw-bob">${t('bobKey')}</label>
          <input type="password" id="rpw-bob"
                 autocomplete="current-password"
                 placeholder="${t('bobPh')}" />
        </div>
        <div class="form-group">
          <label for="rpw-carol">${t('carolKey')}</label>
          <input type="password" id="rpw-carol"
                 autocomplete="current-password"
                 placeholder="${t('carolPh')}" />
        </div>
      </div>
      <div class="show-password-toggle">
        <label>
          <input type="checkbox" id="show-rpw-toggle" />
          ${t('showPasswords')}
        </label>
      </div>
      <div id="pipeline-area"></div>
      <div class="form-actions">
        <button class="btn-primary" id="btn-open">${t('openBtn')}</button>
        <button class="btn-outline" id="btn-cancel-retrieve">${t('cancelBtn')}</button>
      </div>
      <div id="retrieve-result" aria-live="polite" aria-atomic="true"></div>
    </div>
  `;

  openPanel(panel);

  // Retrieve password visibility toggle
  const rpwToggle = panel.querySelector<HTMLInputElement>('#show-rpw-toggle')!;
  rpwToggle.addEventListener('change', () => {
    const type = rpwToggle.checked ? 'text' : 'password';
    (['rpw-alice', 'rpw-bob', 'rpw-carol']).forEach(id => {
      panel.querySelector<HTMLInputElement>(`#${id}`)!.type = type;
    });
  });

  // Move focus into the panel so keyboard/screen-reader users start at first password field
  setTimeout(() => {
    const first = panel.querySelector<HTMLElement>('input[type="password"]');
    first?.focus();
  }, 50);

  panel.querySelector('.btn-cancel-x')!.addEventListener('click', onCancel);
  panel.querySelector('#btn-cancel-retrieve')!.addEventListener('click', onCancel);
  panel.querySelector('#btn-export')!.addEventListener('click', onExport);

  panel.querySelector('#btn-open')!.addEventListener('click', async () => {
    const aliceVal = panel.querySelector<HTMLInputElement>('#rpw-alice')!.value.trim();
    const bobVal = panel.querySelector<HTMLInputElement>('#rpw-bob')!.value.trim();
    const carolVal = panel.querySelector<HTMLInputElement>('#rpw-carol')!.value.trim();

    const btn = panel.querySelector<HTMLButtonElement>('#btn-open')!;
    btn.disabled = true;
    btn.textContent = t('opening');
    const cancelBtn = panel.querySelector<HTMLButtonElement>('#btn-cancel-retrieve')!;
    cancelBtn.disabled = true;

    await onSubmit({
      passwords: [aliceVal || null, bobVal || null, carolVal || null],
    });

    // Re-enable for retry
    btn.disabled = false;
    btn.textContent = t('openBtn');
    cancelBtn.disabled = false;
  });
}

export function updateRetrieveTitle(panel: HTMLElement, title: string): void {
  const el = panel.querySelector<HTMLElement>('#retrieve-title');
  if (el) el.textContent = title;
}

export function showDepositSuccess(panel: HTMLElement, boxNumber: string): void {
  const resultEl = panel.querySelector<HTMLElement>('#deposit-result')!;
  resultEl.innerHTML = `
    <div class="result-box result-success" role="status">
      ${t('sealedIn')} ${boxNumber}. ${t('sealedCheck')}
    </div>
  `;
}

export function openPanel(panel: HTMLElement): void {
  panel.classList.add('open');
}

export function closePanel(panel: HTMLElement): void {
  // Clear sensitive content synchronously before the close animation begins.
  panel.innerHTML = '';
  panel.classList.remove('open');
}
