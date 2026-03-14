// Deposit and retrieval panel forms with inline validation

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
  onCancel: () => void,
): void {
  panel.innerHTML = `
    <div class="panel-inner">
      <div class="panel-header">
        <h2 class="panel-title">Box ${boxNumber} — store a secret</h2>
        <button class="btn-cancel-x" aria-label="Close panel">✕</button>
      </div>
      <div class="form-group">
        <label for="deposit-message">Secret message</label>
        <textarea id="deposit-message" placeholder="Type your secret..." rows="3"></textarea>
        <div class="field-error" id="err-message"></div>
      </div>
      <div class="password-row">
        <div class="form-group">
          <label for="pw-alice">Alice's key</label>
          <input type="text" id="pw-alice" autocomplete="off" placeholder="alice's password" />
          <div class="field-error" id="err-alice"></div>
        </div>
        <div class="form-group">
          <label for="pw-bob">Bob's key</label>
          <input type="text" id="pw-bob" autocomplete="off" placeholder="bob's password" />
          <div class="field-error" id="err-bob"></div>
        </div>
        <div class="form-group">
          <label for="pw-carol">Carol's key</label>
          <input type="text" id="pw-carol" autocomplete="off" placeholder="carol's password" />
          <div class="field-error" id="err-carol"></div>
        </div>
      </div>
      <p class="panel-note">Any 2 of these 3 passwords will be needed to open this box.</p>
      <div id="pipeline-area"></div>
      <div class="form-actions">
        <button class="btn-primary" id="btn-seal">Seal deposit box</button>
        <button class="btn-outline" id="btn-cancel-deposit">Cancel</button>
      </div>
      <div id="deposit-result"></div>
    </div>
  `;

  openPanel(panel);

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
      (panel.querySelector('#err-message') as HTMLElement).textContent =
        'Message cannot be empty.';
      valid = false;
    }
    if (!alice || alice.length < 4) {
      (panel.querySelector('#err-alice') as HTMLElement).textContent = alice
        ? 'Min 4 characters.'
        : 'Required.';
      valid = false;
    }
    if (!bob || bob.length < 4) {
      (panel.querySelector('#err-bob') as HTMLElement).textContent = bob
        ? 'Min 4 characters.'
        : 'Required.';
      valid = false;
    }
    if (!carol || carol.length < 4) {
      (panel.querySelector('#err-carol') as HTMLElement).textContent = carol
        ? 'Min 4 characters.'
        : 'Required.';
      valid = false;
    }
    if (valid && (alice === bob || bob === carol || alice === carol)) {
      (panel.querySelector('#err-alice') as HTMLElement).textContent =
        'All 3 passwords must be different.';
      valid = false;
    }

    if (!valid) return;

    const btn = panel.querySelector<HTMLButtonElement>('#btn-seal')!;
    btn.disabled = true;
    btn.textContent = 'Sealing…';
    // Hide cancel while crypto runs
    (panel.querySelector<HTMLButtonElement>('#btn-cancel-deposit')!).disabled = true;

    await onSubmit({ message, passwords: [alice, bob, carol] });
  });
}

export function showRetrievePanel(
  panel: HTMLElement,
  boxNumber: string,
  onSubmit: (data: RetrieveFormData) => Promise<void>,
  onCancel: () => void,
): void {
  panel.innerHTML = `
    <div class="panel-inner">
      <div class="panel-header">
        <h2 class="panel-title" id="retrieve-title">Box ${boxNumber} — enter passwords to open</h2>
        <button class="btn-cancel-x" aria-label="Close panel">✕</button>
      </div>
      <p class="panel-note">Enter at least 2 of the 3 passwords to unlock this box.</p>
      <div class="password-row">
        <div class="form-group">
          <label for="rpw-alice">Alice's key</label>
          <input type="password" id="rpw-alice" autocomplete="off" placeholder="alice's password" />
        </div>
        <div class="form-group">
          <label for="rpw-bob">Bob's key</label>
          <input type="password" id="rpw-bob" autocomplete="off" placeholder="bob's password" />
        </div>
        <div class="form-group">
          <label for="rpw-carol">Carol's key</label>
          <input type="password" id="rpw-carol" autocomplete="off" placeholder="carol's password" />
        </div>
      </div>
      <div id="pipeline-area"></div>
      <div class="form-actions">
        <button class="btn-primary" id="btn-open">Open box</button>
        <button class="btn-outline" id="btn-cancel-retrieve">Cancel</button>
      </div>
      <div id="retrieve-result"></div>
    </div>
  `;

  openPanel(panel);

  panel.querySelector('.btn-cancel-x')!.addEventListener('click', onCancel);
  panel.querySelector('#btn-cancel-retrieve')!.addEventListener('click', onCancel);

  panel.querySelector('#btn-open')!.addEventListener('click', async () => {
    const aliceVal = panel.querySelector<HTMLInputElement>('#rpw-alice')!.value;
    const bobVal = panel.querySelector<HTMLInputElement>('#rpw-bob')!.value;
    const carolVal = panel.querySelector<HTMLInputElement>('#rpw-carol')!.value;

    const btn = panel.querySelector<HTMLButtonElement>('#btn-open')!;
    btn.disabled = true;
    btn.textContent = 'Opening…';
    const cancelBtn = panel.querySelector<HTMLButtonElement>('#btn-cancel-retrieve')!;
    cancelBtn.disabled = true;

    await onSubmit({
      passwords: [aliceVal || null, bobVal || null, carolVal || null],
    });

    // Re-enable for retry (success case: user may want to close; failure: allow retry)
    btn.disabled = false;
    btn.textContent = 'Open box';
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
    <div class="result-box result-success">
      Secret sealed in box ${boxNumber}. ✓
    </div>
  `;
}

export function openPanel(panel: HTMLElement): void {
  panel.classList.add('open');
}

export function closePanel(panel: HTMLElement): void {
  panel.classList.remove('open');
  // Clear content after transition
  setTimeout(() => {
    panel.innerHTML = '';
  }, 320);
}
