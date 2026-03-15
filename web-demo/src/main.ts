// Entry point: initialize vault, wire up all interactions

import './styles/vault.css';

import { initCrypto } from './crypto/init';
import { loadVaultState, saveVaultState, clearVaultState, emptyVaultState, serializeSealedBox, deserializeSealedBox } from './vault/state';
import type { VaultState } from './vault/state';
import { generateDemoBoxes } from './vault/demo';
import { sealMessage, openBox } from './crypto/pipeline';
import type { SealedBox } from './crypto/pipeline';
import { exportQvault, vaultBoxToSealedBox, exportFullVault, importFullVault, QvaultImportError } from './vault/file';
import { renderVaultWall } from './ui/wall';
import {
  showDepositPanel,
  showRetrievePanel,
  closePanel,
  showDepositSuccess,
  updateRetrieveTitle,
} from './ui/panel';
import { animateSealPipeline, animateOpenPipeline } from './ui/pipeline-ui';
import { revealMessage, showGibberish } from './ui/reveal';
import { sleep } from './crypto/utils';
import { setLang, t } from './i18n';

const initDiagnostics: string[] = [];

function recordInitStep(step: string): void {
  initDiagnostics.push(`[${new Date().toISOString()}] ${step}`);
  // Keep the diagnostics short enough to show on-screen without flooding.
  if (initDiagnostics.length > 40) initDiagnostics.shift();
}

function formatInitError(err: unknown): string {
  if (err instanceof Error) {
    if (err.stack) return err.stack;
    return `${err.name}: ${err.message}`;
  }
  return String(err);
}

async function init(): Promise<void> {
  recordInitStep('init:start');
  // Language toggle is wired up after renderWall is defined (so it can trigger re-render)

  // Load both KpqC WASM modules (SMAUG-T + HAETAE) before any vault operations
  const loaderEl = document.getElementById('wasm-loader');
  if (loaderEl) loaderEl.style.display = 'block';
  recordInitStep('crypto:init:start');
  await initCrypto();
  recordInitStep('crypto:init:done');
  if (loaderEl) loaderEl.style.display = 'none';

  let state: VaultState;

  recordInitStep('state:load:start');
  const existing = loadVaultState();
  if (existing) {
    recordInitStep('state:load:existing');
    state = existing;
  } else {
    recordInitStep('state:load:none');
    // First visit: generate real demo boxes and show hint.
    // If generation fails (e.g. stale cache/corrupt runtime), recover to empty state.
    try {
      recordInitStep('demo:generate:start');
      state = await generateDemoBoxes(emptyVaultState());
      saveVaultState(state);
      showHintBanner();
      recordInitStep('demo:generate:done');
    } catch (err) {
      console.error('Demo box generation failed, recovering with empty vault:', err);
      recordInitStep(`demo:generate:failed:${String(err)}`);
      clearVaultState();
      state = emptyVaultState();
      saveVaultState(state);
      recordInitStep('demo:recovery:empty-state');
    }
  }

  let selectedBox: string | null = null;

  const wallEl = document.getElementById('vault-wall')!;
  const panelEl = document.getElementById('panel')!;

  // ---- Render vault wall ----
  function renderWall(): void {
    renderVaultWall(wallEl, state.boxes, selectedBox, handleBoxClick);
  }

  // ---- Handle box click ----
  function handleBoxClick(boxNumber: string): void {
    if (selectedBox === boxNumber) {
      // Second click on same box — deselect and close
      selectedBox = null;
      closePanel(panelEl);
      renderWall();
      return;
    }

    selectedBox = boxNumber;
    renderWall();

    if (state.boxes[boxNumber]) {
      showRetrievePanel(
        panelEl,
        boxNumber,
        data => handleRetrieve(boxNumber, data.passwords),
        () => handleExport(boxNumber),
        () => { selectedBox = null; closePanel(panelEl); renderWall(); },
      );
    } else {
      showDepositPanel(
        panelEl,
        boxNumber,
        data => handleDeposit(boxNumber, data.message, data.passwords),
        box => handleImport(boxNumber, box),
        () => { selectedBox = null; closePanel(panelEl); renderWall(); },
      );
    }

    // Scroll panel into view smoothly
    setTimeout(() => {
      panelEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 50);
  }

  // ---- Seal a new secret ----
  async function handleDeposit(
    boxNumber: string,
    message: string,
    passwords: [string, string, string],
  ): Promise<void> {
    const pipelineArea = panelEl.querySelector<HTMLElement>('#pipeline-area')!;

    // Run crypto and animation concurrently — animation is purely cosmetic (2 s)
    // and crypto typically completes in ~4–6 s (3 × PBKDF2 600k iterations).
    const [sealedBox] = await Promise.all([
      sealMessage(message, passwords),
      animateSealPipeline(pipelineArea),
    ]);

    state.boxes[boxNumber] = serializeSealedBox(sealedBox);
    saveVaultState(state);

    showDepositSuccess(panelEl, boxNumber);
    renderWall();
  }

  // ---- Open an existing box ----
  async function handleRetrieve(
    boxNumber: string,
    passwords: [string | null, string | null, string | null],
  ): Promise<void> {
    const pipelineArea = panelEl.querySelector<HTMLElement>('#pipeline-area')!;
    const resultEl = panelEl.querySelector<HTMLElement>('#retrieve-result')!;

    const sealedBox = deserializeSealedBox(state.boxes[boxNumber]);

    // Run crypto first (determines pipeline animation outcome)
    const result = await openBox(sealedBox, passwords);

    // Animate pipeline based on known result
    await animateOpenPipeline(pipelineArea, !result.success);

    if (result.success) {
      updateRetrieveTitle(panelEl, `Box ${boxNumber} — ${t('decrypted')}`);

      const msgEl = document.createElement('div');
      msgEl.className = 'result-box result-success reveal-text';
      msgEl.setAttribute('aria-live', 'polite');
      resultEl.replaceChildren(msgEl);

      await revealMessage(msgEl, result.message);

      const infoEl = document.createElement('p');
      infoEl.className = 'result-info';
      infoEl.textContent = `${result.validShareCount} ${t('thresholdMet')}`;
      resultEl.appendChild(infoEl);
    } else {
      updateRetrieveTitle(panelEl, `Box ${boxNumber} — ${t('accessDenied')}`);

      const msgEl = document.createElement('div');
      msgEl.className = 'result-box result-failure reveal-text';
      msgEl.setAttribute('role', 'alert');
      resultEl.replaceChildren(msgEl);

      await showGibberish(msgEl, result.gibberish);
      msgEl.textContent = `${t('accessDeniedMsg')} — ${t('needPasswords')} ${result.validShareCount} ${t('correct')}`;

      // Pause so the user reads the denial, then reset inputs for retry
      await sleep(1500);

      panelEl.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach(
        inp => { inp.value = ''; },
      );
    }
  }
  // ---- Export a sealed container ----
  function handleExport(boxNumber: string): void {
    const vaultBox = state.boxes[boxNumber];
    if (!vaultBox) return;
    const sealedBox = vaultBoxToSealedBox(vaultBox);
    exportQvault(sealedBox, boxNumber);
  }

  // ---- Import a sealed container ----
  async function handleImport(boxNumber: string, box: SealedBox): Promise<void> {
    // Store the imported container (already verified by importQvault)
    state.boxes[boxNumber] = serializeSealedBox(box);
    saveVaultState(state);
    
    // Close deposit panel and show retrieve panel for the newly imported box
    closePanel(panelEl);
    renderWall();
    
    // Open retrieve panel so user can enter passwords
    setTimeout(() => {
      showRetrievePanel(
        panelEl,
        boxNumber,
        data => handleRetrieve(boxNumber, data.passwords),
        () => handleExport(boxNumber),
        () => { selectedBox = null; closePanel(panelEl); renderWall(); },
      );
      panelEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
  }
  // ---- Reset vault ----
  document.getElementById('btn-reset')?.addEventListener('click', async () => {
    if (!confirm('Reset vault? Your custom secrets will be permanently deleted. Demo boxes will be restored.')) {
      return;
    }
    clearVaultState();
    state = await generateDemoBoxes(emptyVaultState());
    saveVaultState(state);
    selectedBox = null;
    closePanel(panelEl);
    renderWall();
  });

  // ---- Export entire vault ----
  document.getElementById('btn-export-vault')?.addEventListener('click', () => {
    const boxCount = Object.keys(state.boxes).length;
    if (boxCount === 0) {
      alert('Vault is empty — nothing to export.');
      return;
    }
    exportFullVault(state);
  });

  // ---- Import entire vault ----
  document.getElementById('input-import-vault')?.addEventListener('change', async (e) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    if (!confirm('Import vault? This will replace all current boxes with the imported data.')) {
      input.value = '';
      return;
    }

    try {
      const imported = await importFullVault(file);
      state = imported;
      saveVaultState(state);
      selectedBox = null;
      closePanel(panelEl);
      renderWall();
      alert(`Vault imported successfully — ${Object.keys(state.boxes).length} box(es) loaded.`);
    } catch (err) {
      if (err instanceof QvaultImportError) {
        alert(`Import failed: ${err.message}`);
      } else {
        alert(`Import failed: ${String(err)}`);
      }
    } finally {
      input.value = '';
    }
  });

  // ---- Clear vault ----
  document.getElementById('btn-clear-vault')?.addEventListener('click', () => {
    if (Object.keys(state.boxes).length === 0) {
      alert('Vault is already empty.');
      return;
    }
    if (!confirm('Clear vault? All boxes will be permanently deleted. This cannot be undone.')) {
      return;
    }
    clearVaultState();
    state = emptyVaultState();
    saveVaultState(state);
    selectedBox = null;
    closePanel(panelEl);
    renderWall();
  });

  // Wire language toggle now that renderWall is in scope
  setupLangToggle(() => {
    // Close any open panel so it re-renders in the new language
    if (selectedBox) {
      const currentBox = selectedBox;
      selectedBox = null;
      closePanel(panelEl);
      renderWall();
      // Re-open the same box in the new language
      setTimeout(() => handleBoxClick(currentBox), 50);
    } else {
      renderWall();
    }
  });

  // Initial render
  recordInitStep('ui:render:start');
  renderWall();
  recordInitStep('init:done');
}

// ---- Language toggle ----
function setupLangToggle(onLangChange?: () => void): void {
  document.querySelectorAll<HTMLButtonElement>('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const lang = (btn.dataset.lang ?? 'en') as 'en' | 'ko';
      setLang(lang);
      // Update html[lang] for screen readers and OS language detection
      document.documentElement.lang = lang === 'ko' ? 'ko' : 'en';
      document.querySelectorAll<HTMLButtonElement>('.lang-btn').forEach(b => {
        const isActive = b.dataset.lang === lang;
        b.classList.toggle('active', isActive);
        b.setAttribute('aria-current', isActive ? 'true' : 'false');
        b.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      });
      document.querySelectorAll<HTMLElement>('[data-en]').forEach(el => {
        const translated = el.getAttribute(`data-${lang}`);
        if (translated !== null) el.textContent = translated;
      });
      // Toggle language-specific password tables
      document.querySelectorAll<HTMLElement>('[data-lang-table]').forEach(table => {
        table.style.display = table.dataset.langTable === lang ? '' : 'none';
      });
      onLangChange?.();
    });
  });
}

// ---- Dismissible hint banner ----
function showHintBanner(): void {
  const banner = document.getElementById('hint-banner');
  if (banner) banner.classList.add('visible');

  document.getElementById('btn-dismiss-hint')?.addEventListener('click', () => {
    const b = document.getElementById('hint-banner');
    if (b) b.classList.remove('visible');
  });
}

init().catch(err => {
  recordInitStep(`init:failed:${String(err)}`);
  console.error('Vault initialization failed:', err);
  const div = document.createElement('div');
  div.style.cssText = 'padding:2rem;color:#c00;font-family:monospace;';
  div.textContent = `Failed to initialize vault: ${String(err)}`;
  const note = document.createElement('p');
  note.textContent = 'Check that your browser supports Web Crypto API (requires HTTPS or localhost).';
  div.appendChild(note);

  const details = document.createElement('details');
  details.open = true;
  details.style.marginTop = '1rem';
  const summary = document.createElement('summary');
  summary.textContent = 'Startup diagnostics';
  details.appendChild(summary);

  const pre = document.createElement('pre');
  pre.style.whiteSpace = 'pre-wrap';
  pre.style.wordBreak = 'break-word';
  pre.textContent = [
    `URL: ${window.location.href}`,
    `User-Agent: ${navigator.userAgent}`,
    '',
    'Steps:',
    ...initDiagnostics,
    '',
    'Error:',
    formatInitError(err),
  ].join('\n');
  details.appendChild(pre);
  div.appendChild(details);

  document.body.replaceChildren(div);
});
