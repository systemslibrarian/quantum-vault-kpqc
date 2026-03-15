// Entry point: initialize vault, wire up all interactions

import './styles/vault.css';

import { initCrypto } from './crypto/init';
import { loadVaultState, saveVaultState, clearVaultState, emptyVaultState, serializeSealedBox, deserializeSealedBox } from './vault/state';
import type { VaultState } from './vault/state';
import { generateDemoBoxes } from './vault/demo';
import { sealMessage, openBox } from './crypto/pipeline';
import type { SealedBox } from './crypto/pipeline';
import { exportQvault, vaultBoxToSealedBox } from './vault/file';
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

async function init(): Promise<void> {
  // Language toggle is wired up after renderWall is defined (so it can trigger re-render)

  // Load both KpqC WASM modules (SMAUG-T + HAETAE) before any vault operations
  const loaderEl = document.getElementById('wasm-loader');
  if (loaderEl) loaderEl.style.display = 'block';
  await initCrypto();
  if (loaderEl) loaderEl.style.display = 'none';

  let state: VaultState;

  const existing = loadVaultState();
  if (existing) {
    state = existing;
    // Fix: Ensure demo boxes exist if they were missing or failed to initialize
    state = await generateDemoBoxes(state);
    saveVaultState(state);
  } else {
    // First visit: generate real demo boxes and show hint
    state = await generateDemoBoxes(emptyVaultState());
    saveVaultState(state);
    showHintBanner();
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

  // Wire language toggle now that renderWall is in scope
  setupLangToggle(() => renderWall());

  // Initial render
  renderWall();
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
  console.error('Vault initialization failed:', err);
  const div = document.createElement('div');
  div.style.cssText = 'padding:2rem;color:#c00;font-family:monospace;';
  div.textContent = `Failed to initialize vault: ${String(err)}`;
  const note = document.createElement('p');
  note.textContent = 'Check that your browser supports Web Crypto API (requires HTTPS or localhost).';
  div.appendChild(note);
  document.body.replaceChildren(div);
});
