'use client';

import { useVault } from '@/hooks/useVault';
import DeckGrid from '@/components/DeckGrid';
import ParticipantPanel from '@/components/ParticipantPanel';
import StepIndicator from '@/components/StepIndicator';
import VaultSeal from '@/components/VaultSeal';
import ThresholdControls from '@/components/ThresholdControls';
import clsx from 'clsx';

export default function Home() {
  const {
    deck,
    cardStates,
    phase,
    animating,
    participants,
    shareCount,
    threshold,
    statusMsg,
    sealValid,
    container,
    shuffle,
    encrypt,
    decrypt,
    toggleParticipant,
    setShareCount,
    setThreshold,
  } = useVault(3, 2);

  const canShuffle  = !animating && (phase === 'idle' || phase === 'decrypted' || phase === 'failed');
  const canEncrypt  = !animating && (phase === 'idle' || phase === 'decrypted');
  const canDecrypt  = !animating && phase === 'encrypted';

  return (
    <main className="flex flex-col items-center gap-8 px-4 py-10 max-w-3xl mx-auto">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-3xl font-bold tracking-tight">
          🔐 Quantum Vault
        </h1>
        <p className="text-vault-muted mt-1 text-sm">
          AES-256-GCM · Shamir Secret Sharing · Post-Quantum KEM (dev backend)
        </p>
      </div>

      {/* Step indicator */}
      <StepIndicator phase={phase} />

      {/* Status message */}
      <div
        className={clsx(
          'w-full rounded-lg px-4 py-3 text-sm',
          phase === 'failed'
            ? 'bg-red-900/40 border border-red-700 text-red-300'
            : 'bg-vault-card border border-gray-700 text-gray-300',
        )}
      >
        {statusMsg}
      </div>

      {/* Threshold controls */}
      <ThresholdControls
        threshold={threshold}
        shareCount={shareCount}
        onThresholdChange={setThreshold}
        onShareCountChange={setShareCount}
        disabled={phase !== 'idle'}
      />

      {/* Deck + seal */}
      <div className="relative w-full">
        <div
          className={clsx(
            'relative rounded-xl p-4 border transition-colors',
            phase === 'encrypted' || phase === 'encrypting'
              ? 'bg-vault-card border-purple-800'
              : 'bg-vault-card border-gray-700',
          )}
        >
          <DeckGrid deck={deck} cardStates={cardStates} animating={animating} />
        </div>
        <VaultSeal visible={phase === 'encrypted' || phase === 'decrypted'} valid={sealValid} />
      </div>

      {/* Participants */}
      {participants.length > 0 && (
        <div className="w-full">
          <ParticipantPanel
            participants={participants}
            phase={phase}
            onToggle={toggleParticipant}
          />
          {phase === 'encrypted' && (
            <p className="text-xs text-vault-muted mt-2">
              Click participants to select their shares. Need{' '}
              <span className="text-white font-semibold">{threshold}</span> of{' '}
              <span className="text-white font-semibold">{shareCount}</span>.{' '}
              Currently selected:{' '}
              <span
                className={clsx(
                  'font-semibold',
                  participants.filter((p) => p.selected).length >= threshold
                    ? 'text-green-400'
                    : 'text-yellow-400',
                )}
              >
                {participants.filter((p) => p.selected).length}
              </span>
            </p>
          )}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex gap-3 flex-wrap justify-center">
        <button
          disabled={!canShuffle}
          onClick={shuffle}
          className={clsx(
            'px-5 py-2 rounded-lg font-semibold text-sm transition-all',
            'border border-gray-600 bg-vault-card text-gray-300',
            'hover:border-gray-400 hover:text-white',
            'disabled:opacity-30 disabled:cursor-not-allowed',
          )}
        >
          🃏 Shuffle
        </button>

        <button
          disabled={!canEncrypt}
          onClick={encrypt}
          className={clsx(
            'px-5 py-2 rounded-lg font-semibold text-sm transition-all',
            'bg-vault-accent border border-purple-600 text-white shadow-lg shadow-purple-900/40',
            'hover:bg-purple-500',
            'disabled:opacity-30 disabled:cursor-not-allowed',
          )}
        >
          🔐 Encrypt
        </button>

        <button
          disabled={!canDecrypt}
          onClick={decrypt}
          className={clsx(
            'px-5 py-2 rounded-lg font-semibold text-sm transition-all',
            'bg-green-800 border border-green-600 text-white shadow-lg shadow-green-900/40',
            'hover:bg-green-700',
            'disabled:opacity-30 disabled:cursor-not-allowed',
          )}
        >
          🔓 Decrypt
        </button>
      </div>

      {/* Container info */}
      {container && (
        <div className="w-full rounded-lg bg-vault-card border border-gray-700 p-4 text-xs font-mono text-gray-400 space-y-1">
          <div className="text-gray-500 text-[10px] uppercase tracking-wider mb-2">Container info</div>
          <div><span className="text-gray-500">version:</span> {container.version}</div>
          <div><span className="text-gray-500">threshold:</span> {container.threshold} of {container.shareCount}</div>
          <div><span className="text-gray-500">nonce:</span> {Array.from(container.nonce).map(b => b.toString(16).padStart(2,'0')).join('')}</div>
          <div><span className="text-gray-500">ciphertext:</span> {container.ciphertext.length} bytes</div>
          <div><span className="text-gray-500">signature:</span> {Array.from(container.signature).map(b => b.toString(16).padStart(2,'0')).join('').slice(0, 32)}…</div>
        </div>
      )}

      {/* Footer */}
      <footer className="text-center text-xs text-vault-muted mt-4 space-y-1">
        <p>
          Crypto: AES-256-GCM (Web Crypto API) · Shamir SSS over GF(2⁸) ·
          Dev KEM stub (not production-secure)
        </p>
        <p>
          SMAUG-T + HAETAE WASM integration coming in a future release.
        </p>
        <p className="text-gray-700">
          © 2026 Paul Clark · MIT License
        </p>
      </footer>
    </main>
  );
}
