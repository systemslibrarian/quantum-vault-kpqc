'use client';

import clsx from 'clsx';

const STEPS = [
  { id: 'idle',      label: 'Shuffle',     icon: '🃏' },
  { id: 'encrypting', label: 'Encrypting', icon: '⚙️'  },
  { id: 'encrypted', label: 'Encrypted',   icon: '🔐' },
  { id: 'decrypting', label: 'Decrypting', icon: '⚙️'  },
  { id: 'decrypted', label: 'Decrypted',   icon: '✅' },
  { id: 'failed',    label: 'Failed',      icon: '❌' },
];

interface Props {
  phase: string;
}

export default function StepIndicator({ phase }: Props) {
  const visible = STEPS.filter((s) => !['encrypting', 'decrypting'].includes(s.id));
  const active = ['encrypting', 'decrypting'].includes(phase) ? phase.replace('ing', 'ed') : phase;

  return (
    <div className="flex items-center gap-1 text-xs text-vault-muted">
      {visible.map((step, i) => (
        <span key={step.id} className="flex items-center gap-1">
          {i > 0 && <span className="text-gray-700">→</span>}
          <span
            className={clsx(
              'flex items-center gap-1 px-2 py-1 rounded',
              active === step.id
                ? 'bg-vault-accent text-white font-semibold'
                : 'text-vault-muted',
            )}
          >
            {step.icon} {step.label}
          </span>
        </span>
      ))}
      {['encrypting', 'decrypting'].includes(phase) && (
        <span className="ml-2 text-yellow-400 animate-pulse">⚙️ Processing…</span>
      )}
    </div>
  );
}
