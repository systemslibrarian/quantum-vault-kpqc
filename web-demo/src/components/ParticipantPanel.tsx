'use client';

import type { Participant } from '@/lib/types';
import clsx from 'clsx';

interface Props {
  participants: Participant[];
  phase: string;
  onToggle: (id: number) => void;
}

export default function ParticipantPanel({ participants, phase, onToggle }: Props) {
  const canToggle = phase === 'encrypted';

  return (
    <div className="flex flex-col gap-2">
      <h3 className="text-sm font-semibold text-vault-muted uppercase tracking-wider">
        Participants
      </h3>
      <div className="flex flex-wrap gap-2">
        {participants.map((p) => (
          <button
            key={p.id}
            disabled={!canToggle || p.shareIndex === null}
            onClick={() => onToggle(p.id)}
            className={clsx(
              'flex flex-col items-center gap-1 px-3 py-2 rounded-lg border transition-all text-sm',
              'disabled:opacity-40 disabled:cursor-not-allowed',
              p.selected && canToggle
                ? 'bg-vault-accent border-purple-500 text-white shadow-lg shadow-purple-900/40'
                : 'bg-vault-card border-gray-700 text-gray-300 hover:border-gray-500',
            )}
          >
            <span className="text-lg">
              {p.selected ? '🔓' : p.shareIndex !== null ? '🔒' : '👤'}
            </span>
            <span className="font-medium">{p.name}</span>
            {p.shareIndex !== null && (
              <span className="text-[10px] text-vault-muted">Share #{p.shareIndex}</span>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
