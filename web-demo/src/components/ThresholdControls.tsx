'use client';

import clsx from 'clsx';

interface Props {
  threshold: number;
  shareCount: number;
  onThresholdChange: (n: number) => void;
  onShareCountChange: (n: number) => void;
  disabled: boolean;
}

export default function ThresholdControls({
  threshold,
  shareCount,
  onThresholdChange,
  onShareCountChange,
  disabled,
}: Props) {
  return (
    <div className="flex flex-wrap gap-6 items-center">
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-vault-muted">Participants (shares)</span>
        <input
          type="range"
          min={2}
          max={7}
          value={shareCount}
          disabled={disabled}
          onChange={(e) => {
            const n = Number(e.target.value);
            onShareCountChange(n);
            if (threshold > n) onThresholdChange(n);
          }}
          className="accent-purple-500"
        />
        <span className="text-center font-bold text-white">{shareCount}</span>
      </label>

      <label className="flex flex-col gap-1 text-sm">
        <span className="text-vault-muted">Threshold (min to decrypt)</span>
        <input
          type="range"
          min={2}
          max={shareCount}
          value={threshold}
          disabled={disabled}
          onChange={(e) => onThresholdChange(Number(e.target.value))}
          className="accent-purple-500"
        />
        <span className="text-center font-bold text-white">{threshold}</span>
      </label>

      <div className="text-sm text-vault-muted">
        <span className="text-white font-semibold">{threshold}</span>
        {' of '}
        <span className="text-white font-semibold">{shareCount}</span>
        {' participants needed'}
      </div>
    </div>
  );
}
