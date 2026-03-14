'use client';

import clsx from 'clsx';

interface Props {
  visible: boolean;
  valid: boolean;
}

/** Wax-seal overlay stamped on the container after signing. */
export default function VaultSeal({ visible, valid }: Props) {
  if (!visible) return null;

  return (
    <div
      className={clsx(
        'absolute -top-4 -right-4 w-16 h-16 rounded-full flex items-center justify-center',
        'text-3xl shadow-lg animate-seal-stamp select-none',
        valid
          ? 'bg-vault-gold border-4 border-yellow-600 shadow-yellow-900/60'
          : 'bg-red-700 border-4 border-red-900 shadow-red-900/60',
      )}
      title={valid ? 'Signature valid' : 'Signature invalid'}
    >
      {valid ? '🪙' : '💔'}
    </div>
  );
}
