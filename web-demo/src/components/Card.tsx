'use client';

import type { PlayingCard, CardState } from '@/lib/types';
import { suitSymbol, isRed } from '@/lib/cards';
import clsx from 'clsx';

interface Props {
  card: PlayingCard;
  state: CardState;
  delay?: number;   // animation stagger delay in ms
}

export default function Card({ card, state, delay = 0 }: Props) {
  const faceDown = state === 'face-down';
  const red = isRed(card.suit);

  return (
    <div
      className="relative w-9 h-14 sm:w-11 sm:h-16 select-none"
      style={{ perspective: '400px' }}
    >
      {/* Card flipper */}
      <div
        className={clsx(
          'absolute inset-0 transition-transform duration-500',
          faceDown && 'rotate-y-180',
        )}
        style={{
          transformStyle: 'preserve-3d',
          transitionDelay: `${delay}ms`,
        }}
      >
        {/* Face-up side */}
        <div
          className={clsx(
            'absolute inset-0 rounded backface-hidden flex flex-col items-center justify-between p-[2px]',
            'bg-white border border-gray-300 shadow-sm',
          )}
        >
          <span className={clsx('text-[10px] font-bold leading-none', red ? 'text-red-600' : 'text-gray-900')}>
            {card.rank}
          </span>
          <span className={clsx('text-base leading-none', red ? 'text-red-600' : 'text-gray-900')}>
            {suitSymbol(card.suit)}
          </span>
          <span className={clsx('text-[10px] font-bold leading-none rotate-180', red ? 'text-red-600' : 'text-gray-900')}>
            {card.rank}
          </span>
        </div>

        {/* Face-down side */}
        <div
          className="absolute inset-0 rounded backface-hidden bg-vault-accent border border-purple-800 shadow-sm"
          style={{ transform: 'rotateY(180deg)' }}
        >
          <div className="absolute inset-[3px] rounded border border-purple-600 opacity-40" />
          <div className="absolute inset-0 flex items-center justify-center text-purple-300 text-lg opacity-60">
            🔒
          </div>
        </div>
      </div>
    </div>
  );
}
