'use client';

import type { PlayingCard, CardState } from '@/lib/types';
import Card from './Card';

interface Props {
  deck: PlayingCard[];
  cardStates: CardState[];
  animating: boolean;
}

export default function DeckGrid({ deck, cardStates, animating }: Props) {
  return (
    <div className="flex flex-wrap gap-1 justify-center max-w-2xl mx-auto">
      {deck.map((card, i) => (
        <Card
          key={card.id}
          card={card}
          state={cardStates[i] ?? 'face-up'}
          delay={animating ? i * 18 : 0}
        />
      ))}
    </div>
  );
}
