// Deck utilities — build and shuffle a standard 52-card deck.

import type { PlayingCard, Rank, Suit } from './types';

const SUITS: Suit[] = ['spades', 'hearts', 'diamonds', 'clubs'];
const RANKS: Rank[] = ['A','2','3','4','5','6','7','8','9','10','J','Q','K'];

/** Build a sorted 52-card deck (Ace of Spades first). */
export function buildDeck(): PlayingCard[] {
  const deck: PlayingCard[] = [];
  let id = 0;
  for (const suit of SUITS) {
    for (const rank of RANKS) {
      deck.push({ id: id++, suit, rank });
    }
  }
  return deck;
}

/** Fisher-Yates shuffle — returns a new array. */
export function shuffleDeck(deck: PlayingCard[]): PlayingCard[] {
  const d = [...deck];
  for (let i = d.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [d[i], d[j]] = [d[j], d[i]];
  }
  return d;
}

/** Encode a deck permutation as a Uint8Array (one byte per card id, 0–51). */
export function encodePermutation(deck: PlayingCard[]): Uint8Array {
  return new Uint8Array(deck.map((c) => c.id));
}

/** Decode a permutation Uint8Array back into a PlayingCard array. */
export function decodePermutation(
  perm: Uint8Array,
  reference: PlayingCard[],
): PlayingCard[] {
  return Array.from(perm).map((id) => reference[id]);
}

/** Human-readable suit symbol. */
export function suitSymbol(suit: Suit): string {
  return { spades: '♠', hearts: '♥', diamonds: '♦', clubs: '♣' }[suit];
}

/** True for red suits. */
export function isRed(suit: Suit): boolean {
  return suit === 'hearts' || suit === 'diamonds';
}
