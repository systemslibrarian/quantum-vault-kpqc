// Shared types for the Quantum Vault web demo.

export type Suit = 'spades' | 'hearts' | 'diamonds' | 'clubs';
export type Rank =
  | 'A' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '10'
  | 'J' | 'Q' | 'K';

export interface PlayingCard {
  id: number;       // 0–51
  suit: Suit;
  rank: Rank;
}

/** State a card can be in during the demo. */
export type CardState =
  | 'face-up'      // visible, pre-encryption
  | 'face-down'    // encrypted
  | 'revealed';    // decrypted and restored

/** One Shamir share after KEM protection. */
export interface EncryptedShare {
  index: number;         // x-coordinate (1-based)
  kemCiphertext: Uint8Array;
  encryptedData: Uint8Array;
}

/** The in-memory vault container (parallel to Rust QuantumVaultContainer). */
export interface VaultContainer {
  version: number;
  threshold: number;
  shareCount: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;   // includes GCM auth tag
  shares: EncryptedShare[];
  signature: Uint8Array;
}

/** One participant who holds a KEM keypair and possibly a share. */
export interface Participant {
  id: number;
  name: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  shareIndex: number | null;   // null until shares are distributed
  selected: boolean;           // included in decryption attempt
}

/** Current phase of the demo UI. */
export type DemoPhase =
  | 'idle'          // cards face-up, ready to shuffle/encrypt
  | 'encrypting'    // animation in progress
  | 'encrypted'     // cards face-down, shares distributed
  | 'decrypting'    // animation in progress
  | 'decrypted'     // cards face-up again
  | 'failed';       // threshold not met
