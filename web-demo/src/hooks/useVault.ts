'use client';

import { useState, useCallback } from 'react';
import { buildDeck, shuffleDeck, encodePermutation, decodePermutation } from '@/lib/cards';
import {
  kemGenerateKeypair,
  sigGenerateKeypair,
  encryptPayload,
  decryptPayload,
} from '@/lib/wasm-bridge';
import type {
  PlayingCard,
  CardState,
  DemoPhase,
  Participant,
  VaultContainer,
} from '@/lib/types';

const NAMES = ['Alice', 'Bob', 'Carol', 'Dave', 'Eve', 'Frank', 'Grace'];
const REFERENCE_DECK = buildDeck();

export function useVault(initialShareCount = 3, initialThreshold = 2) {
  const [deck, setDeck]               = useState<PlayingCard[]>(shuffleDeck(REFERENCE_DECK));
  const [cardStates, setCardStates]   = useState<CardState[]>(Array(52).fill('face-up'));
  const [phase, setPhase]             = useState<DemoPhase>('idle');
  const [animating, setAnimating]     = useState(false);
  const [participants, setParticipants] = useState<Participant[]>([]);
  const [container, setContainer]     = useState<VaultContainer | null>(null);
  const [signerKeys, setSignerKeys]   = useState<{ pub: Uint8Array; priv: Uint8Array } | null>(null);
  const [shareCount, setShareCount]   = useState(initialShareCount);
  const [threshold, setThreshold]     = useState(initialThreshold);
  const [statusMsg, setStatusMsg]     = useState('Shuffle the deck and hit Encrypt.');
  const [sealValid, setSealValid]     = useState(false);

  const shuffle = useCallback(() => {
    if (phase !== 'idle' && phase !== 'decrypted') return;
    setDeck(shuffleDeck(REFERENCE_DECK));
    setCardStates(Array(52).fill('face-up'));
    setPhase('idle');
    setContainer(null);
    setParticipants([]);
    setSealValid(false);
    setStatusMsg('Deck shuffled. Hit Encrypt when ready.');
  }, [phase]);

  const encrypt = useCallback(async () => {
    if (phase !== 'idle' && phase !== 'decrypted') return;
    setPhase('encrypting');
    setAnimating(true);
    setStatusMsg('Generating keys…');

    try {
      // Generate participant keypairs.
      const parts: Participant[] = await Promise.all(
        Array.from({ length: shareCount }, async (_, i) => {
          const kp = await kemGenerateKeypair();
          return {
            id: i,
            name: NAMES[i] ?? `P${i + 1}`,
            publicKey: kp.publicKey,
            privateKey: kp.privateKey,
            shareIndex: null,
            selected: false,
          };
        }),
      );

      // Generate signing keypair.
      const sigKp = await sigGenerateKeypair();
      setSignerKeys({ pub: sigKp.publicKey, priv: sigKp.privateKey });

      setStatusMsg('Encrypting deck permutation…');

      const permutation = encodePermutation(deck);
      const vault = await encryptPayload(permutation, parts, threshold, sigKp.privateKey);

      // Assign share indices to participants.
      const withShares = parts.map((p, i) => ({
        ...p,
        shareIndex: vault.shares[i]?.index ?? null,
      }));

      // Stagger card flip animations.
      const newStates: CardState[] = Array(52).fill('face-down');
      for (let i = 0; i < 52; i++) {
        setTimeout(() => {
          setCardStates((prev) => {
            const next = [...prev];
            next[i] = 'face-down';
            return next;
          });
        }, i * 18);
      }

      setTimeout(() => {
        setContainer(vault);
        setParticipants(withShares);
        setCardStates(newStates);
        setSealValid(true);
        setAnimating(false);
        setPhase('encrypted');
        setStatusMsg(
          `Encrypted ✓  Select ≥ ${threshold} participants and hit Decrypt.`,
        );
      }, 52 * 18 + 600);

    } catch (err) {
      setPhase('failed');
      setStatusMsg(`Encryption error: ${(err as Error).message}`);
      setAnimating(false);
    }
  }, [deck, phase, shareCount, threshold]);

  const toggleParticipant = useCallback((id: number) => {
    setParticipants((prev) =>
      prev.map((p) => (p.id === id ? { ...p, selected: !p.selected } : p)),
    );
  }, []);

  const decrypt = useCallback(async () => {
    if (!container || !signerKeys || phase !== 'encrypted') return;

    const selected = participants.filter((p) => p.selected);
    if (selected.length < threshold) {
      setPhase('failed');
      setStatusMsg(
        `Need at least ${threshold} shares — only ${selected.length} selected. The cards stay dark.`,
      );
      setTimeout(() => {
        setPhase('encrypted');
        setStatusMsg(`Select ≥ ${threshold} participants and try again.`);
      }, 3000);
      return;
    }

    setPhase('decrypting');
    setAnimating(true);
    setStatusMsg('Verifying container seal…');

    try {
      const permutation = await decryptPayload(container, selected, signerKeys.pub);
      const restoredDeck = decodePermutation(permutation, REFERENCE_DECK);

      setStatusMsg('Flipping cards…');
      for (let i = 0; i < 52; i++) {
        setTimeout(() => {
          setCardStates((prev) => {
            const next = [...prev];
            next[i] = 'revealed';
            return next;
          });
        }, i * 18);
      }

      setTimeout(() => {
        setDeck(restoredDeck);
        setCardStates(Array(52).fill('face-up'));
        setAnimating(false);
        setPhase('decrypted');
        setStatusMsg('Decrypted ✓  Original deck order restored. Shuffle to start again.');
      }, 52 * 18 + 600);

    } catch (err) {
      setPhase('failed');
      setSealValid(false);
      setStatusMsg(`Decryption failed: ${(err as Error).message}`);
      setAnimating(false);
      setTimeout(() => {
        setPhase('encrypted');
        setStatusMsg(`Select ≥ ${threshold} participants and try again.`);
      }, 4000);
    }
  }, [container, signerKeys, participants, phase, threshold]);

  return {
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
  };
}
