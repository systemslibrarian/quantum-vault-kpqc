import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        vault: {
          bg: '#0f0f1a',
          card: '#1a1a2e',
          accent: '#7c3aed',
          gold: '#d4af37',
          red: '#dc2626',
          green: '#16a34a',
          muted: '#6b7280',
        },
      },
      animation: {
        'flip-down': 'flipDown 0.5s ease-in-out forwards',
        'flip-up': 'flipUp 0.5s ease-in-out forwards',
        'pulse-lock': 'pulseLock 1s ease-in-out 3',
        'seal-stamp': 'sealStamp 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards',
        'deal': 'deal 0.3s ease-out forwards',
        'shake': 'shake 0.4s ease-in-out',
      },
      keyframes: {
        flipDown: {
          '0%':   { transform: 'rotateY(0deg)' },
          '50%':  { transform: 'rotateY(90deg)' },
          '100%': { transform: 'rotateY(180deg)' },
        },
        flipUp: {
          '0%':   { transform: 'rotateY(180deg)' },
          '50%':  { transform: 'rotateY(90deg)' },
          '100%': { transform: 'rotateY(0deg)' },
        },
        pulseLock: {
          '0%, 100%': { transform: 'scale(1)', opacity: '1' },
          '50%':      { transform: 'scale(1.3)', opacity: '0.8' },
        },
        sealStamp: {
          '0%':   { transform: 'scale(2)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
        deal: {
          '0%':   { transform: 'translateY(-40px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        shake: {
          '0%, 100%': { transform: 'translateX(0)' },
          '20%':      { transform: 'translateX(-8px)' },
          '40%':      { transform: 'translateX(8px)' },
          '60%':      { transform: 'translateX(-6px)' },
          '80%':      { transform: 'translateX(6px)' },
        },
      },
    },
  },
  plugins: [],
};

export default config;
