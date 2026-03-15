import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Node environment gives us globalThis.crypto (WebCrypto) without a browser
    environment: 'node',
    globals: true,
    // Resolve bare imports the same way Vite does
    root: '.',
    exclude: ['e2e/**', '**/node_modules/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      exclude: [
        '**/wasm/**',
        '**/*.d.ts',
        '**/node_modules/**',
        'vite.config.ts',
        'vitest.config.ts',
        'eslint.config.js',
      ],
    },
  },
});
