import { defineConfig } from 'vite';

export default defineConfig({
  // Must match the GitHub repository name exactly for GitHub Pages
  base: '/crypto-lab-quantum-vault-kpqc/',
  build: {
    outDir: 'dist',
    // Enable source maps for easier debugging of production builds
    sourcemap: true,
  },
  // Enable high-resolution performance.now() for timing analysis
  // These headers are required for Cross-Origin Isolation
  server: {
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
});
