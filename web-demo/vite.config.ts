import { defineConfig } from 'vite';

export default defineConfig({
  // Must match the GitHub repository name exactly for GitHub Pages
  base: '/quantum-vault-kpqc/',
  build: {
    outDir: 'dist',
    // Enable source maps for easier debugging of production builds
    sourcemap: true,
  },
});
