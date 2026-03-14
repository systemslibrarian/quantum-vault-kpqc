/** @type {import('next').NextConfig} */

// When deployed to GitHub Pages the site lives at /<repo-name>/.
// Set NEXT_PUBLIC_BASE_PATH env var (or GITHUB_PAGES=true) to activate.
const basePath =
  process.env.GITHUB_PAGES === 'true'
    ? '/quantum-vault-kpqc'
    : (process.env.NEXT_PUBLIC_BASE_PATH ?? '');

const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: { unoptimized: true },
  basePath,
  assetPrefix: basePath,

  // No webpack WASM experiment needed: the bridge uses a Function-constructor
  // dynamic import so webpack never bundles the WASM module.  The .wasm file
  // and its JS glue live in public/wasm-pkg/ and are fetched at runtime by
  // the browser when built (`npm run wasm:build`).
};

export default nextConfig;
