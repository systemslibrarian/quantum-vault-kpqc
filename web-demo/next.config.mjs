/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: { unoptimized: true },

  // No webpack WASM experiment needed: the bridge uses a Function-constructor
  // dynamic import so webpack never bundles the WASM module.  The .wasm file
  // and its JS glue live in public/wasm-pkg/ and are fetched at runtime by
  // the browser when built (`npm run wasm:build`).
};

export default nextConfig;
