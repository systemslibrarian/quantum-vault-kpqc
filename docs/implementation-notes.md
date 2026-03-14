# Quantum Vault — Implementation Notes

**Version:** 1.0  
**Date:** 2026-03  
**Applies to:** Web demo v5.0 (real KpqC WASM)

---

## Overview

The web demo uses genuine C reference implementations of SMAUG-T and HAETAE,
compiled to WebAssembly via Emscripten 5.0.3.  This document covers the
compilation pipeline, the JS↔WASM interface, memory management, and the
rationale behind key design choices.

---

## 1. Compilation Pipeline

### 1.1 Prerequisites

```
emsdk 5.0.3 (emcc and em++ must be on PATH)
source ~/emsdk/emsdk_env.sh
```

The vendor C sources live under `wasm/vendor/`; they are not modified.  All
browser-incompatible platform code (`randombytes.c`) is replaced by a single
shim (`wasm/src/randombytes_wasm.c`) that is substituted at compile time by
listing it after the vendor sources.

### 1.2 SMAUG-T Level 1

```bash
emcc \
  -O2 \
  -DSMAUG_MODE=1 \
  -I"wasm/vendor/smaug-t/reference_implementation/include" \
  [13 vendor .c files] \
  wasm/src/randombytes_wasm.c \
  wasm/src/smaug_exports.c \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='createSmaugModule' \
  -s ENVIRONMENT='web,node' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_RUNTIME_METHODS='["cwrap","getValue"]' \
  -o wasm/dist/smaug.js
```

`-DSMAUG_MODE=1` selects the Level 1 (128-bit PQC) parameter set.  The
reference implementation's preprocessor guards gate the key-size constants on
this macro.

### 1.3 HAETAE Mode 2

```bash
emcc \
  -O2 \
  -I"wasm/vendor/haetae/HAETAE-1.1.2/reference_implementation" \
  [15 vendor .c files] \
  wasm/src/randombytes_wasm.c \
  wasm/src/haetae_exports.c \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='createHaetaeModule' \
  -s ENVIRONMENT='web,node' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_RUNTIME_METHODS='["cwrap","getValue"]' \
  -o wasm/dist/haetae.js
```

HAETAE 1.1.2 defaults to Mode 2 (128-bit PQC) when compiled without an explicit
mode override.  The mode is not selectable by a preprocessor macro in this
release; it is set by the parameter files included from the reference
implementation directory.

### 1.4 Build Outputs

| File | Destination in web-demo |
|------|------------------------|
| `wasm/dist/smaug.js` | `web-demo/src/crypto/wasm/smaug.js` |
| `wasm/dist/smaug.wasm` | `web-demo/public/smaug.wasm` |
| `wasm/dist/haetae.js` | `web-demo/src/crypto/wasm/haetae.js` |
| `wasm/dist/haetae.wasm` | `web-demo/public/haetae.wasm` |

The compiled binaries are committed to the repository so that CI and GitHub
Pages deployment do not require a C toolchain.

---

## 2. Exported Functions

### 2.1 SMAUG-T (`smaug_exports.c`)

The export shim includes `kem.h` (not `api.h`) to obtain the correct
`void`-return signature for `crypto_kem_keypair`.  Using `api.h` would introduce
a conflicting `int`-return declaration.

| Export | Signature | Description |
|--------|-----------|-------------|
| `smaug_keypair` | `(uint8_t *pk, uint8_t *sk) → int` | Key generation; 0 on success |
| `smaug_encapsulate` | `(uint8_t *ct, uint8_t *ss, const uint8_t *pk) → int` | Generate CT + SS from PK |
| `smaug_decapsulate` | `(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) → int` | Recover SS from CT + SK |
| `smaug_publickeybytes` | `(void) → int` | Returns 672 |
| `smaug_secretkeybytes` | `(void) → int` | Returns 832 |
| `smaug_ciphertextbytes` | `(void) → int` | Returns 672 |
| `smaug_sharedsecretbytes` | `(void) → int` | Returns 32 |

All exports use `__attribute__((export_name(...), used, visibility("default")))`,
which is the correct mechanism for Emscripten 5 / wasm-ld (the older
`EMSCRIPTEN_KEEPALIVE` macro is not used).

### 2.2 HAETAE (`haetae_exports.c`)

HAETAE 1.1.2 follows the FIPS 204–style context-string API.  The shim passes
`(NULL, 0)` as the context, which is equivalent to the plain message API.

| Export | Signature | Description |
|--------|-----------|-------------|
| `haetae_keypair` | `(uint8_t *vk, uint8_t *sk) → int` | Key generation; 0 on success |
| `haetae_sign` | `(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) → int` | Detached sign; 0 on success |
| `haetae_verify` | `(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *vk) → int` | 0 if valid |
| `haetae_publickeybytes` | `(void) → int` | Returns 992 |
| `haetae_secretkeybytes` | `(void) → int` | Returns 1408 |
| `haetae_sigbytes` | `(void) → int` | Returns 1474 (maximum) |

`haetae_sign` writes the actual signature length into `*siglen`.  Since wasm32
uses 32-bit `size_t`, TypeScript reads this 4-byte value with `getValue(ptr,
'i32')`.

---

## 3. Randomness (`randombytes_wasm.c`)

The reference implementations call `randombytes(out, outlen)` internally.  Both
vendor trees include their own `randombytes.c` that calls POSIX `getrandom()` or
`/dev/urandom`, which do not exist in the browser sandbox.

`wasm/src/randombytes_wasm.c` replaces these by appearing last on the compiler
command line, which causes the linker to resolve the `randombytes` symbol from
this file instead.

```c
EM_JS(void, js_randombytes, (uint8_t *buf, size_t len), {
    crypto.getRandomValues(new Uint8Array(Module.HEAPU8.buffer, buf, len));
});

int randombytes(uint8_t *out, size_t outlen) {
    js_randombytes(out, outlen);
    return 0;
}
```

`EM_JS` emits a JavaScript function that is inlined into the generated `.js`
loader.  It writes directly into the Emscripten heap (`Module.HEAPU8.buffer`)
at the pointer passed from C.  `crypto.getRandomValues` is available in all
modern browsers and in Node.js ≥ 19 (used for `vitest`).

The shim also provides no-op stubs for `randombytes_init` and
`AES256_CTR_DRBG_Update`, which appear in HAETAE's `randombytes.h` for KAT test
generation and are never called in the browser build.

---

## 4. Memory Management

Emscripten compiles to a flat 32-bit address space (wasm32).  All pointers are
32-bit offsets into `Module.HEAPU8.buffer`.

**Caller-allocates pattern:**  
The TypeScript wrappers (`smaug.ts`, `haetae.ts`) allocate output buffers before
calling any WASM function:

```typescript
const pk = smaugMod._malloc(smaugMod.smaug_publickeybytes());
const sk = smaugMod._malloc(smaugMod.smaug_secretkeybytes());
smaugMod.smaug_keypair(pk, sk);
const pkBytes = smaugMod.HEAPU8.slice(pk, pk + PK_BYTES);
smaugMod._free(pk);
smaugMod._free(sk);
```

`_malloc` / `_free` are Emscripten's wrappers around the WASM heap allocator.
All allocations are freed immediately after copying the output into a JavaScript
`Uint8Array`.  There are no persistent WASM-heap allocations across calls.

`ALLOW_MEMORY_GROWTH=1` permits the WASM heap to grow beyond its initial size
(default 16 MB) if a large key operation requires it.  In practice, Level 1 /
Mode 2 parameters are small enough that growth is never triggered.

---

## 5. Module Loading

Both WASM modules are loaded lazily on first use via async initialiser functions:

```typescript
// web-demo/src/crypto/smaug.ts
let _mod: SmaugModule | null = null;

async function getSmaugModule(): Promise<SmaugModule> {
  if (!_mod) _mod = await createSmaugModule();
  return _mod;
}
```

`createSmaugModule()` is the Emscripten factory function (`EXPORT_NAME`).  It
fetches the `.wasm` binary from `<origin>/smaug.wasm`, compiles it, and
resolves the returned Promise.  On subsequent calls the cached `_mod` is returned
without re-fetching.

`MODULARIZE=1` wraps the entire Emscripten runtime in a factory function rather
than polluting the global scope — necessary in a bundled ES-module environment.

`ENVIRONMENT='web,node'` instructs Emscripten to emit fetch-based WASM loading
(for browsers) and `fs.readFile`-based loading (for Node.js), allowing the same
`.js` loader to work in both `vitest` and the browser.

---

## 6. Parameter Choices

### 6.1 Level 1 / Mode 2 for the Web Demo

The web demo uses Level 1 (SMAUG-T) and Mode 2 (HAETAE) — the lowest parameter
set of each algorithm.  The Rust CLI uses Level 3 / Mode 3.

| Artifact | Level 1 / Mode 2 | Level 3 / Mode 3 |
|----------|-----------------|-----------------|
| SMAUG-T PK | 672 B | 1 088 B |
| SMAUG-T SK | 832 B | 1 312 B |
| SMAUG-T CT | 672 B | 992 B |
| HAETAE PK | 992 B | 1 472 B |
| HAETAE SK | 1 408 B | 2 112 B |
| HAETAE max sig | 1 474 B | 2 349 B |

The web demo stores three `WrappedShare` records per container, each containing
a PK, a wrapped SK, a KEM ciphertext, and two AES-GCM outputs.  Using Level 1 /
Mode 2 reduces per-box storage by roughly 3 × (400 B PK + 480 B SK + 320 B CT)
≈ 3.6 KB per box.  In a session-storage–backed app this is not critical, but
keeping the WASM binary smaller also reduces initial load time.

Both level choices maintain 128-bit post-quantum security — the same target as
AES-256 under Grover's algorithm for a quantum adversary.

### 6.2 GF(2⁸) Polynomial 0x11d

The Shamir implementation uses the primitive polynomial x⁸ + x⁴ + x³ + x² + 1
(`0x11d`) to define GF(2⁸).  The element 2 is a primitive root of this field,
meaning it has multiplicative order 255.  This allows a compact LOG/EXP table
construction where `LOG[EXP[i]] = i` for all i ∈ {0..254}.

The polynomial `0x11b` (the AES polynomial x⁸ + x⁴ + x³ + x + 1) was used in
an earlier version.  Generator 2 has order **51** in that field (not 255),
causing the LOG table to fill with repeated cycles and silently corrupting all
Shamir round-trips for non-trivial secrets.  See `docs/specification.md §4.1`
for the formal field definition.

---

## 7. Known Limitations

**No key persistence:** The HAETAE signing keypair is ephemeral — generated at
seal time and stored only as `sigPublicKey` in the container.  The SK is
discarded after signing.  This provides authenticity (the container was sealed
by whoever holds the SK at the time) but not attribution — the public key is
stored in the clear and any consumer can verify it, but the identity of the
sealer is not tracked.

**Session storage only:** `VaultState` is serialised to `sessionStorage`.
Closing the browser tab destroys all sealed boxes.  This is intentional for the
demo; a production deployment would persist to an encrypted backend.

**No HSM or secure enclave:** All key material exists in the JavaScript heap
during crypto operations.  A compromised browser extension or malicious script
on the same origin could read it.  The demo assumes a trusted browser context.

**PBKDF2 iteration count:** 100 000 iterations of SHA-256 was the NIST-
recommended minimum at PBKDF2's introduction.  Current guidance (NIST SP 800-132
rev 1, 2023) recommends at least 600 000 for SHA-256 in high-value contexts.
The demo uses 100 000 as a balance between usability (PBKDF2 runs on the main
thread) and resistance to offline dictionary attacks.

**WASM binary size:** `smaug.wasm` (~180 KB) and `haetae.wasm` (~220 KB) are
fetched on first use.  They are cached by the browser after the first load.

**No streaming decrypt:** The entire ciphertext is held in memory.  The current
design is appropriate for short secrets (message strings); it is not suitable
for large file encryption without rearchitecting the pipeline.
