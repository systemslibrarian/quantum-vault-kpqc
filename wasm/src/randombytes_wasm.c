/*
 * randombytes_wasm.c — replaces the native randombytes.c from both
 * SMAUG-T and HAETAE reference implementations when compiling to WebAssembly.
 *
 * Uses Emscripten's built-in getentropy() which routes to
 * crypto.getRandomValues() in a way that's safe during module initialization.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>  /* getentropy() */

/* SMAUG-T uses: int randombytes(uint8_t *x, size_t xlen) */
/* HAETAE uses:  int randombytes(uint8_t *out, size_t outlen) */
int randombytes(uint8_t *out, size_t outlen) {
    /* getentropy() is limited to 256 bytes per call, so loop if needed */
    while (outlen > 0) {
        size_t chunk = outlen > 256 ? 256 : outlen;
        if (getentropy(out, chunk) != 0) {
            /* Failed to get entropy — abort rather than continue with
             * uninitialised data. */
            abort();
        }
        out += chunk;
        outlen -= chunk;
    }
    return 0;
}

/*
 * HAETAE's randombytes.h also declares randombytes_init and
 * AES256_CTR_DRBG_Update for KAT test generation. These are no-ops
 * in the WASM build since we never run KAT tests from the browser.
 */
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength) {
    (void)entropy_input;
    (void)personalization_string;
    (void)security_strength;
}

void AES256_CTR_DRBG_Update(unsigned char *provided_data,
                             unsigned char *Key,
                             unsigned char *V) {
    (void)provided_data;
    (void)Key;
    (void)V;
}
