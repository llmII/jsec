/*
 * jcrypto/random.c - Cryptographic random number generation
 */

#include "internal.h"

/* Random bytes */
Janet cfun_random_bytes(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    int32_t n = janet_getinteger(argv, 0);
    if (n <= 0 || n > 65536) {
        crypto_panic_param("byte count must be 1-65536, got %d", n);
    }

    /* Write directly into Janet string memory - no intermediate buffer copy
     */
    uint8_t *buf = janet_string_begin(n);
    if (RAND_bytes(buf, n) != 1) {
        crypto_panic_ssl("failed to generate random bytes");
    }

    return janet_wrap_string(janet_string_end(buf));
}

/* Generate a challenge (random nonce for SCEP) */
Janet cfun_generate_challenge(int32_t argc, Janet *argv) {
    janet_arity(argc, 0, 1);
    int32_t len = 16; /* Default 16 bytes = 128 bits */
    if (argc > 0) {
        len = janet_getinteger(argv, 0);
        if (len < 8 || len > 64) {
            crypto_panic_param("challenge length must be 8-64 bytes, got %d",
                               len);
        }
    }

    /* Write directly into Janet string memory - no intermediate buffer copy
     */
    uint8_t *buf = janet_string_begin(len);
    if (RAND_bytes(buf, len) != 1) {
        crypto_panic_ssl("failed to generate random challenge");
    }

    return janet_wrap_string(janet_string_end(buf));
}
