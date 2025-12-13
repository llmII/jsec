/*
 * jcrypto/random.c - Cryptographic random number generation
 */

#include "jcrypto_internal.h"

/* Random bytes */
Janet cfun_random_bytes(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    int32_t n = janet_getinteger(argv, 0);
    if (n <= 0 || n > 65536) {
        crypto_panic_param("byte count must be 1-65536, got %d", n);
    }

    unsigned char *buf = janet_malloc(n);
    if (!buf) {
        crypto_panic_resource("failed to allocate buffer for random bytes");
    }
    if (RAND_bytes(buf, n) != 1) {
        janet_free(buf);
        crypto_panic_ssl("failed to generate random bytes");
    }

    Janet result = janet_stringv(buf, n);
    janet_free(buf);
    return result;
}

/* Generate a challenge (random nonce for SCEP) */
Janet cfun_generate_challenge(int32_t argc, Janet *argv) {
    janet_arity(argc, 0, 1);
    int32_t len = 16;  /* Default 16 bytes = 128 bits */
    if (argc > 0) {
        len = janet_getinteger(argv, 0);
        if (len < 8 || len > 64) {
            crypto_panic_param("challenge length must be 8-64 bytes, got %d", len);
        }
    }

    unsigned char *buf = janet_malloc(len);
    if (!buf) {
        crypto_panic_resource("failed to allocate buffer for challenge");
    }
    if (RAND_bytes(buf, len) != 1) {
        janet_free(buf);
        crypto_panic_ssl("failed to generate random challenge");
    }

    Janet result = janet_stringv(buf, len);
    janet_free(buf);
    return result;
}
