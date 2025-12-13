/*
 * jcrypto/hmac.c - HMAC functions
 */

#include "jcrypto_internal.h"

/* HMAC */
Janet cfun_hmac(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    const uint8_t *alg_kw = janet_getkeyword(argv, 0);
    const char *alg = (const char *)alg_kw;
    JanetByteView key = janet_getbytes(argv, 1);
    JanetByteView data = janet_getbytes(argv, 2);

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) crypto_panic_config("unknown digest algorithm: %s", alg);

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    if (!HMAC(md, key.bytes, (int)key.len, data.bytes, (size_t)data.len, result,
              &result_len)) {
        crypto_panic_ssl("HMAC computation failed");
    }

    return janet_stringv(result, result_len);
}
