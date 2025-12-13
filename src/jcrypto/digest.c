/*
 * jcrypto/digest.c - Message digest functions
 */

#include "jcrypto_internal.h"

/* Digest */
Janet cfun_digest(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    const uint8_t *alg_kw = janet_getkeyword(argv, 0);
    const char *alg = (const char *)alg_kw;
    JanetByteView data = janet_getbytes(argv, 1);

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) crypto_panic_config("unknown digest algorithm: %s", alg);

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.bytes, (size_t)data.len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    return janet_stringv(md_value, md_len);
}
