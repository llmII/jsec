/*
 * jcrypto/digest.c - Message digest functions
 */

#include "internal.h"

/* Digest Context Abstract Type (boxed EVP_MD_CTX *) */

Janet cfun_digest_update(int32_t argc, Janet *argv);
Janet cfun_digest_finish(int32_t argc, Janet *argv);
Janet cfun_digest_close(int32_t argc, Janet *argv);

static int jcrypto_digest_ctx_gc(void *p, size_t s) {
    (void)p;
    (void)s;
    EVP_MD_CTX **box = (EVP_MD_CTX **)p;
    if (*box) {
        EVP_MD_CTX_free(*box);
        *box = NULL;
    }
    return 0;
}

static int jcrypto_digest_ctx_get(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD)) return 0;
    const uint8_t *kw = janet_unwrap_keyword(key);
    if (!janet_cstrcmp(kw, "update")) {
        *out = janet_wrap_cfunction(cfun_digest_update);
        return 1;
    }
    if (!janet_cstrcmp(kw, "finish")) {
        *out = janet_wrap_cfunction(cfun_digest_finish);
        return 1;
    }
    if (!janet_cstrcmp(kw, "close")) {
        *out = janet_wrap_cfunction(cfun_digest_close);
        return 1;
    }
    return 0;
}

static const JanetAbstractType jcrypto_digest_ctx_type = {
    "jsec/digest-ctx", jcrypto_digest_ctx_gc, NULL, jcrypto_digest_ctx_get,
    JANET_ATEND_GET};

void jcrypto_register_digest_type(void) {
    janet_register_abstract_type(&jcrypto_digest_ctx_type);
}

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
    if (!mdctx) crypto_panic_ssl("failed to allocate digest context");

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.bytes, (size_t)data.len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    return janet_stringv(md_value, md_len);
}

Janet cfun_digest_begin(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    const uint8_t *alg_kw = janet_getkeyword(argv, 0);
    const char *alg = (const char *)alg_kw;

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) crypto_panic_config("unknown digest algorithm: %s", alg);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) crypto_panic_ssl("failed to allocate digest context");

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        crypto_panic_ssl("failed to initialize digest context");
    }

    EVP_MD_CTX **box = (EVP_MD_CTX **)janet_abstract(&jcrypto_digest_ctx_type,
                                                     sizeof(EVP_MD_CTX *));
    *box = mdctx;

    return janet_wrap_abstract(box);
}

Janet cfun_digest_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    EVP_MD_CTX **box =
        (EVP_MD_CTX **)janet_getabstract(argv, 0, &jcrypto_digest_ctx_type);
    if (!*box) crypto_panic_param("digest context is closed");

    JanetByteView data = janet_getbytes(argv, 1);
    if (EVP_DigestUpdate(*box, data.bytes, (size_t)data.len) != 1) {
        crypto_panic_ssl("failed to update digest context");
    }

    return argv[0];
}

Janet cfun_digest_finish(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    EVP_MD_CTX **box =
        (EVP_MD_CTX **)janet_getabstract(argv, 0, &jcrypto_digest_ctx_type);
    if (!*box) crypto_panic_param("digest context is closed");

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    EVP_MD_CTX *mdctx = *box;
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        *box = NULL;
        crypto_panic_ssl("failed to finalize digest context");
    }

    EVP_MD_CTX_free(mdctx);
    *box = NULL;

    return janet_stringv(md_value, md_len);
}

Janet cfun_digest_close(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    EVP_MD_CTX **box =
        (EVP_MD_CTX **)janet_getabstract(argv, 0, &jcrypto_digest_ctx_type);
    if (*box) {
        EVP_MD_CTX_free(*box);
        *box = NULL;
    }
    return janet_wrap_nil();
}
