/*
 * jcrypto/sign.c - Digital signature functions
 */

#include "internal.h"

/* Sign */
Janet cfun_sign(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView key_pem = janet_getbytes(argv, 0);
    JanetByteView data = janet_getbytes(argv, 1);

    BIO *bio = BIO_new_mem_buf(key_pem.bytes, key_pem.len);
    EVP_PKEY *pkey =
        PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(bio);

    if (!pkey) crypto_panic_ssl("failed to load private key");

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        crypto_panic_ssl("failed to init sign");
    }

    size_t siglen;
    if (EVP_DigestSign(mdctx, NULL, &siglen, data.bytes, (size_t)data.len) <=
        0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        crypto_panic_ssl("failed to get signature length");
    }

    /* Write directly into Janet string memory - no intermediate buffer copy */
    uint8_t *sig = janet_string_begin((int32_t)siglen);

    if (EVP_DigestSign(mdctx, sig, &siglen, data.bytes, (size_t)data.len) <=
        0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        crypto_panic_ssl("failed to sign");
    }

    janet_string_head(sig)->length = (int32_t)siglen;
    sig[siglen] = 0;

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);

    return janet_wrap_string(janet_string_end(sig));
}

/* Verify */
Janet cfun_verify(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetByteView key_pem = janet_getbytes(argv, 0);
    JanetByteView data = janet_getbytes(argv, 1);
    JanetByteView sig = janet_getbytes(argv, 2);

    BIO *bio = BIO_new_mem_buf(key_pem.bytes, key_pem.len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        /* Try reading as private key and extracting public */
        (void)BIO_reset(bio);
        pkey =
            PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    }
    BIO_free(bio);

    if (!pkey) crypto_panic_ssl("failed to load key");

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        crypto_panic_ssl("failed to init verify");
    }

    int ret = EVP_DigestVerify(mdctx, sig.bytes, (size_t)sig.len, data.bytes,
                               (size_t)data.len);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);

    /* 0 is the wrong-signature verdict; a negative return is an internal
     * verify failure (malformed encoding, OOM, algorithm failure) and must
     * not read as "signature invalid". */
    if (ret < 0) crypto_panic_ssl("failed to verify signature");
    return janet_wrap_boolean(ret == 1);
}
