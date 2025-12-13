/*
 * jcrypto/kdf.c - Key Derivation Functions (HKDF, PBKDF2, ECDH)
 */

#include "jcrypto_internal.h"

/* HKDF - HMAC-based Key Derivation Function */
Janet cfun_hkdf(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);
    const uint8_t *alg_kw = janet_getkeyword(argv, 0);
    const char *alg = (const char *)alg_kw;
    JanetByteView ikm = janet_getbytes(argv, 1);  /* Input keying material */
    JanetByteView salt = janet_getbytes(argv, 2);
    JanetByteView info = janet_getbytes(argv, 3);
    int32_t length = janet_getinteger(argv, 4);

    if (length <= 0 || length > 255 * 64) {
        crypto_panic_param("output length must be 1-%d, got %d", 255 * 64, length);
    }

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) crypto_panic_config("unknown digest algorithm: %s", alg);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) crypto_panic_ssl("failed to create HKDF context");

    unsigned char *out = janet_malloc(length);
    if (!out) {
        EVP_PKEY_CTX_free(pctx);
        crypto_panic_resource("failed to allocate output buffer for HKDF");
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.bytes, salt.len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.bytes, ikm.len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info.bytes, info.len) <= 0) {
        janet_free(out);
        EVP_PKEY_CTX_free(pctx);
        crypto_panic_ssl("failed to set HKDF parameters");
    }

    size_t outlen = (size_t)length;
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
        janet_free(out);
        EVP_PKEY_CTX_free(pctx);
        crypto_panic_ssl("HKDF derivation failed");
    }

    EVP_PKEY_CTX_free(pctx);
    Janet result = janet_stringv(out, outlen);
    janet_free(out);
    return result;
}

/* PBKDF2 - Password-Based Key Derivation Function 2 */
Janet cfun_pbkdf2(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);
    const uint8_t *alg_kw = janet_getkeyword(argv, 0);
    const char *alg = (const char *)alg_kw;
    JanetByteView password = janet_getbytes(argv, 1);
    JanetByteView salt = janet_getbytes(argv, 2);
    int32_t iterations = janet_getinteger(argv, 3);
    int32_t length = janet_getinteger(argv, 4);

    if (iterations <= 0) crypto_panic_param("iterations must be positive");
    if (length <= 0 ||
        length > 1024) crypto_panic_param("output length must be 1-1024, got %d",
                                              length);

    const EVP_MD *md = EVP_get_digestbyname(alg);
    if (!md) crypto_panic_config("unknown digest algorithm: %s", alg);

    unsigned char *out = janet_malloc(length);
    if (!out) {
        crypto_panic_resource("failed to allocate output buffer for PBKDF2");
    }

    if (!PKCS5_PBKDF2_HMAC((const char *)password.bytes, password.len,
                           salt.bytes, salt.len, iterations, md, length, out)) {
        janet_free(out);
        crypto_panic_ssl("PBKDF2 derivation failed");
    }

    Janet result = janet_stringv(out, length);
    janet_free(out);
    return result;
}

/* ECDH key derivation - derive shared secret from private and peer public key */
Janet cfun_ecdh_derive(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView priv_pem = janet_getbytes(argv, 0);
    JanetByteView peer_pub_pem = janet_getbytes(argv, 1);

    /* Load private key */
    BIO *bio = BIO_new_mem_buf(priv_pem.bytes, priv_pem.len);
    EVP_PKEY *priv = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!priv) crypto_panic_ssl("failed to load private key");

    /* Load peer public key */
    bio = BIO_new_mem_buf(peer_pub_pem.bytes, peer_pub_pem.len);
    EVP_PKEY *peer = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!peer) {
        EVP_PKEY_free(priv);
        crypto_panic_ssl("failed to load peer public key");
    }

    /* Create derivation context */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        crypto_panic_ssl("failed to create derivation context");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        crypto_panic_ssl("failed to init derivation");
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        crypto_panic_ssl("failed to set peer key");
    }

    /* Determine buffer size */
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        crypto_panic_ssl("failed to determine secret length");
    }

    unsigned char *secret = janet_malloc(secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        crypto_panic_resource("failed to allocate buffer for shared secret");
    }
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) {
        janet_free(secret);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(peer);
        crypto_panic_ssl("key derivation failed");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);

    Janet result = janet_stringv(secret, secret_len);
    janet_free(secret);
    return result;
}
