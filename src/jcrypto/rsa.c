/*
 * jcrypto/rsa.c - RSA encryption/decryption operations
 *
 * Direct RSA encryption is primarily used for:
 * - Key wrapping (encrypting symmetric keys)
 * - Small data encryption (up to key-size minus padding overhead)
 * - Hybrid encryption schemes
 *
 * WARNING: RSA encryption has size limits based on key size and padding:
 * - RSA-2048 with OAEP-SHA256: max 190 bytes plaintext
 * - RSA-4096 with OAEP-SHA256: max 446 bytes plaintext
 * For larger data, use symmetric encryption with RSA-wrapped key.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <openssl/rsa.h>

/*
 * Get RSA padding mode from keyword
 */
static int get_rsa_padding(const char *name, const EVP_MD **oaep_md) {
    *oaep_md = NULL;

    if (strcmp(name, "oaep-sha256") == 0) {
        *oaep_md = EVP_sha256();
        return RSA_PKCS1_OAEP_PADDING;
    }
    if (strcmp(name, "oaep-sha1") == 0) {
        *oaep_md = EVP_sha1();
        return RSA_PKCS1_OAEP_PADDING;
    }
    if (strcmp(name, "oaep-sha384") == 0) {
        *oaep_md = EVP_sha384();
        return RSA_PKCS1_OAEP_PADDING;
    }
    if (strcmp(name, "oaep-sha512") == 0) {
        *oaep_md = EVP_sha512();
        return RSA_PKCS1_OAEP_PADDING;
    }
    if (strcmp(name, "pkcs1") == 0) {
        return RSA_PKCS1_PADDING;
    }

    return -1;  /* Invalid */
}

/*
 * Encrypt data with RSA public key
 * (crypto/rsa-encrypt key-pem plaintext &opt opts)
 * opts: {:padding :oaep-sha256}
 * Returns ciphertext buffer
 */
Janet cfun_rsa_encrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView key_pem = janet_getbytes(argv, 0);
    JanetByteView plaintext = janet_getbytes(argv, 1);

    /* Default to OAEP-SHA256 (most secure commonly supported) */
    const char *padding_name = "oaep-sha256";

    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        if (janet_checktype(argv[2], JANET_TABLE)) {
            JanetTable *opts = janet_unwrap_table(argv[2]);
            Janet pad_val = janet_table_get(opts, janet_ckeywordv("padding"));
            if (!janet_checktype(pad_val, JANET_NIL)) {
                padding_name = (const char *)janet_getkeyword(&pad_val, 0);
            }
        } else if (janet_checktype(argv[2], JANET_STRUCT)) {
            JanetStruct opts = janet_unwrap_struct(argv[2]);
            Janet pad_val = janet_struct_get(opts, janet_ckeywordv("padding"));
            if (!janet_checktype(pad_val, JANET_NIL)) {
                padding_name = (const char *)janet_getkeyword(&pad_val, 0);
            }
        }
    }

    const EVP_MD *oaep_md = NULL;
    int padding = get_rsa_padding(padding_name, &oaep_md);
    if (padding < 0) {
        crypto_panic_param("unsupported padding mode: %s (supported: oaep-sha256, oaep-sha1, oaep-sha384, oaep-sha512, pkcs1)",
                           padding_name);
    }

    /* Load key - try public key first, then private key (extracts public) */
    BIO *bio = BIO_new_mem_buf(key_pem.bytes, (int)key_pem.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        /* Reset and try as private key */
        BIO_free(bio);
        bio = BIO_new_mem_buf(key_pem.bytes, (int)key_pem.len);
        pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    }
    BIO_free(bio);

    if (!pkey) {
        crypto_panic_ssl("failed to load key");
    }

    /* Verify it's an RSA key */
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        crypto_panic_param("RSA encryption requires RSA key, got different key type");
    }

    /* Create encryption context */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to create encryption context");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to initialize encryption");
    }

    /* Set padding */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to set padding mode");
    }

    /* Set OAEP hash if using OAEP */
    if (oaep_md) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep_md) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            crypto_panic_ssl("failed to set OAEP hash");
        }
        /* Set MGF1 hash to match */
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, oaep_md) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            crypto_panic_ssl("failed to set MGF1 hash");
        }
    }

    /* Determine output size */
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext.bytes,
                         plaintext.len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to determine output size");
    }

    /* Allocate output buffer */
    uint8_t *outbuf = janet_malloc(outlen);
    if (!outbuf) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_resource("out of memory");
    }

    /* Encrypt */
    if (EVP_PKEY_encrypt(ctx, outbuf, &outlen, plaintext.bytes,
                         plaintext.len) <= 0) {
        janet_free(outbuf);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("encryption failed (plaintext may be too large for key size)");
    }

    Janet result = janet_stringv(outbuf, (int32_t)outlen);

    janet_free(outbuf);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result;
}

/*
 * Decrypt data with RSA private key
 * (crypto/rsa-decrypt key-pem ciphertext &opt opts)
 * opts: {:padding :oaep-sha256}
 * Returns plaintext buffer
 */
Janet cfun_rsa_decrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView key_pem = janet_getbytes(argv, 0);
    JanetByteView ciphertext = janet_getbytes(argv, 1);

    /* Default to OAEP-SHA256 */
    const char *padding_name = "oaep-sha256";

    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        if (janet_checktype(argv[2], JANET_TABLE)) {
            JanetTable *opts = janet_unwrap_table(argv[2]);
            Janet pad_val = janet_table_get(opts, janet_ckeywordv("padding"));
            if (!janet_checktype(pad_val, JANET_NIL)) {
                padding_name = (const char *)janet_getkeyword(&pad_val, 0);
            }
        } else if (janet_checktype(argv[2], JANET_STRUCT)) {
            JanetStruct opts = janet_unwrap_struct(argv[2]);
            Janet pad_val = janet_struct_get(opts, janet_ckeywordv("padding"));
            if (!janet_checktype(pad_val, JANET_NIL)) {
                padding_name = (const char *)janet_getkeyword(&pad_val, 0);
            }
        }
    }

    const EVP_MD *oaep_md = NULL;
    int padding = get_rsa_padding(padding_name, &oaep_md);
    if (padding < 0) {
        crypto_panic_param("unsupported padding mode: %s", padding_name);
    }

    /* Load private key */
    BIO *bio = BIO_new_mem_buf(key_pem.bytes, (int)key_pem.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb,
                     NULL);
    BIO_free(bio);

    if (!pkey) {
        crypto_panic_ssl("failed to load private key (RSA decryption requires private key)");
    }

    /* Verify it's an RSA key */
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        crypto_panic_param("RSA decryption requires RSA key");
    }

    /* Create decryption context */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to create decryption context");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to initialize decryption");
    }

    /* Set padding */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to set padding mode");
    }

    /* Set OAEP hash if using OAEP */
    if (oaep_md) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep_md) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            crypto_panic_ssl("failed to set OAEP hash");
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, oaep_md) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            crypto_panic_ssl("failed to set MGF1 hash");
        }
    }

    /* Determine output size */
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext.bytes,
                         ciphertext.len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to determine output size");
    }

    /* Allocate output buffer */
    uint8_t *outbuf = janet_malloc(outlen);
    if (!outbuf) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_resource("out of memory");
    }

    /* Decrypt */
    if (EVP_PKEY_decrypt(ctx, outbuf, &outlen, ciphertext.bytes,
                         ciphertext.len) <= 0) {
        janet_free(outbuf);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("decryption failed (wrong key, corrupted data, or padding mismatch)");
    }

    Janet result = janet_stringv(outbuf, (int32_t)outlen);

    janet_free(outbuf);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return result;
}

/*
 * Get maximum plaintext size for RSA encryption with given key
 * (crypto/rsa-max-plaintext key-pem &opt opts)
 * opts: {:padding :oaep-sha256}
 * Returns maximum bytes that can be encrypted
 */
Janet cfun_rsa_max_plaintext(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    JanetByteView key_pem = janet_getbytes(argv, 0);

    const char *padding_name = "oaep-sha256";

    if (argc > 1 && !janet_checktype(argv[1], JANET_NIL)) {
        if (janet_checktype(argv[1], JANET_TABLE)) {
            JanetTable *opts = janet_unwrap_table(argv[1]);
            Janet pad_val = janet_table_get(opts, janet_ckeywordv("padding"));
            if (!janet_checktype(pad_val, JANET_NIL)) {
                padding_name = (const char *)janet_getkeyword(&pad_val, 0);
            }
        } else if (janet_checktype(argv[1], JANET_STRUCT)) {
            JanetStruct opts = janet_unwrap_struct(argv[1]);
            Janet pad_val = janet_struct_get(opts, janet_ckeywordv("padding"));
            if (!janet_checktype(pad_val, JANET_NIL)) {
                padding_name = (const char *)janet_getkeyword(&pad_val, 0);
            }
        }
    }

    /* Load key */
    BIO *bio = BIO_new_mem_buf(key_pem.bytes, (int)key_pem.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        bio = BIO_new_mem_buf(key_pem.bytes, (int)key_pem.len);
        pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    }
    BIO_free(bio);

    if (!pkey) {
        crypto_panic_ssl("failed to load key");
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        crypto_panic_param("RSA operation requires RSA key");
    }

    int key_size = EVP_PKEY_size(pkey);  /* In bytes */
    EVP_PKEY_free(pkey);

    int max_plaintext = 0;

    /* Calculate based on padding overhead */
    if (strcmp(padding_name, "oaep-sha256") == 0) {
        /* OAEP overhead = 2 * hash_size + 2 = 2*32+2 = 66 bytes */
        max_plaintext = key_size - 66;
    } else if (strcmp(padding_name, "oaep-sha1") == 0) {
        /* OAEP overhead = 2 * 20 + 2 = 42 bytes */
        max_plaintext = key_size - 42;
    } else if (strcmp(padding_name, "oaep-sha384") == 0) {
        /* OAEP overhead = 2 * 48 + 2 = 98 bytes */
        max_plaintext = key_size - 98;
    } else if (strcmp(padding_name, "oaep-sha512") == 0) {
        /* OAEP overhead = 2 * 64 + 2 = 130 bytes */
        max_plaintext = key_size - 130;
    } else if (strcmp(padding_name, "pkcs1") == 0) {
        /* PKCS#1 v1.5 overhead = 11 bytes */
        max_plaintext = key_size - 11;
    } else {
        crypto_panic_param("unsupported padding mode: %s", padding_name);
    }

    if (max_plaintext < 0) max_plaintext = 0;

    return janet_wrap_integer(max_plaintext);
}
