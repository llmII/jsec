/*
 * cipher.c - Symmetric encryption/decryption operations
 *
 * Provides AEAD encryption (AES-GCM, ChaCha20-Poly1305) and traditional
 * block cipher modes (AES-CBC).
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "jcrypto_internal.h"

/*============================================================================
 * Cipher Algorithm Lookup
 *============================================================================*/

typedef struct {
    const char *name;
    const EVP_CIPHER *(*get_cipher)(void);
    int key_len;
    int nonce_len;      /* IV length for non-AEAD */
    int tag_len;        /* 0 for non-AEAD */
    int is_aead;
} CipherInfo;

static const CipherInfo cipher_table[] = {
    /* AEAD ciphers - recommended */
    {"aes-128-gcm",       EVP_aes_128_gcm,       16, 12, 16, 1},
    {"aes-256-gcm",       EVP_aes_256_gcm,       32, 12, 16, 1},
    {"chacha20-poly1305", EVP_chacha20_poly1305, 32, 12, 16, 1},
    /* Traditional block ciphers - use with care */
    {"aes-128-cbc",       EVP_aes_128_cbc,       16, 16, 0,  0},
    {"aes-256-cbc",       EVP_aes_256_cbc,       32, 16, 0,  0},
    {NULL, NULL, 0, 0, 0, 0}
};

static const CipherInfo *get_cipher_info(Janet algo) {
    if (!janet_checktype(algo, JANET_KEYWORD)) {
        return NULL;
    }
    const uint8_t *kw = janet_unwrap_keyword(algo);
    for (const CipherInfo *info = cipher_table; info->name != NULL; info++) {
        if (strcmp((const char *)kw, info->name) == 0) {
            return info;
        }
    }
    return NULL;
}

/*============================================================================
 * AEAD Encryption
 *============================================================================*/

/*
 * (crypto/encrypt algo key nonce plaintext &opt aad)
 *
 * Encrypt data using an AEAD cipher.
 *
 * Parameters:
 *   algo      - Cipher algorithm keyword (:aes-128-gcm, :aes-256-gcm, :chacha20-poly1305)
 *   key       - Encryption key (must match algorithm requirements)
 *   nonce     - Nonce/IV (12 bytes for GCM/ChaCha20)
 *   plaintext - Data to encrypt (string or buffer)
 *   aad       - Additional authenticated data (optional, not encrypted but authenticated)
 *
 * Returns struct:
 *   {:ciphertext <buffer> :tag <buffer>}
 *
 * The tag must be stored alongside ciphertext and provided during decryption.
 * NEVER reuse a nonce with the same key.
 */
Janet cfun_encrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 4, 5);

    /* Get cipher info */
    const CipherInfo *info = get_cipher_info(argv[0]);
    if (info == NULL) {
        crypto_panic_param("unsupported cipher algorithm: %v", argv[0]);
    }

    /* Get key */
    JanetByteView key = janet_getbytes(argv, 1);
    if (key.len != info->key_len) {
        crypto_panic_param("key must be %d bytes for %s, got %d",
                           info->key_len, info->name, key.len);
    }

    /* Get nonce */
    JanetByteView nonce = janet_getbytes(argv, 2);
    if (nonce.len != info->nonce_len) {
        crypto_panic_param("nonce must be %d bytes for %s, got %d",
                           info->nonce_len, info->name, nonce.len);
    }

    /* Get plaintext */
    JanetByteView plaintext = janet_getbytes(argv, 3);

    /* Get optional AAD */
    JanetByteView aad = {NULL, 0};
    if (argc > 4 && !janet_checktype(argv[4], JANET_NIL)) {
        aad = janet_getbytes(argv, 4);
    }

    /* Create cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        crypto_panic_ssl("failed to create cipher context");
    }

    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, info->get_cipher(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_panic_ssl("failed to initialize cipher");
    }

    /* Set nonce length for GCM/CCM if needed */
    if (info->is_aead) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, info->nonce_len,
                                NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            crypto_panic_ssl("failed to set nonce length");
        }
    }

    /* Set key and nonce */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.bytes, nonce.bytes) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_panic_ssl("failed to set key/nonce");
    }

    /* Process AAD if provided (for AEAD) */
    if (info->is_aead && aad.len > 0) {
        int aad_len;
        if (EVP_EncryptUpdate(ctx, NULL, &aad_len, aad.bytes, (int)aad.len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            crypto_panic_ssl("failed to process AAD");
        }
    }

    /* Allocate output buffer (ciphertext may be larger due to padding for CBC) */
    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    size_t out_len = (size_t)plaintext.len + (size_t)block_size;
    JanetBuffer *ciphertext = janet_buffer((int32_t)out_len);

    /* Encrypt */
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext->data, &len,
                          plaintext.bytes, (int)plaintext.len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_panic_ssl("encryption failed");
    }
    ciphertext->count = len;

    /* Finalize (handles padding for CBC) */
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext->data + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_panic_ssl("encryption finalization failed");
    }
    ciphertext->count += final_len;

    /* Build result */
    JanetKV *result = janet_struct_begin(2);
    janet_struct_put(result, janet_ckeywordv("ciphertext"),
                     janet_wrap_buffer(ciphertext));

    /* Get authentication tag for AEAD */
    if (info->is_aead) {
        JanetBuffer *tag = janet_buffer(info->tag_len);
        tag->count = info->tag_len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, info->tag_len,
                                tag->data) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            crypto_panic_ssl("failed to get authentication tag");
        }
        janet_struct_put(result, janet_ckeywordv("tag"), janet_wrap_buffer(tag));
    } else {
        janet_struct_put(result, janet_ckeywordv("tag"), janet_wrap_nil());
    }

    EVP_CIPHER_CTX_free(ctx);
    return janet_wrap_struct(janet_struct_end(result));
}

/*============================================================================
 * AEAD Decryption
 *============================================================================*/

/*
 * (crypto/decrypt algo key nonce ciphertext tag &opt aad)
 *
 * Decrypt data using an AEAD cipher.
 *
 * Parameters:
 *   algo       - Cipher algorithm keyword (must match encryption)
 *   key        - Decryption key (same as encryption key)
 *   nonce      - Nonce/IV (same as used for encryption)
 *   ciphertext - Encrypted data
 *   tag        - Authentication tag from encryption (nil for non-AEAD)
 *   aad        - Additional authenticated data (must match encryption)
 *
 * Returns:
 *   Decrypted plaintext buffer
 *
 * Errors if authentication fails (tag mismatch).
 */
Janet cfun_decrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 5, 6);

    /* Get cipher info */
    const CipherInfo *info = get_cipher_info(argv[0]);
    if (info == NULL) {
        crypto_panic_param("unsupported cipher algorithm: %v", argv[0]);
    }

    /* Get key */
    JanetByteView key = janet_getbytes(argv, 1);
    if (key.len != info->key_len) {
        crypto_panic_param("key must be %d bytes for %s, got %d",
                           info->key_len, info->name, key.len);
    }

    /* Get nonce */
    JanetByteView nonce = janet_getbytes(argv, 2);
    if (nonce.len != info->nonce_len) {
        crypto_panic_param("nonce must be %d bytes for %s, got %d",
                           info->nonce_len, info->name, nonce.len);
    }

    /* Get ciphertext */
    JanetByteView ciphertext = janet_getbytes(argv, 3);

    /* Get tag (required for AEAD, nil for non-AEAD) */
    JanetByteView tag = {NULL, 0};
    if (info->is_aead) {
        if (janet_checktype(argv[4], JANET_NIL)) {
            crypto_panic_param("authentication tag required for AEAD cipher %s",
                               info->name);
        }
        tag = janet_getbytes(argv, 4);
        if (tag.len != info->tag_len) {
            crypto_panic_param("tag must be %d bytes for %s, got %d",
                               info->tag_len, info->name, tag.len);
        }
    }

    /* Get optional AAD */
    JanetByteView aad = {NULL, 0};
    if (argc > 5 && !janet_checktype(argv[5], JANET_NIL)) {
        aad = janet_getbytes(argv, 5);
    }

    /* Create cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        crypto_panic_ssl("failed to create cipher context");
    }

    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, info->get_cipher(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_panic_ssl("failed to initialize cipher");
    }

    /* Set nonce length for GCM/CCM if needed */
    if (info->is_aead) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, info->nonce_len,
                                NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            crypto_panic_ssl("failed to set nonce length");
        }
    }

    /* Set key and nonce */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.bytes, nonce.bytes) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_panic_ssl("failed to set key/nonce");
    }

    /* Process AAD if provided (for AEAD) */
    if (info->is_aead && aad.len > 0) {
        int aad_len;
        if (EVP_DecryptUpdate(ctx, NULL, &aad_len, aad.bytes, (int)aad.len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            crypto_panic_ssl("failed to process AAD");
        }
    }

    /* Allocate output buffer */
    JanetBuffer *plaintext = janet_buffer(ciphertext.len);

    /* Decrypt */
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext->data, &len,
                          ciphertext.bytes, (int)ciphertext.len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        crypto_panic_ssl("decryption failed");
    }
    plaintext->count = len;

    /* Set expected tag for AEAD verification */
    if (info->is_aead) {
        /* Need to cast away const for OpenSSL API */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, info->tag_len,
                                (void *)tag.bytes) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            crypto_panic_ssl("failed to set authentication tag");
        }
    }

    /* Finalize and verify tag */
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext->data + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        if (info->is_aead) {
            crypto_panic_config("decryption failed: authentication tag mismatch");
        } else {
            crypto_panic_ssl("decryption finalization failed");
        }
    }
    plaintext->count += final_len;

    EVP_CIPHER_CTX_free(ctx);
    return janet_wrap_buffer(plaintext);
}

/*============================================================================
 * Nonce Generation
 *============================================================================*/

/*
 * (crypto/generate-nonce algo)
 *
 * Generate a random nonce suitable for the specified cipher algorithm.
 *
 * Parameters:
 *   algo - Cipher algorithm keyword
 *
 * Returns:
 *   Random nonce buffer of appropriate length
 *
 * IMPORTANT: Never reuse a nonce with the same key!
 */
Janet cfun_generate_nonce(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    const CipherInfo *info = get_cipher_info(argv[0]);
    if (info == NULL) {
        crypto_panic_param("unsupported cipher algorithm: %v", argv[0]);
    }

    JanetBuffer *nonce = janet_buffer(info->nonce_len);
    nonce->count = info->nonce_len;

    if (RAND_bytes(nonce->data, info->nonce_len) != 1) {
        crypto_panic_ssl("failed to generate random nonce");
    }

    return janet_wrap_buffer(nonce);
}

/*============================================================================
 * Cipher Info Query
 *============================================================================*/

/*
 * (crypto/cipher-info algo)
 *
 * Get information about a cipher algorithm.
 *
 * Parameters:
 *   algo - Cipher algorithm keyword
 *
 * Returns struct:
 *   {:name "aes-256-gcm"
 *    :key-length 32
 *    :nonce-length 12
 *    :tag-length 16
 *    :aead true}
 */
Janet cfun_cipher_info(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    const CipherInfo *info = get_cipher_info(argv[0]);
    if (info == NULL) {
        crypto_panic_param("unsupported cipher algorithm: %v", argv[0]);
    }

    JanetKV *result = janet_struct_begin(5);
    janet_struct_put(result, janet_ckeywordv("name"), janet_cstringv(info->name));
    janet_struct_put(result, janet_ckeywordv("key-length"),
                     janet_wrap_integer(info->key_len));
    janet_struct_put(result, janet_ckeywordv("nonce-length"),
                     janet_wrap_integer(info->nonce_len));
    janet_struct_put(result, janet_ckeywordv("tag-length"),
                     janet_wrap_integer(info->tag_len));
    janet_struct_put(result, janet_ckeywordv("aead"),
                     janet_wrap_boolean(info->is_aead));

    return janet_wrap_struct(janet_struct_end(result));
}
