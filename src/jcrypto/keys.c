/*
 * jcrypto/keys.c - Key generation and management
 */

#include "jcrypto_internal.h"

/* Key Management */
Janet cfun_generate_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    const uint8_t *alg_kw = janet_getkeyword(argv, 0);
    const char *alg = (const char *)alg_kw;

    int type = EVP_PKEY_NONE;
    int bits = 2048;  /* Default for RSA */
    int nid = 0;      /* For EC curves */

    if (strcmp(alg, "ed25519") == 0) {
        type = EVP_PKEY_ED25519;
    } else if (strcmp(alg, "x25519") == 0) {
        type = EVP_PKEY_X25519;
    } else if (strcmp(alg, "rsa") == 0) {
        type = EVP_PKEY_RSA;
        if (argc > 1 && janet_checktype(argv[1], JANET_NUMBER)) {
            bits = (int)janet_unwrap_number(argv[1]);
        }
    } else if (strcmp(alg, "ec-p256") == 0 || strcmp(alg, "p256") == 0) {
        type = EVP_PKEY_EC;
        nid = NID_X9_62_prime256v1;
    } else if (strcmp(alg, "ec-p384") == 0 || strcmp(alg, "p384") == 0) {
        type = EVP_PKEY_EC;
        nid = NID_secp384r1;
    } else if (strcmp(alg, "ec-p521") == 0 || strcmp(alg, "p521") == 0) {
        type = EVP_PKEY_EC;
        nid = NID_secp521r1;
    } else {
        crypto_panic_config("unsupported key algorithm: %s (supported: rsa, ed25519, x25519, ec-p256, ec-p384, ec-p521)",
                            alg);
    }

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    if (type == EVP_PKEY_EC) {
        /* EC key generation */
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!pctx) crypto_panic_ssl("failed to create EC context");

        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            crypto_panic_ssl("failed to init EC keygen");
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            crypto_panic_ssl("failed to set EC curve");
        }

        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            crypto_panic_ssl("failed to generate EC key");
        }
    } else {
        pctx = EVP_PKEY_CTX_new_id(type, NULL);
        if (!pctx) crypto_panic_ssl("failed to create context");

        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            crypto_panic_ssl("failed to init keygen");
        }

        if (type == EVP_PKEY_RSA) {
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits);
        }

        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            crypto_panic_ssl("failed to generate key");
        }
    }
    EVP_PKEY_CTX_free(pctx);

    /* Export to PEM */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    Janet result = janet_stringv((const uint8_t *)data, len);

    BIO_free(bio);
    EVP_PKEY_free(pkey);

    return result;
}

/* Export public key from private key */
Janet cfun_export_public_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView key_pem = janet_getbytes(argv, 0);

    BIO *bio = BIO_new_mem_buf(key_pem.bytes, key_pem.len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(bio);

    if (!pkey) crypto_panic_ssl("failed to load private key");

    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(out, pkey);

    char *data;
    long len = BIO_get_mem_data(out, &data);
    Janet result = janet_stringv((const uint8_t *)data, len);

    BIO_free(out);
    EVP_PKEY_free(pkey);

    return result;
}

/*
 * Load a private key (optionally encrypted with password)
 * (crypto/load-key key-pem &opt password)
 * => EVP_PKEY as PEM string (decrypted)
 */
Janet cfun_load_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    JanetByteView key_data = janet_getbytes(argv, 0);
    const char *password = NULL;

    if (argc > 1 && !janet_checktype(argv[1], JANET_NIL)) {
        JanetByteView pwd = janet_getbytes(argv, 1);
        password = (const char *)pwd.bytes;
    }

    BIO *bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_password_cb,
                                             (void *)password);
    BIO_free(bio);

    if (!pkey) {
        /* Check if it's a password issue */
        unsigned long err = ERR_peek_last_error();
        int reason = ERR_GET_REASON(err);
        /* EVP_R_BAD_DECRYPT = 100 in OpenSSL */
        if (reason == 100) {
            crypto_panic_param("incorrect password or encrypted key requires password");
        }
        crypto_panic_ssl("failed to load private key");
    }

    /* Export as unencrypted PEM */
    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        EVP_PKEY_free(pkey);
        crypto_panic_resource("failed to create output BIO");
    }

    if (!PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(out);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to export key");
    }

    char *data;
    long len = BIO_get_mem_data(out, &data);
    Janet result = janet_stringv((const uint8_t *)data, (int32_t)len);

    BIO_free(out);
    EVP_PKEY_free(pkey);

    return result;
}

/*
 * Helper to get cipher from keyword
 */
static const EVP_CIPHER *get_export_cipher(const char *name) {
    if (strcmp(name, "aes-256-cbc") == 0) return EVP_aes_256_cbc();
    if (strcmp(name, "aes-128-cbc") == 0) return EVP_aes_128_cbc();
    if (strcmp(name, "des-ede3-cbc") == 0) return EVP_des_ede3_cbc();
    return NULL;
}

/*
 * Export a private key, optionally encrypted with password
 * (crypto/export-key key-pem &opt opts)
 * opts: {:password "secret" :cipher :aes-256-cbc}
 * => PEM string (encrypted if password provided)
 */
Janet cfun_export_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    JanetByteView key_data = janet_getbytes(argv, 0);

    const char *password = NULL;
    size_t password_len = 0;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  /* Default */

    if (argc > 1 && janet_checktype(argv[1], JANET_TABLE)) {
        JanetTable *opts = janet_unwrap_table(argv[1]);

        Janet pwd_val = janet_table_get(opts, janet_ckeywordv("password"));
        if (!janet_checktype(pwd_val, JANET_NIL)) {
            JanetByteView pwd = janet_getbytes(&pwd_val, 0);
            password = (const char *)pwd.bytes;
            password_len = pwd.len;
        }

        Janet cipher_val = janet_table_get(opts, janet_ckeywordv("cipher"));
        if (!janet_checktype(cipher_val, JANET_NIL)) {
            const uint8_t *cipher_kw = janet_getkeyword(&cipher_val, 0);
            cipher = get_export_cipher((const char *)cipher_kw);
            if (!cipher) {
                crypto_panic_param("unsupported cipher: %s (supported: aes-256-cbc, aes-128-cbc, des-ede3-cbc)",
                                   (const char *)cipher_kw);
            }
        }
    } else if (argc > 1 && janet_checktype(argv[1], JANET_STRUCT)) {
        JanetStruct opts = janet_unwrap_struct(argv[1]);

        Janet pwd_val = janet_struct_get(opts, janet_ckeywordv("password"));
        if (!janet_checktype(pwd_val, JANET_NIL)) {
            JanetByteView pwd = janet_getbytes(&pwd_val, 0);
            password = (const char *)pwd.bytes;
            password_len = pwd.len;
        }

        Janet cipher_val = janet_struct_get(opts, janet_ckeywordv("cipher"));
        if (!janet_checktype(cipher_val, JANET_NIL)) {
            const uint8_t *cipher_kw = janet_getkeyword(&cipher_val, 0);
            cipher = get_export_cipher((const char *)cipher_kw);
            if (!cipher) {
                crypto_panic_param("unsupported cipher: %s (supported: aes-256-cbc, aes-128-cbc, des-ede3-cbc)",
                                   (const char *)cipher_kw);
            }
        }
    }

    /* Load the key */
    BIO *bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(bio);

    if (!pkey) crypto_panic_ssl("failed to load private key");

    /* Export */
    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        EVP_PKEY_free(pkey);
        crypto_panic_resource("failed to create output BIO");
    }

    int result;
    if (password && password_len > 0) {
        result = PEM_write_bio_PrivateKey(out, pkey, cipher,
                                          (unsigned char *)password, (int)password_len,
                                          NULL, NULL);
    } else {
        result = PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
    }

    if (!result) {
        BIO_free(out);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to export key");
    }

    char *data;
    long len = BIO_get_mem_data(out, &data);
    Janet ret = janet_stringv((const uint8_t *)data, (int32_t)len);

    BIO_free(out);
    EVP_PKEY_free(pkey);

    return ret;
}

/*
 * Get key metadata without loading private material
 * (crypto/key-info key-pem)
 * => {:type :rsa :bits 2048 :encrypted false}
 */
Janet cfun_key_info(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView key_data = janet_getbytes(argv, 0);

    JanetTable *info = janet_table(4);

    /* Check if encrypted by looking for "ENCRYPTED" in PEM header */
    int encrypted = 0;
    const char *data = (const char *)key_data.bytes;
    if (strstr(data, "ENCRYPTED") != NULL) {
        encrypted = 1;
    }
    janet_table_put(info, janet_ckeywordv("encrypted"),
                    janet_wrap_boolean(encrypted));

    /* Try to load as public key first (works even for encrypted private keys) */
    BIO *bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    EVP_PKEY *pkey = NULL;

    /* Try loading as private key (if not encrypted) */
    if (!encrypted) {
        pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    }

    if (!pkey) {
        /* Reset BIO and try loading as public key */
        BIO_free(bio);
        bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);

    if (!pkey) {
        /* Can't load - still report encrypted status */
        janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("unknown"));
        return janet_wrap_table(info);
    }

    /* Get key type */
    int key_type = EVP_PKEY_base_id(pkey);
    const char *type_str = "unknown";

    switch (key_type) {
        case EVP_PKEY_RSA:
            type_str = "rsa";
            janet_table_put(info, janet_ckeywordv("bits"),
                            janet_wrap_integer(EVP_PKEY_bits(pkey)));
            break;
        case EVP_PKEY_EC: {
                type_str = "ec";
                janet_table_put(info, janet_ckeywordv("bits"),
                                janet_wrap_integer(EVP_PKEY_bits(pkey)));
                /* Try to get curve name */
                char curve_name[64] = {0};
                size_t curve_name_len = sizeof(curve_name);
                if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                                   curve_name, curve_name_len, &curve_name_len) > 0) {
                    /* Map OpenSSL curve names to our keywords */
                    if (strcmp(curve_name, "prime256v1") == 0 ||
                        strcmp(curve_name, "P-256") == 0) {
                        janet_table_put(info, janet_ckeywordv("curve"), janet_ckeywordv("p-256"));
                    } else if (strcmp(curve_name, "secp384r1") == 0 ||
                               strcmp(curve_name, "P-384") == 0) {
                        janet_table_put(info, janet_ckeywordv("curve"), janet_ckeywordv("p-384"));
                    } else if (strcmp(curve_name, "secp521r1") == 0 ||
                               strcmp(curve_name, "P-521") == 0) {
                        janet_table_put(info, janet_ckeywordv("curve"), janet_ckeywordv("p-521"));
                    } else if (strcmp(curve_name, "secp256k1") == 0) {
                        janet_table_put(info, janet_ckeywordv("curve"), janet_ckeywordv("secp256k1"));
                    } else {
                        janet_table_put(info, janet_ckeywordv("curve"),
                                        janet_cstringv(curve_name));
                    }
                }
                break;
            }
        case EVP_PKEY_ED25519:
            type_str = "ed25519";
            break;
        case EVP_PKEY_X25519:
            type_str = "x25519";
            break;
        case EVP_PKEY_ED448:
            type_str = "ed448";
            break;
        case EVP_PKEY_X448:
            type_str = "x448";
            break;
        default:
            break;
    }

    janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv(type_str));

    EVP_PKEY_free(pkey);

    return janet_wrap_table(info);
}
