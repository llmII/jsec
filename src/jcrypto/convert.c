/*
 * jcrypto/convert.c - Key and certificate format conversion
 *
 * Converts between PEM, DER, and PKCS#8 formats for keys and certificates.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "jcrypto_internal.h"
#include <openssl/pkcs12.h>

/*
 * Convert key between formats
 * (crypto/convert-key key-data target-format &opt opts)
 * target-format: :pem, :der, :pkcs8, :pkcs8-der
 * opts: {:password "secret"} for encrypted PKCS#8
 */
Janet cfun_convert_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView key_data = janet_getbytes(argv, 0);
    const uint8_t *format_kw = janet_getkeyword(argv, 1);
    const char *format = (const char *)format_kw;

    const char *password = NULL;

    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        if (janet_checktype(argv[2], JANET_TABLE)) {
            JanetTable *opts = janet_unwrap_table(argv[2]);
            Janet pwd_val = janet_table_get(opts, janet_ckeywordv("password"));
            if (!janet_checktype(pwd_val, JANET_NIL)) {
                JanetByteView pwd = janet_getbytes(&pwd_val, 0);
                password = (const char *)pwd.bytes;
            }
        } else if (janet_checktype(argv[2], JANET_STRUCT)) {
            JanetStruct opts = janet_unwrap_struct(argv[2]);
            Janet pwd_val = janet_struct_get(opts, janet_ckeywordv("password"));
            if (!janet_checktype(pwd_val, JANET_NIL)) {
                JanetByteView pwd = janet_getbytes(&pwd_val, 0);
                password = (const char *)pwd.bytes;
            }
        }
    }

    /* Try to load as PEM first, then DER */
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    /* Try PEM private key */
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        /* Reset and try PEM public key */
        BIO_free(bio);
        bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    if (!pkey) {
        /* Reset and try DER private key */
        BIO_free(bio);
        bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
        pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    if (!pkey) {
        /* Reset and try DER public key */
        BIO_free(bio);
        bio = BIO_new_mem_buf(key_data.bytes, (int)key_data.len);
        pkey = d2i_PUBKEY_bio(bio, NULL);
    }
    BIO_free(bio);

    if (!pkey) {
        crypto_panic_ssl("failed to load key (tried PEM and DER formats)");
    }

    /* Output in requested format */
    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        EVP_PKEY_free(pkey);
        crypto_panic_resource("failed to create output BIO");
    }

    int result = 0;

    if (strcmp(format, "pem") == 0) {
        /* Output as PEM */
        result = PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
        if (!result) {
            /* Try public key */
            result = PEM_write_bio_PUBKEY(out, pkey);
        }
    } else if (strcmp(format, "der") == 0) {
        /* Output as DER */
        result = i2d_PrivateKey_bio(out, pkey);
        if (!result) {
            result = i2d_PUBKEY_bio(out, pkey);
        }
    } else if (strcmp(format, "pkcs8") == 0) {
        /* Output as PKCS#8 PEM */
        if (password && strlen(password) > 0) {
            result = PEM_write_bio_PKCS8PrivateKey(out, pkey, EVP_aes_256_cbc(),
                                                   (char *)password, (int)strlen(password),
                                                   NULL, NULL);
        } else {
            result = PEM_write_bio_PKCS8PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
        }
    } else if (strcmp(format, "pkcs8-der") == 0) {
        /* Output as PKCS#8 DER */
        if (password && strlen(password) > 0) {
            /* For encrypted PKCS#8 DER, we write encrypted PEM then convert */
            /* This is simpler and more portable across OpenSSL versions */
            PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(pkey);
            if (p8inf) {
                X509_SIG *p8 = PKCS8_encrypt(-1, EVP_aes_256_cbc(), password,
                                             (int)strlen(password),
                                             NULL, 0, 0, p8inf);
                PKCS8_PRIV_KEY_INFO_free(p8inf);
                if (p8) {
                    result = i2d_PKCS8_bio(out, p8);
                    X509_SIG_free(p8);
                }
            }
        } else {
            PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(pkey);
            if (p8inf) {
                result = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf);
                PKCS8_PRIV_KEY_INFO_free(p8inf);
            }
        }
    } else {
        BIO_free(out);
        EVP_PKEY_free(pkey);
        crypto_panic_param("unsupported format: %s (supported: pem, der, pkcs8, pkcs8-der)",
                           format);
    }

    if (!result) {
        BIO_free(out);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to convert key");
    }

    char *data;
    long len = BIO_get_mem_data(out, &data);
    Janet ret = janet_stringv((const uint8_t *)data, (int32_t)len);

    BIO_free(out);
    EVP_PKEY_free(pkey);

    return ret;
}

/*
 * Convert certificate between formats
 * (crypto/convert-cert cert-data target-format)
 * target-format: :pem, :der
 */
Janet cfun_convert_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView cert_data = janet_getbytes(argv, 0);
    const uint8_t *format_kw = janet_getkeyword(argv, 1);
    const char *format = (const char *)format_kw;

    /* Try to load as PEM first, then DER */
    X509 *cert = NULL;
    BIO *bio = BIO_new_mem_buf(cert_data.bytes, (int)cert_data.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        bio = BIO_new_mem_buf(cert_data.bytes, (int)cert_data.len);
        cert = d2i_X509_bio(bio, NULL);
    }
    BIO_free(bio);

    if (!cert) {
        crypto_panic_ssl("failed to load certificate");
    }

    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        X509_free(cert);
        crypto_panic_resource("failed to create output BIO");
    }

    int result = 0;

    if (strcmp(format, "pem") == 0) {
        result = PEM_write_bio_X509(out, cert);
    } else if (strcmp(format, "der") == 0) {
        result = i2d_X509_bio(out, cert);
    } else {
        BIO_free(out);
        X509_free(cert);
        crypto_panic_param("unsupported format: %s (supported: pem, der)", format);
    }

    if (!result) {
        BIO_free(out);
        X509_free(cert);
        crypto_panic_ssl("failed to convert certificate");
    }

    char *data;
    long len = BIO_get_mem_data(out, &data);
    Janet ret = janet_stringv((const uint8_t *)data, (int32_t)len);

    BIO_free(out);
    X509_free(cert);

    return ret;
}

/*
 * Detect format of key or certificate data
 * (crypto/detect-format data)
 * Returns :pem or :der
 */
Janet cfun_detect_format(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView data = janet_getbytes(argv, 0);

    /* PEM format starts with "-----BEGIN" */
    if (data.len >= 11 && memcmp(data.bytes, "-----BEGIN", 10) == 0) {
        return janet_ckeywordv("pem");
    }

    /* Otherwise assume DER (binary) */
    return janet_ckeywordv("der");
}
