/*
 * jcrypto/pkcs12.c - PKCS#12 (PFX) bundle support
 *
 * Import/export PKCS#12 bundles for cross-platform certificate exchange.
 * Common in Windows environments for bundling certificates with private keys.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <openssl/pkcs12.h>

/*
 * Parse a PKCS#12 bundle
 * (crypto/parse-pkcs12 pfx-data password)
 * Returns {:cert <pem> :key <pem> :chain [<pem> ...] :friendly-name "name"}
 */
Janet cfun_parse_pkcs12(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView pfx_data = janet_getbytes(argv, 0);
    JanetByteView password_bv = janet_getbytes(argv, 1);
    const char *password = (const char *)password_bv.bytes;

    /* Parse PKCS#12 structure */
    BIO *bio = BIO_new_mem_buf(pfx_data.bytes, (int)pfx_data.len);
    if (!bio) crypto_panic_resource("failed to create BIO");

    PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio);

    if (!p12) {
        crypto_panic_ssl("failed to parse PKCS#12 data");
    }

    /* Extract contents */
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
        PKCS12_free(p12);
        crypto_panic_ssl("failed to decrypt PKCS#12 (wrong password?)");
    }

    JanetTable *result = janet_table(4);

    /* Export certificate */
    if (cert) {
        BIO *cert_bio = BIO_new(BIO_s_mem());
        if (cert_bio) {
            PEM_write_bio_X509(cert_bio, cert);
            char *data;
            long len = BIO_get_mem_data(cert_bio, &data);
            janet_table_put(result, janet_ckeywordv("cert"),
                            janet_stringv((const uint8_t *)data, (int32_t)len));
            BIO_free(cert_bio);
        }

        /* Get friendly name if present */
        int len;
        char *name = (char *)X509_alias_get0(cert, &len);
        if (name && len > 0) {
            janet_table_put(result, janet_ckeywordv("friendly-name"),
                            janet_stringv((const uint8_t *)name, len));
        }

        X509_free(cert);
    }

    /* Export private key */
    if (pkey) {
        BIO *key_bio = BIO_new(BIO_s_mem());
        if (key_bio) {
            PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL);
            char *data;
            long len = BIO_get_mem_data(key_bio, &data);
            janet_table_put(result, janet_ckeywordv("key"),
                            janet_stringv((const uint8_t *)data, (int32_t)len));
            BIO_free(key_bio);
        }
        EVP_PKEY_free(pkey);
    }

    /* Export CA chain */
    if (ca && sk_X509_num(ca) > 0) {
        JanetArray *chain = janet_array(sk_X509_num(ca));
        for (int i = 0; i < sk_X509_num(ca); i++) {
            X509 *ca_cert = sk_X509_value(ca, i);
            BIO *ca_bio = BIO_new(BIO_s_mem());
            if (ca_bio) {
                PEM_write_bio_X509(ca_bio, ca_cert);
                char *data;
                long len = BIO_get_mem_data(ca_bio, &data);
                janet_array_push(chain, janet_stringv((const uint8_t *)data, (int32_t)len));
                BIO_free(ca_bio);
            }
        }
        janet_table_put(result, janet_ckeywordv("chain"), janet_wrap_array(chain));
        sk_X509_pop_free(ca, X509_free);
    }

    PKCS12_free(p12);

    return janet_wrap_table(result);
}

/*
 * Create a PKCS#12 bundle
 * (crypto/create-pkcs12 cert-pem key-pem opts)
 * opts:
 *   :password "secret" - required
 *   :chain [<pem> ...] - CA certificates to include
 *   :friendly-name "My Cert" - friendly name attribute
 * Returns PKCS#12 bytes
 */
Janet cfun_create_pkcs12(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView cert_pem = janet_getbytes(argv, 0);
    JanetByteView key_pem = janet_getbytes(argv, 1);

    const char *password = NULL;
    const char *friendly_name = NULL;
    JanetArray *chain_arr = NULL;

    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        JanetTable *opts = NULL;
        JanetStruct opts_struct = NULL;

        if (janet_checktype(argv[2], JANET_TABLE)) {
            opts = janet_unwrap_table(argv[2]);
        } else if (janet_checktype(argv[2], JANET_STRUCT)) {
            opts_struct = janet_unwrap_struct(argv[2]);
        }

        Janet val;

        /* :password (required) */
        val = opts ? janet_table_get(opts, janet_ckeywordv("password"))
              : janet_struct_get(opts_struct, janet_ckeywordv("password"));
        if (!janet_checktype(val, JANET_NIL)) {
            JanetByteView pwd = janet_getbytes(&val, 0);
            password = (const char *)pwd.bytes;
        }

        /* :friendly-name */
        val = opts ? janet_table_get(opts, janet_ckeywordv("friendly-name"))
              : janet_struct_get(opts_struct, janet_ckeywordv("friendly-name"));
        if (!janet_checktype(val, JANET_NIL)) {
            JanetByteView name = janet_getbytes(&val, 0);
            friendly_name = (const char *)name.bytes;
        }

        /* :chain */
        val = opts ? janet_table_get(opts, janet_ckeywordv("chain"))
              : janet_struct_get(opts_struct, janet_ckeywordv("chain"));
        if (!janet_checktype(val, JANET_NIL)) {
            if (janet_checktype(val, JANET_ARRAY)) {
                chain_arr = janet_unwrap_array(val);
            } else if (janet_checktype(val, JANET_TUPLE)) {
                JanetTuple tup = janet_unwrap_tuple(val);
                chain_arr = janet_array(janet_tuple_length(tup));
                for (int32_t i = 0; i < janet_tuple_length(tup); i++) {
                    janet_array_push(chain_arr, tup[i]);
                }
            }
        }
    }

    if (!password || strlen(password) == 0) {
        crypto_panic_param("password is required for PKCS#12 creation");
    }

    /* Load certificate */
    BIO *cert_bio = BIO_new_mem_buf(cert_pem.bytes, (int)cert_pem.len);
    if (!cert_bio) crypto_panic_resource("failed to create BIO");

    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio);

    if (!cert) {
        crypto_panic_ssl("failed to parse certificate");
    }

    /* Load private key */
    BIO *key_bio = BIO_new_mem_buf(key_pem.bytes, (int)key_pem.len);
    if (!key_bio) {
        X509_free(cert);
        crypto_panic_resource("failed to create BIO");
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(key_bio);

    if (!pkey) {
        X509_free(cert);
        crypto_panic_ssl("failed to parse private key");
    }

    /* Load CA chain if provided */
    STACK_OF(X509) *ca = NULL;
    if (chain_arr && chain_arr->count > 0) {
        ca = sk_X509_new_null();
        for (int32_t i = 0; i < chain_arr->count; i++) {
            JanetByteView ca_pem = janet_getbytes(&chain_arr->data[i], 0);
            BIO *ca_bio = BIO_new_mem_buf(ca_pem.bytes, (int)ca_pem.len);
            if (ca_bio) {
                X509 *ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
                BIO_free(ca_bio);
                if (ca_cert) {
                    sk_X509_push(ca, ca_cert);
                }
            }
        }
    }

    /* Set friendly name if provided */
    if (friendly_name) {
        X509_alias_set1(cert, (unsigned char *)friendly_name,
                        (int)strlen(friendly_name));
    }

    /* Create PKCS#12 */
    PKCS12 *p12 = PKCS12_create(password, friendly_name, pkey, cert, ca,
                                0, 0, 0, 0, 0);

    /* Cleanup inputs */
    EVP_PKEY_free(pkey);
    X509_free(cert);
    if (ca) sk_X509_pop_free(ca, X509_free);

    if (!p12) {
        crypto_panic_ssl("failed to create PKCS#12");
    }

    /* Serialize to DER */
    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        PKCS12_free(p12);
        crypto_panic_resource("failed to create output BIO");
    }

    if (!i2d_PKCS12_bio(out, p12)) {
        BIO_free(out);
        PKCS12_free(p12);
        crypto_panic_ssl("failed to serialize PKCS#12");
    }

    char *data;
    long len = BIO_get_mem_data(out, &data);
    Janet result = janet_stringv((const uint8_t *)data, (int32_t)len);

    BIO_free(out);
    PKCS12_free(p12);

    return result;
}
