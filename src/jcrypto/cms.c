/*
 * jcrypto/cms.c - CMS/PKCS#7 functions for SCEP support
 */

#include "internal.h"

/* CMS/PKCS#7 Sign - Create signed data structure */
Janet cfun_cms_sign(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);
    JanetByteView cert_pem = janet_getbytes(argv, 0);
    JanetByteView key_pem = janet_getbytes(argv, 1);
    JanetByteView data = janet_getbytes(argv, 2);

    int detached = 0;
    if (argc > 3) {
        Janet opts = argv[3];
        if (janet_checktype(opts, JANET_TABLE) ||
            janet_checktype(opts, JANET_STRUCT)) {
            Janet val = janet_get(opts, janet_ckeywordv("detached"));
            if (janet_truthy(val)) detached = 1;
        }
    }

    /* Load certificate */
    BIO *cert_bio = BIO_new_mem_buf(cert_pem.bytes, cert_pem.len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio);
    if (!cert) crypto_panic_ssl("failed to load certificate");

    /* Load private key */
    BIO *key_bio = BIO_new_mem_buf(key_pem.bytes, key_pem.len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(key_bio);
    if (!pkey) {
        X509_free(cert);
        crypto_panic_ssl("failed to load private key");
    }

    /* Create signed data */
    BIO *data_bio = BIO_new_mem_buf(data.bytes, data.len);
    unsigned int flags = CMS_BINARY;
    if (detached) flags |= (unsigned int)CMS_DETACHED;

    CMS_ContentInfo *cms = CMS_sign(cert, pkey, NULL, data_bio, flags);
    BIO_free(data_bio);

    if (!cms) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to create CMS signed data");
    }

    /* Export to DER */
    BIO *out = BIO_new(BIO_s_mem());
    if (!i2d_CMS_bio(out, cms)) {
        BIO_free(out);
        CMS_ContentInfo_free(cms);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to encode CMS");
    }

    char *out_data;
    long out_len = BIO_get_mem_data(out, &out_data);
    Janet result = janet_stringv((const uint8_t *)out_data, out_len);

    BIO_free(out);
    CMS_ContentInfo_free(cms);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return result;
}

/* CMS/PKCS#7 Verify - Verify signed data */
Janet cfun_cms_verify(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 3);
    JanetByteView cms_der = janet_getbytes(argv, 0);

    /* Optional: trusted certificates for verification */
    STACK_OF(X509) *certs = NULL;
    X509_STORE *store = NULL;
    unsigned int flags = CMS_BINARY | (unsigned int)CMS_NO_SIGNER_CERT_VERIFY;

    if (argc > 1 && !janet_checktype(argv[1], JANET_NIL)) {
        /* Load trusted certs */
        JanetByteView trust_pem = janet_getbytes(argv, 1);
        BIO *trust_bio = BIO_new_mem_buf(trust_pem.bytes, trust_pem.len);
        store = X509_STORE_new();
        X509 *trust_cert;
        while ((trust_cert = PEM_read_bio_X509(trust_bio, NULL, NULL,
                                               NULL)) != NULL) {
            X509_STORE_add_cert(store, trust_cert);
            X509_free(trust_cert);
        }
        BIO_free(trust_bio);
        flags = CMS_BINARY;  /* Enable full verification */
    }

    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        JanetByteView detached_data = janet_getbytes(argv, 2);
        flags |= (unsigned int)CMS_DETACHED;
        /* Note: detached data handling would need additional implementation */
        (void)detached_data;
    }

    /* Parse CMS */
    BIO *cms_bio = BIO_new_mem_buf(cms_der.bytes, cms_der.len);
    CMS_ContentInfo *cms = d2i_CMS_bio(cms_bio, NULL);
    BIO_free(cms_bio);

    if (!cms) {
        if (store) X509_STORE_free(store);
        crypto_panic_ssl("failed to parse CMS data");
    }

    /* Verify and extract content */
    BIO *content = BIO_new(BIO_s_mem());
    int verify_result = CMS_verify(cms, certs, store, NULL, content, flags);

    JanetTable *result = janet_table(3);
    janet_table_put(result, janet_ckeywordv("valid"),
                    janet_wrap_boolean(verify_result == 1));

    /* Extract content if verification succeeded */
    if (verify_result == 1) {
        char *content_data;
        long content_len = BIO_get_mem_data(content, &content_data);
        janet_table_put(result, janet_ckeywordv("content"),
                        janet_stringv((const uint8_t *)content_data, content_len));
    }

    /* Extract signer certificates */
    STACK_OF(X509) *signers = CMS_get0_signers(cms);
    if (signers && sk_X509_num(signers) > 0) {
        JanetArray *signer_arr = janet_array(sk_X509_num(signers));
        for (int i = 0; i < sk_X509_num(signers); i++) {
            X509 *signer = sk_X509_value(signers, i);
            BIO *signer_bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(signer_bio, signer);
            char *signer_data;
            long signer_len = BIO_get_mem_data(signer_bio, &signer_data);
            janet_array_push(signer_arr, janet_stringv((const uint8_t *)signer_data,
                             signer_len));
            BIO_free(signer_bio);
        }
        janet_table_put(result, janet_ckeywordv("signers"),
                        janet_wrap_array(signer_arr));
        sk_X509_free(signers);
    }

    BIO_free(content);
    CMS_ContentInfo_free(cms);
    if (store) X509_STORE_free(store);

    return janet_wrap_table(result);
}

/* CMS/PKCS#7 Encrypt - Create enveloped data */
Janet cfun_cms_encrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView data = janet_getbytes(argv, 0);

    /* Recipient certificates */
    STACK_OF(X509) *recips = sk_X509_new_null();

    Janet certs_arg = argv[1];
    if (janet_checktype(certs_arg, JANET_STRING) ||
        janet_checktype(certs_arg, JANET_BUFFER)) {
        /* Single certificate */
        JanetByteView cert_pem = janet_getbytes(argv, 1);
        BIO *cert_bio = BIO_new_mem_buf(cert_pem.bytes, cert_pem.len);
        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        BIO_free(cert_bio);
        if (!cert) {
            sk_X509_free(recips);
            crypto_panic_ssl("failed to load recipient certificate");
        }
        sk_X509_push(recips, cert);
    } else if (janet_checktype(certs_arg, JANET_ARRAY) ||
               janet_checktype(certs_arg, JANET_TUPLE)) {
        /* Array of certificates */
        const Janet *certs;
        int32_t certs_len;
        janet_indexed_view(certs_arg, &certs, &certs_len);
        for (int32_t i = 0; i < certs_len; i++) {
            JanetByteView cert_pem = janet_getbytes(certs, i);
            BIO *cert_bio = BIO_new_mem_buf(cert_pem.bytes, cert_pem.len);
            X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
            BIO_free(cert_bio);
            if (!cert) {
                sk_X509_pop_free(recips, X509_free);
                crypto_panic_config("failed to load recipient certificate %d", i);
            }
            sk_X509_push(recips, cert);
        }
    } else {
        sk_X509_free(recips);
        crypto_panic_config("certificates must be string or array of strings");
    }

    /* Default cipher: AES-256-CBC */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        Janet opts = argv[2];
        if (janet_checktype(opts, JANET_TABLE) ||
            janet_checktype(opts, JANET_STRUCT)) {
            Janet cipher_val = janet_get(opts, janet_ckeywordv("cipher"));
            if (janet_checktype(cipher_val, JANET_KEYWORD)) {
                const char *cipher_name = (const char *)janet_unwrap_keyword(cipher_val);
                if (strcmp(cipher_name, "aes-128-cbc") == 0) cipher = EVP_aes_128_cbc();
                else if (strcmp(cipher_name, "aes-192-cbc") == 0) cipher = EVP_aes_192_cbc();
                else if (strcmp(cipher_name, "aes-256-cbc") == 0) cipher = EVP_aes_256_cbc();
                else if (strcmp(cipher_name, "des3") == 0 || strcmp(cipher_name, "3des") == 0)
                    cipher = EVP_des_ede3_cbc();
            }
        }
    }

    /* Create enveloped data */
    BIO *data_bio = BIO_new_mem_buf(data.bytes, data.len);
    CMS_ContentInfo *cms = CMS_encrypt(recips, data_bio, cipher, CMS_BINARY);
    BIO_free(data_bio);
    sk_X509_pop_free(recips, X509_free);

    if (!cms) crypto_panic_ssl("failed to create CMS enveloped data");

    /* Export to DER */
    BIO *out = BIO_new(BIO_s_mem());
    if (!i2d_CMS_bio(out, cms)) {
        BIO_free(out);
        CMS_ContentInfo_free(cms);
        crypto_panic_ssl("failed to encode CMS");
    }

    char *out_data;
    long out_len = BIO_get_mem_data(out, &out_data);
    Janet result = janet_stringv((const uint8_t *)out_data, out_len);

    BIO_free(out);
    CMS_ContentInfo_free(cms);

    return result;
}

/* CMS/PKCS#7 Decrypt - Decrypt enveloped data */
Janet cfun_cms_decrypt(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetByteView cms_der = janet_getbytes(argv, 0);
    JanetByteView cert_pem = janet_getbytes(argv, 1);
    JanetByteView key_pem = janet_getbytes(argv, 2);

    /* Load certificate */
    BIO *cert_bio = BIO_new_mem_buf(cert_pem.bytes, cert_pem.len);
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio);
    if (!cert) crypto_panic_ssl("failed to load certificate");

    /* Load private key */
    BIO *key_bio = BIO_new_mem_buf(key_pem.bytes, key_pem.len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(key_bio);
    if (!pkey) {
        X509_free(cert);
        crypto_panic_ssl("failed to load private key");
    }

    /* Parse CMS */
    BIO *cms_bio = BIO_new_mem_buf(cms_der.bytes, cms_der.len);
    CMS_ContentInfo *cms = d2i_CMS_bio(cms_bio, NULL);
    BIO_free(cms_bio);

    if (!cms) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to parse CMS data");
    }

    /* Decrypt */
    BIO *content = BIO_new(BIO_s_mem());
    if (!CMS_decrypt(cms, pkey, cert, NULL, content, 0)) {
        BIO_free(content);
        CMS_ContentInfo_free(cms);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to decrypt CMS data");
    }

    char *content_data;
    long content_len = BIO_get_mem_data(content, &content_data);
    Janet result = janet_stringv((const uint8_t *)content_data, content_len);

    BIO_free(content);
    CMS_ContentInfo_free(cms);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return result;
}

/* Create degenerate signed data (certificate-only PKCS#7) - used in SCEP */
Janet cfun_cms_certs_only(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    STACK_OF(X509) *certs = sk_X509_new_null();

    Janet certs_arg = argv[0];
    if (janet_checktype(certs_arg, JANET_STRING) ||
        janet_checktype(certs_arg, JANET_BUFFER)) {
        /* Single certificate */
        JanetByteView cert_pem = janet_getbytes(argv, 0);
        BIO *cert_bio = BIO_new_mem_buf(cert_pem.bytes, cert_pem.len);
        X509 *cert;
        while ((cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL) {
            sk_X509_push(certs, cert);
        }
        BIO_free(cert_bio);
    } else if (janet_checktype(certs_arg, JANET_ARRAY) ||
               janet_checktype(certs_arg, JANET_TUPLE)) {
        const Janet *cert_arr;
        int32_t cert_len;
        janet_indexed_view(certs_arg, &cert_arr, &cert_len);
        for (int32_t i = 0; i < cert_len; i++) {
            JanetByteView cert_pem = janet_getbytes(cert_arr, i);
            BIO *cert_bio = BIO_new_mem_buf(cert_pem.bytes, cert_pem.len);
            X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
            BIO_free(cert_bio);
            if (cert) sk_X509_push(certs, cert);
        }
    }

    if (sk_X509_num(certs) == 0) {
        sk_X509_free(certs);
        crypto_panic_param("no certificates provided");
    }

    /* Create degenerate signed-data (no signers, just certs) */
    CMS_ContentInfo *cms = CMS_ContentInfo_new();
    if (!cms) {
        sk_X509_pop_free(certs, X509_free);
        crypto_panic_ssl("failed to create CMS structure");
    }

    /* Set as signed-data type */
    if (!CMS_SignedData_init(cms)) {
        CMS_ContentInfo_free(cms);
        sk_X509_pop_free(certs, X509_free);
        crypto_panic_ssl("failed to init CMS signed-data");
    }

    /* Add certificates */
    for (int i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        if (!CMS_add0_cert(cms, cert)) {
            CMS_ContentInfo_free(cms);
            sk_X509_pop_free(certs, X509_free);
            crypto_panic_ssl("failed to add certificate to CMS");
        }
    }
    /* Clear the stack but don't free certs (ownership transferred to CMS) */
    sk_X509_free(certs);

    /* Export to DER */
    BIO *out = BIO_new(BIO_s_mem());
    if (!i2d_CMS_bio(out, cms)) {
        BIO_free(out);
        CMS_ContentInfo_free(cms);
        crypto_panic_ssl("failed to encode CMS");
    }

    char *out_data;
    long out_len = BIO_get_mem_data(out, &out_data);
    Janet result = janet_stringv((const uint8_t *)out_data, out_len);

    BIO_free(out);
    CMS_ContentInfo_free(cms);

    return result;
}

/* Extract certificates from CMS/PKCS#7 structure */
Janet cfun_cms_get_certs(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView cms_der = janet_getbytes(argv, 0);

    BIO *cms_bio = BIO_new_mem_buf(cms_der.bytes, cms_der.len);
    CMS_ContentInfo *cms = d2i_CMS_bio(cms_bio, NULL);
    BIO_free(cms_bio);

    if (!cms) crypto_panic_ssl("failed to parse CMS data");

    STACK_OF(X509) *certs = CMS_get1_certs(cms);
    JanetArray *result = janet_array(certs ? sk_X509_num(certs) : 0);

    if (certs) {
        for (int i = 0; i < sk_X509_num(certs); i++) {
            X509 *cert = sk_X509_value(certs, i);
            BIO *cert_bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(cert_bio, cert);
            char *cert_data;
            long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
            janet_array_push(result, janet_stringv((const uint8_t *)cert_data, cert_len));
            BIO_free(cert_bio);
        }
        sk_X509_pop_free(certs, X509_free);
    }

    CMS_ContentInfo_free(cms);
    return janet_wrap_array(result);
}
