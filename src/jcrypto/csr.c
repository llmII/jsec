/*
 * jcrypto/csr.c - Certificate Signing Request functions
 */

#include "internal.h"

/* Generate CSR (Certificate Signing Request) */
Janet cfun_generate_csr(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView key_pem = janet_getbytes(argv, 0);
    Janet opts = argv[1];

    if (!janet_checktype(opts, JANET_TABLE) &&
        !janet_checktype(opts, JANET_STRUCT)) {
        crypto_panic_param("options must be a table or struct");
    }

    /* Load private key */
    BIO *bio = BIO_new_mem_buf(key_pem.bytes, key_pem.len);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(bio);
    if (!pkey) crypto_panic_ssl("failed to load private key");

    X509_REQ *req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to create CSR");
    }

    X509_REQ_set_version(req, 0);  /* Version 1 */
    X509_REQ_set_pubkey(req, pkey);

    X509_NAME *name = X509_REQ_get_subject_name(req);

    /* Extract subject fields from options */
    Janet val;
    val = janet_get(opts, janet_ckeywordv("common-name"));
    if (janet_checktype(val, JANET_STRING)) {
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   OSSL_STR(janet_unwrap_string(val)), -1, -1, 0);
    }

    val = janet_get(opts, janet_ckeywordv("country"));
    if (janet_checktype(val, JANET_STRING)) {
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                   OSSL_STR(janet_unwrap_string(val)), -1, -1, 0);
    }

    val = janet_get(opts, janet_ckeywordv("state"));
    if (janet_checktype(val, JANET_STRING)) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
                                   OSSL_STR(janet_unwrap_string(val)), -1, -1, 0);
    }

    val = janet_get(opts, janet_ckeywordv("locality"));
    if (janet_checktype(val, JANET_STRING)) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                                   OSSL_STR(janet_unwrap_string(val)), -1, -1, 0);
    }

    val = janet_get(opts, janet_ckeywordv("organization"));
    if (janet_checktype(val, JANET_STRING)) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                   OSSL_STR(janet_unwrap_string(val)), -1, -1, 0);
    }

    val = janet_get(opts, janet_ckeywordv("organizational-unit"));
    if (janet_checktype(val, JANET_STRING)) {
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                                   OSSL_STR(janet_unwrap_string(val)), -1, -1, 0);
    }

    val = janet_get(opts, janet_ckeywordv("email"));
    if (janet_checktype(val, JANET_STRING)) {
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC,
                                   OSSL_STR(janet_unwrap_string(val)), -1, -1, 0);
    }

    /* Add Subject Alternative Names if provided */
    val = janet_get(opts, janet_ckeywordv("san"));
    if (janet_checktype(val, JANET_TUPLE) || janet_checktype(val, JANET_ARRAY)) {
        const Janet *san_arr;
        int32_t san_len;
        janet_indexed_view(val, &san_arr, &san_len);

        if (san_len > 0) {
            STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
            JanetBuffer *san_buf = janet_buffer(256);

            for (int32_t i = 0; i < san_len; i++) {
                if (!janet_checktype(san_arr[i], JANET_STRING)) continue;
                const uint8_t *san = janet_unwrap_string(san_arr[i]);
                if (i > 0) janet_buffer_push_u8(san_buf, ',');
                janet_buffer_push_cstring(san_buf, (const char *)san);
            }

            X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                                  (char *)san_buf->data);
            if (ext) {
                sk_X509_EXTENSION_push(exts, ext);
                X509_REQ_add_extensions(req, exts);
            }
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }

    /* Sign the CSR */
    const EVP_MD *md = EVP_sha256();
    val = janet_get(opts, janet_ckeywordv("digest"));
    if (janet_checktype(val, JANET_KEYWORD)) {
        const char *digest_name = (const char *)janet_unwrap_keyword(val);
        const EVP_MD *custom_md = EVP_get_digestbyname(digest_name);
        if (custom_md) md = custom_md;
    }

    if (!X509_REQ_sign(req, pkey, md)) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to sign CSR");
    }

    /* Export to PEM */
    BIO *out = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509_REQ(out, req)) {
        BIO_free(out);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to export CSR");
    }

    char *data;
    long len = BIO_get_mem_data(out, &data);
    Janet result = janet_stringv((const uint8_t *)data, len);

    BIO_free(out);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return result;
}

/* Parse CSR */
Janet cfun_parse_csr(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView csr_pem = janet_getbytes(argv, 0);

    BIO *bio = BIO_new_mem_buf(csr_pem.bytes, csr_pem.len);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!req) crypto_panic_ssl("failed to parse CSR");

    JanetTable *result = janet_table(8);

    /* Extract subject */
    X509_NAME *name = X509_REQ_get_subject_name(req);
    int count = X509_NAME_entry_count(name);

    JanetTable *subject = janet_table(count);
    for (int i = 0; i < count; i++) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING *str = X509_NAME_ENTRY_get_data(entry);

        char obj_buf[128];
        OBJ_obj2txt(obj_buf, sizeof(obj_buf), obj, 0);

        janet_table_put(subject, janet_ckeywordv(obj_buf),
                        janet_stringv(ASN1_STRING_get0_data(str), ASN1_STRING_length(str)));
    }
    janet_table_put(result, janet_ckeywordv("subject"),
                    janet_wrap_table(subject));

    /* Extract public key algorithm */
    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
    if (pkey) {
        int key_type = EVP_PKEY_base_id(pkey);
        const char *key_type_str = "unknown";
        if (key_type == EVP_PKEY_RSA) key_type_str = "rsa";
        else if (key_type == EVP_PKEY_EC) key_type_str = "ec";
        else if (key_type == EVP_PKEY_ED25519) key_type_str = "ed25519";
        else if (key_type == EVP_PKEY_X25519) key_type_str = "x25519";

        janet_table_put(result, janet_ckeywordv("key-type"),
                        janet_ckeywordv(key_type_str));
        janet_table_put(result, janet_ckeywordv("key-bits"),
                        janet_wrap_number(EVP_PKEY_bits(pkey)));
        EVP_PKEY_free(pkey);
    }

    /* Verify signature */
    pkey = X509_REQ_get_pubkey(req);
    if (pkey) {
        int verify = X509_REQ_verify(req, pkey);
        janet_table_put(result, janet_ckeywordv("signature-valid"),
                        janet_wrap_boolean(verify == 1));
        EVP_PKEY_free(pkey);
    }

    X509_REQ_free(req);
    return janet_wrap_table(result);
}
