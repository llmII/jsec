/*
 * jcrypto/csr.c - Certificate Signing Request functions
 */

#include "internal.h"

/* ASCII case-insensitive match of the first plen bytes of entry against the
 * NUL-terminated keyword kw, mirroring OpenSSL's general-name type table. */
static int csr_prefix_is(const char *entry, int32_t plen, const char *kw) {
    for (int32_t i = 0; i < plen; i++) {
        if (kw[i] == 0) return 0;
        char a = entry[i];
        char b = kw[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
        if (a != b) return 0;
    }
    return kw[plen] == 0;
}

/* Push one string-valued general name (GEN_DNS, GEN_EMAIL, GEN_URI) onto
 * gens. The bytes are taken with an explicit length, so an entry keeps its
 * commas and embedded NULs exactly as given. Returns 0 on allocation
 * failure (no raise: the caller frees and raises). */
static int csr_san_push_ia5(GENERAL_NAMES *gens, int type, const char *value,
                            int32_t len) {
    ASN1_IA5STRING *str = ASN1_IA5STRING_new();
    GENERAL_NAME *gen = NULL;
    if (!str) return 0;
    if (!ASN1_STRING_set(str, value, len)) {
        ASN1_IA5STRING_free(str);
        return 0;
    }
    gen = GENERAL_NAME_new();
    if (!gen) {
        ASN1_IA5STRING_free(str);
        return 0;
    }
    GENERAL_NAME_set0_value(gen, type, str);
    if (!sk_GENERAL_NAME_push(gens, gen)) {
        GENERAL_NAME_free(gen);
        return 0;
    }
    return 1;
}

/* Push one GEN_IPADD name onto gens. Takes ownership of ip. Returns 0 on
 * allocation failure (no raise: the caller frees and raises). */
static int csr_san_push_ip(GENERAL_NAMES *gens, ASN1_OCTET_STRING *ip) {
    GENERAL_NAME *gen = GENERAL_NAME_new();
    if (!gen) {
        ASN1_OCTET_STRING_free(ip);
        return 0;
    }
    GENERAL_NAME_set0_value(gen, GEN_IPADD, ip);
    if (!sk_GENERAL_NAME_push(gens, gen)) {
        GENERAL_NAME_free(gen);
        return 0;
    }
    return 1;
}

/* Push one entry parsed with OpenSSL's subjectAltName value syntax, one
 * entry per call. This keeps the general names without a simple literal
 * spelling (otherName:, dirName:) working exactly as the old comma-joined
 * config call parsed them. Returns 0 when OpenSSL rejects the entry (no
 * raise: the caller frees and raises). */
static int csr_san_push_via_conf(GENERAL_NAMES *gens, const char *entry) {
    X509_EXTENSION *ext =
        X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, entry);
    if (!ext) {
        ERR_clear_error();
        return 0;
    }
    GENERAL_NAMES *parsed = X509V3_EXT_d2i(ext);
    X509_EXTENSION_free(ext);
    if (!parsed) {
        ERR_clear_error();
        return 0;
    }
    int ok = 1;
    while (sk_GENERAL_NAME_num(parsed) > 0) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_shift(parsed);
        if (!sk_GENERAL_NAME_push(gens, gen)) {
            GENERAL_NAME_free(gen);
            ok = 0;
            break;
        }
    }
    GENERAL_NAMES_free(parsed);
    return ok;
}

/* Build the SubjectAltName extension from a :san container and attach it to
 * req. Every entry becomes its own general name, so bare DNS/IP literals
 * are canonicalised like the jca builders (a2i_IPADDRESS classifies, else
 * DNS) and a comma inside an entry never splits it. A non-string entry, an
 * invalid container, or an entry OpenSSL cannot parse raises
 * [CRYPTO:PARAM]; failed extension pushes raise. Every raise frees gens,
 * req, and pkey first - no raise unwinds past live OpenSSL objects. */
static void csr_add_san(X509_REQ *req, EVP_PKEY *pkey, Janet san) {
    if (!janet_checktype(san, JANET_TUPLE) &&
        !janet_checktype(san, JANET_ARRAY)) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_param(":san must be a tuple or array of strings");
    }

    const Janet *entries;
    int32_t count;
    janet_indexed_view(san, &entries, &count);

    if (count == 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_param(":san must not be empty");
    }

    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    if (!gens) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_resource("failed to allocate subjectAltName entries");
    }

    for (int32_t i = 0; i < count; i++) {
        if (!janet_checktype(entries[i], JANET_STRING)) {
            GENERAL_NAMES_free(gens);
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param(":san entry %d must be a string, got %q", i,
                               entries[i]);
        }

        const uint8_t *bytes = janet_unwrap_string(entries[i]);
        const char *entry = (const char *)bytes;
        int32_t elen = janet_string_length(bytes);
        const char *colon = (const char *)memchr(entry, ':', (size_t)elen);
        int ok = 0;

        if (!colon) {
            ASN1_OCTET_STRING *ip = a2i_IPADDRESS(entry);
            ok = ip ? csr_san_push_ip(gens, ip)
                    : csr_san_push_ia5(gens, GEN_DNS, entry, elen);
        } else {
            int32_t plen = (int32_t)(colon - entry);
            const char *rest = colon + 1;
            int32_t rlen = elen - plen - 1;

            if (csr_prefix_is(entry, plen, "ip")) {
                ASN1_OCTET_STRING *ip = a2i_IPADDRESS(rest);
                if (!ip) ERR_clear_error();
                ok = ip && csr_san_push_ip(gens, ip);
            } else if (csr_prefix_is(entry, plen, "dns")) {
                ok = csr_san_push_ia5(gens, GEN_DNS, rest, rlen);
            } else if (csr_prefix_is(entry, plen, "email")) {
                ok = csr_san_push_ia5(gens, GEN_EMAIL, rest, rlen);
            } else if (csr_prefix_is(entry, plen, "uri")) {
                ok = csr_san_push_ia5(gens, GEN_URI, rest, rlen);
            } else if (csr_prefix_is(entry, plen, "rid")) {
                ASN1_OBJECT *obj = OBJ_txt2obj(rest, 0);
                if (!obj) {
                    ERR_clear_error();
                } else {
                    GENERAL_NAME *gen = GENERAL_NAME_new();
                    if (!gen) {
                        ASN1_OBJECT_free(obj);
                    } else {
                        GENERAL_NAME_set0_value(gen, GEN_RID, obj);
                        if (sk_GENERAL_NAME_push(gens, gen))
                            ok = 1;
                        else
                            GENERAL_NAME_free(gen);
                    }
                }
            } else {
                ok = csr_san_push_via_conf(gens, entry);
            }
        }

        if (!ok) {
            GENERAL_NAMES_free(gens);
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param(":san entry %q is not a valid subjectAltName",
                               entries[i]);
        }
    }

    X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
    GENERAL_NAMES_free(gens);
    if (!ext) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to encode the SubjectAltName extension");
    }

    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        X509_EXTENSION_free(ext);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_resource("failed to allocate the extension stack");
    }
    if (!sk_X509_EXTENSION_push(exts, ext)) {
        X509_EXTENSION_free(ext);
        sk_X509_EXTENSION_free(exts);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_resource("failed to collect the SubjectAltName extension");
    }
    if (!X509_REQ_add_extensions(req, exts)) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to add the SubjectAltName extension");
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
}

/* Resolve the :digest option to a message digest. A string or keyword names
 * the digest exactly like EVP_get_digestbyname spells it; anything else, and
 * any name it does not know, raises [CRYPTO:PARAM] instead of silently
 * signing with SHA-256. */
static const EVP_MD *csr_resolve_digest(X509_REQ *req, EVP_PKEY *pkey,
                                        Janet digest) {
    if (janet_checktype(digest, JANET_NIL)) return EVP_sha256();
    const char *name = NULL;
    if (janet_checktype(digest, JANET_KEYWORD)) {
        name = (const char *)janet_unwrap_keyword(digest);
    } else if (janet_checktype(digest, JANET_STRING)) {
        name = (const char *)janet_unwrap_string(digest);
    } else {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_param(":digest must be a string or keyword, got %q",
                           digest);
    }
    const EVP_MD *md = EVP_get_digestbyname(name);
    if (!md) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        crypto_panic_param("unknown :digest %q", digest);
    }
    return md;
}

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
    EVP_PKEY *pkey =
        PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    BIO_free(bio);
    if (!pkey) crypto_panic_ssl("failed to load private key");

    X509_REQ *req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        crypto_panic_ssl("failed to create CSR");
    }

    X509_REQ_set_version(req, 0); /* Version 1 */
    X509_REQ_set_pubkey(req, pkey);

    X509_NAME *name = X509_REQ_get_subject_name(req);

    /* Extract subject fields from options */
    Janet val;
    val = janet_get(opts, janet_ckeywordv("common-name"));
    if (janet_checktype(val, JANET_STRING)) {
        if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                        OSSL_STR(janet_unwrap_string(val)), -1,
                                        -1, 0)) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param("failed to add common-name entry");
        }
    }

    val = janet_get(opts, janet_ckeywordv("country"));
    if (janet_checktype(val, JANET_STRING)) {
        if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                        OSSL_STR(janet_unwrap_string(val)), -1,
                                        -1, 0)) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param("failed to add country entry");
        }
    }

    val = janet_get(opts, janet_ckeywordv("state"));
    if (janet_checktype(val, JANET_STRING)) {
        if (!X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
                                        OSSL_STR(janet_unwrap_string(val)), -1,
                                        -1, 0)) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param("failed to add state entry");
        }
    }

    val = janet_get(opts, janet_ckeywordv("locality"));
    if (janet_checktype(val, JANET_STRING)) {
        if (!X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                                        OSSL_STR(janet_unwrap_string(val)), -1,
                                        -1, 0)) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param("failed to add locality entry");
        }
    }

    val = janet_get(opts, janet_ckeywordv("organization"));
    if (janet_checktype(val, JANET_STRING)) {
        if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                        OSSL_STR(janet_unwrap_string(val)), -1,
                                        -1, 0)) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param("failed to add organization entry");
        }
    }

    val = janet_get(opts, janet_ckeywordv("organizational-unit"));
    if (janet_checktype(val, JANET_STRING)) {
        if (!X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                                        OSSL_STR(janet_unwrap_string(val)), -1,
                                        -1, 0)) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param("failed to add organizational-unit entry");
        }
    }

    val = janet_get(opts, janet_ckeywordv("email"));
    if (janet_checktype(val, JANET_STRING)) {
        if (!X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC,
                                        OSSL_STR(janet_unwrap_string(val)), -1,
                                        -1, 0)) {
            X509_REQ_free(req);
            EVP_PKEY_free(pkey);
            crypto_panic_param("failed to add email entry");
        }
    }

    /* Add Subject Alternative Names if provided */
    val = janet_get(opts, janet_ckeywordv("san"));
    if (!janet_checktype(val, JANET_NIL)) {
        csr_add_san(req, pkey, val);
    }

    /* Sign the CSR */
    val = janet_get(opts, janet_ckeywordv("digest"));
    const EVP_MD *md = csr_resolve_digest(req, pkey, val);
    /* Ed25519 is a pure signature scheme and takes no digest (NULL, like the
     * working pattern in jcert.c) */
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_ED25519) {
        md = NULL;
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
                        janet_stringv(ASN1_STRING_get0_data(str),
                                      ASN1_STRING_length(str)));
    }
    janet_table_put(result, janet_ckeywordv("subject"),
                    janet_wrap_table(subject));

    /* Extract public key algorithm */
    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
    if (pkey) {
        int key_type = EVP_PKEY_base_id(pkey);
        const char *key_type_str = "unknown";
        if (key_type == EVP_PKEY_RSA)
            key_type_str = "rsa";
        else if (key_type == EVP_PKEY_EC)
            key_type_str = "ec";
        else if (key_type == EVP_PKEY_ED25519)
            key_type_str = "ed25519";
        else if (key_type == EVP_PKEY_X25519)
            key_type_str = "x25519";

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
