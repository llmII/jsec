/*
 * jca/types.c - CA abstract type definition and constructors
 *
 * Provides:
 * - JanetCA type with GC management
 * - ca/create - Create CA from existing cert+key
 * - ca/generate - Generate new root CA
 * - ca/generate-intermediate - Generate intermediate CA
 *
 * Author: jsec project
 * License: ISC
 */

#include "internal.h"
#include <openssl/rand.h>

/*
 * =============================================================================
 * GC Callbacks
 * =============================================================================
 */

int ca_gc(void *p, size_t s) {
    (void)s;
    JanetCA *ca = (JanetCA *)p;

    if (ca->cert) {
        X509_free(ca->cert);
        ca->cert = NULL;
    }
    if (ca->key) {
        EVP_PKEY_free(ca->key);
        ca->key = NULL;
    }
    if (ca->issued) {
        sk_X509_pop_free(ca->issued, X509_free);
        ca->issued = NULL;
    }
    if (ca->revoked) {
        sk_X509_REVOKED_pop_free(ca->revoked, X509_REVOKED_free);
        ca->revoked = NULL;
    }

    return 0;
}

int ca_gcmark(void *p, size_t s) {
    (void)p;
    (void)s;
    /* No Janet values to mark */
    return 0;
}

/*
 * =============================================================================
 * Method Table
 * =============================================================================
 */

const JanetMethod ca_methods[] = {
    /* sign.c methods */
    {"sign-csr", cfun_ca_sign_csr},
    {"issue", cfun_ca_issue},
    {"get-cert", cfun_ca_get_cert},
    {"get-serial", cfun_ca_get_serial},
    {"set-serial", cfun_ca_set_serial},
    {"is-tracking", cfun_ca_is_tracking},
    {"get-issued", cfun_ca_get_issued},

    /* crl.c methods */
    {"revoke", cfun_ca_revoke},
    {"generate-crl", cfun_ca_generate_crl},
    {"get-revoked", cfun_ca_get_revoked},

    /* ocsp.c methods */
    {"parse-ocsp-request", cfun_ca_parse_ocsp_request},
    {"create-ocsp-response", cfun_ca_create_ocsp_response},

    {NULL, NULL}
};

int ca_get(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }
    return janet_getmethod(janet_unwrap_keyword(key), ca_methods, out);
}

/*
 * =============================================================================
 * Abstract Type Definition
 * =============================================================================
 */

const JanetAbstractType ca_type = {
    "ca/CA",
    ca_gc,
    ca_gcmark,
    ca_get,
    NULL,  /* put */
    NULL,  /* marshal */
    NULL,  /* unmarshal */
    NULL,  /* tostring */
    NULL,  /* compare */
    NULL,  /* hash */
    NULL,  /* next */
    JANET_ATEND_NEXT
};

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/* Load X509 from PEM string or buffer */
X509 *ca_pem_to_x509(Janet pem) {
    JanetByteView bytes = janet_getbytes(&pem, 0);
    BIO *bio = BIO_new_mem_buf(bytes.bytes, (int)bytes.len);
    if (!bio) {
        ca_panic_resource("failed to create BIO for certificate");
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) {
        ca_panic_ssl("failed to parse certificate PEM");
    }

    return cert;
}

/* Load EVP_PKEY from PEM string or buffer */
EVP_PKEY *ca_pem_to_key(Janet pem) {
    JanetByteView bytes = janet_getbytes(&pem, 0);
    BIO *bio = BIO_new_mem_buf(bytes.bytes, (int)bytes.len);
    if (!bio) {
        ca_panic_resource("failed to create BIO for private key");
    }

    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb,
                                            NULL);
    BIO_free(bio);

    if (!key) {
        ca_panic_ssl("failed to parse private key PEM");
    }

    return key;
}

/* Convert X509 to PEM string */
Janet ca_x509_to_pem(X509 *cert) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ca_panic_resource("failed to create BIO");
    }

    if (!PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        ca_panic_ssl("failed to write certificate PEM");
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    Janet result = janet_stringv((const uint8_t *)data, (int32_t)len);
    BIO_free(bio);

    return result;
}

/* Convert EVP_PKEY to PEM string */
Janet ca_key_to_pem(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ca_panic_resource("failed to create BIO");
    }

    if (!PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio);
        ca_panic_ssl("failed to write private key PEM");
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    Janet result = janet_stringv((const uint8_t *)data, (int32_t)len);
    BIO_free(bio);

    return result;
}

/* Generate keypair based on type keyword */
EVP_PKEY *ca_generate_keypair(Janet key_type) {
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    const char *type_str = "ec-p256";  /* default */
    if (!janet_checktype(key_type, JANET_NIL)) {
        type_str = janet_to_string_or_keyword(key_type);
    }

    if (strcmp(type_str, "ec-p256") == 0 || strcmp(type_str, "ec") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx) goto error;
        if (EVP_PKEY_keygen_init(ctx) <= 0) goto error;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                NID_X9_62_prime256v1) <= 0) goto error;
        if (EVP_PKEY_keygen(ctx, &key) <= 0) goto error;
    } else if (strcmp(type_str, "ec-p384") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx) goto error;
        if (EVP_PKEY_keygen_init(ctx) <= 0) goto error;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                NID_secp384r1) <= 0) goto error;
        if (EVP_PKEY_keygen(ctx, &key) <= 0) goto error;
    } else if (strcmp(type_str, "ec-p521") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx) goto error;
        if (EVP_PKEY_keygen_init(ctx) <= 0) goto error;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx,
                NID_secp521r1) <= 0) goto error;
        if (EVP_PKEY_keygen(ctx, &key) <= 0) goto error;
    } else if (strcmp(type_str, "rsa-2048") == 0 ||
               strcmp(type_str, "rsa") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) goto error;
        if (EVP_PKEY_keygen_init(ctx) <= 0) goto error;
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto error;
        if (EVP_PKEY_keygen(ctx, &key) <= 0) goto error;
    } else if (strcmp(type_str, "rsa-4096") == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) goto error;
        if (EVP_PKEY_keygen_init(ctx) <= 0) goto error;
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0) goto error;
        if (EVP_PKEY_keygen(ctx, &key) <= 0) goto error;
    } else {
        ca_panic_param("unknown key type: %s (expected ec-p256, ec-p384, ec-p521, rsa-2048, rsa-4096)",
                       type_str);
    }

    EVP_PKEY_CTX_free(ctx);
    return key;

error:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (key) EVP_PKEY_free(key);
    ca_panic_ssl("failed to generate keypair");
    return NULL;  /* unreachable */
}

/* Add X509v3 extension to certificate */
int ca_add_extension(X509 *cert, X509 *issuer, int nid, const char *value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ext) {
        return 0;
    }

    int result = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    return result;
}

/* Get next serial and increment atomically */
int64_t ca_next_serial(JanetCA *ca) {
    return ca->serial++;
}

/*
 * =============================================================================
 * ca/create - Create CA from existing cert+key
 * =============================================================================
 */

static const char *cfun_ca_create_docstring =
    "(ca/create cert-pem key-pem &opt opts)\n\n"
    "Create a CA from existing certificate and private key PEM data.\n\n"
    "Options:\n"
    "  :serial <number>       - Starting serial number (default: 1)\n"
    "  :track-issued <bool>   - Track issued certificates (default: false)\n\n"
    "Returns a CA object that can sign CSRs and issue certificates.";

Janet cfun_ca_create(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    Janet cert_pem = argv[0];
    Janet key_pem = argv[1];
    Janet opts = argc > 2 ? argv[2] : janet_wrap_nil();

    /* Parse options */
    int64_t serial = 1;
    int track_issued = 0;

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "serial");
        if (!janet_checktype(v, JANET_NIL)) {
            serial = janet_getinteger64(&v, 0);
        }

        v = ca_opts_get(opts, "track-issued");
        if (janet_truthy(v)) {
            track_issued = 1;
        }
    }

    /* Load cert and key */
    X509 *cert = ca_pem_to_x509(cert_pem);
    EVP_PKEY *key = ca_pem_to_key(key_pem);

    /* Verify key matches cert */
    if (!X509_check_private_key(cert, key)) {
        X509_free(cert);
        EVP_PKEY_free(key);
        ca_panic_verify("private key does not match certificate");
    }

    /* Create CA object */
    JanetCA *ca = janet_abstract(&ca_type, sizeof(JanetCA));
    ca->cert = cert;
    ca->key = key;
    ca->serial = serial;
    ca->track_issued = track_issued;
    ca->issued = track_issued ? sk_X509_new_null() : NULL;
    ca->revoked = sk_X509_REVOKED_new_null();

    return janet_wrap_abstract(ca);
}

/*
 * =============================================================================
 * ca/generate - Generate new root CA
 * =============================================================================
 */

static const char *cfun_ca_generate_docstring =
    "(ca/generate &opt opts)\n\n"
    "Generate a new self-signed root CA certificate.\n\n"
    "Options:\n"
    "  :common-name <string>  - CA common name (default: \"Root CA\")\n"
    "  :days-valid <number>   - Validity period in days (default: 3650)\n"
    "  :key-type <keyword>    - Key type: :ec-p256, :ec-p384, :rsa-2048, :rsa-4096 (default: :ec-p256)\n"
    "  :serial <number>       - Starting serial number (default: 1)\n"
    "  :track-issued <bool>   - Track issued certificates (default: false)\n"
    "  :organization <string> - Organization name\n"
    "  :country <string>      - Country code (2 letters)\n\n"
    "Returns a CA object.";

Janet cfun_ca_generate(int32_t argc, Janet *argv) {
    janet_arity(argc, 0, 1);

    Janet opts = argc > 0 ? argv[0] : janet_wrap_nil();

    /* Parse options */
    const char *common_name = "Root CA";
    int days_valid = 3650;
    Janet key_type = janet_wrap_nil();
    int64_t serial = 1;
    int track_issued = 0;
    const char *organization = NULL;
    const char *country = NULL;

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "common-name");
        if (!janet_checktype(v, JANET_NIL)) {
            common_name = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "days-valid");
        if (!janet_checktype(v, JANET_NIL)) {
            days_valid = janet_getinteger(&v, 0);
        }

        v = ca_opts_get(opts, "key-type");
        if (!janet_checktype(v, JANET_NIL)) {
            key_type = v;
        }

        v = ca_opts_get(opts, "serial");
        if (!janet_checktype(v, JANET_NIL)) {
            serial = janet_getinteger64(&v, 0);
        }

        v = ca_opts_get(opts, "track-issued");
        if (janet_truthy(v)) {
            track_issued = 1;
        }

        v = ca_opts_get(opts, "organization");
        if (!janet_checktype(v, JANET_NIL)) {
            organization = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "country");
        if (!janet_checktype(v, JANET_NIL)) {
            country = janet_to_string_or_keyword(v);
        }
    }

    /* Generate keypair */
    EVP_PKEY *key = ca_generate_keypair(key_type);

    /* Create certificate */
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(key);
        ca_panic_ssl("failed to create X509");
    }

    /* Set version to v3 */
    X509_set_version(cert, 2);

    /* Set serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    /* Set validity */
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), (long)days_valid * 24 * 60 * 60);

    /* Set subject name */
    X509_NAME *name = X509_get_subject_name(cert);
    if (country) {
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, OSSL_STR(country), -1, -1,
                                   0);
    }
    if (organization) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, OSSL_STR(organization),
                                   -1, -1, 0);
    }
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, OSSL_STR(common_name),
                               -1, -1, 0);

    /* Self-signed: issuer = subject */
    X509_set_issuer_name(cert, name);

    /* Set public key */
    X509_set_pubkey(cert, key);

    /* Add CA extensions */
    ca_add_extension(cert, cert, NID_basic_constraints, "critical,CA:TRUE");
    ca_add_extension(cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    ca_add_extension(cert, cert, NID_subject_key_identifier, "hash");
    ca_add_extension(cert, cert, NID_authority_key_identifier, "keyid:always");

    /* Sign the certificate */
    if (!X509_sign(cert, key, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(key);
        ca_panic_ssl("failed to sign certificate");
    }

    /* Create CA object */
    JanetCA *ca = janet_abstract(&ca_type, sizeof(JanetCA));
    ca->cert = cert;
    ca->key = key;
    ca->serial = serial;
    ca->track_issued = track_issued;
    ca->issued = track_issued ? sk_X509_new_null() : NULL;
    ca->revoked = sk_X509_REVOKED_new_null();

    return janet_wrap_abstract(ca);
}

/*
 * =============================================================================
 * ca/generate-intermediate - Generate intermediate CA signed by parent
 * =============================================================================
 */

static const char *cfun_ca_generate_intermediate_docstring =
    "(ca/generate-intermediate parent-ca &opt opts)\n\n"
    "Generate an intermediate CA signed by a parent CA.\n\n"
    "Options:\n"
    "  :common-name <string>  - CA common name (default: \"Intermediate CA\")\n"
    "  :days-valid <number>   - Validity period in days (default: 1825)\n"
    "  :key-type <keyword>    - Key type (default: :ec-p256)\n"
    "  :path-length <number>  - Max number of sub-CAs allowed (default: 0)\n"
    "  :serial <number>       - Starting serial for new CA (default: 1)\n"
    "  :track-issued <bool>   - Track issued certificates (default: false)\n"
    "  :organization <string> - Organization name\n"
    "  :country <string>      - Country code\n\n"
    "Returns a new CA object representing the intermediate CA.";

Janet cfun_ca_generate_intermediate(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    JanetCA *parent = janet_getabstract(argv, 0, &ca_type);
    Janet opts = argc > 1 ? argv[1] : janet_wrap_nil();

    /* Parse options */
    const char *common_name = "Intermediate CA";
    int days_valid = 1825;  /* 5 years */
    Janet key_type = janet_wrap_nil();
    int path_length = 0;
    int64_t serial = 1;
    int track_issued = 0;
    const char *organization = NULL;
    const char *country = NULL;

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "common-name");
        if (!janet_checktype(v, JANET_NIL)) {
            common_name = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "days-valid");
        if (!janet_checktype(v, JANET_NIL)) {
            days_valid = janet_getinteger(&v, 0);
        }

        v = ca_opts_get(opts, "key-type");
        if (!janet_checktype(v, JANET_NIL)) {
            key_type = v;
        }

        v = ca_opts_get(opts, "path-length");
        if (!janet_checktype(v, JANET_NIL)) {
            path_length = janet_getinteger(&v, 0);
        }

        v = ca_opts_get(opts, "serial");
        if (!janet_checktype(v, JANET_NIL)) {
            serial = janet_getinteger64(&v, 0);
        }

        v = ca_opts_get(opts, "track-issued");
        if (janet_truthy(v)) {
            track_issued = 1;
        }

        v = ca_opts_get(opts, "organization");
        if (!janet_checktype(v, JANET_NIL)) {
            organization = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "country");
        if (!janet_checktype(v, JANET_NIL)) {
            country = janet_to_string_or_keyword(v);
        }
    }

    /* Generate keypair for intermediate */
    EVP_PKEY *key = ca_generate_keypair(key_type);

    /* Create certificate */
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(key);
        ca_panic_ssl("failed to create X509 for intermediate");
    }

    /* Set version to v3 */
    X509_set_version(cert, 2);

    /* Set serial number (from parent's counter) */
    int64_t cert_serial = ca_next_serial(parent);
    ASN1_INTEGER_set_int64(X509_get_serialNumber(cert), cert_serial);

    /* Set validity */
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), (long)days_valid * 24 * 60 * 60);

    /* Set subject name */
    X509_NAME *name = X509_get_subject_name(cert);
    if (country) {
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, OSSL_STR(country), -1, -1,
                                   0);
    }
    if (organization) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, OSSL_STR(organization),
                                   -1, -1, 0);
    }
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, OSSL_STR(common_name),
                               -1, -1, 0);

    /* Set issuer from parent */
    X509_set_issuer_name(cert, X509_get_subject_name(parent->cert));

    /* Set public key */
    X509_set_pubkey(cert, key);

    /* Add CA extensions with pathLenConstraint */
    char basic_constraints[64];
    snprintf(basic_constraints, sizeof(basic_constraints),
             "critical,CA:TRUE,pathlen:%d", path_length);
    ca_add_extension(cert, parent->cert, NID_basic_constraints,
                     basic_constraints);
    ca_add_extension(cert, parent->cert, NID_key_usage,
                     "critical,keyCertSign,cRLSign");
    ca_add_extension(cert, parent->cert, NID_subject_key_identifier, "hash");
    ca_add_extension(cert, parent->cert, NID_authority_key_identifier,
                     "keyid:always");

    /* Sign with parent's key */
    if (!X509_sign(cert, parent->key, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(key);
        ca_panic_ssl("failed to sign intermediate certificate");
    }

    /* Track in parent if enabled */
    if (parent->track_issued && parent->issued) {
        X509_up_ref(cert);  /* Increase ref count */
        sk_X509_push(parent->issued, cert);
    }

    /* Create CA object */
    JanetCA *ca = janet_abstract(&ca_type, sizeof(JanetCA));
    ca->cert = cert;
    ca->key = key;
    ca->serial = serial;
    ca->track_issued = track_issued;
    ca->issued = track_issued ? sk_X509_new_null() : NULL;
    ca->revoked = sk_X509_REVOKED_new_null();

    return janet_wrap_abstract(ca);
}

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

void jca_register_types(JanetTable *env) {
    janet_def(env, "create", janet_wrap_cfunction(cfun_ca_create),
              cfun_ca_create_docstring);
    janet_def(env, "generate", janet_wrap_cfunction(cfun_ca_generate),
              cfun_ca_generate_docstring);
    janet_def(env, "generate-intermediate",
              janet_wrap_cfunction(cfun_ca_generate_intermediate),
              cfun_ca_generate_intermediate_docstring);
}
