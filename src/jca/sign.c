/*
 * jca/sign.c - CSR signing and certificate issuance
 *
 * Provides:
 * - :sign-csr / ca/sign - Sign a CSR to issue a certificate
 * - :issue / ca/issue - Generate key + CSR + sign in one step
 * - :get-cert / ca/get-cert - Get CA certificate
 * - :get-serial / ca/get-serial - Get current serial number
 * - :set-serial / ca/set-serial - Set serial number
 * - :is-tracking / ca/is-tracking - Check if tracking enabled
 * - :get-issued / ca/get-issued - Get issued certificates
 *
 * Author: jsec project
 * License: ISC
 */

#include "internal.h"

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/* Load X509_REQ (CSR) from PEM string */
X509_REQ *ca_pem_to_csr(Janet pem) {
    JanetByteView bytes = janet_getbytes(&pem, 0);
    BIO *bio = BIO_new_mem_buf(bytes.bytes, (int)bytes.len);
    if (!bio) {
        ca_panic_resource("failed to create BIO for CSR");
    }

    X509_REQ *csr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!csr) {
        ca_panic_ssl("failed to parse CSR PEM");
    }

    return csr;
}

/* Parse SAN entries from Janet array */
static void add_san_entries(X509 *cert, X509 *issuer, JanetArray *san_arr) {
    if (!san_arr || san_arr->count == 0) return;

    JanetBuffer *san_buf = janet_buffer(256);

    for (int32_t i = 0; i < san_arr->count; i++) {
        if (i > 0) {
            janet_buffer_push_cstring(san_buf, ",");
        }
        const char *entry = janet_to_string_or_keyword(san_arr->data[i]);
        janet_buffer_push_cstring(san_buf, entry);
    }

    /* Null-terminate */
    janet_buffer_push_u8(san_buf, 0);

    ca_add_extension(cert, issuer, NID_subject_alt_name,
                     (const char *)san_buf->data);
}

/*
 * =============================================================================
 * :sign-csr / ca/sign - Sign a CSR
 * =============================================================================
 */

/* Docstring for :sign-csr method - used in help/documentation */
#define SIGN_CSR_DOC \
    "(:sign-csr ca csr-pem &opt opts) or (ca/sign ca csr-pem &opt opts)\n\n" \
    "Sign a Certificate Signing Request (CSR) to issue a certificate.\n\n" \
    "Options:\n" \
    "  :days-valid <number>      - Validity period in days (default: 365)\n" \
    "  :not-before <time>        - Custom start time\n" \
    "  :not-after <time>         - Custom end time\n" \
    "  :serial <number>          - Override serial (default: auto-increment)\n" \
    "  :copy-extensions <bool>   - Copy extensions from CSR (default: false)\n" \
    "  :key-usage <string>       - Override key usage\n" \
    "  :extended-key-usage <string> - e.g., \"serverAuth,clientAuth\"\n" \
    "  :san [\"DNS:...\" ...]    - Subject Alternative Names\n" \
    "  :basic-constraints <string> - e.g., \"CA:FALSE\"\n\n" \
    "Returns certificate in PEM format."

Janet cfun_ca_sign_csr(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    Janet csr_pem = argv[1];
    Janet opts = argc > 2 ? argv[2] : janet_wrap_nil();

    /* Parse options */
    int days_valid = 365;
    int64_t serial = -1;  /* -1 means auto */
    int copy_extensions = 0;
    const char *key_usage = NULL;
    const char *extended_key_usage = NULL;
    JanetArray *san_arr = NULL;
    const char *basic_constraints = "CA:FALSE";

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "days-valid");
        if (!janet_checktype(v, JANET_NIL)) {
            days_valid = janet_getinteger(&v, 0);
        }

        v = ca_opts_get(opts, "serial");
        if (!janet_checktype(v, JANET_NIL)) {
            serial = janet_getinteger64(&v, 0);
        }

        v = ca_opts_get(opts, "copy-extensions");
        if (janet_truthy(v)) {
            copy_extensions = 1;
        }

        v = ca_opts_get(opts, "key-usage");
        if (!janet_checktype(v, JANET_NIL)) {
            key_usage = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "extended-key-usage");
        if (!janet_checktype(v, JANET_NIL)) {
            extended_key_usage = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "san");
        if (janet_checktype(v, JANET_ARRAY)) {
            san_arr = janet_unwrap_array(v);
        } else if (janet_checktype(v, JANET_TUPLE)) {
            /* Convert tuple to array for iteration */
            const Janet *tuple = janet_unwrap_tuple(v);
            int32_t len = janet_tuple_length(tuple);
            san_arr = janet_array(len);
            for (int32_t i = 0; i < len; i++) {
                janet_array_push(san_arr, tuple[i]);
            }
        }

        v = ca_opts_get(opts, "basic-constraints");
        if (!janet_checktype(v, JANET_NIL)) {
            basic_constraints = janet_to_string_or_keyword(v);
        }
    }

    /* Load CSR */
    X509_REQ *csr = ca_pem_to_csr(csr_pem);

    /* Verify CSR signature */
    EVP_PKEY *csr_key = X509_REQ_get_pubkey(csr);
    if (!csr_key) {
        X509_REQ_free(csr);
        ca_panic_ssl("failed to get public key from CSR");
    }

    if (X509_REQ_verify(csr, csr_key) <= 0) {
        EVP_PKEY_free(csr_key);
        X509_REQ_free(csr);
        ca_panic_verify("CSR signature verification failed");
    }

    /* Create certificate */
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(csr_key);
        X509_REQ_free(csr);
        ca_panic_ssl("failed to create X509");
    }

    /* Set version to v3 */
    X509_set_version(cert, 2);

    /* Set serial number */
    if (serial < 0) {
        serial = ca_next_serial(ca);
    }
    ASN1_INTEGER_set_int64(X509_get_serialNumber(cert), serial);

    /* Set validity */
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), (long)days_valid * 24 * 60 * 60);

    /* Copy subject from CSR */
    X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));

    /* Set issuer from CA */
    X509_set_issuer_name(cert, X509_get_subject_name(ca->cert));

    /* Set public key from CSR */
    X509_set_pubkey(cert, csr_key);

    /* Copy extensions from CSR if requested */
    if (copy_extensions) {
        STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(csr);
        if (exts) {
            for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
                X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
                X509_add_ext(cert, ext, -1);
            }
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }

    /* Add standard extensions */
    ca_add_extension(cert, ca->cert, NID_basic_constraints, basic_constraints);
    ca_add_extension(cert, ca->cert, NID_subject_key_identifier, "hash");
    ca_add_extension(cert, ca->cert, NID_authority_key_identifier,
                     "keyid:always");

    /* Add key usage if specified */
    if (key_usage) {
        ca_add_extension(cert, ca->cert, NID_key_usage, key_usage);
    } else {
        /* Default for end-entity cert */
        ca_add_extension(cert, ca->cert, NID_key_usage,
                         "digitalSignature,keyEncipherment");
    }

    /* Add extended key usage if specified */
    if (extended_key_usage) {
        ca_add_extension(cert, ca->cert, NID_ext_key_usage, extended_key_usage);
    }

    /* Add SAN if specified */
    if (san_arr && san_arr->count > 0) {
        add_san_entries(cert, ca->cert, san_arr);
    }

    /* Sign with CA key */
    if (!X509_sign(cert, ca->key, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(csr_key);
        X509_REQ_free(csr);
        ca_panic_ssl("failed to sign certificate");
    }

    /* Track if enabled */
    if (ca->track_issued && ca->issued) {
        X509_up_ref(cert);
        sk_X509_push(ca->issued, cert);
    }

    /* Convert to PEM */
    Janet result = ca_x509_to_pem(cert);

    /* Cleanup */
    X509_free(cert);
    EVP_PKEY_free(csr_key);
    X509_REQ_free(csr);

    return result;
}

/*
 * =============================================================================
 * :issue / ca/issue - Generate key + CSR + sign in one step
 * =============================================================================
 */

static const char *cfun_ca_issue_docstring =
    "(:issue ca &opt opts) or (ca/issue ca &opt opts)\n\n"
    "Issue a new certificate (generate key, create CSR, sign - all in one step).\n"
    "This is the recommended method for most use cases.\n\n"
    "Options:\n"
    "  :common-name <string>     - Certificate common name (required)\n"
    "  :san [\"DNS:...\" ...]    - Subject Alternative Names\n"
    "  :days-valid <number>      - Validity period (default: 365)\n"
    "  :key-type <keyword>       - Key type (default: :ec-p256)\n"
    "  :key-usage <string>       - Key usage extension\n"
    "  :extended-key-usage <string> - e.g., \"serverAuth\"\n"
    "  :organization <string>    - Organization name\n"
    "  :country <string>         - Country code\n\n"
    "Returns: {:cert <pem> :key <pem>}";

Janet cfun_ca_issue(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    Janet opts = argc > 1 ? argv[1] : janet_wrap_nil();

    /* Parse options */
    const char *common_name = NULL;
    JanetArray *san_arr = NULL;
    int days_valid = 365;
    Janet key_type = janet_wrap_nil();
    const char *key_usage = NULL;
    const char *extended_key_usage = NULL;
    const char *organization = NULL;
    const char *country = NULL;

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "common-name");
        if (!janet_checktype(v, JANET_NIL)) {
            common_name = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "san");
        if (janet_checktype(v, JANET_ARRAY)) {
            san_arr = janet_unwrap_array(v);
        } else if (janet_checktype(v, JANET_TUPLE)) {
            const Janet *tuple = janet_unwrap_tuple(v);
            int32_t len = janet_tuple_length(tuple);
            san_arr = janet_array(len);
            for (int32_t i = 0; i < len; i++) {
                janet_array_push(san_arr, tuple[i]);
            }
        }

        v = ca_opts_get(opts, "days-valid");
        if (!janet_checktype(v, JANET_NIL)) {
            days_valid = janet_getinteger(&v, 0);
        }

        v = ca_opts_get(opts, "key-type");
        if (!janet_checktype(v, JANET_NIL)) {
            key_type = v;
        }

        v = ca_opts_get(opts, "key-usage");
        if (!janet_checktype(v, JANET_NIL)) {
            key_usage = janet_to_string_or_keyword(v);
        }

        v = ca_opts_get(opts, "extended-key-usage");
        if (!janet_checktype(v, JANET_NIL)) {
            extended_key_usage = janet_to_string_or_keyword(v);
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

    if (!common_name) {
        ca_panic_param(":common-name is required for ca/issue");
    }

    /* Generate keypair */
    EVP_PKEY *key = ca_generate_keypair(key_type);

    /* Create certificate directly (skip CSR for efficiency) */
    X509 *cert = X509_new();
    if (!cert) {
        EVP_PKEY_free(key);
        ca_panic_ssl("failed to create X509");
    }

    /* Set version to v3 */
    X509_set_version(cert, 2);

    /* Set serial number */
    int64_t serial = ca_next_serial(ca);
    ASN1_INTEGER_set_int64(X509_get_serialNumber(cert), serial);

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

    /* Set issuer from CA */
    X509_set_issuer_name(cert, X509_get_subject_name(ca->cert));

    /* Set public key */
    X509_set_pubkey(cert, key);

    /* Add extensions */
    ca_add_extension(cert, ca->cert, NID_basic_constraints, "CA:FALSE");
    ca_add_extension(cert, ca->cert, NID_subject_key_identifier, "hash");
    ca_add_extension(cert, ca->cert, NID_authority_key_identifier,
                     "keyid:always");

    /* Key usage */
    if (key_usage) {
        ca_add_extension(cert, ca->cert, NID_key_usage, key_usage);
    } else {
        ca_add_extension(cert, ca->cert, NID_key_usage,
                         "digitalSignature,keyEncipherment");
    }

    /* Extended key usage */
    if (extended_key_usage) {
        ca_add_extension(cert, ca->cert, NID_ext_key_usage, extended_key_usage);
    }

    /* SAN */
    if (san_arr && san_arr->count > 0) {
        add_san_entries(cert, ca->cert, san_arr);
    }

    /* Sign with CA key */
    if (!X509_sign(cert, ca->key, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(key);
        ca_panic_ssl("failed to sign certificate");
    }

    /* Track if enabled */
    if (ca->track_issued && ca->issued) {
        X509_up_ref(cert);
        sk_X509_push(ca->issued, cert);
    }

    /* Build result table */
    JanetTable *result = janet_table(2);
    janet_table_put(result, janet_ckeywordv("cert"), ca_x509_to_pem(cert));
    janet_table_put(result, janet_ckeywordv("key"), ca_key_to_pem(key));

    /* Cleanup */
    X509_free(cert);
    EVP_PKEY_free(key);

    return janet_wrap_table(result);
}

/*
 * =============================================================================
 * Accessor Methods
 * =============================================================================
 */

static const char *cfun_ca_get_cert_docstring =
    "(:get-cert ca) or (ca/get-cert ca)\n\n"
    "Get the CA's certificate in PEM format.";

Janet cfun_ca_get_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    return ca_x509_to_pem(ca->cert);
}

static const char *cfun_ca_get_serial_docstring =
    "(:get-serial ca) or (ca/get-serial ca)\n\n"
    "Get the CA's current serial number.\n"
    "Use this for persistence - save before shutdown, restore on startup.";

Janet cfun_ca_get_serial(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    return janet_wrap_s64(ca->serial);
}

static const char *cfun_ca_set_serial_docstring =
    "(:set-serial ca serial) or (ca/set-serial ca serial)\n\n"
    "Set the CA's serial number.\n"
    "Use this to restore state from persistent storage.";

Janet cfun_ca_set_serial(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    int64_t serial = janet_getinteger64(argv, 1);
    ca->serial = serial;
    return janet_wrap_nil();
}

static const char *cfun_ca_is_tracking_docstring =
    "(:is-tracking ca) or (ca/is-tracking ca)\n\n"
    "Check if the CA is tracking issued certificates.";

Janet cfun_ca_is_tracking(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    return janet_wrap_boolean(ca->track_issued);
}

static const char *cfun_ca_get_issued_docstring =
    "(:get-issued ca) or (ca/get-issued ca)\n\n"
    "Get list of issued certificates (only if tracking is enabled).\n"
    "Returns an array of PEM-encoded certificates, or nil if tracking disabled.";

Janet cfun_ca_get_issued(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);

    if (!ca->track_issued || !ca->issued) {
        return janet_wrap_nil();
    }

    int num = sk_X509_num(ca->issued);
    JanetArray *arr = janet_array(num);

    for (int i = 0; i < num; i++) {
        X509 *cert = sk_X509_value(ca->issued, i);
        janet_array_push(arr, ca_x509_to_pem(cert));
    }

    return janet_wrap_array(arr);
}

/*
 * =============================================================================
 * Standalone Functions (operate on CA object)
 * =============================================================================
 */

static const char *cfun_ca_sign_docstring =
    "(ca/sign ca csr-pem &opt opts)\n\n"
    "Sign a CSR with a CA. Standalone function version of :sign-csr method.\n"
    "See :sign-csr for options.";

static Janet cfun_ca_sign(int32_t argc, Janet *argv) {
    return cfun_ca_sign_csr(argc, argv);
}

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

void jca_register_sign(JanetTable *env) {
    /* Standalone functions */
    janet_def(env, "sign", janet_wrap_cfunction(cfun_ca_sign),
              cfun_ca_sign_docstring);
    janet_def(env, "issue", janet_wrap_cfunction(cfun_ca_issue),
              cfun_ca_issue_docstring);
    janet_def(env, "get-cert", janet_wrap_cfunction(cfun_ca_get_cert),
              cfun_ca_get_cert_docstring);
    janet_def(env, "get-serial", janet_wrap_cfunction(cfun_ca_get_serial),
              cfun_ca_get_serial_docstring);
    janet_def(env, "set-serial", janet_wrap_cfunction(cfun_ca_set_serial),
              cfun_ca_set_serial_docstring);
    janet_def(env, "is-tracking", janet_wrap_cfunction(cfun_ca_is_tracking),
              cfun_ca_is_tracking_docstring);
    janet_def(env, "get-issued", janet_wrap_cfunction(cfun_ca_get_issued),
              cfun_ca_get_issued_docstring);
}
