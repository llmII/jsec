/*
 * jca/crl.c - CRL generation and revocation tracking
 *
 * Provides:
 * - :revoke / ca/revoke - Revoke a certificate
 * - :generate-crl / ca/crl - Generate Certificate Revocation List
 * - :get-revoked / ca/get-revoked - Get list of revoked serials
 *
 * Author: jsec project
 * License: ISC
 */

#include "internal.h"

/*
 * =============================================================================
 * Revocation Reason Conversion
 * =============================================================================
 */

CARevocationReason ca_keyword_to_reason(Janet kw) {
    if (janet_checktype(kw, JANET_NIL)) {
        return CA_REVOKE_UNSPECIFIED;
    }

    const char *str = janet_to_string_or_keyword(kw);

    if (strcmp(str, "unspecified") == 0) return CA_REVOKE_UNSPECIFIED;
    if (strcmp(str, "key-compromise") == 0) return CA_REVOKE_KEY_COMPROMISE;
    if (strcmp(str, "ca-compromise") == 0) return CA_REVOKE_CA_COMPROMISE;
    if (strcmp(str, "affiliation-changed") == 0) return
            CA_REVOKE_AFFILIATION_CHANGED;
    if (strcmp(str, "superseded") == 0) return CA_REVOKE_SUPERSEDED;
    if (strcmp(str, "cessation-of-operation") == 0) return
            CA_REVOKE_CESSATION_OF_OPERATION;
    if (strcmp(str, "certificate-hold") == 0) return CA_REVOKE_CERTIFICATE_HOLD;
    if (strcmp(str, "remove-from-crl") == 0) return CA_REVOKE_REMOVE_FROM_CRL;
    if (strcmp(str, "privilege-withdrawn") == 0) return
            CA_REVOKE_PRIVILEGE_WITHDRAWN;
    if (strcmp(str, "aa-compromise") == 0) return CA_REVOKE_AA_COMPROMISE;

    ca_panic_param("unknown revocation reason: %s", str);
    return CA_REVOKE_UNSPECIFIED;  /* unreachable */
}

Janet ca_reason_to_keyword(CARevocationReason reason) {
    switch (reason) {
        case CA_REVOKE_UNSPECIFIED: return janet_ckeywordv("unspecified");
        case CA_REVOKE_KEY_COMPROMISE: return janet_ckeywordv("key-compromise");
        case CA_REVOKE_CA_COMPROMISE: return janet_ckeywordv("ca-compromise");
        case CA_REVOKE_AFFILIATION_CHANGED: return
                janet_ckeywordv("affiliation-changed");
        case CA_REVOKE_SUPERSEDED: return janet_ckeywordv("superseded");
        case CA_REVOKE_CESSATION_OF_OPERATION: return
                janet_ckeywordv("cessation-of-operation");
        case CA_REVOKE_CERTIFICATE_HOLD: return janet_ckeywordv("certificate-hold");
        case CA_REVOKE_REMOVE_FROM_CRL: return janet_ckeywordv("remove-from-crl");
        case CA_REVOKE_PRIVILEGE_WITHDRAWN: return
                janet_ckeywordv("privilege-withdrawn");
        case CA_REVOKE_AA_COMPROMISE: return janet_ckeywordv("aa-compromise");
        default: return janet_ckeywordv("unspecified");
    }
}

/*
 * =============================================================================
 * :revoke / ca/revoke - Revoke a certificate
 * =============================================================================
 */

static const char *cfun_ca_revoke_docstring =
    "(:revoke ca serial &opt reason) or (ca/revoke ca serial &opt reason)\n\n"
    "Revoke a certificate by its serial number.\n\n"
    "Reason keywords:\n"
    "  :unspecified           - Default\n"
    "  :key-compromise        - Private key compromised\n"
    "  :ca-compromise         - CA key compromised\n"
    "  :affiliation-changed   - Subject affiliation changed\n"
    "  :superseded            - Replaced by new certificate\n"
    "  :cessation-of-operation - No longer in use\n"
    "  :certificate-hold      - Temporarily suspended\n"
    "  :remove-from-crl       - Remove from CRL (unrevoke)\n"
    "  :privilege-withdrawn   - Privileges revoked\n"
    "  :aa-compromise         - AA key compromised\n\n"
    "The revocation is recorded for CRL generation.";

Janet cfun_ca_revoke(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    int64_t serial = janet_getinteger64(argv, 1);
    Janet reason_kw = argc > 2 ? argv[2] : janet_wrap_nil();

    CARevocationReason reason = ca_keyword_to_reason(reason_kw);

    /* Create X509_REVOKED entry */
    X509_REVOKED *revoked = X509_REVOKED_new();
    if (!revoked) {
        ca_panic_ssl("failed to create revocation entry");
    }

    /* Set serial number */
    ASN1_INTEGER *asn_serial = ASN1_INTEGER_new();
    ASN1_INTEGER_set_int64(asn_serial, serial);
    X509_REVOKED_set_serialNumber(revoked, asn_serial);
    ASN1_INTEGER_free(asn_serial);

    /* Set revocation time to now */
    ASN1_TIME *revtime = ASN1_TIME_new();
    X509_gmtime_adj(revtime, 0);
    X509_REVOKED_set_revocationDate(revoked, revtime);
    ASN1_TIME_free(revtime);

    /* Set revocation reason if not unspecified */
    if (reason != CA_REVOKE_UNSPECIFIED) {
        ASN1_ENUMERATED *reason_enum = ASN1_ENUMERATED_new();
        ASN1_ENUMERATED_set(reason_enum, reason);
        X509_REVOKED_add1_ext_i2d(revoked, NID_crl_reason, reason_enum, 0, 0);
        ASN1_ENUMERATED_free(reason_enum);
    }

    /* Add to revoked list */
    if (!ca->revoked) {
        ca->revoked = sk_X509_REVOKED_new_null();
    }
    sk_X509_REVOKED_push(ca->revoked, revoked);

    return janet_wrap_nil();
}

/*
 * =============================================================================
 * :generate-crl / ca/crl - Generate CRL
 * =============================================================================
 */

static const char *cfun_ca_generate_crl_docstring =
    "(:generate-crl ca &opt opts) or (ca/crl ca &opt opts)\n\n"
    "Generate a Certificate Revocation List (CRL).\n\n"
    "Options:\n"
    "  :days-valid <number>   - CRL validity period (default: 30)\n"
    "  :revoked [...]         - Additional revocations (if not using :revoke method)\n"
    "                           Each entry: {:serial N :reason <kw>}\n\n"
    "Returns CRL in PEM format.";

Janet cfun_ca_generate_crl(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);
    Janet opts = argc > 1 ? argv[1] : janet_wrap_nil();

    /* Parse options */
    int days_valid = 30;
    JanetArray *additional_revoked = NULL;

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "days-valid");
        if (!janet_checktype(v, JANET_NIL)) {
            days_valid = janet_getinteger(&v, 0);
        }

        v = ca_opts_get(opts, "revoked");
        if (janet_checktype(v, JANET_ARRAY)) {
            additional_revoked = janet_unwrap_array(v);
        }
    }

    /* Create CRL */
    X509_CRL *crl = X509_CRL_new();
    if (!crl) {
        ca_panic_ssl("failed to create CRL");
    }

    /* Set version (v2 for extensions) */
    X509_CRL_set_version(crl, 1);

    /* Set issuer */
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca->cert));

    /* Set update times */
    ASN1_TIME *last_update = ASN1_TIME_new();
    ASN1_TIME *next_update = ASN1_TIME_new();
    X509_gmtime_adj(last_update, 0);
    X509_gmtime_adj(next_update, (long)days_valid * 24 * 60 * 60);
    X509_CRL_set1_lastUpdate(crl, last_update);
    X509_CRL_set1_nextUpdate(crl, next_update);
    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);

    /* Add revoked certificates from CA's list */
    if (ca->revoked) {
        int num = sk_X509_REVOKED_num(ca->revoked);
        for (int i = 0; i < num; i++) {
            X509_REVOKED *rev = sk_X509_REVOKED_value(ca->revoked, i);
            /* Duplicate the entry since CRL takes ownership */
            X509_REVOKED *rev_copy = X509_REVOKED_dup(rev);
            X509_CRL_add0_revoked(crl, rev_copy);
        }
    }

    /* Add additional revoked certificates from options */
    if (additional_revoked) {
        for (int32_t i = 0; i < additional_revoked->count; i++) {
            Janet entry = additional_revoked->data[i];
            if (!janet_checktype(entry, JANET_TABLE) &&
                !janet_checktype(entry, JANET_STRUCT)) {
                X509_CRL_free(crl);
                ca_panic_param("revoked entry must be a table with :serial and optional :reason");
            }

            JanetTable *t = janet_checktype(entry, JANET_TABLE)
                            ? janet_unwrap_table(entry)
                            : NULL;
            const JanetKV *s = janet_checktype(entry, JANET_STRUCT)
                               ? janet_unwrap_struct(entry)
                               : NULL;

            Janet serial_v = t
                             ? janet_table_get(t, janet_ckeywordv("serial"))
                             : janet_struct_get(s, janet_ckeywordv("serial"));
            Janet reason_v = t
                             ? janet_table_get(t, janet_ckeywordv("reason"))
                             : janet_struct_get(s, janet_ckeywordv("reason"));

            if (janet_checktype(serial_v, JANET_NIL)) {
                X509_CRL_free(crl);
                ca_panic_param("revoked entry missing :serial");
            }

            int64_t serial = janet_getinteger64(&serial_v, 0);
            CARevocationReason reason = ca_keyword_to_reason(reason_v);

            X509_REVOKED *revoked = X509_REVOKED_new();
            ASN1_INTEGER *asn_serial = ASN1_INTEGER_new();
            ASN1_INTEGER_set_int64(asn_serial, serial);
            X509_REVOKED_set_serialNumber(revoked, asn_serial);
            ASN1_INTEGER_free(asn_serial);

            ASN1_TIME *revtime = ASN1_TIME_new();
            X509_gmtime_adj(revtime, 0);
            X509_REVOKED_set_revocationDate(revoked, revtime);
            ASN1_TIME_free(revtime);

            if (reason != CA_REVOKE_UNSPECIFIED) {
                ASN1_ENUMERATED *reason_enum = ASN1_ENUMERATED_new();
                ASN1_ENUMERATED_set(reason_enum, reason);
                X509_REVOKED_add1_ext_i2d(revoked, NID_crl_reason, reason_enum, 0, 0);
                ASN1_ENUMERATED_free(reason_enum);
            }

            X509_CRL_add0_revoked(crl, revoked);
        }
    }

    /* Sort the revoked list (required by X.509) */
    X509_CRL_sort(crl);

    /* Sign the CRL */
    if (!X509_CRL_sign(crl, ca->key, EVP_sha256())) {
        X509_CRL_free(crl);
        ca_panic_ssl("failed to sign CRL");
    }

    /* Convert to PEM */
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        X509_CRL_free(crl);
        ca_panic_resource("failed to create BIO");
    }

    if (!PEM_write_bio_X509_CRL(bio, crl)) {
        BIO_free(bio);
        X509_CRL_free(crl);
        ca_panic_ssl("failed to write CRL PEM");
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    Janet result = janet_stringv((const uint8_t *)data, (int32_t)len);

    BIO_free(bio);
    X509_CRL_free(crl);

    return result;
}

/*
 * =============================================================================
 * :get-revoked / ca/get-revoked - Get revoked certificates
 * =============================================================================
 */

static const char *cfun_ca_get_revoked_docstring =
    "(:get-revoked ca) or (ca/get-revoked ca)\n\n"
    "Get list of revoked certificate serials.\n"
    "Returns array of {:serial N :reason <kw>} tables.";

Janet cfun_ca_get_revoked(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);

    if (!ca->revoked) {
        return janet_wrap_array(janet_array(0));
    }

    int num = sk_X509_REVOKED_num(ca->revoked);
    JanetArray *arr = janet_array(num);

    for (int i = 0; i < num; i++) {
        X509_REVOKED *rev = sk_X509_REVOKED_value(ca->revoked, i);

        /* Get serial */
        const ASN1_INTEGER *serial = X509_REVOKED_get0_serialNumber(rev);
        int64_t serial_val = 0;
        ASN1_INTEGER_get_int64(&serial_val, serial);

        /* Get reason */
        CARevocationReason reason = CA_REVOKE_UNSPECIFIED;
        int crit;
        ASN1_ENUMERATED *reason_enum = X509_REVOKED_get_ext_d2i(rev, NID_crl_reason,
                                       &crit, NULL);
        if (reason_enum) {
            reason = (CARevocationReason)ASN1_ENUMERATED_get(reason_enum);
            ASN1_ENUMERATED_free(reason_enum);
        }

        JanetTable *entry = janet_table(2);
        janet_table_put(entry, janet_ckeywordv("serial"), janet_wrap_s64(serial_val));
        janet_table_put(entry, janet_ckeywordv("reason"),
                        ca_reason_to_keyword(reason));

        janet_array_push(arr, janet_wrap_table(entry));
    }

    return janet_wrap_array(arr);
}

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

void jca_register_crl(JanetTable *env) {
    janet_def(env, "revoke", janet_wrap_cfunction(cfun_ca_revoke),
              cfun_ca_revoke_docstring);
    janet_def(env, "crl", janet_wrap_cfunction(cfun_ca_generate_crl),
              cfun_ca_generate_crl_docstring);
    janet_def(env, "get-revoked", janet_wrap_cfunction(cfun_ca_get_revoked),
              cfun_ca_get_revoked_docstring);
}
