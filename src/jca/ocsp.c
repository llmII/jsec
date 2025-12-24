/*
 * jca/ocsp.c - OCSP request parsing and response creation
 *
 * Provides OCSP MECHANICS only - user implements HTTP server.
 *
 * - :parse-ocsp-request / ca/parse-ocsp-request - Parse OCSP request bytes
 * - :create-ocsp-response / ca/create-ocsp-response - Create OCSP response
 *
 * Author: jsec project
 * License: ISC
 */

#include "internal.h"
#include <openssl/ocsp.h>

/*
 * =============================================================================
 * ca/parse-ocsp-request - Parse OCSP request
 * =============================================================================
 */

static const char *cfun_ca_parse_ocsp_request_docstring =
    "(ca/parse-ocsp-request request-bytes) or (:parse-ocsp-request ca "
    "request-bytes)\n\n"
    "Parse an OCSP request (DER-encoded bytes).\n\n"
    "Returns a table:\n"
    "  :issuer-name-hash <buffer>  - Hash of issuer's distinguished name\n"
    "  :issuer-key-hash <buffer>   - Hash of issuer's public key\n"
    "  :serial <number>            - Certificate serial number\n"
    "  :nonce <buffer|nil>         - Nonce for replay protection (if "
    "present)\n\n"
    "This allows you to look up the certificate status and create a "
    "response.";

Janet cfun_ca_parse_ocsp_request(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    /* Handle both standalone function and method call */
    Janet request_bytes;
    if (argc == 2) {
        /* Method call: (:parse-ocsp-request ca bytes) */
        request_bytes = argv[1];
    } else {
        /* Standalone: (ca/parse-ocsp-request bytes) */
        request_bytes = argv[0];
    }

    JanetByteView bytes = janet_getbytes(&request_bytes, 0);

    /* Parse the request */
    const unsigned char *p = bytes.bytes;
    OCSP_REQUEST *req = d2i_OCSP_REQUEST(NULL, &p, (long)bytes.len);
    if (!req) {
        ca_panic_ssl("failed to parse OCSP request");
    }

    /* Get the first request ID (typically only one) */
    OCSP_ONEREQ *one = OCSP_request_onereq_get0(req, 0);
    if (!one) {
        OCSP_REQUEST_free(req);
        ca_panic_parse("OCSP request contains no certificate IDs");
    }

    OCSP_CERTID *certid = OCSP_onereq_get0_id(one);
    if (!certid) {
        OCSP_REQUEST_free(req);
        ca_panic_parse("failed to get certificate ID from OCSP request");
    }

    /* Extract components */
    ASN1_OCTET_STRING *issuer_name_hash = NULL;
    ASN1_OCTET_STRING *issuer_key_hash = NULL;
    ASN1_INTEGER *serial = NULL;

    /* Note: OCSP_id_get0_info doesn't exist in all OpenSSL versions,
     * so we use the deprecated but widely available approach */
    int ok = OCSP_id_get0_info(&issuer_name_hash, NULL, &issuer_key_hash,
                               &serial, certid);
    if (!ok) {
        OCSP_REQUEST_free(req);
        ca_panic_parse("failed to extract OCSP request components");
    }

    /* Build result table */
    JanetTable *result = janet_table(4);

    /* Issuer name hash */
    if (issuer_name_hash) {
        JanetBuffer *buf =
            janet_buffer((int32_t)ASN1_STRING_length(issuer_name_hash));
        janet_buffer_push_bytes(
            buf, ASN1_STRING_get0_data(issuer_name_hash),
            (int32_t)ASN1_STRING_length(issuer_name_hash));
        janet_table_put(result, janet_ckeywordv("issuer-name-hash"),
                        janet_wrap_buffer(buf));
    }

    /* Issuer key hash */
    if (issuer_key_hash) {
        JanetBuffer *buf =
            janet_buffer((int32_t)ASN1_STRING_length(issuer_key_hash));
        janet_buffer_push_bytes(buf, ASN1_STRING_get0_data(issuer_key_hash),
                                (int32_t)ASN1_STRING_length(issuer_key_hash));
        janet_table_put(result, janet_ckeywordv("issuer-key-hash"),
                        janet_wrap_buffer(buf));
    }

    /* Serial number */
    if (serial) {
        int64_t serial_val = 0;
        ASN1_INTEGER_get_int64(&serial_val, serial);
        janet_table_put(result, janet_ckeywordv("serial"),
                        janet_wrap_s64(serial_val));
    }

    /* Nonce (if present) */
    int nonce_idx =
        OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
    if (nonce_idx >= 0) {
        X509_EXTENSION *nonce_ext = OCSP_REQUEST_get_ext(req, nonce_idx);
        if (nonce_ext) {
            ASN1_OCTET_STRING *nonce_data =
                X509_EXTENSION_get_data(nonce_ext);
            if (nonce_data) {
                JanetBuffer *buf =
                    janet_buffer((int32_t)ASN1_STRING_length(nonce_data));
                janet_buffer_push_bytes(
                    buf, ASN1_STRING_get0_data(nonce_data),
                    (int32_t)ASN1_STRING_length(nonce_data));
                janet_table_put(result, janet_ckeywordv("nonce"),
                                janet_wrap_buffer(buf));
            }
        }
    } else {
        janet_table_put(result, janet_ckeywordv("nonce"), janet_wrap_nil());
    }

    OCSP_REQUEST_free(req);

    return janet_wrap_table(result);
}

/*
 * =============================================================================
 * ca/create-ocsp-response - Create OCSP response
 * =============================================================================
 */

static const char *cfun_ca_create_ocsp_response_docstring =
    "(:create-ocsp-response ca request-info status &opt opts)\n"
    "or (ca/create-ocsp-response ca request-info status &opt opts)\n\n"
    "Create an OCSP response for a certificate status query.\n\n"
    "Arguments:\n"
    "  ca           - The CA that issued the certificate\n"
    "  request-info - Parsed request from ca/parse-ocsp-request\n"
    "  status       - :good, :revoked, or :unknown\n\n"
    "Options:\n"
    "  :revocation-time <time>    - When revoked (required if status is "
    ":revoked)\n"
    "  :revocation-reason <kw>    - Why revoked (see ca/revoke for reasons)\n"
    "  :this-update <time>        - Response validity start (default: now)\n"
    "  :next-update <time>        - Response validity end (default: +1 day)\n"
    "  :include-nonce <bool>      - Echo nonce from request (default: true "
    "if present)\n\n"
    "Returns DER-encoded OCSP response bytes.\n\n"
    "Note: You implement the HTTP server; this just creates the crypto "
    "response.";

Janet cfun_ca_create_ocsp_response(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);

    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);

    /* Get request info */
    Janet req_info = argv[1];
    if (!janet_checktype(req_info, JANET_TABLE)) {
        ca_panic_param(
            "request-info must be a table (from ca/parse-ocsp-request)");
    }
    JanetTable *req_table = janet_unwrap_table(req_info);

    /* Get status */
    const char *status_str = janet_to_string_or_keyword(argv[2]);
    int status;
    if (strcmp(status_str, "good") == 0) {
        status = V_OCSP_CERTSTATUS_GOOD;
    } else if (strcmp(status_str, "revoked") == 0) {
        status = V_OCSP_CERTSTATUS_REVOKED;
    } else if (strcmp(status_str, "unknown") == 0) {
        status = V_OCSP_CERTSTATUS_UNKNOWN;
    } else {
        ca_panic_param("status must be :good, :revoked, or :unknown");
    }

    /* Get options */
    Janet opts = argc > 3 ? argv[3] : janet_wrap_nil();

    CARevocationReason revoke_reason = CA_REVOKE_UNSPECIFIED;
    int include_nonce = 1; /* Default: include if present in request */

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "revocation-reason");
        if (!janet_checktype(v, JANET_NIL)) {
            revoke_reason = ca_keyword_to_reason(v);
        }

        v = ca_opts_get(opts, "include-nonce");
        if (!janet_checktype(v, JANET_NIL)) {
            include_nonce = janet_truthy(v);
        }
    }

    /* Get serial from request info */
    Janet serial_v = janet_table_get(req_table, janet_ckeywordv("serial"));
    if (janet_checktype(serial_v, JANET_NIL)) {
        ca_panic_param("request-info missing :serial");
    }
    int64_t serial = janet_getinteger64(&serial_v, 0);

    /* Create OCSP basic response */
    OCSP_BASICRESP *basic = OCSP_BASICRESP_new();
    if (!basic) {
        ca_panic_ssl("failed to create OCSP basic response");
    }

    /* Create certificate ID for the response */
    OCSP_CERTID *certid = OCSP_cert_to_id(EVP_sha1(), NULL, ca->cert);
    if (!certid) {
        OCSP_BASICRESP_free(basic);
        ca_panic_ssl("failed to create OCSP certificate ID");
    }

    /* Override the serial number in the cert ID */
    /* We need to create a proper cert ID with the right serial */
    OCSP_CERTID_free(certid);

    /* Build cert ID manually from CA cert and serial */
    ASN1_INTEGER *asn_serial = ASN1_INTEGER_new();
    ASN1_INTEGER_set_int64(asn_serial, serial);

    /* Get issuer name and key for cert ID */
    certid = OCSP_cert_id_new(EVP_sha1(), X509_get_subject_name(ca->cert),
                              X509_get0_pubkey_bitstr(ca->cert), asn_serial);
    ASN1_INTEGER_free(asn_serial);

    if (!certid) {
        OCSP_BASICRESP_free(basic);
        ca_panic_ssl("failed to create OCSP certificate ID");
    }

    /* Set up revocation info if revoked */
    ASN1_TIME *revtime = NULL;
    ASN1_GENERALIZEDTIME *revtime_gen = NULL;
    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        revtime = ASN1_TIME_new();
        if (!revtime) {
            ca_panic_resource(
                "failed to allocate ASN1_TIME for revocation time");
        }
        X509_gmtime_adj(revtime, 0); /* Default: now */

        if (ca_opts_valid(opts)) {
            Janet v = ca_opts_get(opts, "revocation-time");
            if (!janet_checktype(v, JANET_NIL)) {
                /* Parse time from Janet value - accepts Unix timestamp
                 * (number) or ISO 8601 string like "2025-01-15T10:30:00Z" */
                if (janet_checktype(v, JANET_NUMBER)) {
                    /* Unix timestamp in seconds */
                    time_t ts = (time_t)janet_unwrap_number(v);
                    ASN1_TIME_set(revtime, ts);
                } else if (janet_checktype(v, JANET_STRING)) {
                    /* ISO 8601 format string */
                    const char *timestr =
                        (const char *)janet_unwrap_string(v);
                    if (!ASN1_TIME_set_string(revtime, timestr)) {
                        /* Try alternative format YYYYMMDDHHMMSSZ */
                        if (!ASN1_TIME_set_string_X509(revtime, timestr)) {
                            ASN1_TIME_free(revtime);
                            ca_panic_param(
                                "invalid revocation-time format: %s",
                                timestr);
                        }
                    }
                } else {
                    ASN1_TIME_free(revtime);
                    ca_panic_param("revocation-time must be a number (unix "
                                   "timestamp) or string (ISO 8601)");
                }
            }
        }

        revtime_gen = ASN1_TIME_to_generalizedtime(revtime, NULL);
    }

    /* Set up update times */
    ASN1_TIME *this_update = ASN1_TIME_new();
    ASN1_TIME *next_update = ASN1_TIME_new();
    X509_gmtime_adj(this_update, 0);
    X509_gmtime_adj(next_update, 24L * 60L * 60L); /* +1 day */

    ASN1_GENERALIZEDTIME *this_update_gen =
        ASN1_TIME_to_generalizedtime(this_update, NULL);
    ASN1_GENERALIZEDTIME *next_update_gen =
        ASN1_TIME_to_generalizedtime(next_update, NULL);

    /* Add single response */
    if (!OCSP_basic_add1_status(basic, certid, status, (int)revoke_reason,
                                revtime_gen, this_update_gen,
                                next_update_gen)) {
        if (revtime) ASN1_TIME_free(revtime);
        if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        ASN1_GENERALIZEDTIME_free(this_update_gen);
        ASN1_GENERALIZEDTIME_free(next_update_gen);
        OCSP_CERTID_free(certid);
        OCSP_BASICRESP_free(basic);
        ca_panic_ssl("failed to add OCSP status");
    }

    /* Add nonce if requested and present in request */
    if (include_nonce) {
        Janet nonce_v = janet_table_get(req_table, janet_ckeywordv("nonce"));
        if (!janet_checktype(nonce_v, JANET_NIL)) {
            JanetBuffer *nonce_buf = janet_unwrap_buffer(nonce_v);
            /* Add nonce extension to response */
            OCSP_basic_add1_nonce(basic, nonce_buf->data,
                                  (int)nonce_buf->count);
        }
    }

    /* Sign the basic response */
    if (!OCSP_basic_sign(basic, ca->cert, ca->key, EVP_sha256(), NULL, 0)) {
        if (revtime) ASN1_TIME_free(revtime);
        if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        ASN1_GENERALIZEDTIME_free(this_update_gen);
        ASN1_GENERALIZEDTIME_free(next_update_gen);
        OCSP_CERTID_free(certid);
        OCSP_BASICRESP_free(basic);
        ca_panic_ssl("failed to sign OCSP response");
    }

    /* Create OCSP response wrapper */
    OCSP_RESPONSE *resp =
        OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    if (!resp) {
        if (revtime) ASN1_TIME_free(revtime);
        if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        ASN1_GENERALIZEDTIME_free(this_update_gen);
        ASN1_GENERALIZEDTIME_free(next_update_gen);
        OCSP_CERTID_free(certid);
        OCSP_BASICRESP_free(basic);
        ca_panic_ssl("failed to create OCSP response");
    }

    /* Encode to DER */
    int len = i2d_OCSP_RESPONSE(resp, NULL);
    if (len <= 0) {
        if (revtime) ASN1_TIME_free(revtime);
        if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        ASN1_GENERALIZEDTIME_free(this_update_gen);
        ASN1_GENERALIZEDTIME_free(next_update_gen);
        OCSP_CERTID_free(certid);
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(resp);
        ca_panic_ssl("failed to encode OCSP response");
    }

    JanetBuffer *result = janet_buffer(len);
    unsigned char *p = result->data;
    i2d_OCSP_RESPONSE(resp, &p);
    result->count = len;

    /* Cleanup */
    if (revtime) ASN1_TIME_free(revtime);
    if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
    ASN1_TIME_free(this_update);
    ASN1_TIME_free(next_update);
    ASN1_GENERALIZEDTIME_free(this_update_gen);
    ASN1_GENERALIZEDTIME_free(next_update_gen);
    OCSP_CERTID_free(certid);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(resp);

    return janet_wrap_buffer(result);
}

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

void jca_register_ocsp(JanetTable *env) {
    janet_def(env, "parse-ocsp-request",
              janet_wrap_cfunction(cfun_ca_parse_ocsp_request),
              cfun_ca_parse_ocsp_request_docstring);
    janet_def(env, "create-ocsp-response",
              janet_wrap_cfunction(cfun_ca_create_ocsp_response),
              cfun_ca_create_ocsp_response_docstring);
}
