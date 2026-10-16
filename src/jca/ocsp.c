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
    "  :digest <string>            - CertID digest name the request named "
    "(e.g. \"sha256\")\n"
    "  :nonce <buffer|nil>         - Nonce extension's content bytes (if "
    "present)\n\n"
    "The :nonce buffer is the request nonce extension's content bytes - "
    "the exact value OCSP_check_nonce compares - and ca/create-ocsp-response "
    "echoes it back byte for byte.\n\n"
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
    ASN1_OBJECT *digest = NULL;
    ASN1_OCTET_STRING *issuer_key_hash = NULL;
    ASN1_INTEGER *serial = NULL;

    /* Note: OCSP_id_get0_info doesn't exist in all OpenSSL versions,
     * so we use the deprecated but widely available approach */
    int ok = OCSP_id_get0_info(&issuer_name_hash, &digest, &issuer_key_hash,
                               &serial, certid);
    if (!ok) {
        OCSP_REQUEST_free(req);
        ca_panic_parse("failed to extract OCSP request components");
    }

    /* Build result table */
    JanetTable *result = janet_table(5);

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

    /* CertID digest the request named */
    if (digest) {
        char digest_name[128];
        if (OBJ_obj2txt(digest_name, sizeof(digest_name), digest, 0) < 0) {
            OCSP_REQUEST_free(req);
            ca_panic_parse("failed to name the OCSP request CertID digest");
        }
        janet_table_put(result, janet_ckeywordv("digest"),
                        janet_cstringv(digest_name));
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
    "if present)\n"
    "  :nonce <bytes>             - Generate a response nonce when the "
    "request carries none\n\n"
    "A <time> is a number (unix timestamp) or string (ISO 8601 or "
    "YYYYMMDDHHMMSSZ).\n\n"
    "Nonce and CertID: request-info's :nonce is the request nonce "
    "extension's content bytes and is copied into the response extension "
    "verbatim - the byte-identical echo OCSP_check_nonce compares. A :nonce "
    "option value is generated instead via OCSP_basic_add1_nonce, which "
    "wraps it in an OCTET STRING: echo and generate differ by design. The "
    "response CertID uses the digest the request named (request-info's "
    ":digest, SHA-1 when absent) and the request's :serial.\n\n"
    "Returns DER-encoded OCSP response bytes.\n\n"
    "Note: You implement the HTTP server; this just creates the crypto "
    "response.";

/* Result codes for ca_ocsp_set_time. */
enum {
    CA_OCSP_TIME_BAD_FORMAT = 0,
    CA_OCSP_TIME_OK = 1,
    CA_OCSP_TIME_BAD_SHAPE = -1,
    CA_OCSP_TIME_NO_MEM = 2
};

/* Normalize the ISO 8601 extended form YYYY-MM-DDTHH:MM:SSZ into the
 * ASN.1 form YYYYMMDDHHMMSSZ. Returns 1 when the input matched the
 * extended form (normalized copy written to out), 0 otherwise. */
static int ca_ocsp_iso_to_asn1(const char *s, char *out, size_t out_len) {
    static const size_t dst[] = {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15,
                                 17, 18};
    size_t i;
    if (strlen(s) != 20 || out_len < 16) {
        return 0;
    }
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z') {
        return 0;
    }
    for (i = 0; i < sizeof(dst) / sizeof(dst[0]); i++) {
        if (s[dst[i]] < '0' || s[dst[i]] > '9') {
            return 0;
        }
    }
    for (i = 0; i < sizeof(dst) / sizeof(dst[0]); i++) {
        out[i] = s[dst[i]];
    }
    out[14] = 'Z';
    out[15] = '\0';
    return 1;
}

/* Set t from a Janet time value: number = unix timestamp, string = ISO
 * 8601 or YYYYMMDDHHMMSSZ. The same shapes are accepted for
 * :revocation-time, :this-update and :next-update. Returns
 * CA_OCSP_TIME_OK on success and one of the other CA_OCSP_TIME_* codes
 * on failure; the caller frees its live objects and raises. */
static int ca_ocsp_set_time(ASN1_TIME *t, Janet v) {
    if (janet_checktype(v, JANET_NUMBER)) {
        time_t ts = (time_t)janet_unwrap_number(v);
        return ASN1_TIME_set(t, ts) ? CA_OCSP_TIME_OK : CA_OCSP_TIME_NO_MEM;
    }
    if (janet_checktype(v, JANET_STRING)) {
        const char *timestr = (const char *)janet_unwrap_string(v);
        if (ASN1_TIME_set_string(t, timestr) ||
            ASN1_TIME_set_string_X509(t, timestr)) {
            return CA_OCSP_TIME_OK;
        }
        /* The documented ISO 8601 extended form YYYY-MM-DDTHH:MM:SSZ is
         * not an ASN.1 time string; normalize and retry. */
        char asn1[32];
        if (ca_ocsp_iso_to_asn1(timestr, asn1, sizeof(asn1)) &&
            ASN1_TIME_set_string_X509(t, asn1)) {
            return CA_OCSP_TIME_OK;
        }
        return CA_OCSP_TIME_BAD_FORMAT;
    }
    return CA_OCSP_TIME_BAD_SHAPE;
}

Janet cfun_ca_create_ocsp_response(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);

    JanetCA *ca = janet_getabstract(argv, 0, &ca_type);

    /* Get request info */
    Janet req_info = argv[1];
    JanetTable *req_table = NULL;
    JanetStruct req_struct = NULL;
    if (janet_checktype(req_info, JANET_TABLE)) {
        req_table = janet_unwrap_table(req_info);
    } else if (janet_checktype(req_info, JANET_STRUCT)) {
        req_struct = janet_unwrap_struct(req_info);
    } else {
        ca_panic_param("request-info must be a table or struct (from "
                       "ca/parse-ocsp-request)");
    }

    /* Get status */
    const char *status_str = janet_to_string_or_keyword(argv[2]);
    if (!status_str) {
        ca_panic_param("status must be a string or keyword");
    }
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
    Janet this_update_v = janet_wrap_nil();
    Janet next_update_v = janet_wrap_nil();
    Janet gen_nonce_v = janet_wrap_nil();

    if (ca_opts_valid(opts)) {
        Janet v = ca_opts_get(opts, "revocation-reason");
        if (!janet_checktype(v, JANET_NIL)) {
            revoke_reason = ca_keyword_to_reason(v);
        }

        v = ca_opts_get(opts, "include-nonce");
        if (!janet_checktype(v, JANET_NIL)) {
            include_nonce = janet_truthy(v);
        }

        v = ca_opts_get(opts, "this-update");
        if (!janet_checktype(v, JANET_NIL)) {
            this_update_v = v;
        }

        v = ca_opts_get(opts, "next-update");
        if (!janet_checktype(v, JANET_NIL)) {
            next_update_v = v;
        }

        v = ca_opts_get(opts, "nonce");
        if (!janet_checktype(v, JANET_NIL)) {
            gen_nonce_v = v;
        }
    } else if (!janet_checktype(opts, JANET_NIL)) {
        ca_panic_param("options must be a table or struct");
    }

    /* Get serial from request info */
    Janet serial_v = req_table
                         ? janet_table_get(req_table, janet_ckeywordv("serial"))
                         : janet_struct_get(req_struct,
                                            janet_ckeywordv("serial"));
    if (janet_checktype(serial_v, JANET_NIL)) {
        ca_panic_param("request-info missing :serial");
    }
    int64_t serial = janet_getinteger64(&serial_v, 0);

    /* Resolve the CertID digest the request named. Hand-built request-info
     * tables without a :digest key keep the SHA-1 default; an unsupported
     * digest is a parameter error, never a silent SHA-1 fallback. */
    const EVP_MD *digest_md = EVP_sha1();
    Janet digest_v = req_table
                         ? janet_table_get(req_table, janet_ckeywordv("digest"))
                         : janet_struct_get(req_struct,
                                            janet_ckeywordv("digest"));
    if (!janet_checktype(digest_v, JANET_NIL)) {
        const char *digest_name = janet_to_string_or_keyword(digest_v);
        if (!digest_name) {
            ca_panic_param("request-info :digest must be a string or keyword");
        }
        digest_md = EVP_get_digestbyname(digest_name);
        if (!digest_md) {
            ca_panic_param("unsupported CertID digest: %s", digest_name);
        }
    }

    /* Create OCSP basic response */
    OCSP_BASICRESP *basic = OCSP_BASICRESP_new();
    if (!basic) {
        ca_panic_ssl("failed to create OCSP basic response");
    }

    /* Build cert ID from the CA cert, the request serial and the
     * resolved digest */
    ASN1_INTEGER *asn_serial = ASN1_INTEGER_new();
    if (!asn_serial) {
        OCSP_BASICRESP_free(basic);
        ca_panic_resource(
            "failed to allocate ASN1_INTEGER for the certificate ID");
    }
    if (!ASN1_INTEGER_set_int64(asn_serial, serial)) {
        ASN1_INTEGER_free(asn_serial);
        OCSP_BASICRESP_free(basic);
        ca_panic_resource("failed to set the certificate ID serial number");
    }

    /* Get issuer name and key for cert ID */
    OCSP_CERTID *certid =
        OCSP_cert_id_new(digest_md, X509_get_subject_name(ca->cert),
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
            OCSP_CERTID_free(certid);
            OCSP_BASICRESP_free(basic);
            ca_panic_resource(
                "failed to allocate ASN1_TIME for revocation time");
        }
        X509_gmtime_adj(revtime, 0); /* Default: now */

        if (ca_opts_valid(opts)) {
            Janet v = ca_opts_get(opts, "revocation-time");
            if (!janet_checktype(v, JANET_NIL)) {
                /* Parse time from Janet value - accepts Unix timestamp
                 * (number) or ISO 8601 string like "2025-01-15T10:30:00Z" */
                int ok = ca_ocsp_set_time(revtime, v);
                if (ok != CA_OCSP_TIME_OK) {
                    ASN1_TIME_free(revtime);
                    OCSP_CERTID_free(certid);
                    OCSP_BASICRESP_free(basic);
                    if (ok == CA_OCSP_TIME_BAD_FORMAT) {
                        ca_panic_param(
                            "invalid revocation-time format: %s",
                            (const char *)janet_unwrap_string(v));
                    }
                    if (ok == CA_OCSP_TIME_BAD_SHAPE) {
                        ca_panic_param("revocation-time must be a number (unix "
                                       "timestamp) or string (ISO 8601)");
                    }
                    ca_panic_resource("failed to set revocation time");
                }
            }
        }

        revtime_gen = ASN1_TIME_to_generalizedtime(revtime, NULL);
        if (!revtime_gen) {
            ASN1_TIME_free(revtime);
            OCSP_CERTID_free(certid);
            OCSP_BASICRESP_free(basic);
            ca_panic_resource(
                "failed to convert revocation time to GeneralizedTime");
        }
    }

    /* Set up update times: honour :this-update and :next-update when
     * supplied (same value shapes as :revocation-time), otherwise now and
     * now plus one day */
    ASN1_TIME *this_update = ASN1_TIME_new();
    ASN1_TIME *next_update = ASN1_TIME_new();
    if (!this_update || !next_update) {
        if (this_update) ASN1_TIME_free(this_update);
        if (next_update) ASN1_TIME_free(next_update);
        if (revtime) ASN1_TIME_free(revtime);
        if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
        OCSP_CERTID_free(certid);
        OCSP_BASICRESP_free(basic);
        ca_panic_resource("failed to allocate ASN1_TIME for update times");
    }

    if (!janet_checktype(this_update_v, JANET_NIL)) {
        int ok = ca_ocsp_set_time(this_update, this_update_v);
        if (ok != CA_OCSP_TIME_OK) {
            ASN1_TIME_free(this_update);
            ASN1_TIME_free(next_update);
            if (revtime) ASN1_TIME_free(revtime);
            if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
            OCSP_CERTID_free(certid);
            OCSP_BASICRESP_free(basic);
            if (ok == CA_OCSP_TIME_BAD_FORMAT) {
                ca_panic_param("invalid this-update format: %s",
                               (const char *)janet_unwrap_string(this_update_v));
            }
            if (ok == CA_OCSP_TIME_BAD_SHAPE) {
                ca_panic_param("this-update must be a number (unix timestamp) "
                               "or string (ISO 8601)");
            }
            ca_panic_resource("failed to set this-update time");
        }
    } else {
        X509_gmtime_adj(this_update, 0);
    }

    if (!janet_checktype(next_update_v, JANET_NIL)) {
        int ok = ca_ocsp_set_time(next_update, next_update_v);
        if (ok != CA_OCSP_TIME_OK) {
            ASN1_TIME_free(this_update);
            ASN1_TIME_free(next_update);
            if (revtime) ASN1_TIME_free(revtime);
            if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
            OCSP_CERTID_free(certid);
            OCSP_BASICRESP_free(basic);
            if (ok == CA_OCSP_TIME_BAD_FORMAT) {
                ca_panic_param("invalid next-update format: %s",
                               (const char *)janet_unwrap_string(next_update_v));
            }
            if (ok == CA_OCSP_TIME_BAD_SHAPE) {
                ca_panic_param("next-update must be a number (unix timestamp) "
                               "or string (ISO 8601)");
            }
            ca_panic_resource("failed to set next-update time");
        }
    } else {
        X509_gmtime_adj(next_update, 24L * 60L * 60L); /* +1 day */
    }

    ASN1_GENERALIZEDTIME *this_update_gen =
        ASN1_TIME_to_generalizedtime(this_update, NULL);
    if (!this_update_gen) {
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        if (revtime) ASN1_TIME_free(revtime);
        if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
        OCSP_CERTID_free(certid);
        OCSP_BASICRESP_free(basic);
        ca_panic_resource("failed to convert this-update to GeneralizedTime");
    }
    ASN1_GENERALIZEDTIME *next_update_gen =
        ASN1_TIME_to_generalizedtime(next_update, NULL);
    if (!next_update_gen) {
        ASN1_GENERALIZEDTIME_free(this_update_gen);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        if (revtime) ASN1_TIME_free(revtime);
        if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
        OCSP_CERTID_free(certid);
        OCSP_BASICRESP_free(basic);
        ca_panic_resource("failed to convert next-update to GeneralizedTime");
    }

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

    /* Nonce: echo the request's extension content bytes verbatim when
     * present (the byte-identical echo OCSP_check_nonce compares). A
     * caller-supplied :nonce is generated instead via
     * OCSP_basic_add1_nonce, which wraps it in an OCTET STRING - echo and
     * generate differ by design. */
    int nonce_added = 0;
    if (include_nonce) {
        Janet nonce_v = req_table
                            ? janet_table_get(req_table,
                                              janet_ckeywordv("nonce"))
                            : janet_struct_get(req_struct,
                                               janet_ckeywordv("nonce"));
        if (!janet_checktype(nonce_v, JANET_NIL)) {
            if (!janet_checktype(nonce_v, JANET_BUFFER) &&
                !janet_checktype(nonce_v, JANET_STRING)) {
                if (revtime) ASN1_TIME_free(revtime);
                if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
                ASN1_TIME_free(this_update);
                ASN1_TIME_free(next_update);
                ASN1_GENERALIZEDTIME_free(this_update_gen);
                ASN1_GENERALIZEDTIME_free(next_update_gen);
                OCSP_CERTID_free(certid);
                OCSP_BASICRESP_free(basic);
                ca_panic_param(
                    "request-info :nonce must be a buffer or string");
            }
            Janet nonce_arg = nonce_v;
            JanetByteView nonce_bytes = janet_getbytes(&nonce_arg, 0);
            ASN1_OCTET_STRING *nonce_oct = ASN1_OCTET_STRING_new();
            if (!nonce_oct) {
                if (revtime) ASN1_TIME_free(revtime);
                if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
                ASN1_TIME_free(this_update);
                ASN1_TIME_free(next_update);
                ASN1_GENERALIZEDTIME_free(this_update_gen);
                ASN1_GENERALIZEDTIME_free(next_update_gen);
                OCSP_CERTID_free(certid);
                OCSP_BASICRESP_free(basic);
                ca_panic_resource(
                    "failed to allocate the nonce extension value");
            }
            if (!ASN1_OCTET_STRING_set(nonce_oct, nonce_bytes.bytes,
                                       (int)nonce_bytes.len)) {
                ASN1_OCTET_STRING_free(nonce_oct);
                if (revtime) ASN1_TIME_free(revtime);
                if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
                ASN1_TIME_free(this_update);
                ASN1_TIME_free(next_update);
                ASN1_GENERALIZEDTIME_free(this_update_gen);
                ASN1_GENERALIZEDTIME_free(next_update_gen);
                OCSP_CERTID_free(certid);
                OCSP_BASICRESP_free(basic);
                ca_panic_resource("failed to set the nonce extension value");
            }
            X509_EXTENSION *nonce_ext = X509_EXTENSION_create_by_NID(
                NULL, NID_id_pkix_OCSP_Nonce, 0, nonce_oct);
            ASN1_OCTET_STRING_free(nonce_oct);
            if (!nonce_ext) {
                if (revtime) ASN1_TIME_free(revtime);
                if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
                ASN1_TIME_free(this_update);
                ASN1_TIME_free(next_update);
                ASN1_GENERALIZEDTIME_free(this_update_gen);
                ASN1_GENERALIZEDTIME_free(next_update_gen);
                OCSP_CERTID_free(certid);
                OCSP_BASICRESP_free(basic);
                ca_panic_ssl("failed to create the nonce extension");
            }
            if (!OCSP_BASICRESP_add_ext(basic, nonce_ext, -1)) {
                X509_EXTENSION_free(nonce_ext);
                if (revtime) ASN1_TIME_free(revtime);
                if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
                ASN1_TIME_free(this_update);
                ASN1_TIME_free(next_update);
                ASN1_GENERALIZEDTIME_free(this_update_gen);
                ASN1_GENERALIZEDTIME_free(next_update_gen);
                OCSP_CERTID_free(certid);
                OCSP_BASICRESP_free(basic);
                ca_panic_ssl("failed to add the nonce extension");
            }
            X509_EXTENSION_free(nonce_ext);
            nonce_added = 1;
        }
    }
    if (!nonce_added && !janet_checktype(gen_nonce_v, JANET_NIL)) {
        if (!janet_checktype(gen_nonce_v, JANET_BUFFER) &&
            !janet_checktype(gen_nonce_v, JANET_STRING)) {
            if (revtime) ASN1_TIME_free(revtime);
            if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
            ASN1_TIME_free(this_update);
            ASN1_TIME_free(next_update);
            ASN1_GENERALIZEDTIME_free(this_update_gen);
            ASN1_GENERALIZEDTIME_free(next_update_gen);
            OCSP_CERTID_free(certid);
            OCSP_BASICRESP_free(basic);
            ca_panic_param(":nonce must be a buffer or string");
        }
        Janet gen_arg = gen_nonce_v;
        JanetByteView gen_bytes = janet_getbytes(&gen_arg, 0);
        if (!OCSP_basic_add1_nonce(basic, (unsigned char *)gen_bytes.bytes,
                                   (int)gen_bytes.len)) {
            if (revtime) ASN1_TIME_free(revtime);
            if (revtime_gen) ASN1_GENERALIZEDTIME_free(revtime_gen);
            ASN1_TIME_free(this_update);
            ASN1_TIME_free(next_update);
            ASN1_GENERALIZEDTIME_free(this_update_gen);
            ASN1_GENERALIZEDTIME_free(next_update_gen);
            OCSP_CERTID_free(certid);
            OCSP_BASICRESP_free(basic);
            ca_panic_ssl("failed to add a generated nonce");
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
    int encoded = i2d_OCSP_RESPONSE(resp, &p);
    if (encoded != len) {
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
