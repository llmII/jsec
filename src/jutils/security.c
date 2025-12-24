/*
 * security.c - Security options parsing and application
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <string.h>

/*============================================================================
 * PROTOCOL VERSION PARSING
 *============================================================================
 * Parse protocol version string to OpenSSL version constant.
 */

/* Parse TLS version string to OpenSSL constant */
static int parse_tls_version(const char *ver_str) {
    if (strcmp(ver_str, "TLS1.0") == 0 || strcmp(ver_str, "TLS1_0") == 0)
        return TLS1_VERSION;
    if (strcmp(ver_str, "TLS1.1") == 0 || strcmp(ver_str, "TLS1_1") == 0)
        return TLS1_1_VERSION;
    if (strcmp(ver_str, "TLS1.2") == 0 || strcmp(ver_str, "TLS1_2") == 0)
        return TLS1_2_VERSION;
    if (strcmp(ver_str, "TLS1.3") == 0 || strcmp(ver_str, "TLS1_3") == 0)
        return TLS1_3_VERSION;
    return 0; /* Invalid */
}

/* Parse DTLS version string to OpenSSL constant */
static int parse_dtls_version(const char *ver_str) {
    if (strcmp(ver_str, "DTLS1.0") == 0 || strcmp(ver_str, "DTLS1_0") == 0)
        return DTLS1_VERSION;
    if (strcmp(ver_str, "DTLS1.2") == 0 || strcmp(ver_str, "DTLS1_2") == 0)
        return DTLS1_2_VERSION;
    return 0; /* Invalid */
}

/*============================================================================
 * APPLY SECURITY OPTIONS
 *============================================================================
 * Apply a Janet table of security options to an SSL_CTX.
 *
 * Supported options:
 *   :min-version - Minimum TLS/DTLS version (e.g., "TLS1.2", "DTLS1.2")
 *   :max-version - Maximum TLS/DTLS version
 *   :ciphers     - Cipher suite string for TLS 1.2 and earlier
 *   :ciphersuites - Cipher suite string for TLS 1.3
 *   :curves      - EC curves for ECDHE (e.g., "prime256v1:secp384r1")
 *   :ca-file     - CA file path or PEM data
 *   :ca-path     - CA directory path
 */
int apply_security_options(SSL_CTX *ctx, Janet opts, int is_dtls) {
    /* Always set secure minimum version default */
    SSL_CTX_set_min_proto_version(ctx,
                                  is_dtls ? DTLS1_2_VERSION : TLS1_2_VERSION);

    /* If no options provided, use defaults */
    if (janet_checktype(opts, JANET_NIL)) return 1;
    if (!janet_checktype(opts, JANET_TABLE) &&
        !janet_checktype(opts, JANET_STRUCT)) {
        return 1;
    }

    /* Apply minimum protocol version (override default if specified) */
    Janet min_ver = janet_get(opts, janet_ckeywordv("min-version"));
    if (!janet_checktype(min_ver, JANET_NIL)) {
        const char *ver_str = janet_to_string_or_keyword(min_ver);
        if (!ver_str) {
            janet_panicf(
                "[TLS:CFG] :min-version must be a string or keyword");
        }

        int version = is_dtls ? parse_dtls_version(ver_str)
                              : parse_tls_version(ver_str);
        if (version == 0) {
            if (is_dtls) {
                janet_panicf("[TLS:CFG] invalid :min-version '%s', "
                             "expected DTLS1.0 or DTLS1.2",
                             ver_str);
            } else {
                janet_panicf("[TLS:CFG] invalid :min-version '%s', "
                             "expected TLS1.0, TLS1.1, TLS1.2, or TLS1.3",
                             ver_str);
            }
        }

        if (!SSL_CTX_set_min_proto_version(ctx, version)) {
            return 0;
        }
    }

    /* Apply maximum protocol version */
    Janet max_ver = janet_get(opts, janet_ckeywordv("max-version"));
    if (!janet_checktype(max_ver, JANET_NIL)) {
        const char *ver_str = janet_to_string_or_keyword(max_ver);
        if (!ver_str) {
            janet_panicf(
                "[TLS:CFG] :max-version must be a string or keyword");
        }

        int version = is_dtls ? parse_dtls_version(ver_str)
                              : parse_tls_version(ver_str);
        if (version == 0) {
            if (is_dtls) {
                janet_panicf("[TLS:CFG] invalid :max-version '%s', "
                             "expected DTLS1.0 or DTLS1.2",
                             ver_str);
            } else {
                janet_panicf("[TLS:CFG] invalid :max-version '%s', "
                             "expected TLS1.0, TLS1.1, TLS1.2, or TLS1.3",
                             ver_str);
            }
        }

        if (!SSL_CTX_set_max_proto_version(ctx, version)) {
            return 0;
        }
    }

    /* Apply cipher suites (TLS 1.2 and earlier) */
    Janet ciphers = janet_get(opts, janet_ckeywordv("ciphers"));
    if (!janet_checktype(ciphers, JANET_NIL)) {
        const char *cipher_str = janet_to_string_or_keyword(ciphers);
        if (!cipher_str) return 0;

        if (!SSL_CTX_set_cipher_list(ctx, cipher_str)) {
            return 0;
        }
    }

    /* Apply TLS 1.3 ciphersuites (separate from TLS 1.2 ciphers) */
    Janet ciphersuites = janet_get(opts, janet_ckeywordv("ciphersuites"));
    if (!janet_checktype(ciphersuites, JANET_NIL)) {
        const char *suites_str = janet_to_string_or_keyword(ciphersuites);
        if (!suites_str) return 0;

        if (!SSL_CTX_set_ciphersuites(ctx, suites_str)) {
            return 0;
        }
    }

    /* Apply EC curves */
    Janet curves = janet_get(opts, janet_ckeywordv("curves"));
    if (!janet_checktype(curves, JANET_NIL)) {
        const char *curves_str = janet_to_string_or_keyword(curves);
        if (!curves_str) return 0;

        if (!SSL_CTX_set1_curves_list(ctx, curves_str)) {
            return 0;
        }
    }

    /* Apply CA file/path */
    Janet ca_file = janet_get(opts, janet_ckeywordv("ca-file"));
    Janet ca_path = janet_get(opts, janet_ckeywordv("ca-path"));

    const char *cfile = NULL;
    const char *cpath = NULL;
    const unsigned char *ca_data = NULL;
    int ca_len = 0;

    /* Check if ca-file is a file path or PEM data */
    if (janet_checktype(ca_file, JANET_STRING)) {
        const uint8_t *s = janet_unwrap_string(ca_file);
        if (strstr((const char *)s, "-----BEGIN")) {
            ca_data = s;
            ca_len = janet_string_length(s);
        } else {
            cfile = (const char *)s;
        }
    } else if (janet_checktype(ca_file, JANET_BUFFER)) {
        JanetBuffer *b = janet_unwrap_buffer(ca_file);
        ca_data = b->data;
        ca_len = b->count;
    }

    if (janet_checktype(ca_path, JANET_STRING)) {
        cpath = (const char *)janet_unwrap_string(ca_path);
    }

    /* Load from file/path if specified */
    if (cfile || cpath) {
        if (!SSL_CTX_load_verify_locations(ctx, cfile, cpath)) {
            return 0;
        }
    }

    /* Load from memory if PEM data provided */
    if (ca_data) {
        if (!load_ca_mem(ctx, ca_data, ca_len)) {
            return 0;
        }
    }

    return 1;
}
