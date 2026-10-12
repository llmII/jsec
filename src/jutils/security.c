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
 * VALIDATE SECURITY OPTIONS
 *============================================================================
 * Raise on a non-dictionary :security value and on a bad
 * :session-cache-size. Called before any SSL_CTX or ctx_cache_lock
 * exists so the raise never longjmps past cleanup.
 */
void jutils_validate_security_options(Janet opts) {
    if (janet_checktype(opts, JANET_NIL)) return;
    if (!janet_checktype(opts, JANET_TABLE) &&
        !janet_checktype(opts, JANET_STRUCT)) {
        utils_panic_param(":security must be a table or struct");
    }

    Janet size_opt = janet_get(opts, janet_ckeywordv("session-cache-size"));
    if (!janet_checktype(size_opt, JANET_NIL)) {
        if (!janet_checktype(size_opt, JANET_NUMBER)) {
            utils_panic_param(":session-cache-size must be a number");
        }
        double size = janet_unwrap_number(size_opt);
        if (!(size >= 0.0) || size > 4294967295.0) {
            utils_panic_param(
                ":session-cache-size must be a non-negative number");
        }
    }
}

/*============================================================================
 * APPLY SESSION CACHE OPTIONS
 *============================================================================
 * The session trio shared by every context builder and both parser sites:
 * :session-cache, :session-tickets, :session-cache-size. Accepts nil,
 * table, or struct.
 */
void jutils_apply_session_cache_options(SSL_CTX *ctx, Janet opts,
                                        int is_server) {
    int session_cache = 1;
    int tickets = 1;
    long cache_size = 1000;

    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet v = janet_get(opts, janet_ckeywordv("session-cache"));
        if (!janet_checktype(v, JANET_NIL)) {
            session_cache = janet_truthy(v);
        }

        v = janet_get(opts, janet_ckeywordv("session-tickets"));
        if (!janet_checktype(v, JANET_NIL)) {
            tickets = janet_truthy(v);
        }

        v = janet_get(opts, janet_ckeywordv("session-cache-size"));
        if (janet_checktype(v, JANET_NUMBER)) {
            cache_size = (long)janet_unwrap_number(v);
        }
    }

    SSL_CTX_set_session_cache_mode(
        ctx, session_cache
                 ? (is_server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT)
                 : SSL_SESS_CACHE_OFF);
    if (!tickets) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }
    SSL_CTX_sess_set_cache_size(ctx, cache_size);
}

/*============================================================================
 * APPLY SECURITY OPTIONS
 *============================================================================
 * Apply a Janet table or struct of security options to an SSL_CTX.
 *
 * Supported options:
 *   :min-version - Minimum TLS/DTLS version (e.g., "TLS1.2", "DTLS1.2")
 *   :max-version - Maximum TLS/DTLS version
 *   :ciphers     - Cipher suite string for TLS 1.2 and earlier
 *   :ciphersuites - Cipher suite string for TLS 1.3
 *   :curves      - EC curves for ECDHE (e.g., "prime256v1:secp384r1")
 *   :ca-file     - CA file path or PEM data
 *   :ca-path     - CA directory path
 *   :session-cache - Boolean, cache sessions (default true)
 *   :session-tickets - Boolean, stateless session tickets (default true)
 *   :session-cache-size - Number, maximum cached sessions (default 1000)
 *
 * The container contract is one for both parser sites (this function and
 * apply_session_options in src/jtls/context/server.c): nil, table, or
 * struct; anything else raises [UTILS:PARAM] via
 * jutils_validate_security_options, which every context builder calls
 * BEFORE allocating an SSL_CTX or taking ctx_cache_lock so the raise
 * never longjmps past live cleanup. This function never reports
 * success for a value it cannot read.
 */
int apply_security_options(SSL_CTX *ctx, Janet opts, int is_dtls,
                           int is_server) {
    /* Always set secure minimum version default */
    SSL_CTX_set_min_proto_version(ctx,
                                  is_dtls ? DTLS1_2_VERSION : TLS1_2_VERSION);

    /* If no options provided, use defaults */
    if (janet_checktype(opts, JANET_NIL)) {
        jutils_apply_session_cache_options(ctx, opts, is_server);
        return 1;
    }
    /* Contract: table or struct. jutils_validate_security_options raises
     * on anything else before this point is reachable; never report
     * success for a value we cannot read. */
    if (!janet_checktype(opts, JANET_TABLE) &&
        !janet_checktype(opts, JANET_STRUCT)) {
        return 0;
    }

    /* Session options: the same keys this parser shares with
     * apply_session_options, honored for every context builder. */
    jutils_apply_session_cache_options(ctx, opts, is_server);

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
