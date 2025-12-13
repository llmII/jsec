/*
 * client.c - Client SSL context creation
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../jtls_internal.h"

/*============================================================================
 * CREATE CLIENT CONTEXT
 *============================================================================
 * Create an SSL_CTX for client connections.
 *
 * Parameters:
 *   verify        - Whether to verify server certificate
 *   security_opts - Janet table with security options (:min-version, :ciphers, etc.)
 */
SSL_CTX *jtls_create_client_ctx(int verify, Janet security_opts) {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;

    /* Set verification mode */
    if (verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Apply security options */
    if (!apply_security_options(ctx, security_opts, 0)) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Disable renegotiation by default for security */
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

    /* Handle session cache option - default enabled for client */
    int session_cache = 1;
    if (janet_checktype(security_opts, JANET_TABLE)) {
        JanetTable *opts_table = janet_unwrap_table(security_opts);
        Janet cache_opt = janet_table_get(opts_table,
                                          janet_ckeywordv("session-cache"));
        if (!janet_checktype(cache_opt, JANET_NIL)) {
            session_cache = janet_truthy(cache_opt);
        }
    }
    SSL_CTX_set_session_cache_mode(ctx, session_cache ? SSL_SESS_CACHE_CLIENT : SSL_SESS_CACHE_OFF);

    /* Handle session tickets */
    int tickets = 1;
    if (janet_checktype(security_opts, JANET_TABLE)) {
        JanetTable *opts_table = janet_unwrap_table(security_opts);
        Janet ticket_opt = janet_table_get(opts_table,
                                           janet_ckeywordv("session-tickets"));
        if (!janet_checktype(ticket_opt, JANET_NIL)) {
            tickets = janet_truthy(ticket_opt);
        }
    }
    if (!tickets) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }

    /* Enable key logging if SSLKEYLOGFILE is set */
    if (keylog_file) {
        SSL_CTX_set_keylog_callback(ctx, jtls_keylog_callback);
    }

    /* Get cache size from security options (default: 1000) */
    long cache_size = 1000;
    if (janet_checktype(security_opts, JANET_TABLE)) {
        JanetTable *opts_table = janet_unwrap_table(security_opts);
        Janet size_opt = janet_table_get(opts_table,
                                         janet_ckeywordv("session-cache-size"));
        if (janet_checktype(size_opt, JANET_NUMBER)) {
            cache_size = (long)janet_unwrap_number(size_opt);
            if (cache_size < 0) cache_size = 1000;
        }
    }
    SSL_CTX_sess_set_cache_size(ctx, cache_size);

    return ctx;
}
