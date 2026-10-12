/*
 * client.c - Client SSL context creation
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"

/*============================================================================
 * CREATE CLIENT CONTEXT
 *============================================================================
 * Create an SSL_CTX for client connections.
 *
 * Parameters:
 *   verify        - Whether to verify server certificate
 *   security_opts - Janet table or struct with security options
 * (:min-version, :ciphers, etc.)
 */
SSL_CTX *jtls_create_client_ctx(int verify, Janet security_opts) {
    /* Validate :security before any SSL_CTX exists or ctx_cache_lock
     * is taken (never longjmp past cleanup). */
    jutils_validate_security_options(security_opts);

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

    /* Apply security options (including the shared session cache,
     * session tickets and session cache size keys) */
    if (!apply_security_options(ctx, security_opts, 0, 0)) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Disable renegotiation by default for security */
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

    /* Enable key logging if SSLKEYLOGFILE is set */
    if (keylog_file) {
        SSL_CTX_set_keylog_callback(ctx, jtls_keylog_callback);
    }

    return ctx;
}
