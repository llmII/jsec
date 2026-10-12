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
 *                   (:min-version, :ciphers, etc.)
 *   ca_opt        - Supplied CA (trust source). When provided, the system
 * default roots are NOT loaded: the supplied CA replaces them.
 */
SSL_CTX *jtls_create_client_ctx(int verify, Janet security_opts, Janet ca_opt) {
    /* Validate :security before any SSL_CTX exists or ctx_cache_lock
     * is taken (never longjmp past cleanup). */
    jutils_validate_security_options(security_opts);

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;

    int have_ca = !janet_checktype(ca_opt, JANET_NIL);

    /* Set verification mode */
    if (verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (!have_ca) {
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                SSL_CTX_free(ctx);
                return NULL;
            }
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Supplied :ca is the trust source (restrictive): replaces the system
     * default roots rather than adding to them */
    if (have_ca) {
        if (!jutils_load_ca(ctx, ca_opt)) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* Apply security options (including the shared session cache,
     * session tickets and session cache size keys) */
    if (!apply_security_options(ctx, security_opts, 0, 0)) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Disable renegotiation by default for security */
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

    /* Handle OCSP stapling option - opt-in status requests on the wire */
    Janet ocsp_opt =
        janet_get(security_opts, janet_ckeywordv("ocsp-stapling"));
    if (!janet_checktype(ocsp_opt, JANET_NIL) && janet_truthy(ocsp_opt)) {
        SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
    }
    /* Enable key logging if SSLKEYLOGFILE is set */
    if (keylog_file) {
        SSL_CTX_set_keylog_callback(ctx, jtls_keylog_callback);
    }

    return ctx;
}
