/*
 * context.c - DTLS reusable context implementation
 *
 * Now uses the unified SSLContext type from jshared.c.
 * The dtls_context_type macro aliases ssl_context_type.
 *
 * A DTLSContext (SSLContext) can be passed to dtls/connect or dtls/listen via
 * the :context option to reuse SSL_CTX settings across multiple connections.
 */

#include "internal.h"
#include <string.h>
#include <openssl/x509v3.h>

/*
 * =============================================================================
 * Context Creation - now uses shared implementation
 * =============================================================================
 */

/*
 * (dtls/new-context &opt opts)
 *
 * Create a reusable DTLS context.
 * Returns an SSLContext that can be passed to dtls/connect or dtls/listen.
 *
 * Options:
 *   :cert - Certificate (PEM string or file path)
 *   :key - Private key (PEM string or file path)
 *   :verify - Verify peer certificates (default true for client, false for
 * server) :ca - CA certificate path :trusted-cert - Trust specific
 * certificate (for self-signed) :ciphers - Cipher suite string :min-version -
 * Minimum DTLS version (:dtls1.0 or :dtls1.2) :max-version - Maximum DTLS
 * version :security - Security options table
 *
 * If :cert and :key are provided, creates a server-capable context.
 * Otherwise creates a client-only context.
 */
static Janet cfun_dtls_new_context(int32_t argc, Janet *argv) {
    janet_arity(argc, 0, 1);

    Janet opts = argc > 0 ? argv[0] : janet_wrap_nil();

    /* Use shared implementation with is_dtls = 1 */
    SSLContext *ctx = jutils_create_context(opts, 1);

    return janet_wrap_abstract(ctx);
}

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

static const JanetReg context_cfuns[] = {
    {"new-context", cfun_dtls_new_context,
     "(dtls/new-context &opt opts)\n\n"
     "Create a reusable DTLS context.\n"
     "Returns an SSLContext that can be passed to dtls/connect or "
     "dtls/listen.\n\n"
     "Options:\n"
     "  :cert - Certificate (PEM string or file path)\n"
     "  :key - Private key (PEM string or file path)\n"
     "  :verify - Verify peer certificates (default: true for client, false "
     "for server)\n"
     "  :ca - CA certificate path\n"
     "  :trusted-cert - Trust specific certificate (for self-signed)\n"
     "  :ciphers - Cipher suite string\n"
     "  :security - Security options table\n\n"
     "If :cert and :key are provided, creates a server-capable context.\n"
     "Otherwise creates a client-only context."},
    {NULL, NULL, NULL}};

void jdtls_register_context(JanetTable *env) {
    /* Note: SSLContext type is registered by jsec/utils module */
    janet_cfuns(env, "jsec/dtls", context_cfuns);
}
