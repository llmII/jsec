/*
 * context.c - Unified SSL context type implementation
 *
 * Provides a single abstract type for both TLS and DTLS contexts.
 * The is_dtls flag determines which SSL_METHOD was used at creation.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <string.h>

/*============================================================================
 * CONTEXT TYPE DEFINITION
 *============================================================================*/

/* Method table for SSLContext */
const JanetMethod ssl_context_methods[] = {
    {"trust-cert", cfun_ssl_context_trust_cert},
    {NULL, NULL}
};

/* GC callback for unified context */
int ssl_context_gc(void *p, size_t s) {
    (void)s;
    SSLContext *ctx = (SSLContext *)p;
    if (ctx->ctx) {
        SSL_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
    return 0;
}

/* Get method for unified context */
int ssl_context_get(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD)) return 0;
    return janet_getmethod(janet_unwrap_keyword(key), ssl_context_methods, out);
}

/* The unified context type */
const JanetAbstractType ssl_context_type = {
    "jsec/ssl-context",
    ssl_context_gc,
    NULL,  /* gcmark */
    ssl_context_get,
    NULL,  /* put */
    NULL,  /* marshal */
    NULL,  /* unmarshal */
    NULL,  /* tostring */
    NULL,  /* compare */
    NULL,  /* hash */
    JANET_ATEND_HASH
};

/* Flag to track if type is registered */
static int ssl_context_type_registered = 0;

/* Initialize the shared context type */
void jutils_init_context_type(void) {
    if (!ssl_context_type_registered) {
        janet_register_abstract_type(&ssl_context_type);
        ssl_context_type_registered = 1;
    }
}

/*============================================================================
 * CONTEXT METHODS
 *============================================================================*/

/*
 * (:trust-cert ctx cert-pem)
 *
 * Trust a specific certificate in this context.
 * Useful for self-signed certificates or certificate pinning.
 */
Janet cfun_ssl_context_trust_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    SSLContext *ssl_ctx = janet_getabstract(argv, 0, &ssl_context_type);

    if (!ssl_ctx->ctx) {
        utils_panic_config("invalid SSL context");
    }

    if (!add_trusted_cert(ssl_ctx->ctx, argv[1])) {
        utils_panic_ssl("failed to add trusted certificate");
    }

    return janet_wrap_nil();
}

/*============================================================================
 * CONTEXT CREATION
 *============================================================================
 * Create a unified SSL context from options.
 *
 * Options:
 *   :cert - Certificate (PEM string or file path)
 *   :key - Private key (PEM string or file path)
 *   :verify - Verify peer certificates (default: true for client, false for server)
 *   :ca - CA certificate path
 *   :trusted-cert - Trust specific certificate (for self-signed)
 *   :ciphers - Cipher suite string
 *   :security - Security options table
 *
 * If :cert and :key are provided, creates a server-capable context.
 * Otherwise creates a client-only context.
 */
SSLContext *jutils_create_context(Janet opts, int is_dtls) {
    int is_server = 0;
    int verify = -1;  /* -1 means use default */

    /* Check if this is a server context (has cert and key) */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet cert = janet_get(opts, janet_ckeywordv("cert"));
        Janet key = janet_get(opts, janet_ckeywordv("key"));

        if (!janet_checktype(cert, JANET_NIL) && !janet_checktype(key, JANET_NIL)) {
            is_server = 1;
        }

        Janet v = janet_get(opts, janet_ckeywordv("verify"));
        if (!janet_checktype(v, JANET_NIL)) {
            verify = janet_truthy(v) ? 1 : 0;
        }
    }

    /* Create SSLContext */
    SSLContext *ssl_ctx = janet_abstract(&ssl_context_type, sizeof(SSLContext));
    memset(ssl_ctx, 0, sizeof(SSLContext));
    ssl_ctx->is_dtls = is_dtls;

    /* Create SSL_CTX with appropriate method */
    if (is_dtls) {
        ssl_ctx->ctx = SSL_CTX_new(is_server ? DTLS_server_method() :
                                   DTLS_client_method());
    } else {
        ssl_ctx->ctx = SSL_CTX_new(is_server ? TLS_server_method() :
                                   TLS_client_method());
    }

    if (!ssl_ctx->ctx) {
        utils_panic_ssl("failed to create SSL context");
    }

    /* Apply security options */
    Janet security = janet_wrap_nil();
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        security = janet_get(opts, janet_ckeywordv("security"));
    }
    if (!apply_security_options(ssl_ctx->ctx, security, is_dtls)) {
        SSL_CTX_free(ssl_ctx->ctx);
        ssl_ctx->ctx = NULL;
        utils_panic_ssl("failed to apply security options");
    }

    /* Load certificates if provided */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet cert = janet_get(opts, janet_ckeywordv("cert"));
        Janet key = janet_get(opts, janet_ckeywordv("key"));

        /* Validate: cert and key must be provided together */
        int has_cert = !janet_checktype(cert, JANET_NIL);
        int has_key = !janet_checktype(key, JANET_NIL);
        if (has_cert != has_key) {
            SSL_CTX_free(ssl_ctx->ctx);
            ssl_ctx->ctx = NULL;
            janet_panicf("[TLS:CFG] :cert and :key must be provided together");
        }

        if (has_cert) {
            if (!jutils_load_cert(ssl_ctx->ctx, cert)) {
                SSL_CTX_free(ssl_ctx->ctx);
                ssl_ctx->ctx = NULL;
                utils_panic_ssl("failed to load certificate");
            }
        }

        if (has_key) {
            if (!jutils_load_key(ssl_ctx->ctx, key)) {
                SSL_CTX_free(ssl_ctx->ctx);
                ssl_ctx->ctx = NULL;
                utils_panic_ssl("failed to load private key");
            }
        }

        /* Verify key matches certificate if both provided */
        if (is_server && !SSL_CTX_check_private_key(ssl_ctx->ctx)) {
            SSL_CTX_free(ssl_ctx->ctx);
            ssl_ctx->ctx = NULL;
            utils_panic_verify("private key does not match certificate");
        }

        /* CA certificates */
        Janet ca = janet_get(opts, janet_ckeywordv("ca"));
        if (!janet_checktype(ca, JANET_NIL)) {
            if (!jutils_load_ca(ssl_ctx->ctx, ca)) {
                SSL_CTX_free(ssl_ctx->ctx);
                ssl_ctx->ctx = NULL;
                utils_panic_ssl("failed to load CA certificates");
            }
        }

        /* Trust specific certificate */
        Janet trusted = janet_get(opts, janet_ckeywordv("trusted-cert"));
        if (!janet_checktype(trusted, JANET_NIL)) {
            if (!add_trusted_cert(ssl_ctx->ctx, trusted)) {
                SSL_CTX_free(ssl_ctx->ctx);
                ssl_ctx->ctx = NULL;
                utils_panic_ssl("failed to add trusted certificate");
            }
        }

        /* Cipher suites */
        Janet ciphers = janet_get(opts, janet_ckeywordv("ciphers"));
        if (!janet_checktype(ciphers, JANET_NIL) &&
            janet_checktype(ciphers, JANET_STRING)) {
            const char *cipher_str = (const char *)janet_unwrap_string(ciphers);
            if (SSL_CTX_set_cipher_list(ssl_ctx->ctx, cipher_str) != 1) {
                SSL_CTX_free(ssl_ctx->ctx);
                ssl_ctx->ctx = NULL;
                utils_panic_config("failed to set ciphers: %s", cipher_str);
            }
        }
    }

    /* Set verification mode */
    if (verify == -1) {
        /* Default: verify for client, no verify for server */
        verify = is_server ? 0 : 1;
    }

    if (verify) {
        SSL_CTX_set_verify(ssl_ctx->ctx, SSL_VERIFY_PEER, NULL);
        /* Load default verify paths if no trusted cert was provided */
        if (janet_checktype(opts, JANET_TABLE) ||
            janet_checktype(opts, JANET_STRUCT)) {
            Janet trusted = janet_get(opts, janet_ckeywordv("trusted-cert"));
            Janet ca = janet_get(opts, janet_ckeywordv("ca"));
            if (janet_checktype(trusted, JANET_NIL) && janet_checktype(ca, JANET_NIL)) {
                SSL_CTX_set_default_verify_paths(ssl_ctx->ctx);
            }
        } else {
            SSL_CTX_set_default_verify_paths(ssl_ctx->ctx);
        }
    } else {
        SSL_CTX_set_verify(ssl_ctx->ctx, SSL_VERIFY_NONE, NULL);
    }

    return ssl_ctx;
}
