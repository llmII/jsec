/*
 * client/types.c - DTLSClient type definition and lifecycle
 *
 * Defines the DTLSClient abstract type including GC, mark, and method dispatch.
 * Function declarations are in internal.h for separate compilation.
 */

#include "../internal.h"
#include <string.h>

static int dtls_client_gc(void *p, size_t s) {
    (void)s;
    DTLSClient *client = (DTLSClient *)p;

    if (client->ssl) {
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    /* Only free ctx if we own it (not from a shared DTLSContext) */
    if (client->ctx && client->owns_ctx) {
        SSL_CTX_free(client->ctx);
        client->ctx = NULL;
    }
    /* Transport is a Janet stream - GC handles it */

    return 0;
}

static int dtls_client_mark(void *p, size_t s) {
    (void)s;
    DTLSClient *client = (DTLSClient *)p;

    if (client->transport) {
        janet_mark(janet_wrap_abstract(client->transport));
    }

    return 0;
}

/* Method table for DTLSClient - matches Janet's connected UDP pattern */
const JanetMethod dtls_client_methods[] = {
    {"read", cfun_dtls_read},
    {"chunk", cfun_dtls_chunk},
    {"write", cfun_dtls_write},
    {"close", cfun_dtls_close},
    {"shutdown", cfun_dtls_shutdown},
    {"version", cfun_dtls_get_version},
    {"cipher", cfun_dtls_get_cipher},
    {"cipher-bits", cfun_dtls_get_cipher_bits},
    {"connection-info", cfun_dtls_get_connection_info},
    {"session-reused?", cfun_dtls_session_reused},
    {"session", cfun_dtls_get_session},
    {"set-session", cfun_dtls_set_session},
    {"localname", cfun_dtls_localname},
    {"peername", cfun_dtls_peername},
    {"trust-cert", cfun_dtls_trust_cert},
    {"handshake-time", cfun_dtls_get_handshake_time},
    {NULL, NULL}
};

/* Method dispatch using janet_getmethod like TLS does */
static int dtls_client_get(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD)) return 0;
    return janet_getmethod(janet_unwrap_keyword(key), dtls_client_methods, out);
}

const JanetAbstractType dtls_client_type = {
    "jsec/dtls-client",
    dtls_client_gc,
    dtls_client_mark,
    dtls_client_get,
    NULL,                       /* put */
    NULL,                       /* marshal */
    NULL,                       /* unmarshal */
    NULL,                       /* tostring */
    NULL,                       /* compare */
    NULL,                       /* hash */
    JANET_ATEND_HASH
};
