/*
 * types.c - Global type definitions and state for JTLS
 *
 * This file defines:
 * - Global OpenSSL ex_data indices
 * - Server context cache
 * - Abstract type definitions for TLS streams and contexts
 * - Method table for TLS streams
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"

/*============================================================================
 * GLOBAL STATE
 *============================================================================
 * These are initialized once in jtls_module_init and used throughout.
 * Thread safety is provided by Janet's mutex for the context cache.
 */

/* OpenSSL ex_data indices for storing custom data on SSL_CTX objects */
int sni_idx = -1;
int ocsp_idx = -1;
int alpn_idx = -1;

/* Server context cache for session resumption */
ServerCTXCache server_ctx_cache = {NULL, NULL, NULL, NULL, 0,
                                   NULL, 0,    NULL, 0};

/* Mutex protecting the context cache (allocated in module init) */
JanetOSMutex *ctx_cache_lock = NULL;

/* Optional key log file for debugging (enabled by SSLKEYLOGFILE env var) */
FILE *keylog_file = NULL;

/*============================================================================
 * TLS CONTEXT ABSTRACT TYPE
 *============================================================================
 * Now uses the unified SSLContext type from jshared.c.
 * The tls_context_type macro aliases ssl_context_type.
 * jtls_context_gc is kept for backwards compatibility but delegates to
 * shared.
 */

int jtls_context_gc(void *p, size_t s) {
    /* Delegate to shared implementation */
    return ssl_context_gc(p, s);
}

/* tls_context_type is now defined as a macro aliasing ssl_context_type */

/*============================================================================
 * TLS STREAM ABSTRACT TYPE
 *============================================================================
 * The TLS stream type provides methods for TLS I/O operations.
 * Methods are looked up through the getter callback.
 */

/* GC callback - clean up SSL resources */
int jtls_stream_gc(void *p, size_t s) {
    (void)s;
    TLSStream *tls = (TLSStream *)p;

    /* Free BIO read-ahead buffer */
    if (tls->bio_ahead.data) {
        janet_free(tls->bio_ahead.data);
        tls->bio_ahead.data = NULL;
        tls->bio_ahead.p = NULL;
        tls->bio_ahead.pe = NULL;
    }

    if (tls->ssl) {
        SSL_free(tls->ssl);
        tls->ssl = NULL;
        tls->bio = NULL; /* BIO is freed by SSL_free */
    }
    if (tls->ctx && tls->owns_ctx) {
        SSL_CTX_free(tls->ctx);
        tls->ctx = NULL;
    }
    return 0;
}

/* GC mark callback - mark referenced Janet values */
int jtls_stream_mark(void *p, size_t s) {
    (void)s;
    TLSStream *tls = (TLSStream *)p;
    if (tls->transport) {
        janet_mark(janet_wrap_abstract(tls->transport));
    }
    return 0;
}

/* Method lookup callback */
int jtls_stream_getter(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD)) return 0;
    return janet_getmethod(janet_unwrap_keyword(key), tls_stream_methods,
                           out);
}

/*============================================================================
 * TLS STREAM METHOD TABLE
 *============================================================================
 * Methods available on TLS stream objects. These implement the Janet stream
 * API plus TLS-specific extensions.
 *
 * Standard stream methods:
 *   :read   - Read decrypted data
 *   :write  - Write data (encrypts before sending)
 *   :close  - Close with TLS shutdown
 *   :chunk  - Read exact number of bytes (alias for read)
 *   :localname - Get local address/port
 *   :peername  - Get remote peer's address/port
 *
 * TLS-specific methods:
 *   :shutdown         - TLS shutdown without closing socket
 *   :session-reused?  - Check if session was resumed
 *   :session          - Get session data for resumption
 *   :set-session      - Set session data before handshake
 *   :version          - Get TLS version string
 *   :cipher           - Get cipher suite name
 *   :cipher-bits      - Get cipher strength
 *   :connection-info  - Get detailed connection info
 *   :handshake-time   - Get handshake duration in seconds (nil if not
 * complete) :renegotiate      - Trigger renegotiation (TLS 1.2) :key-update
 *     - Trigger key update (TLS 1.3)
 */
const JanetMethod tls_stream_methods[] = {
    {"close", cfun_close},
    {"shutdown", cfun_shutdown},
    {"read", cfun_read},
    {"chunk", cfun_chunk}, /* Proper chunk (blocks until n bytes or EOF) */
    {"write", cfun_write},
    {"localname", cfun_localname},
    {"peername", cfun_peername},
    {"session-reused?", cfun_session_reused},
    {"session", cfun_get_session},
    {"set-session", cfun_set_session},
    {"version", cfun_get_version},
    {"cipher", cfun_get_cipher},
    {"cipher-bits", cfun_get_cipher_bits},
    {"connection-info", cfun_get_connection_info},
    {"handshake-time", cfun_get_handshake_time},
    {"renegotiate", cfun_renegotiate},
    {"key-update", cfun_key_update},
    {NULL, NULL}};

const JanetAbstractType tls_stream_type = {
    "jsec/tls-stream",
    jtls_stream_gc,
    jtls_stream_mark,
    jtls_stream_getter,
    NULL, /* put */
    NULL, /* marshal */
    NULL, /* unmarshal */
    NULL, /* tostring */
    NULL, /* compare */
    NULL, /* hash */
    NULL, /* next */
    NULL, /* call */
    NULL, /* length */
    NULL, /* bytes */
    NULL  /* gcperthread */
};
