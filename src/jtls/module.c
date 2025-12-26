/*
 * module.c - Module entry point for jsec/tls
 *
 * This file initializes the TLS module:
 * - Allocates global mutex for context cache
 * - Opens SSLKEYLOGFILE if set
 * - Registers OpenSSL ex_data indices
 * - Registers all public API functions
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"

/*============================================================================
 * MODULE INITIALIZATION
 *============================================================================
 * Called when the module is loaded. Initializes global state and registers
 * all public functions.
 *
 * Note: We do NOT call any OpenSSL initialization functions.
 * OpenSSL 1.1.1+ is automatically initialized and thread-safe.
 * We only initialize our own state (mutex, ex_data indices, keylog file).
 */
void jtls_module_init(JanetTable *env) {
    /* Initialize Winsock on Windows - must happen before any socket
     * operations */
#ifdef JANET_WINDOWS
    if (jsec_winsock_init() != 0) {
        tls_panic_config("failed to initialize Winsock");
    }
#endif

    /* Initialize BIO method first - must happen before any threads */
    jtls_init_bio_method();

    /* Allocate and initialize mutex for context cache */
    ctx_cache_lock = janet_malloc(janet_os_mutex_size());
    if (!ctx_cache_lock) {
        tls_panic_config("failed to allocate ctx_cache_lock");
    }
    janet_os_mutex_init(ctx_cache_lock);

    /* Check for SSLKEYLOGFILE environment variable for debugging */
    const char *keylog_path = getenv("SSLKEYLOGFILE");
    if (keylog_path && !keylog_file) {
        keylog_file = fopen(keylog_path, "a");
        if (!keylog_file) {
            janet_eprintf("Warning: Could not open SSLKEYLOGFILE: %s\n",
                          keylog_path);
        }
    }

    /* Get ex_data indices for storing custom data on SSL_CTX objects.
     * These are registered once and used for SNI, OCSP, and ALPN callbacks.
     * Thread-safe in OpenSSL 1.1.1+ */
    if (alpn_idx == -1) {
        alpn_idx =
            SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, jtls_alpn_free_cb);
    }
    if (sni_idx == -1) {
        sni_idx =
            SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, jtls_sni_free_cb);
    }
    if (ocsp_idx == -1) {
        ocsp_idx =
            SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, jtls_ocsp_free_cb);
    }

    /* Register all public API functions */
    JanetReg cfuns[] = {
        {"new-context", cfun_new_context,
         "(new-context &opt options)\n\n"
         "Create a reusable TLS context.\n"
         "Options:\n"
         "  :cert, :key - Server certificate/key paths\n"
         "  :verify - Client verification (default true)\n"
         "  :security - Security options table\n"
         "  :alpn - ALPN protocols array\n"
         "  :sni - SNI hostname->options table (server only)\n"},
        {"wrap", cfun_wrap,
         "(wrap stream &opt config options)\n\n"
         "Wrap an existing stream with TLS.\n"
         "Client: (wrap stream hostname &opt {:verify true})\n"
         "Client: (wrap stream {:hostname \"example.com\" :verify false})\n"
         "Server: (wrap stream {:cert path :key path})\n"
         "Advanced: (wrap stream context &opt options)\n"},
        {"upgrade", cfun_upgrade,
         "(upgrade stream &opt config options)\n\n"
         "Upgrade an existing connection to TLS (STARTTLS pattern).\n"
         "Same arguments as wrap.\n"},
        {"connect", cfun_connect,
         "(connect host port &opt opts)\n\n"
         "Create a TLS client connection to host:port.\n"
         "Options:\n"
         "  :verify - Certificate verification (default true)\n"
         "  :alpn - ALPN protocols to offer\n"
         "  :session - Session data for resumption\n"},
        {"accept-loop", cfun_accept_loop,
         "(accept-loop listener context handler)\n\n"
         "Continuously accept TLS connections on listener.\n"
         "Blocks until listener is closed. Returns listener.\n"
         "This is the TLS equivalent of net/accept-loop.\n"},
        {"listen", cfun_listen,
         "(listen host port &opt opts)\n\n"
         "Create a TCP listener socket for TLS server.\n"
         "Options table can include:\n"
         "  :backlog - listen backlog size (default 1024)\n"
         "Returns a stream usable with net/localname and accept.\n"},
        {"accept", cfun_accept,
         "(accept listener context &opt timeout)\n\n"
         "Accept a connection on a listener and wrap with TLS.\n"
         "Context can be a TLS context or options table with :cert/:key.\n"},
        {"read", cfun_read,
         "(read stream n &opt buffer timeout)\n\n"
         "Read up to n bytes from TLS stream into buffer. `n` can also be\n"
         "the keyword `:all` to read until end of stream. Optionally "
         "provide\n"
         "a buffer and timeout in seconds. Returns buffer or nil on EOF.\n"},
        {"chunk", cfun_chunk,
         "(chunk stream n &opt buffer timeout)\n\n"
         "Same as read, but will not return early if less than n bytes are\n"
         "available. If end of stream is reached, returns collected "
         "bytes.\n"},
        {"write", cfun_write,
         "(write stream data &opt timeout)\n\n"
         "Write data to TLS stream. Takes optional timeout in seconds.\n"
         "Returns nil, or raises an error if write failed.\n"},
        {"close", cfun_close,
         "(close stream &opt force)\n\n"
         "Close TLS stream. Sends close_notify per RFC unless force is "
         "true.\n"
         "Safe for use with `with` blocks.\n"},
        {"shutdown", cfun_shutdown,
         "(shutdown stream &opt direction)\n\n"
         "Perform TLS shutdown but keep underlying socket open.\n"
         "Useful for transitioning back to raw TCP.\n"},
        {"session-reused?", cfun_session_reused,
         "(session-reused? stream)\n\n"
         "Check if TLS session was resumed from cache.\n"},
        {"get-session", cfun_get_session,
         "(get-session stream)\n\n"
         "Export session data for resumption. Returns byte string or nil.\n"
         "Call after handshake completes.\n"},
        {"set-session", cfun_set_session,
         "(set-session stream session-data)\n\n"
         "Import session data for resumption. Call before handshake.\n"},
        {"renegotiate", cfun_renegotiate,
         "(renegotiate stream)\n\n"
         "Trigger TLS renegotiation (TLS 1.2 and earlier).\n"
         "Returns :ok on success.\n"},
        {"key-update", cfun_key_update,
         "(key-update stream)\n\n"
         "Trigger TLS key update (TLS 1.3).\n"
         "Returns :ok on success.\n"},
        {"set-ocsp-response", cfun_set_ocsp_response,
         "(set-ocsp-response context response-der)\n\n"
         "Set OCSP response (DER format) for stapling on a context.\n"},
        {"trust-cert", cfun_trust_cert,
         "(trust-cert context cert-pem)\n\n"
         "Add a certificate to the context's trusted store.\n"
         "Allows verification against specific certs without a CA.\n"
         "Useful for certificate pinning or self-signed cert "
         "verification.\n"},
        {"get-version", cfun_get_version,
         "(get-version stream)\n\n"
         "Get TLS protocol version string (e.g., \"TLSv1.3\").\n"},
        {"get-cipher", cfun_get_cipher,
         "(get-cipher stream)\n\n"
         "Get negotiated cipher suite name.\n"},
        {"get-cipher-bits", cfun_get_cipher_bits,
         "(get-cipher-bits stream)\n\n"
         "Get cipher strength in bits.\n"},
        {"get-connection-info", cfun_get_connection_info,
         "(get-connection-info stream)\n\n"
         "Get detailed connection info as a struct.\n"
         "Keys: :version, :protocol-version, :cipher, :cipher-bits,\n"
         "      :cipher-version, :cipher-description, :alpn, :server-name\n"},
        {"get-handshake-time", cfun_get_handshake_time,
         "(get-handshake-time stream)\n\n"
         "Get handshake duration in seconds as a floating-point number.\n"
         "Returns nil if handshake hasn't completed yet.\n"},
        {NULL, NULL, NULL}};

    janet_cfuns(env, "jsec/tls", cfuns);

    /* Register abstract types */
    janet_register_abstract_type(&tls_stream_type);
    /* Note: SSLContext type is registered by jsec/utils module */
}

/*============================================================================
 * MODULE ENTRY POINT
 *============================================================================
 * Janet calls this when the module is loaded via (import jsec/tls).
 */
JANET_MODULE_ENTRY(JanetTable *env) {
    jtls_module_init(env);
}
