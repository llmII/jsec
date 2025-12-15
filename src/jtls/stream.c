/*
 * stream.c - TLS stream setup and management
 *
 * This file handles the creation and configuration of TLS stream objects.
 * TLSStream wraps a Janet stream with TLS encryption/decryption.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"

/*============================================================================
 * SETUP TLS STREAM
 *============================================================================
 * Create and initialize a TLSStream object.
 *
 * Parameters:
 *   transport   - The underlying Janet stream (TCP/Unix socket)
 *   ctx         - SSL_CTX for this connection
 *   is_server   - True for server-side connections
 *   owns_ctx    - True if we should free ctx when stream is GC'd
 *   buffer_size - Size for I/O buffers
 *   tcp_nodelay - Whether to enable TCP_NODELAY (1=yes, 0=no, -1=default yes)
 *   track_handshake_time - Whether to record handshake timing (0=no, 1=yes)
 *
 * Returns:
 *   Newly created TLSStream, ready for handshake
 */
TLSStream *jtls_setup_stream(JanetStream *transport, SSL_CTX *ctx,
                             int is_server, int owns_ctx, int32_t buffer_size,
                             int tcp_nodelay, int track_handshake_time) {
    TLSStream *tls = (TLSStream *)janet_abstract(&tls_stream_type,
                     sizeof(TLSStream));
    memset(tls, 0, sizeof(TLSStream));

    /* Initialize the embedded JanetStream portion */
    tls->stream.handle = JANET_HANDLE_NONE;
    if (transport) {
        /* Normal mode: TLS wraps a socket transport */
        tls->stream.flags = JANET_STREAM_SOCKET | JANET_STREAM_READABLE |
                            JANET_STREAM_WRITABLE;
    } else {
        /* Manual BIO mode: no underlying socket, user manages I/O
         * Intentionally omit JANET_STREAM_SOCKET flag since there's no socket */
        tls->stream.flags = JANET_STREAM_READABLE | JANET_STREAM_WRITABLE;
    }
    tls->stream.methods = tls_stream_methods;

    /* Initialize TLS-specific fields */
    tls->ctx = ctx;
    tls->owns_ctx = owns_ctx;
    tls->is_server = is_server;
    tls->transport = transport;
    tls->conn_state = TLS_CONN_INIT;
    tls->buffer_size = buffer_size;

    /* Create SSL object */
    tls->ssl = SSL_new(ctx);
    if (!tls->ssl) {
        tls_panic_ssl("failed to create SSL object");
    }

    /* Enable partial writes and moving write buffer
     * This allows SSL_write to succeed with partial writes */
    SSL_set_mode(tls->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
                 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* Create custom BIO for direct socket I/O */
    BIO_METHOD *bio_method = jtls_get_bio_method();
    if (!bio_method) {
        SSL_free(tls->ssl);
        tls_panic_ssl("failed to create BIO method");
    }

    tls->bio = BIO_new(bio_method);
    if (!tls->bio) {
        SSL_free(tls->ssl);
        tls_panic_ssl("failed to create BIO");
    }

    /* Set TLSStream pointer in BIO so callbacks can access it */
    BIO_set_data(tls->bio, tls);
    BIO_set_init(tls->bio, 1);

    /* Connect SSL to our custom BIO */
    SSL_set_bio(tls->ssl, tls->bio, tls->bio);

    /* Enable read-ahead for better performance with non-blocking I/O.
     * This tells OpenSSL to read more data than strictly needed,
     * reducing the number of syscalls. */
    SSL_set_read_ahead(tls->ssl, 1);

    /* Allocate BIO read-ahead buffer.
     * Use buffer_size if specified and reasonable, otherwise default to 128KB.
     * Testing showed 128KB provides best balance of throughput and memory.
     * Minimum is 16KB (one TLS record), maximum capped at 256KB. */
    size_t bio_ahead_size = 131072;  /* Default: 128KB (eight TLS records) */
    if (buffer_size >= 16384 && buffer_size <= 262144) {
        bio_ahead_size = (size_t)buffer_size;
    }
    tls->bio_ahead.capacity = bio_ahead_size;
    tls->bio_ahead.data = (unsigned char *)janet_malloc(tls->bio_ahead.capacity);
    if (tls->bio_ahead.data) {
        tls->bio_ahead.p = tls->bio_ahead.data;
        tls->bio_ahead.pe = tls->bio_ahead.data;  /* Empty initially */
    } else {
        /* Non-fatal: we'll just do direct reads without buffering */
        tls->bio_ahead.capacity = 0;
    }

    /* Set handshake mode */
    if (is_server) {
        SSL_set_accept_state(tls->ssl);
    } else {
        SSL_set_connect_state(tls->ssl);
    }

    /* Prevent SIGPIPE on BSD/macOS */
#ifdef SO_NOSIGPIPE
    if (transport) {
        int enable = 1;
        setsockopt((int)transport->handle, SOL_SOCKET, SO_NOSIGPIPE,
                   &enable, sizeof(int));
    }
#endif

    /* Disable Nagle's algorithm for lower latency (configurable, default on).
     * TLS already does its own buffering, so Nagle just adds delay. */
    if (transport && tcp_nodelay != 0) {
        int enable = 1;
        setsockopt((int)transport->handle, IPPROTO_TCP, TCP_NODELAY,
                   &enable, sizeof(int));
    }

    /* Handshake timing - only record if explicitly enabled.
     * Uses CLOCK_MONOTONIC which is fast (vDSO on Linux) and doesn't
     * suffer from time adjustments. */
    tls->track_handshake_time = track_handshake_time;
    if (track_handshake_time) {
        clock_gettime(CLOCK_MONOTONIC, &tls->ts_connect);
    } else {
        tls->ts_connect.tv_sec = 0;
        tls->ts_connect.tv_nsec = 0;
    }
    /* Zero out handshake timestamp - will be set when handshake completes */
    tls->ts_handshake.tv_sec = 0;
    tls->ts_handshake.tv_nsec = 0;

    return tls;
}
