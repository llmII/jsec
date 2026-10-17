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
    TLSStream *tls =
        (TLSStream *)janet_abstract(&tls_stream_type, sizeof(TLSStream));
    memset(tls, 0, sizeof(TLSStream));

    /* Initialize the embedded JanetStream portion */
    tls->stream.handle = JANET_HANDLE_NONE;
    if (transport) {
        /* Normal mode: TLS wraps a socket transport */
        tls->stream.flags = JANET_STREAM_SOCKET | JANET_STREAM_READABLE |
                            JANET_STREAM_WRITABLE;
    } else {
        /* Manual BIO mode: no underlying socket, user manages I/O
         * Intentionally omit JANET_STREAM_SOCKET flag since there's no socket
         */
        tls->stream.flags = JANET_STREAM_READABLE | JANET_STREAM_WRITABLE;
    }
    tls->stream.methods = tls_stream_methods;

    /* Initialize TLS-specific fields */
    tls->ctx = ctx;
    if (is_server) tls->flags |= JTLS_FLAG_SERVER;
    if (owns_ctx) tls->flags |= JTLS_FLAG_OWNS_CTX;
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
     * This tells the TLS library to read more data than strictly needed,
     * reducing the number of syscalls.
     * Add 325 bytes of TLS record framing headroom (5-byte header + up to
     * 320 bytes of IV/AEAD tag/padding) per 16384-byte TLS record so N full
     * encrypted records summing to the target plaintext size fit in a single
     * socket read() without truncating the trailing record. */
    SSL_set_read_ahead(tls->ssl, 1);
    size_t plaintext_size = (size_t)DEFAULT_TLS_BUFFER_SIZE;
    if (buffer_size > 0 && buffer_size <= MAX_TLS_BUFFER_SIZE) {
        plaintext_size = (size_t)buffer_size;
    }
    size_t num_records = (plaintext_size + 16383) / 16384;
    if (num_records == 0) num_records = 1;
    size_t read_ahead_size = plaintext_size + num_records * 325;
    if (read_ahead_size < 16709) {
        read_ahead_size = 16709;
    }
#if JSEC_LIBRESSL
    /* LibreSSL lacks SSL_set_default_read_buffer_len; maintain our own
     * user-space BIO read-ahead buffer. */
    tls->bio_ahead.capacity = read_ahead_size;
    tls->bio_ahead.data =
        (unsigned char *)janet_malloc(tls->bio_ahead.capacity);
    if (tls->bio_ahead.data) {
        tls->bio_ahead.p = tls->bio_ahead.data;
        tls->bio_ahead.pe = tls->bio_ahead.data; /* Empty initially */
    } else {
        /* Non-fatal: we'll just do direct reads without buffering */
        tls->bio_ahead.capacity = 0;
    }
#else
    /* OpenSSL: enlarge OpenSSL's internal read buffer directly so BIO reads
     * straight from the kernel socket into OpenSSL's rbuf with zero double
     * buffering or intermediate memcpy. */
    SSL_set_default_read_buffer_len(tls->ssl, read_ahead_size);
#endif

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
        setsockopt((jsec_socket_t)transport->handle, SOL_SOCKET, SO_NOSIGPIPE,
                   &enable, sizeof(int));
    }
#endif

    /* Disable Nagle's algorithm for lower latency (configurable, default on).
     * TLS already does its own buffering, so Nagle just adds delay. */
    if (transport && tcp_nodelay != 0) {
        int enable = 1;
        setsockopt((jsec_socket_t)transport->handle, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&enable, sizeof(int));
    }

    /* Handshake timing - only record if explicitly enabled.
     * Uses CLOCK_MONOTONIC which is fast (vDSO on Linux) and doesn't
     * suffer from time adjustments. */
    if (track_handshake_time) {
        tls->flags |= JTLS_FLAG_TRACK_HANDSHAKE;
        clock_gettime(CLOCK_MONOTONIC, &tls->ts_connect);
    }

    return tls;
}
