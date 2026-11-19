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
 * PARSE BUFFER OPTIONS
 *============================================================================
 * Parse per-connection buffer configuration from options.
 *
 * Supported formats:
 *   :buffer {:read <bool|int> :write <bool|int>}
 *   :buffer <bool> (shorthand to enable/disable both)
 *   :buffer <int>  (shorthand to set both; 0 disables)
 *   :buffer-size <int> (legacy fallback)
 *
 * Validation:
 *   - 0 disables buffering in that direction (unbuffered)
 *   - positive integers set bounded sizes
 *   - negative integers raise a parameter error
 *   - invalid types raise a parameter error
 */
void jtls_parse_buffer_opts(Janet opts, int32_t *read_buf_size,
                            int32_t *write_buf_size) {
    *read_buf_size = DEFAULT_TLS_BUFFER_SIZE;
    *write_buf_size = JSEC_DEFAULT_WRITE_BUFFER_SIZE;

    if (janet_checktype(opts, JANET_NIL)) {
        return;
    }
    if (!janet_checktype(opts, JANET_TABLE) &&
        !janet_checktype(opts, JANET_STRUCT)) {
        return;
    }

    /* 1. Check legacy :buffer-size first if present */
    Janet legacy_buf = janet_get(opts, janet_ckeywordv("buffer-size"));
    if (!janet_checktype(legacy_buf, JANET_NIL)) {
        if (!janet_checktype(legacy_buf, JANET_NUMBER)) {
            tls_panic_param("buffer-size must be a number");
        }
        int32_t size = (int32_t)janet_unwrap_integer(legacy_buf);
        if (size < 0) {
            tls_panic_param("buffer-size must be non-negative");
        } else if (size == 0) {
            *read_buf_size = 0;
            *write_buf_size = 0;
        } else {
            if (size < MIN_TLS_BUFFER_SIZE) size = MIN_TLS_BUFFER_SIZE;
            if (size > MAX_TLS_BUFFER_SIZE) size = MAX_TLS_BUFFER_SIZE;
            *read_buf_size = size;
            *write_buf_size = size;
        }
    }

    /* 2. Structured :buffer option takes precedence */
    Janet buf_opt = janet_get(opts, janet_ckeywordv("buffer"));
    if (janet_checktype(buf_opt, JANET_NIL)) {
        return;
    }

    /* :buffer can be boolean */
    if (janet_checktype(buf_opt, JANET_BOOLEAN)) {
        int enable = janet_unwrap_boolean(buf_opt);
        if (!enable) {
            *read_buf_size = 0;
            *write_buf_size = 0;
        } else {
            *read_buf_size = DEFAULT_TLS_BUFFER_SIZE;
            *write_buf_size = JSEC_DEFAULT_WRITE_BUFFER_SIZE;
        }
        return;
    }

    /* :buffer can be numeric */
    if (janet_checktype(buf_opt, JANET_NUMBER)) {
        int32_t size = (int32_t)janet_unwrap_integer(buf_opt);
        if (size < 0) {
            tls_panic_param("buffer size must be non-negative");
        } else if (size == 0) {
            *read_buf_size = 0;
            *write_buf_size = 0;
        } else {
            if (size < MIN_TLS_BUFFER_SIZE) size = MIN_TLS_BUFFER_SIZE;
            if (size > MAX_TLS_BUFFER_SIZE) size = MAX_TLS_BUFFER_SIZE;
            *read_buf_size = size;
            *write_buf_size = size;
        }
        return;
    }

    /* Dictionary: must be struct or table */
    if (!janet_checktype(buf_opt, JANET_TABLE) &&
        !janet_checktype(buf_opt, JANET_STRUCT)) {
        tls_panic_param(
            "buffer option must be a table, struct, boolean, or number");
    }

    /* :read option */
    Janet r_opt = janet_get(buf_opt, janet_ckeywordv("read"));
    if (!janet_checktype(r_opt, JANET_NIL)) {
        if (janet_checktype(r_opt, JANET_BOOLEAN)) {
            *read_buf_size =
                janet_unwrap_boolean(r_opt) ? DEFAULT_TLS_BUFFER_SIZE : 0;
        } else if (janet_checktype(r_opt, JANET_NUMBER)) {
            int32_t size = (int32_t)janet_unwrap_integer(r_opt);
            if (size < 0) {
                tls_panic_param("buffer :read size must be non-negative");
            } else if (size == 0) {
                *read_buf_size = 0;
            } else {
                if (size < MIN_TLS_BUFFER_SIZE) size = MIN_TLS_BUFFER_SIZE;
                if (size > MAX_TLS_BUFFER_SIZE) size = MAX_TLS_BUFFER_SIZE;
                *read_buf_size = size;
            }
        } else {
            tls_panic_param(
                "buffer :read option must be a boolean or integer");
        }
    }

    /* :write option */
    Janet w_opt = janet_get(buf_opt, janet_ckeywordv("write"));
    if (!janet_checktype(w_opt, JANET_NIL)) {
        if (janet_checktype(w_opt, JANET_BOOLEAN)) {
            *write_buf_size = janet_unwrap_boolean(w_opt)
                                  ? JSEC_DEFAULT_WRITE_BUFFER_SIZE
                                  : 0;
        } else if (janet_checktype(w_opt, JANET_NUMBER)) {
            int32_t size = (int32_t)janet_unwrap_integer(w_opt);
            if (size < 0) {
                tls_panic_param("buffer :write size must be non-negative");
            } else if (size == 0) {
                *write_buf_size = 0;
            } else {
                if (size < MIN_TLS_BUFFER_SIZE) size = MIN_TLS_BUFFER_SIZE;
                if (size > JSEC_MAX_WRITE_BUFFER_BOUND)
                    size = JSEC_MAX_WRITE_BUFFER_BOUND;
                *write_buf_size = size;
            }
        } else {
            tls_panic_param(
                "buffer :write option must be a boolean or integer");
        }
    }
}

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
 *   read_buffer_size  - Size for read ahead/batching buffer (0 if disabled)
 *   write_buffer_size - Size for write coalescing buffer (0 if disabled)
 *   tcp_nodelay - Whether to enable TCP_NODELAY (1=yes, 0=no, -1=default yes)
 *   track_handshake_time - Whether to record handshake timing (0=no, 1=yes)
 *
 * Returns:
 *   Newly created TLSStream, ready for handshake
 */
TLSStream *jtls_setup_stream(JanetStream *transport, SSL_CTX *ctx,
                             int is_server, int owns_ctx,
                             int32_t read_buffer_size,
                             int32_t write_buffer_size, int tcp_nodelay,
                             int track_handshake_time) {
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
    tls->read_buffer_size = read_buffer_size;
    tls->write_buffer_size = write_buffer_size;

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

    /* Configure read-ahead buffer if enabled */
    if (read_buffer_size > 0) {
        SSL_set_read_ahead(tls->ssl, 1);
        size_t plaintext_size = (size_t)read_buffer_size;
        if (plaintext_size > MAX_TLS_BUFFER_SIZE) {
            plaintext_size = MAX_TLS_BUFFER_SIZE;
        }
        size_t num_records = (plaintext_size + 16383) / 16384;
        if (num_records == 0) num_records = 1;
        size_t read_ahead_size = plaintext_size + num_records * 325;
        if (read_ahead_size < 16709) {
            read_ahead_size = 16709;
        }
#if JSEC_LIBRESSL
        tls->bio_ahead.capacity = read_ahead_size;
        tls->bio_ahead.data =
            (unsigned char *)janet_malloc(tls->bio_ahead.capacity);
        if (tls->bio_ahead.data) {
            tls->bio_ahead.p = tls->bio_ahead.data;
            tls->bio_ahead.pe = tls->bio_ahead.data;
        } else {
            tls->bio_ahead.capacity = 0;
        }
#else
        SSL_set_default_read_buffer_len(tls->ssl, read_ahead_size);
#endif
    } else {
        SSL_set_read_ahead(tls->ssl, 0);
#if JSEC_LIBRESSL
        tls->bio_ahead.capacity = 0;
        tls->bio_ahead.data = NULL;
        tls->bio_ahead.p = NULL;
        tls->bio_ahead.pe = NULL;
#endif
    }

    /* Configure write coalescing buffer if enabled */
    if (write_buffer_size > 0) {
        size_t target_size = (size_t)write_buffer_size;
        if (target_size > JSEC_MAX_WRITE_BUFFER_BOUND) {
            target_size = JSEC_MAX_WRITE_BUFFER_BOUND;
        }
        size_t num_records = (target_size + 16383) / 16384;
        if (num_records == 0) num_records = 1;
        size_t write_capacity = target_size + num_records * 325;
        tls->write_buffer.data =
            (unsigned char *)janet_malloc(write_capacity);
        if (tls->write_buffer.data) {
            tls->write_buffer.capacity = write_capacity;
            tls->write_buffer.head = 0;
            tls->write_buffer.tail = 0;
        } else {
            tls->write_buffer.capacity = 0;
            tls->write_buffer.head = 0;
            tls->write_buffer.tail = 0;
        }
    } else {
        tls->write_buffer.data = NULL;
        tls->write_buffer.capacity = 0;
        tls->write_buffer.head = 0;
        tls->write_buffer.tail = 0;
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
