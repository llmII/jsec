/*
 * io.c - TLS I/O operations
 *
 * This file implements I/O operations:
 * - read - Read from TLS stream
 * - chunk - Read exactly n bytes
 * - write - Write to TLS stream
 * - close - Close TLS stream
 * - shutdown - TLS shutdown without closing socket
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"
#include <math.h>

/*============================================================================
 * CACHED KEYWORDS
 *============================================================================
 * Keywords used in hot paths are cached to avoid repeated interning lookups.
 * Janet keywords are interned (globally unique), so caching the Janet value
 * avoids the hash lookup on every call.
 *
 * Thread safety: Janet guarantees each thread has its own VM state, and
 * keywords are interned per-VM. The init function is called once per module
 * load (which happens once per VM), so this is safe.
 */
static Janet kw_timeout = {0};
static int kw_initialized = 0;

static void ensure_keywords_initialized(void) {
    if (!kw_initialized) {
        kw_timeout = janet_ckeywordv("timeout");
        janet_gcroot(kw_timeout);
        kw_initialized = 1;
    }
}

/* Helper to check if timeout is infinite (avoids float comparison warning) */
static inline int is_infinite_timeout(double timeout) {
    return isinf(timeout) != 0;
}

/*============================================================================
 * HELPER: Parse timeout from argument
 *============================================================================
 * Per the requirement, the last optional parameter can be either:
 * - A number (timeout in seconds)
 * - A table/struct with :timeout key (and potentially other TLS options)
 */
static double parse_timeout_opt(int32_t argc, Janet *argv, int32_t idx) {
    if (argc <= idx) {
        return INFINITY;
    }
    
    Janet arg = argv[idx];
    
    if (janet_checktype(arg, JANET_NIL)) {
        return INFINITY;
    }
    
    double timeout = INFINITY;
    
    if (janet_checktype(arg, JANET_NUMBER)) {
        timeout = janet_unwrap_number(arg);
    } else if (janet_checktype(arg, JANET_TABLE) ||
               janet_checktype(arg, JANET_STRUCT)) {
        ensure_keywords_initialized();
        Janet timeout_val = janet_get(arg, kw_timeout);
        if (janet_checktype(timeout_val, JANET_NUMBER)) {
            timeout = janet_unwrap_number(timeout_val);
        }
    }
    
    /* Validate: negative timeouts are invalid */
    if (timeout < 0) {
        tls_panic_param("timeout must be non-negative, got %f", timeout);
    }
    
    return timeout;
}

/*============================================================================
 * READ - Read from TLS stream
 *============================================================================
 * (read stream &opt n buf)
 */
Janet cfun_read(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 4);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    if (tls->stream.flags & JANET_STREAM_CLOSED) {
        tls_panic_io("stream is closed");
    }

    /* Handle :all keyword or integer for n */
    int read_all = 0;
    int32_t bytes_to_read = 4096;
    
    if (janet_keyeq(argv[1], "all")) {
        read_all = 1;
        bytes_to_read = INT32_MAX;
    } else {
        bytes_to_read = janet_getnat(argv, 1);
    }
    
    JanetBuffer *buffer = janet_optbuffer(argv, argc, 2, 10);
    double timeout = parse_timeout_opt(argc, argv, 3);

    /* Use embedded read_state - no malloc needed.
     * Selective initialization instead of memset(0) for performance.
     * Only set fields actually used by read operations. */
    TLSState *state = &tls->read_state;
    state->tls = tls;
    state->op = read_all ? TLS_OP_CHUNK : TLS_OP_READ;
    state->user_buf = buffer;
    state->bytes_requested = bytes_to_read;
    /* write_data, write_len, write_offset unused for reads - not zeroed */
    /* error_msg only written on error via snprintf - not pre-zeroed */

    /* Add timeout before starting async operation */
    if (!is_infinite_timeout(timeout)) {
        janet_addtimeout(timeout);
    }

    if (jtls_attempt_io(janet_current_fiber(), state, 0)) {
        if (buffer->count == 0 && bytes_to_read > 0) {
            return janet_wrap_nil();
        }
        return janet_wrap_buffer(buffer);
    }

    return janet_wrap_nil();
}

/*============================================================================
 * CHUNK - Read exactly n bytes from TLS stream
 *============================================================================
 * (chunk stream n &opt buffer timeout)
 *
 * Same as read, but will not return early if less than n bytes are available.
 * If an end of stream is reached, will also return early with the collected
 * bytes. Takes an optional timeout in seconds.
 */
Janet cfun_chunk(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 4);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    if (tls->stream.flags & JANET_STREAM_CLOSED) {
        tls_panic_io("stream is closed");
    }

    int32_t bytes_to_read = janet_getnat(argv, 1);
    JanetBuffer *buffer = janet_optbuffer(argv, argc, 2, 10);
    double timeout = parse_timeout_opt(argc, argv, 3);

    /* Use embedded read_state - no malloc needed.
     * Selective initialization instead of memset(0) for performance. */
    TLSState *state = &tls->read_state;
    state->tls = tls;
    state->op = TLS_OP_CHUNK;
    state->user_buf = buffer;
    state->bytes_requested = bytes_to_read;

    /* Add timeout before starting async operation */
    if (!is_infinite_timeout(timeout)) {
        janet_addtimeout(timeout);
    }

    if (jtls_attempt_io(janet_current_fiber(), state, 0)) {
        return janet_wrap_buffer(buffer);
    }

    return janet_wrap_nil();
}

/*============================================================================
 * WRITE - Write to TLS stream
 *============================================================================
 * (write stream data &opt timeout)
 *
 * Write data to TLS stream. Takes an optional timeout in seconds, after
 * which will return nil. The timeout can also be a table/struct with
 * :timeout key for consistency with other TLS options.
 */
Janet cfun_write(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    if (tls->stream.flags & JANET_STREAM_CLOSED) {
        tls_panic_io("stream is closed");
    }

    if (tls->conn_state == TLS_CONN_SHUTDOWN_SENT || tls->conn_state == TLS_CONN_CLOSED) {
        tls_panic_io("connection is shutting down");
    }

    JanetByteView bytes = janet_getbytes(argv, 1);
    double timeout = parse_timeout_opt(argc, argv, 2);

    /* Use embedded write_state - no malloc needed.
     * Selective initialization instead of memset(0) for performance. */
    TLSState *state = &tls->write_state;
    state->tls = tls;
    state->op = TLS_OP_WRITE;
    state->write_data = bytes.bytes;
    state->write_len = bytes.len;
    state->write_offset = 0;  /* Only write field that must be explicitly set */
    /* user_buf, bytes_requested unused for writes - not zeroed */

    /* Add timeout before starting async operation */
    if (!is_infinite_timeout(timeout)) {
        janet_addtimeout(timeout);
    }

    if (jtls_attempt_io(janet_current_fiber(), state, 0)) {
        return janet_wrap_nil();
    }

    return janet_wrap_nil();
}

/*============================================================================
 * CLOSE - Close TLS stream
 *============================================================================
 * (close stream &opt force)
 *
 * Closes TLS stream, sending close_notify unless forced.
 * Uses async state machine to properly handle I/O events during shutdown,
 * which is critical for FreeBSD unix sockets where synchronous shutdown hangs.
 */
Janet cfun_close(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);
    int force = 0;

    if (argc >= 2 && !janet_checktype(argv[1], JANET_NIL)) {
        force = 1;
    }

    if (tls->stream.flags & JANET_STREAM_CLOSED) {
        return janet_wrap_nil();
    }

    /* Cancel pending operations */
    if (tls->stream.read_fiber) {
        janet_cancel(tls->stream.read_fiber, janet_cstringv("stream closed"));
        tls->stream.read_fiber = NULL;
    }
    if (tls->stream.write_fiber) {
        janet_cancel(tls->stream.write_fiber, janet_cstringv("stream closed"));
        tls->stream.write_fiber = NULL;
    }

    /* Force close: skip TLS shutdown, just close transport */
    if (force || !tls->ssl || tls->conn_state != TLS_CONN_READY) {
        tls->stream.flags |= JANET_STREAM_CLOSED;
        if (tls->transport && !(tls->transport->flags & JANET_STREAM_CLOSED)) {
            janet_stream_close(tls->transport);
        }
        return janet_wrap_nil();
    }

    /* Graceful close: use async state machine for TLS shutdown.
     * This schedules the close operation through the event loop,
     * allowing proper handling of I/O events during SSL_shutdown.
     * Critical for FreeBSD unix sockets where synchronous shutdown hangs.
     * Use write_state since close is a write-like operation.
     * Selective initialization - close uses no data fields. */
    TLSState *state = &tls->write_state;
    state->tls = tls;
    state->op = TLS_OP_CLOSE;

    if (jtls_attempt_io(janet_current_fiber(), state, 0)) {
        return janet_wrap_nil();
    }

    return janet_wrap_nil();
}

/*============================================================================
 * SHUTDOWN - TLS shutdown without closing socket
 *============================================================================
 * (shutdown stream &opt direction)
 */
Janet cfun_shutdown(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    /* Direction argument is for API compatibility, ignored for TLS */
    if (argc == 2) {
        if (!janet_checktype(argv[1], JANET_KEYWORD) &&
            !janet_checktype(argv[1], JANET_NIL)) {
            tls_panic_param("expected keyword or nil, got %v", argv[1]);
        }
    }

    if (tls->stream.flags & JANET_STREAM_CLOSED) {
        return janet_wrap_nil();
    }

    if (!tls->ssl || tls->conn_state != TLS_CONN_READY) {
        return janet_wrap_nil();
    }

    /* Use write_state since shutdown is a write-like operation.
     * Selective initialization - shutdown uses no data fields. */
    TLSState *state = &tls->write_state;
    state->tls = tls;
    state->op = TLS_OP_SHUTDOWN;

    if (jtls_attempt_io(janet_current_fiber(), state, 0)) {
        return janet_wrap_nil();
    }

    return janet_wrap_nil();
}
