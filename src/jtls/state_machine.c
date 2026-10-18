/*
 * state_machine.c - Async I/O state machine for TLS operations
 *
 * This file implements the core state machine that integrates TLS operations
 * with Janet's event loop. It handles the non-blocking nature of SSL
 * operations by registering with the event loop when operations need to wait
 * for I/O.
 *
 * STATE MACHINE OVERVIEW
 * ======================
 *
 * The state machine handles four types of operations:
 *   1. HANDSHAKE - SSL_connect (client) or SSL_accept (server)
 *   2. READ      - SSL_read to get decrypted application data
 *   3. WRITE     - SSL_write to encrypt and send application data
 *   4. SHUTDOWN  - SSL_shutdown to close TLS cleanly
 *
 * Each operation follows this flow:
 *
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │                    Operation Started                         │
 *   └─────────────────────────┬────────────────────────────────────┘
 *                             │
 *                             ▼
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │               Call SSL operation                             │
 *   │    (SSL_connect, SSL_accept, SSL_read, SSL_write, etc.)      │
 *   └─────────────────────────┬────────────────────────────────────┘
 *                             │
 *              ┌──────────────┴──────────────┐
 *              │       Check Result          │
 *              └──────────────┬──────────────┘
 *                             │
 *       ┌─────────────────────┼─────────────────────┐
 *       │                     │                     │
 *       ▼                     ▼                     ▼
 *   ┌────────┐          ┌──────────┐          ┌──────────┐
 *   │SUCCESS │          │WANT_READ │          │WANT_WRITE│
 *   └───┬────┘          └────┬─────┘          └────┬─────┘
 *       │                    │                     │
 *       │                    ▼                     ▼
 *       │            ┌─────────────────────────────────┐
 *       │            │   Register with event loop      │
 *       │            │   (janet_async_start)           │
 *       │            └───────────────┬─────────────────┘
 *       │                            │
 *       │                            ▼
 *       │            ┌─────────────────────────────────┐
 *       │            │   Fiber suspended               │
 *       │            │   (yields to other fibers)      │
 *       │            └───────────────┬─────────────────┘
 *       │                            │
 *       │                            ▼
 *       │            ┌─────────────────────────────────┐
 *       │            │   Event loop wakes us           │
 *       │            │   (socket readable/writable)    │
 *       │            └───────────────┬─────────────────┘
 *       │                            │
 *       │                            ▼
 *       │            ┌─────────────────────────────────┐
 *       │            │   Retry SSL operation           │
 *       │            │   (loop back to check result)   │
 *       │            └─────────────────────────────────┘
 *       │
 *       ▼
 *   ┌────────────────────────────────────────────────────┐
 *   │              Resume fiber with result              │
 *   │    (janet_schedule with success value)             │
 *   └────────────────────────────────────────────────────┘
 *
 * ERROR HANDLING
 * ==============
 * When SSL_get_error returns an actual error (not WANT_READ/WANT_WRITE):
 *   - We capture the error message
 *   - Cancel the fiber with janet_cancel
 *   - Clean up the async state with janet_async_end
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <math.h>

/*============================================================================
 * HELPER: Prepare buffer capacity and compute slice size for SSL_read
 *============================================================================
 * Sizes the next SSL_read slice to the caller's pre-allocated buffer capacity
 * or the stream's configured buffer_size, eliminating the fixed 4KB read cap:
 * - If remaining fits in the caller buffer's already-allocated unused
 * capacity (buf->capacity - buf->count), returns remaining with zero realloc.
 * - If remaining <= stream buffer_size, ensures exact capacity (growth=1) and
 *   returns remaining.
 * - If remaining exceeds both unused buffer capacity and stream buffer_size
 *   (e.g., :all / INT32_MAX or a multi-step chunk), grows in stream
 *   buffer_size steps so buffer memory grows with data actually received.
 */
static inline int32_t
jtls_prepare_read_slice(TLSStream *tls, JanetBuffer *buf, int32_t remaining) {
    int32_t step_cap = tls->read_buffer_size > 0 ? tls->read_buffer_size
                                                 : DEFAULT_TLS_BUFFER_SIZE;
    int32_t avail_cap = buf->capacity - buf->count;
    if (remaining < 0) {
        remaining = step_cap;
    }
    if (remaining <= avail_cap) {
        return remaining;
    }
    if (remaining <= step_cap) {
        janet_buffer_ensure(buf, buf->count + remaining, 1);
        return remaining;
    }
    int32_t want = avail_cap > step_cap ? avail_cap : step_cap;
    janet_buffer_extra(buf, want);
    return want;
}

/*============================================================================
 * KEYLOG CALLBACK
 *============================================================================
 * Called by OpenSSL when TLS keys are generated. Writes to SSLKEYLOGFILE
 * for debugging with Wireshark.
 */
void jtls_keylog_callback(const SSL *ssl, const char *line) {
    (void)ssl;
    if (keylog_file) {
        fprintf(keylog_file, "%s\n", line);
        fflush(keylog_file);
    }
}

/*============================================================================
 * HELPER: Record handshake completion on implicit completion
 *============================================================================
 * OpenSSL can complete the handshake implicitly during SSL_read/SSL_write,
 * the lazy path taken by accepted streams (handshake on first I/O). This
 * helper marks the connection TLS_CONN_READY whenever the handshake has
 * finished - readiness must not depend on the handshake-timing option,
 * or a lazy-handshake stream closes without close_notify (cfun_close
 * force-closes anything not TLS_CONN_READY). The completion timestamp is
 * recorded only when handshake timing is tracked.
 */
static inline void check_record_handshake_time(TLSStream *tls) {
    if (tls->conn_state != TLS_CONN_READY && SSL_is_init_finished(tls->ssl)) {
        tls->conn_state = TLS_CONN_READY;
        if ((tls->flags & JTLS_FLAG_TRACK_HANDSHAKE) &&
            tls->ts_handshake.tv_sec == 0 && tls->ts_handshake.tv_nsec == 0) {
            clock_gettime(CLOCK_MONOTONIC, &tls->ts_handshake);
        }
    }
}

/*============================================================================
 * HELPER: Resolve a clean close_notify for an operation
 *============================================================================
 * SSL_ERROR_ZERO_RETURN is the only clean close: the peer sent the
 * close_notify alert. An EOF-shaped SSL_ERROR_SYSCALL (ret 0 or sock_err
 * 0) is NOT clean - it is a truncation without close_notify and raises
 * JSEC_UNEXPECTED_EOF_ERROR in handle_ssl_error. A clean close
 * legitimately ends only the read-style operations: a write still holding
 * bytes would silently drop them, and a handshake that never reached
 * TLS_CONN_READY has failed.
 * Returns TLS_IO_COMPLETE where completion is honest, otherwise fills
 * state->error_msg and returns TLS_IO_ERROR.
 */
static TLSIOState handle_eof_close(TLSState *state, const char *op_name) {
    if (state->op == TLS_OP_WRITE && state->write_offset < state->write_len) {
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "%s error: connection closed with %d of %d bytes unwritten",
                 op_name, state->write_len - state->write_offset,
                 state->write_len);
        return TLS_IO_ERROR;
    }
    if (state->op == TLS_OP_HANDSHAKE &&
        state->tls->conn_state != TLS_CONN_READY) {
        snprintf(state->error_msg, sizeof(state->error_msg),
                 "%s error: connection closed before the handshake completed",
                 op_name);
        return TLS_IO_ERROR;
    }
    return TLS_IO_COMPLETE;
}

/*============================================================================
 * HELPER: Handle SSL error and determine next I/O state
 *============================================================================
 * Common SSL error handling logic extracted from operation handlers.
 * Interprets SSL_get_error result and returns appropriate TLSIOState.
 *
 * Parameters:
 *   ssl_err      - Result from SSL_get_error()
 *   ret          - Return value from the SSL operation
 *   state        - Operation state for error message storage
 *   op_name      - Name of operation for error messages (e.g., "Read",
 * "Write") has_data     - True if we have partial data that can be returned
 *   tls          - TLS stream (for updating conn_state on shutdown)
 *   sock_err     - Socket errno captured before SSL_get_error ran
 *
 * Returns:
 *   Appropriate TLSIOState based on the error
 */
static TLSIOState handle_ssl_error(int ssl_err, int ret, TLSState *state,
                                   const char *op_name, int has_data,
                                   TLSStream *tls, int sock_err) {
    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            return has_data ? TLS_IO_COMPLETE : TLS_IO_WANT_READ;

        case SSL_ERROR_WANT_WRITE:
            return has_data ? TLS_IO_COMPLETE : TLS_IO_WANT_WRITE;

        case SSL_ERROR_ZERO_RETURN:
            /* Clean shutdown received from peer */
            if (tls) tls->conn_state = TLS_CONN_SHUTDOWN_SENT;
            return handle_eof_close(state, op_name);

        case SSL_ERROR_SYSCALL: {
            if (sock_err == JSEC_EAGAIN || sock_err == JSEC_EWOULDBLOCK) {
                return has_data ? TLS_IO_COMPLETE : TLS_IO_WANT_BOTH;
            }
            if (ret == 0 || sock_err == 0) {
                /* Unexpected EOF: the transport ended without a
                 * close_notify, so the stream is truncated, not
                 * complete. Normalise the 1.1.1/LibreSSL surface of the
                 * condition into the one documented error (the OpenSSL
                 * 3.x surface is the SSL_ERROR_SSL arm below). */
                snprintf(state->error_msg, sizeof(state->error_msg), "%s",
                         JSEC_UNEXPECTED_EOF_ERROR);
                return TLS_IO_ERROR;
            }
#ifdef JANET_WINDOWS
            /* Windows: format socket error code */
            snprintf(state->error_msg, sizeof(state->error_msg),
                     "%s syscall error: WSA error %d", op_name, sock_err);
#else
            snprintf(state->error_msg, sizeof(state->error_msg),
                     "%s syscall error: %s", op_name,
                     jsec_socket_strerror(sock_err));
#endif
            return TLS_IO_ERROR;
        }

        default:
            if (jutils_is_unexpected_eof()) {
                /* OpenSSL 3.x reports a transport EOF without
                 * close_notify as SSL_ERROR_SSL with reason
                 * SSL_R_UNEXPECTED_EOF_WHILE_READING. Normalise it into
                 * the one documented error shared with the 1.1.1 and
                 * LibreSSL SSL_ERROR_SYSCALL ret-0 surface. */
                snprintf(state->error_msg, sizeof(state->error_msg), "%s",
                         JSEC_UNEXPECTED_EOF_ERROR);
                return TLS_IO_ERROR;
            }
            snprintf(state->error_msg, sizeof(state->error_msg),
                     "%s error: %s", op_name, get_ssl_error_string());
            return TLS_IO_ERROR;
    }
}

/*============================================================================
 * HELPER: Check for buffered TLS record data
 *============================================================================
 * True while record bytes are still held ahead of the socket: the BIO's
 * read-ahead buffer first (on LibreSSL), then the SSL library's own buffer.
 * The read loops stop at this boundary - one more SSL_read past the last
 * buffered record forces a kernel read of an empty socket that can only come
 * back with EAGAIN. LibreSSL has no SSL_has_pending; its SSL_pending reports
 * the same buffered-record state.
 */
static inline int jtls_has_buffered_data(TLSStream *tls) {
#if JSEC_LIBRESSL
    if (tls->bio_ahead.p < tls->bio_ahead.pe) {
        return 1;
    }
    return SSL_pending(tls->ssl) > 0;
#else
    return SSL_has_pending(tls->ssl);
#endif
}

/*============================================================================
 * PROCESS TLS OPERATION
 *============================================================================
 * Perform a single step of the TLS operation and determine what to do next.
 *
 * This is the core of the state machine. It calls the appropriate SSL
 * function based on the operation type and interprets the result.
 *
 * Parameters:
 *   state - The operation state containing TLS stream and operation info
 *
 * Returns:
 *   TLS_IO_COMPLETE   - Operation finished successfully
 *   TLS_IO_WANT_READ  - Need to wait for socket to be readable
 *   TLS_IO_WANT_WRITE - Need to wait for socket to be writable
 *   TLS_IO_WANT_BOTH  - Need to wait for either (rare)
 *   TLS_IO_ERROR      - Operation failed (error in state->error_msg)
 */
TLSIOState jtls_process_operation(TLSState *state) {
    TLSStream *tls = state->tls;
    int ret, ssl_err;

    ERR_clear_error();

    switch (state->op) {
        /*====================================================================
         * HANDSHAKE OPERATION
         *====================================================================
         * Perform TLS handshake (client or server side).
         *
         * For client: SSL_connect sends ClientHello, processes ServerHello,
         * etc. For server: SSL_accept waits for ClientHello, sends
         * ServerHello, etc.
         *
         * The handshake may require multiple round-trips, each causing
         * WANT_READ or WANT_WRITE.
         */
        case TLS_OP_HANDSHAKE: {
            if (tls->write_buffer.head < tls->write_buffer.tail) {
                int flush_res = jtls_bio_flush(tls);
                if (flush_res < 0) {
                    int sock_err = jsec_socket_errno;
                    return handle_ssl_error(SSL_ERROR_SYSCALL, -1, state,
                                            "Handshake", 0, NULL, sock_err);
                }
                if (flush_res == 0) {
                    return TLS_IO_WANT_WRITE;
                }
            }

            ret = (tls->flags & JTLS_FLAG_SERVER) ? SSL_accept(tls->ssl)
                                                  : SSL_connect(tls->ssl);

            if (ret == 1) {
                /* Handshake complete - connection ready for use */
                tls->conn_state = TLS_CONN_READY;
                if (tls->flags & JTLS_FLAG_TRACK_HANDSHAKE) {
                    clock_gettime(CLOCK_MONOTONIC, &tls->ts_handshake);
                }
                if (tls->write_buffer.head < tls->write_buffer.tail) {
                    jtls_bio_flush(tls);
                }
                return TLS_IO_COMPLETE;
            }

            if (tls->write_buffer.head < tls->write_buffer.tail) {
                int flush_res = jtls_bio_flush(tls);
                if (flush_res < 0) {
                    int sock_err = jsec_socket_errno;
                    return handle_ssl_error(SSL_ERROR_SYSCALL, -1, state,
                                            "Handshake", 0, NULL, sock_err);
                }
                if (flush_res == 0) {
                    return TLS_IO_WANT_WRITE;
                }
            }

            int sock_err = jsec_socket_errno;
            ssl_err = SSL_get_error(tls->ssl, ret);
            return handle_ssl_error(ssl_err, ret, state, "Handshake", 0, NULL,
                                    sock_err);
        }

        /*====================================================================
         * READ OPERATION
         *====================================================================
         * Read decrypted application data from the TLS connection.
         *
         * SSL_read handles:
         * 1. Reading encrypted data from socket (via our BIO)
         * 2. Decrypting the TLS records
         * 3. Returning plaintext to the caller
         *
         * We read as much as available up to the requested amount.
         * If bytes_requested < 0, we read whatever is available.
         *
         * Key: each SSL_read decrypts one buffered TLS record. The loop
         * ends at the caller's request size or at the drain of the
         * buffered records - one more SSL_read past the drain would force
         * a kernel read of an empty socket.
         */
        case TLS_OP_READ: {
            while (1) {
                /* Calculate how many bytes we want to read this iteration.
                 * bytes_requested counts bytes appended since buf_start, not
                 * the buffer's total length (buffers may arrive pre-filled).
                 */
                int32_t read_size =
                    state->bytes_requested -
                    (state->user_buf->count - state->buf_start);
                if (state->bytes_requested >= 0 && read_size <= 0) {
                    return TLS_IO_COMPLETE;
                }
                int32_t want = jtls_prepare_read_slice(
                    tls, state->user_buf,
                    state->bytes_requested < 0 ? -1 : read_size);

                ret = SSL_read(tls->ssl,
                               state->user_buf->data + state->user_buf->count,
                               want);

                if (ret > 0) {
                    check_record_handshake_time(tls);
                    state->user_buf->count += ret;

                    /* Complete at the request size or at the drain of
                     * the buffered records - one more SSL_read would force
                     * a kernel read of an empty socket */
                    if ((state->user_buf->count - state->buf_start) >=
                            state->bytes_requested ||
                        !jtls_has_buffered_data(tls)) {
                        return TLS_IO_COMPLETE;
                    }
                    /* Buffered records remain - coalesce them here */
                } else {
                    int sock_err = jsec_socket_errno;
                    ssl_err = SSL_get_error(tls->ssl, ret);
                    int has_data =
                        (state->user_buf->count > state->buf_start);
                    return handle_ssl_error(ssl_err, ret, state, "Read",
                                            has_data, tls, sock_err);
                }
            }
        }

        /*====================================================================
         * CHUNK OPERATION (like ev/chunk)
         *====================================================================
         * Read until exactly n bytes are read or EOF is reached.
         * Unlike READ, CHUNK will NOT return early with partial data when
         * the socket needs to wait - it continues until the full amount
         * is received or end of stream.
         */
        case TLS_OP_CHUNK: {
            int just_read_data = 0; /* Track if we just successfully read */
            while (1) {
                int32_t remaining =
                    state->bytes_requested -
                    (state->user_buf->count - state->buf_start);
                if (remaining <= 0) {
                    return TLS_IO_COMPLETE;
                }
                int32_t want =
                    jtls_prepare_read_slice(tls, state->user_buf, remaining);

                ret = SSL_read(tls->ssl,
                               state->user_buf->data + state->user_buf->count,
                               want);

                if (ret > 0) {
                    check_record_handshake_time(tls);
                    state->user_buf->count += ret;
                    just_read_data = 1;

                    if ((state->user_buf->count - state->buf_start) >=
                        state->bytes_requested) {
                        return TLS_IO_COMPLETE;
                    }
                    /* Continue reading - unlike READ, don't return early */
                } else {
                    int sock_err = jsec_socket_errno;
                    ssl_err = SSL_get_error(tls->ssl, ret);

                    /* WANT_READ/WANT_BOTH: retry immediately only while
                     * buffered records remain - with none left the retry
                     * is just the redundant EAGAIN read before parking */
                    if (ssl_err == SSL_ERROR_WANT_READ) {
                        if (just_read_data && jtls_has_buffered_data(tls)) {
                            just_read_data = 0;
                            continue;
                        }
                        return TLS_IO_WANT_READ;
                    }
                    if (ssl_err == SSL_ERROR_SYSCALL) {
                        if (sock_err == JSEC_EAGAIN ||
                            sock_err == JSEC_EWOULDBLOCK) {
                            if (just_read_data &&
                                jtls_has_buffered_data(tls)) {
                                just_read_data = 0;
                                continue;
                            }
                            return TLS_IO_WANT_BOTH;
                        }
                    }
                    /* Other errors use standard handler (no has_data for
                     * chunk) */
                    return handle_ssl_error(ssl_err, ret, state, "Chunk read",
                                            0, tls, sock_err);
                }
            }
        }

        /*====================================================================
         * WRITE OPERATION
         *====================================================================
         * Write application data to the TLS connection.
         *
         * SSL_write handles:
         * 1. Encrypting the plaintext into TLS records
         * 2. Writing encrypted data to socket (via our BIO)
         *
         * We write all the data, potentially across multiple calls if
         * the socket buffer fills up.
         */
        case TLS_OP_WRITE: {
            /* Re-derive the byte view from the source object on every
             * attempt: the fiber may have suspended across WANT_WRITE and
             * a buffer source may have been reallocated while parked
             * (SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER makes a moved base
             * pointer legal, but the pointer must be fresh). The span of
             * the operation was fixed at entry - a source whose length
             * changed mid-write fails cleanly with a TLS I/O error rather
             * than reading out-of-bounds memory or delivering bytes the
             * caller never handed to write. */
            const uint8_t *bytes;
            int32_t src_len;
            if (!janet_bytes_view(state->write_src, &bytes, &src_len) ||
                src_len != state->write_len ||
                src_len < state->write_offset) {
                snprintf(state->error_msg, sizeof(state->error_msg),
                         "Write error: write source changed during write");
                return TLS_IO_ERROR;
            }

            /* Drain any pending ciphertext left in write_buffer from a prior
             * partial send before continuing. */
            if (tls->write_buffer.head < tls->write_buffer.tail) {
                int flush_res = jtls_bio_flush(tls);
                if (flush_res < 0) {
                    int sock_err = jsec_socket_errno;
                    return handle_ssl_error(SSL_ERROR_SYSCALL, -1, state,
                                            "Write", 0, tls, sock_err);
                }
                if (flush_res == 0) {
                    return TLS_IO_WANT_WRITE;
                }
            }

            while (state->write_offset < state->write_len) {
                int remaining = state->write_len - state->write_offset;
                int chunk = remaining;

                /* Bound each chunk to write buffer capacity (or default)
                 * so that large writes (e.g. 2 GB) do not cause unbounded
                 * intermediate allocations or OpenSSL state retention. */
                if (tls->write_buffer_size > 0 &&
                    chunk > tls->write_buffer_size) {
                    chunk = tls->write_buffer_size;
                }

                ret = SSL_write(tls->ssl, bytes + state->write_offset, chunk);

                if (ret > 0) {
                    check_record_handshake_time(tls);
                    state->write_offset += ret;
                } else {
                    int sock_err = jsec_socket_errno;
                    ssl_err = SSL_get_error(tls->ssl, ret);
                    return handle_ssl_error(ssl_err, ret, state, "Write", 0,
                                            NULL, sock_err);
                }
            }

            /* All application data passed to SSL_write. Flush any accumulated
             * coalesced records in the write buffer to the network socket. */
            int flush_res = jtls_bio_flush(tls);
            if (flush_res < 0) {
                int sock_err = jsec_socket_errno;
                return handle_ssl_error(SSL_ERROR_SYSCALL, -1, state, "Write",
                                        0, tls, sock_err);
            }
            if (flush_res == 0) {
                return TLS_IO_WANT_WRITE;
            }

            return TLS_IO_COMPLETE;
        }

        /*====================================================================
         * SHUTDOWN OPERATION
         *====================================================================
         * Perform TLS shutdown (send close_notify alert).
         *
         * SSL_shutdown is bidirectional:
         *   - First call sends our close_notify
         *   - Subsequent calls wait for peer's close_notify
         *
         * Return values:
         *   1: Bidirectional shutdown complete
         *   0: Sent our close_notify, waiting for peer's
         *   <0: Error
         */
        case TLS_OP_SHUTDOWN:
        case TLS_OP_CLOSE: {
            if (tls->write_buffer.head < tls->write_buffer.tail) {
                int flush_res = jtls_bio_flush(tls);
                if (flush_res < 0) {
                    int sock_err = jsec_socket_errno;
                    return handle_ssl_error(SSL_ERROR_SYSCALL, -1, state,
                                            "Close", 0, tls, sock_err);
                }
                if (flush_res == 0) {
                    return TLS_IO_WANT_WRITE;
                }
            }

            ret = SSL_shutdown(tls->ssl);

            if (ret == 1) {
                /* Bidirectional shutdown complete */
                tls->conn_state = TLS_CONN_CLOSED;
                return TLS_IO_COMPLETE;
            } else if (ret == 0) {
                /* Sent close_notify, waiting for peer's.
                 * For TLS_OP_CLOSE: don't wait - just complete.
                 * For TLS_OP_SHUTDOWN: wait for peer's close_notify. */
                tls->conn_state = TLS_CONN_SHUTDOWN_SENT;
                if (state->op == TLS_OP_CLOSE) {
                    tls->conn_state = TLS_CONN_CLOSED;
                    return TLS_IO_COMPLETE;
                }
                return TLS_IO_WANT_READ;
            } else {
                ssl_err = SSL_get_error(tls->ssl, ret);

                if (ssl_err == SSL_ERROR_WANT_READ) {
                    /* Need to read for shutdown protocol.
                     * For CLOSE, try once more but don't block. */
                    if (state->op == TLS_OP_CLOSE) {
                        tls->conn_state = TLS_CONN_CLOSED;
                        return TLS_IO_COMPLETE;
                    }
                    return TLS_IO_WANT_READ;
                } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
                    return TLS_IO_WANT_WRITE;
                } else if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                    /* Peer closed - that's fine during shutdown */
                    tls->conn_state = TLS_CONN_CLOSED;
                    return TLS_IO_COMPLETE;
                } else if (ssl_err == SSL_ERROR_SYSCALL) {
                    int sock_err = jsec_socket_errno;
                    if (sock_err == JSEC_EAGAIN ||
                        sock_err == JSEC_EWOULDBLOCK) {
                        if (state->op == TLS_OP_CLOSE) {
                            tls->conn_state = TLS_CONN_CLOSED;
                            return TLS_IO_COMPLETE;
                        }
                        return TLS_IO_WANT_BOTH;
                    }
                    /* Treat syscall errors during shutdown as complete */
                    tls->conn_state = TLS_CONN_CLOSED;
                    return TLS_IO_COMPLETE;
                } else {
                    /* Other errors during shutdown - treat as complete */
                    tls->conn_state = TLS_CONN_CLOSED;
                    return TLS_IO_COMPLETE;
                }
            }
        }

        default:
            snprintf(state->error_msg, sizeof(state->error_msg),
                     "Unknown operation type: %d", state->op);
            return TLS_IO_ERROR;
    }
}

/* Helper to check if timeout is infinite (avoids float comparison warning) */
static inline int is_infinite_timeout(double timeout) {
    return isinf(timeout) != 0;
}

/*============================================================================
 * SCHEDULE ASYNC OPERATION
 *============================================================================
 * Register the operation with Janet's event loop to wait for I/O.
 *
 * Parameters:
 *   fiber    - The fiber running the operation
 *   tls      - The TLS stream
 *   state    - Operation state. On the synchronous path this is the
 *              embedded TLSStream read_state or write_state; on first
 *              suspension it is copied to a heap block (see below).
 *   mode     - What to wait for (read, write, or both)
 *   is_async - True if already in async mode (need to switch modes)
 */
void jtls_schedule_async(JanetFiber *fiber, TLSStream *tls, TLSState *state,
                         JanetAsyncMode mode, int is_async) {
    if (!tls->transport) return;

    if (is_async) {
        /*
         * Already in async mode - we need to switch event modes.
         * This happens when an operation was waiting for read but now
         * needs to wait for write (or vice versa).
         *
         * The state pointer is the heap copy made at first suspension
         * and is already stored in fiber->ev_state. Steal it across
         * janet_async_end (the NULL discipline) so the end does not
         * free it, then hand the same block to the new registration -
         * the copy is reused across mode switches, never re-allocated.
         */
        fiber->ev_state = NULL;
        janet_async_end(fiber);
        janet_async_start_fiber(fiber, tls->transport, mode,
                                jtls_async_callback, state);
    } else {
        /*
         * First time entering async mode. state is still the embedded
         * TLSStream read_state or write_state here, but the runtime owns
         * the ev_state pointer and frees it with janet_free (the
         * janet.h async contract), so handing over the interior pointer
         * would make the fiber-deinit free site free into the middle of
         * the GC-managed TLSStream block. Copy the state to a heap
         * block and register the copy instead: synchronous operations
         * never reach this branch and stay zero-allocation, and the
         * copy is freed by janet_async_end on completion or by fiber
         * teardown when the process exits with the operation parked.
         * The TLSStream is GC-managed and marked during
         * JANET_ASYNC_EVENT_MARK, keeping the copy's tls link alive.
         *
         * Arm the deadline here, at first suspension: if the operation
         * completed synchronously the fiber would never suspend, sched_id
         * would not advance, and a stale timer would later cancel an
         * unrelated wait with a spurious "timeout". The is_async branch
         * above must not re-arm - the fiber is already suspended with its
         * original deadline still live.
         */
        if (state->has_timeout && !is_infinite_timeout(state->timeout)) {
            janet_addtimeout(state->timeout);
        }
        TLSState *async_state = janet_malloc(sizeof(TLSState));
        if (NULL == async_state) {
            JANET_OUT_OF_MEMORY;
        }
        *async_state = *state;
        janet_async_start(tls->transport, mode, jtls_async_callback,
                          async_state);
    }
}

/*============================================================================
 * HELPER: Raise or cancel with state->error_msg under the TLS IO category
 *============================================================================
 * Every hard I/O failure reports "[TLS:IO] " plus the recorded reason, so
 * no path surfaces a category-less message to the caller.
 */
static void jtls_raise_io_error(JanetFiber *fiber, TLSState *state,
                                int is_async) {
    char buf[sizeof(state->error_msg) + 16];
    snprintf(buf, sizeof(buf), "[TLS:IO] %s", state->error_msg);
    if (is_async) {
        janet_cancel(fiber, janet_cstringv(buf));
    } else {
        janet_panic(buf);
    }
}

/*============================================================================
 * ATTEMPT TLS I/O
 *============================================================================
 * The main entry point for TLS operations. Processes the operation and
 * either returns immediately or schedules async continuation.
 *
 * Parameters:
 *   fiber    - The fiber running the operation
 *   state    - Operation state
 *   is_async - True if called from async callback (vs. initial call)
 *
 * Returns:
 *   1:  Operation completed successfully
 *   0:  Operation needs async continuation (fiber suspended)
 *   -1: Operation failed (fiber cancelled with error)
 */
int jtls_attempt_io(JanetFiber *fiber, TLSState *state, int is_async) {
    TLSStream *tls = state->tls;

    /* Track this fiber as pending for its operation type */
    if (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK) {
        tls->pending_read = fiber;
    } else if (state->op == TLS_OP_WRITE) {
        tls->pending_write = fiber;
    }

    /* Loop to process operation as long as we have buffered data.
     * OpenSSL may return WANT_READ even if there is data in the custom BIO
     * buffer that it hasn't consumed yet (e.g. state transitions).
     * We must not yield to the event loop if we can satisfy the read locally.
     */
    TLSIOState io_state;
    int retried = 0;
    do {
        /* Process the operation - calls SSL functions, updates state */
        io_state = jtls_process_operation(state);

        /* Local buffered data can satisfy the read without waiting on
         * the socket, so retry instead of yielding. The ahead buffer
         * makes progress on every retry and drains before we park.
         * OpenSSL-side buffered data earns one retry only: SSL_has_pending
         * also reports a partially received record that still needs
         * network bytes, and retrying that state spins without progress.
         */
        if (io_state == TLS_IO_WANT_READ && jtls_has_buffered_data(tls) &&
#if JSEC_LIBRESSL
            (tls->bio_ahead.p < tls->bio_ahead.pe || !retried)
#else
            !retried
#endif
        ) {
            retried = 1;
            continue;
        }
        break;
    } while (1);

    switch (io_state) {
        case TLS_IO_COMPLETE: {
            /*
             * Operation completed successfully.
             * Clear pending tracking and schedule result.
             */
            if (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK) {
                tls->pending_read = NULL;
            } else if (state->op == TLS_OP_WRITE) {
                tls->pending_write = NULL;
            }

            if (is_async) {
                Janet result;

                switch (state->op) {
                    case TLS_OP_HANDSHAKE:
                        result = janet_wrap_abstract(tls);
                        break;

                    case TLS_OP_READ:
                    case TLS_OP_CHUNK:
                        /* One completion rule for both read shapes,
                         * serving tls/read and tls/chunk and (tls/read s
                         * :all): the buffer holding the bytes appended
                         * during this call when at least one was
                         * appended before the clean close_notify, nil
                         * when zero were. A returned buffer is truthy
                         * and would never terminate a read loop, and an
                         * empty or unchanged caller buffer is not
                         * application data. */
                        result = (state->user_buf->count > state->buf_start)
                                     ? janet_wrap_buffer(state->user_buf)
                                     : janet_wrap_nil();
                        break;

                    case TLS_OP_WRITE:
                    case TLS_OP_SHUTDOWN:
                    case TLS_OP_CLOSE:
                    default:
                        result = janet_wrap_nil();
                        break;
                }

                janet_schedule(fiber, result);
                /* Leave ev_state set so janet_async_end frees the heap
                 * copy made at first suspension */
                janet_async_end(fiber);
            }

            /* For TLS_OP_CLOSE, close transport in both sync and async
             * cases. In the async case this must run after the schedule
             * and detach above: the close completed through a WANT_WRITE
             * suspension, so the fiber is still registered as the
             * transport's write fiber, and janet_stream_close delivers
             * CLOSE to that registration. The CLOSE case of
             * jtls_async_callback cancels the fiber with "Connection
             * closed", and that janet_cancel queues a newer task which
             * supersedes the result just scheduled - only the newest
             * schedule runs. janet_async_end has detached the fiber, so
             * the CLOSE now reaches only fibers still legitimately bound
             * to the transport. */
            if (state->op == TLS_OP_CLOSE) {
                if (tls->transport &&
                    !(tls->transport->flags & JANET_STREAM_CLOSED)) {
                    janet_stream_close(tls->transport);
                }
                tls->stream.flags |= JANET_STREAM_CLOSED;
            }
            return 1;
        }

        case TLS_IO_WANT_READ:
            /*
             * Need to wait for socket to be readable.
             *
             * Cooperative mode switching: If this is a WRITE operation that
             * needs to read (e.g., TLS renegotiation), and there's already a
             * READ operation pending, just stay registered for WRITE events.
             * The read operation will handle receiving the protocol messages,
             * and when it completes, our SSL_write will succeed.
             */
            state->io_state = io_state; /* Store for Windows IOCP probe */
            if (state->op == TLS_OP_WRITE && tls->pending_read != NULL) {
                /* Let the read fiber handle reading, we stay on write */
                jtls_schedule_async(fiber, tls, state,
                                    JANET_ASYNC_LISTEN_WRITE, is_async);
            } else {
                jtls_schedule_async(fiber, tls, state,
                                    JANET_ASYNC_LISTEN_READ, is_async);
            }
            return 0;

        case TLS_IO_WANT_WRITE:
            /*
             * Need to wait for socket to be writable.
             *
             * Cooperative mode switching: If this is a READ operation that
             * needs to write (e.g., TLS renegotiation), and there's already
             * a WRITE operation pending, just stay registered for READ
             * events. The write operation will handle sending the protocol
             * messages, and when it completes, our SSL_read will succeed.
             */
            state->io_state = io_state; /* Store for Windows IOCP probe */
            if ((state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK) &&
                tls->pending_write != NULL) {
                /* Let the write fiber handle writing, we stay on read */
                jtls_schedule_async(fiber, tls, state,
                                    JANET_ASYNC_LISTEN_READ, is_async);
            } else {
                jtls_schedule_async(fiber, tls, state,
                                    JANET_ASYNC_LISTEN_WRITE, is_async);
            }
            return 0;

        case TLS_IO_WANT_BOTH:
            /* Need to wait for either (rare case) */
            state->io_state = io_state; /* Store for Windows IOCP probe */
            jtls_schedule_async(fiber, tls, state, JANET_ASYNC_LISTEN_BOTH,
                                is_async);
            return 0;

        case TLS_IO_ERROR:
            /* Operation failed - clear pending tracking */
            if (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK) {
                tls->pending_read = NULL;
            } else if (state->op == TLS_OP_WRITE) {
                tls->pending_write = NULL;
            }

            jtls_raise_io_error(fiber, state, is_async);
            if (is_async) {
                /* Leave ev_state set so janet_async_end frees the heap
                 * copy made at first suspension */
                janet_async_end(fiber);
            }
            return -1;

        default:
            /* Unknown state - should never happen */
            snprintf(state->error_msg, sizeof(state->error_msg),
                     "Unknown I/O state: %d", io_state);
            jtls_raise_io_error(fiber, state, is_async);
            if (is_async) {
                /* Leave ev_state set so janet_async_end frees the heap
                 * copy made at first suspension */
                janet_async_end(fiber);
            }
            return -1;
    }
}

/*============================================================================
 * HELPER: Clear pending tracking for one operation
 *============================================================================
 * jtls_attempt_io records the operation fiber in the pending_read or
 * pending_write slot and clears it only on completion or error. A
 * registration that ends any other way - a cancelled operation through
 * the DEINIT case, or the hangup and close/error completions - clears
 * through here. A slot left stale feeds the cooperative-mode decision a
 * reader that is gone, so a write that needs READ stays registered for
 * WRITE readiness only and re-enters the state machine on every writable
 * report.
 *
 * The slot is identified by operation role: read and chunk operations
 * record into pending_read, write operations into pending_write, so the
 * op field of the state names the slot exactly even with a read and a
 * write in flight at once. Role matching is required because the state
 * that reaches this helper is the heap copy made at first suspension (see
 * jtls_schedule_async), so a pointer comparison against the embedded
 * read_state or write_state in TLSStream would never match and every slot
 * would go stale. jtls_schedule_async steals the state before
 * janet_async_end on a mode switch, so its DEINIT has no state and must
 * leave the slots alone; callers keep the if (state) guard for that.
 *
 * The earlier fiber comparison was removed because it never matched in
 * practice: jtls_attempt_io records janet_current_fiber() in the slot, but
 * Janet's async machinery registers and cancels janet_vm.root_fiber.
 * Whenever the operation runs inside a child fiber those are two different
 * objects, and a try body is always a child fiber (try expands to
 * fiber/new plus resume), so the helper was handed the root fiber while
 * the slot held the child and nothing was ever cleared. Do not reintroduce
 * a fiber comparison; use the operation role.
 */
void clear_pending_for(TLSState *state) {
    TLSStream *tls = state->tls;
    if (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK) {
        tls->pending_read = NULL;
    }
    if (state->op == TLS_OP_WRITE) {
        tls->pending_write = NULL;
    }
}

/*============================================================================
 * HELPER: Format the pending socket error under the TLS IO category
 *============================================================================
 * The reason is read with getsockopt SO_ERROR (the pattern in
 * src/jtls/api/connect.c:549-563) and formatted with jsec_socket_strerror
 * (src/compat.h:211, :271), the way janet_ev_lasterr carries the OS
 * reason into a cancellation at core ev.c:2600.
 */
static void jtls_socket_error_msg(char *buf, size_t buflen,
                                  JanetStream *stream) {
    int res = 0;
    int r = -1;
    socklen_t size = sizeof(res);
    if (stream) {
#ifdef JANET_WINDOWS
        r = getsockopt((SOCKET)stream->handle, SOL_SOCKET, SO_ERROR,
                       (char *)&res, (int *)&size);
#else
        r = getsockopt(stream->handle, SOL_SOCKET, SO_ERROR, &res, &size);
#endif
    }
    if (r == 0 && res != 0) {
        snprintf(buf, buflen, "[TLS:IO] socket error: %s",
                 jsec_socket_strerror(res));
    } else {
        snprintf(buf, buflen, "[TLS:IO] socket error");
    }
}

/*============================================================================
 * ASYNC CALLBACK
 *============================================================================
 * Called by Janet's event loop when the socket is ready for I/O or when
 * various events occur.
 *
 * Events:
 *   MARK  - GC is running, mark any Janet values we hold
 *   INIT  - Async operation starting (do nothing)
 *   DEINIT - Async operation ending (clear pending tracking)
 *   READ  - Socket is readable
 *   WRITE - Socket is writable
 *   CLOSE - Socket was closed
 *   ERR   - Socket error
 *   HUP   - Socket hangup (peer closed)
 */
void jtls_async_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    TLSState *state = (TLSState *)fiber->ev_state;

    /* State may be NULL if it was stolen during mode switch */
    if (!state && event != JANET_ASYNC_EVENT_DEINIT) {
        return;
    }

    switch (event) {
        case JANET_ASYNC_EVENT_MARK:
            /* GC is running - mark values we reference */
            if (state) {
                janet_mark(janet_wrap_abstract(state->tls));
                if (state->user_buf) {
                    janet_mark(janet_wrap_buffer(state->user_buf));
                }
                if (state->op == TLS_OP_WRITE) {
                    /* Keep the write source alive while the write is
                     * parked. Guarded on the operation because
                     * write_state also carries close/shutdown/handshake
                     * operations that never set write_src and must not
                     * mark a stale value left by an earlier write. */
                    janet_mark(state->write_src);
                }
            }
            break;

        case JANET_ASYNC_EVENT_INIT:
#ifdef JANET_WINDOWS
            /* Windows IOCP: Start zero-byte WSARecv/WSASend as readiness
             * probe. These complete when socket is readable/writable, then
             * our BIO's non-blocking recv/send will succeed. */
            if (state) {
                JanetStream *stream = fiber->ev_stream;
                memset(&state->overlapped, 0, sizeof(WSAOVERLAPPED));
                state->wsa_buf.len = 0;
                state->wsa_buf.buf = NULL;
                state->wsa_flags = 0;

                int status;
                if (state->io_state == TLS_IO_WANT_READ) {
                    status = WSARecv((SOCKET)stream->handle, &state->wsa_buf,
                                     1, NULL, &state->wsa_flags,
                                     &state->overlapped, NULL);
                } else {
                    status = WSASend((SOCKET)stream->handle, &state->wsa_buf,
                                     1, NULL, 0, &state->overlapped, NULL);
                }
                if (status == SOCKET_ERROR &&
                    WSAGetLastError() != WSA_IO_PENDING) {
                    janet_cancel(fiber, janet_cstringv("Socket I/O error"));
                    /* Leave ev_state set so janet_async_end frees the heap
                     * copy made at first suspension */
                    janet_async_end(fiber);
                    return;
                }
                janet_async_in_flight(fiber);
            }
            break;
#else
            /* Unix: return and wait for READ/WRITE events from epoll/kqueue
             */
            return;
#endif

        case JANET_ASYNC_EVENT_DEINIT:
            /* External cancellation ends here with this fiber's pending slot
             * still held. Clear it while the state is reachable through
             * ev_state, then leave ev_state set: the state is the heap copy
             * from first suspension and janet_async_end frees it right after
             * this event returns, completing the registration teardown. */
            if (state) {
                clear_pending_for(state);
            }
            break;

#ifdef JANET_WINDOWS
        case JANET_ASYNC_EVENT_COMPLETE:
        case JANET_ASYNC_EVENT_FAILED:
            /* Windows IOCP: Zero-byte probe completed, socket is now ready.
             * Retry the SSL operation - BIO's non-blocking recv/send will
             * succeed. */
            if (state) {
                jtls_attempt_io(fiber, state, 1);
            }
            break;
#endif

        case JANET_ASYNC_EVENT_HUP:
            /* Peer closed connection. For read operations, there may still
             * be buffered data to read (SSL layer or socket buffer).
             * This is critical for FreeBSD unix sockets where HUP arrives
             * while data is still pending.
             *
             * Do a direct SSL_read without going through the full state
             * machine to avoid rescheduling loops. */
            if (state &&
                (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK)) {
                TLSStream *tls = state->tls;
                int32_t step_cap = tls->read_buffer_size > 0
                                       ? tls->read_buffer_size
                                       : DEFAULT_TLS_BUFFER_SIZE;
                /* For CHUNK, only read what was requested.
                 * For READ, read up to step_cap. */
                int32_t read_size =
                    state->bytes_requested -
                    (state->user_buf->count - state->buf_start);
                if (state->bytes_requested >= 0 && read_size <= 0) {
                    if (state->op == TLS_OP_CHUNK) {
                        /* Already have enough data */
                        janet_schedule(fiber,
                                       janet_wrap_buffer(state->user_buf));
                    } else {
                        janet_schedule(
                            fiber, (state->user_buf->count > state->buf_start)
                                       ? janet_wrap_buffer(state->user_buf)
                                       : janet_wrap_nil());
                    }
                    clear_pending_for(state);
                    janet_async_end(fiber);
                    return;
                }
                if (state->bytes_requested < 0) {
                    read_size = step_cap;
                } else if (state->op != TLS_OP_CHUNK &&
                           read_size > step_cap) {
                    read_size = step_cap;
                }

                /* Drain pending data in bounded slices so the buffer
                 * grows with data read, not read_size; want bounds both
                 * the ensured capacity and the SSL_read length */
                ERR_clear_error();
                int ret = 0;
                int sock_err = 0;
                while (read_size > 0) {
                    int32_t want = jtls_prepare_read_slice(
                        tls, state->user_buf, read_size);
                    ret = SSL_read(
                        tls->ssl,
                        state->user_buf->data + state->user_buf->count, want);
                    if (ret <= 0) {
                        /* Capture the socket errno before SSL_get_error
                         * runs (the jtls_process_operation discipline) */
                        if (ret < 0) sock_err = jsec_socket_errno;
                        break;
                    }
                    state->user_buf->count += ret;
                    read_size -= ret;
                }
                if (ret > 0) {
                    /* Return successfully read data */
                    janet_schedule(fiber, janet_wrap_buffer(state->user_buf));
                    clear_pending_for(state);
                    janet_async_end(fiber);
                    return;
                } else {
                    /* A clean close_notify is the only completion this
                     * drain may report; the same completion rule as the
                     * TLS_IO_COMPLETE read arms: the bytes appended
                     * during this call, or nil when zero were. Any other
                     * outcome of a HUP'd transport is a truncation or an
                     * error and raises, so a platform reaching this
                     * drain through a HUP-only wakeup cannot regress the
                     * rule. */
                    int ssl_err = SSL_get_error(tls->ssl, ret);
                    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                        /* Clean shutdown - return what we have or nil */
                        Janet result =
                            (state->user_buf->count > state->buf_start)
                                ? janet_wrap_buffer(state->user_buf)
                                : janet_wrap_nil();
                        janet_schedule(fiber, result);
                        clear_pending_for(state);
                        janet_async_end(fiber);
                        return;
                    } else if (ssl_err == SSL_ERROR_SYSCALL &&
                               sock_err != 0) {
                        /* A hard reset raises with the OS reason under
                         * the TLS IO category - never a clean nil */
                        char msg[320];
                        snprintf(
                            msg, sizeof(msg), "[TLS:IO] %s syscall error: %s",
                            state->op == TLS_OP_CHUNK ? "Chunk read" : "Read",
                            jsec_socket_strerror(sock_err));
                        janet_cancel(fiber, janet_cstringv(msg));
                        clear_pending_for(state);
                        janet_async_end(fiber);
                        return;
                    }
                    /* Without close_notify the stream is truncated: the
                     * 1.1.1/LibreSSL SSL_ERROR_SYSCALL ret-0 surface and
                     * the OpenSSL 3.x SSL_ERROR_SSL surface both raise
                     * the one documented unexpected-EOF error. */
                    const char *err_msg;
                    if (jutils_is_unexpected_eof() ||
                        (ssl_err == SSL_ERROR_SYSCALL && sock_err == 0)) {
                        err_msg = JSEC_UNEXPECTED_EOF_ERROR;
                    } else if (ssl_err == SSL_ERROR_SSL) {
                        err_msg = get_ssl_error_string();
                    } else {
                        err_msg = "Connection closed";
                    }
                    janet_cancel(fiber, janet_cstringv(err_msg));
                    clear_pending_for(state);
                    janet_async_end(fiber);
                    return;
                }
            }
            /* Fall through for non-read operations and read drains that
             * found no data and no clean end-of-file */
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((fallthrough));
#endif
        case JANET_ASYNC_EVENT_CLOSE:
            /* A local close schedules nil for parked readers (core
             * ev.c:2473-2476) and cancels write- and handshake-class
             * operations the way core ev.c:2723-2726 cancels parked
             * writers with "stream closed". A hangup that fell through
             * here could not establish a clean end-of-file, so it cancels
             * rather than claims nil. */
            if (state) {
                clear_pending_for(state);
                if (event == JANET_ASYNC_EVENT_CLOSE &&
                    (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK)) {
                    janet_schedule(fiber, janet_wrap_nil());
                } else {
                    janet_cancel(fiber,
                                 janet_cstringv("[TLS:IO] stream closed"));
                }
                janet_async_end(fiber);
            }
            break;

        case JANET_ASYNC_EVENT_ERR: {
            /* A genuine socket error raises under the TLS category with
             * the OS reason - never nil, never a hardcoded string. */
            if (state) {
                char msg[320];
                clear_pending_for(state);
                jtls_socket_error_msg(msg, sizeof(msg), fiber->ev_stream);
                janet_cancel(fiber, janet_cstringv(msg));
                janet_async_end(fiber);
            }
            break;
        }

        case JANET_ASYNC_EVENT_READ:
        case JANET_ASYNC_EVENT_WRITE:
            /* Socket is ready - retry the operation */
            if (state) {
                jtls_attempt_io(fiber, state, 1);
            }
            break;

        default:
            break;
    }
}
