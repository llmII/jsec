/*
 * state_machine.c - Async I/O state machine for TLS operations
 *
 * This file implements the core state machine that integrates TLS operations
 * with Janet's event loop. It handles the non-blocking nature of SSL operations
 * by registering with the event loop when operations need to wait for I/O.
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
 * HELPER: Record handshake completion time if just finished
 *============================================================================
 * OpenSSL can complete the handshake implicitly during SSL_read/SSL_write.
 * This helper checks if the handshake just completed and records the timestamp.
 */
static inline void check_record_handshake_time(TLSStream *tls) {
    if (tls->track_handshake_time && tls->conn_state != TLS_CONN_READY &&
        SSL_is_init_finished(tls->ssl) && tls->ts_handshake.tv_sec == 0 &&
        tls->ts_handshake.tv_nsec == 0) {
        clock_gettime(CLOCK_MONOTONIC, &tls->ts_handshake);
        tls->conn_state = TLS_CONN_READY;
    }
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
 *   op_name      - Name of operation for error messages (e.g., "Read", "Write")
 *   has_data     - True if we have partial data that can be returned
 *   tls          - TLS stream (for updating conn_state on shutdown)
 *
 * Returns:
 *   Appropriate TLSIOState based on the error
 */
static TLSIOState handle_ssl_error(int ssl_err, int ret, TLSState *state,
                                   const char *op_name, int has_data,
                                   TLSStream *tls) {
    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            return has_data ? TLS_IO_COMPLETE : TLS_IO_WANT_READ;

        case SSL_ERROR_WANT_WRITE:
            return has_data ? TLS_IO_COMPLETE : TLS_IO_WANT_WRITE;

        case SSL_ERROR_ZERO_RETURN:
            /* Clean shutdown received from peer */
            if (tls)
                tls->conn_state = TLS_CONN_SHUTDOWN_SENT;
            return TLS_IO_COMPLETE;

        case SSL_ERROR_SYSCALL:
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return has_data ? TLS_IO_COMPLETE : TLS_IO_WANT_BOTH;
            }
            if (ret == 0 || errno == 0) {
                /* EOF - not an error for read operations */
                return TLS_IO_COMPLETE;
            }
            snprintf(state->error_msg, sizeof(state->error_msg), "%s syscall error: %s",
                     op_name, strerror(errno));
            return TLS_IO_ERROR;

        default:
            snprintf(state->error_msg, sizeof(state->error_msg), "%s error: %s",
                     op_name, get_ssl_error_string());
            return TLS_IO_ERROR;
    }
}

/*============================================================================
 * PROCESS TLS OPERATION
 *============================================================================
 * Perform a single step of the TLS operation and determine what to do next.
 *
 * This is the core of the state machine. It calls the appropriate SSL function
 * based on the operation type and interprets the result.
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

    switch (state->op) {
        /*====================================================================
         * HANDSHAKE OPERATION
         *====================================================================
         * Perform TLS handshake (client or server side).
         *
         * For client: SSL_connect sends ClientHello, processes ServerHello, etc.
         * For server: SSL_accept waits for ClientHello, sends ServerHello, etc.
         *
         * The handshake may require multiple round-trips, each causing
         * WANT_READ or WANT_WRITE.
         */
        case TLS_OP_HANDSHAKE: {
                ret = tls->is_server ? SSL_accept(tls->ssl) : SSL_connect(tls->ssl);

                if (ret == 1) {
                    /* Handshake complete - connection ready for use */
                    tls->conn_state = TLS_CONN_READY;
                    if (tls->track_handshake_time) {
                        clock_gettime(CLOCK_MONOTONIC, &tls->ts_handshake);
                    }
                    return TLS_IO_COMPLETE;
                }

                ssl_err = SSL_get_error(tls->ssl, ret);
                return handle_ssl_error(ssl_err, ret, state, "Handshake", 0, NULL);
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
         * Key: We keep calling SSL_read until we get WANT_READ, not just
         * until SSL_pending returns 0. SSL_pending only shows buffered data,
         * but the socket may have more TLS records ready to read.
         */
        case TLS_OP_READ: {
                while (1) {
                    int capacity = state->bytes_requested - state->user_buf->count;
                    if (capacity <= 0) {
                        capacity = 65536; /* Read in 64KB chunks if no limit */
                    }

                    janet_buffer_ensure(state->user_buf, state->user_buf->count + capacity,
                                        2);

                    ret = SSL_read(tls->ssl, state->user_buf->data + state->user_buf->count,
                                   capacity);

                    if (ret > 0) {
                        check_record_handshake_time(tls);
                        state->user_buf->count += ret;

                        /* Check if we've read enough */
                        if (state->bytes_requested > 0 &&
                            state->user_buf->count >= state->bytes_requested) {
                            return TLS_IO_COMPLETE;
                        }
                        /* Keep reading until WANT_READ */
                    } else {
                        ssl_err = SSL_get_error(tls->ssl, ret);
                        int has_data = (state->user_buf->count > 0);
                        return handle_ssl_error(ssl_err, ret, state, "Read", has_data, tls);
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
                    int remaining = state->bytes_requested - state->user_buf->count;
                    if (remaining <= 0) {
                        return TLS_IO_COMPLETE;
                    }

                    janet_buffer_ensure(state->user_buf, state->user_buf->count + remaining,
                                        2);

                    ret = SSL_read(tls->ssl, state->user_buf->data + state->user_buf->count,
                                   remaining);

                    if (ret > 0) {
                        check_record_handshake_time(tls);
                        state->user_buf->count += ret;
                        just_read_data = 1;

                        if (state->user_buf->count >= state->bytes_requested) {
                            return TLS_IO_COMPLETE;
                        }
                        /* Continue reading - unlike READ, don't return early */
                    } else {
                        ssl_err = SSL_get_error(tls->ssl, ret);

                        /* WANT_READ/WANT_BOTH: retry immediately if we just read */
                        if (ssl_err == SSL_ERROR_WANT_READ) {
                            if (just_read_data) {
                                just_read_data = 0;
                                continue;
                            }
                            return TLS_IO_WANT_READ;
                        }
                        if (ssl_err == SSL_ERROR_SYSCALL &&
                            (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            if (just_read_data) {
                                just_read_data = 0;
                                continue;
                            }
                            return TLS_IO_WANT_BOTH;
                        }
                        /* Other errors use standard handler (no has_data for chunk) */
                        return handle_ssl_error(ssl_err, ret, state, "Chunk read", 0, tls);
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
                while (state->write_offset < state->write_len) {
                    int remaining = state->write_len - state->write_offset;

                    ret = SSL_write(tls->ssl, state->write_data + state->write_offset,
                                    remaining);

                    if (ret > 0) {
                        check_record_handshake_time(tls);
                        state->write_offset += ret;

                        if (state->write_offset == state->write_len) {
                            return TLS_IO_COMPLETE;
                        }
                        /* Continue writing more */
                    } else {
                        ssl_err = SSL_get_error(tls->ssl, ret);
                        return handle_ssl_error(ssl_err, ret, state, "Write", 0, NULL);
                    }
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
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
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

/*============================================================================
 * SCHEDULE ASYNC OPERATION
 *============================================================================
 * Register the operation with Janet's event loop to wait for I/O.
 *
 * Parameters:
 *   fiber    - The fiber running the operation
 *   tls      - The TLS stream
 *   state    - Operation state (embedded in TLSStream, not heap-allocated)
 *   mode     - What to wait for (read, write, or both)
 *   is_async - True if already in async mode (need to switch modes)
 */
void jtls_schedule_async(JanetFiber *fiber, TLSStream *tls, TLSState *state,
                         JanetAsyncMode mode, int is_async) {
    if (!tls->transport)
        return;

    if (is_async) {
        /*
         * Already in async mode - we need to switch event modes.
         * This happens when an operation was waiting for read but now
         * needs to wait for write (or vice versa).
         *
         * The state pointer is already stored in fiber->ev_state and
         * points to the embedded state in TLSStream. We just need to
         * end the current registration and start a new one.
         */
        fiber->ev_state = NULL;
        janet_async_end(fiber);
        janet_async_start_fiber(fiber, tls->transport, mode, jtls_async_callback,
                                state);
    } else {
        /*
         * First time entering async mode.
         * State is embedded in TLSStream (read_state or write_state),
         * so no heap allocation needed. The TLSStream is GC-managed
         * and marked during JANET_ASYNC_EVENT_MARK, keeping the state alive.
         */
        janet_async_start(tls->transport, mode, jtls_async_callback, state);
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
    do {
        /* Process the operation - calls SSL functions, updates state */
        io_state = jtls_process_operation(state);

        if (io_state == TLS_IO_WANT_READ && tls->bio_ahead.p < tls->bio_ahead.pe) {
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

                /* For TLS_OP_CLOSE, close transport in both sync and async cases */
                if (state->op == TLS_OP_CLOSE) {
                    if (tls->transport && !(tls->transport->flags & JANET_STREAM_CLOSED)) {
                        janet_stream_close(tls->transport);
                    }
                    tls->stream.flags |= JANET_STREAM_CLOSED;
                }

                if (is_async) {
                    Janet result;

                    switch (state->op) {
                        case TLS_OP_HANDSHAKE:
                            result = janet_wrap_abstract(tls);
                            break;

                        case TLS_OP_READ:
                            result = (state->user_buf->count > 0)
                                     ? janet_wrap_buffer(state->user_buf)
                                     : janet_wrap_nil();
                            break;

                        case TLS_OP_CHUNK:
                            /* Chunk always returns buffer (may be empty on EOF) */
                            result = janet_wrap_buffer(state->user_buf);
                            break;

                        case TLS_OP_WRITE:
                        case TLS_OP_SHUTDOWN:
                        case TLS_OP_CLOSE:
                        default:
                            result = janet_wrap_nil();
                            break;
                    }

                    janet_schedule(fiber, result);
                    /* Clear ev_state before janet_async_end to prevent double-free
                     * (state is embedded in TLSStream, not heap-allocated) */
                    fiber->ev_state = NULL;
                    janet_async_end(fiber);
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
            if (state->op == TLS_OP_WRITE && tls->pending_read != NULL) {
                /* Let the read fiber handle reading, we stay on write */
                jtls_schedule_async(fiber, tls, state, JANET_ASYNC_LISTEN_WRITE,
                                    is_async);
            } else {
                jtls_schedule_async(fiber, tls, state, JANET_ASYNC_LISTEN_READ, is_async);
            }
            return 0;

        case TLS_IO_WANT_WRITE:
            /*
             * Need to wait for socket to be writable.
             *
             * Cooperative mode switching: If this is a READ operation that
             * needs to write (e.g., TLS renegotiation), and there's already
             * a WRITE operation pending, just stay registered for READ events.
             * The write operation will handle sending the protocol messages,
             * and when it completes, our SSL_read will succeed.
             */
            if ((state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK) &&
                tls->pending_write != NULL) {
                /* Let the write fiber handle writing, we stay on read */
                jtls_schedule_async(fiber, tls, state, JANET_ASYNC_LISTEN_READ, is_async);
            } else {
                jtls_schedule_async(fiber, tls, state, JANET_ASYNC_LISTEN_WRITE,
                                    is_async);
            }
            return 0;

        case TLS_IO_WANT_BOTH:
            /* Need to wait for either (rare case) */
            jtls_schedule_async(fiber, tls, state, JANET_ASYNC_LISTEN_BOTH, is_async);
            return 0;

        case TLS_IO_ERROR:
            /* Operation failed - clear pending tracking */
            if (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK) {
                tls->pending_read = NULL;
            } else if (state->op == TLS_OP_WRITE) {
                tls->pending_write = NULL;
            }

            if (is_async) {
                janet_cancel(fiber, janet_cstringv(state->error_msg));
                /* Clear ev_state before janet_async_end to prevent double-free
                 * (state is embedded in TLSStream, not heap-allocated) */
                fiber->ev_state = NULL;
                janet_async_end(fiber);
            } else {
                janet_panic(state->error_msg);
            }
            return -1;

        default:
            /* Unknown state - should never happen */
            snprintf(state->error_msg, sizeof(state->error_msg),
                     "Unknown I/O state: %d", io_state);
            if (is_async) {
                janet_cancel(fiber, janet_cstringv(state->error_msg));
                /* Clear ev_state before janet_async_end to prevent double-free
                 * (state is embedded in TLSStream, not heap-allocated) */
                fiber->ev_state = NULL;
                janet_async_end(fiber);
            } else {
                janet_panic(state->error_msg);
            }
            return -1;
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
 *   DEINIT - Async operation ending (do nothing)
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
            }
            break;

        case JANET_ASYNC_EVENT_INIT:
        case JANET_ASYNC_EVENT_DEINIT:
            /* Nothing to do */
            break;

        case JANET_ASYNC_EVENT_HUP:
            /* Peer closed connection. For read operations, there may still
             * be buffered data to read (SSL layer or socket buffer).
             * This is critical for FreeBSD unix sockets where HUP arrives
             * while data is still pending.
             *
             * Do a direct SSL_read without going through the full state machine
             * to avoid rescheduling loops. */
            if (state && (state->op == TLS_OP_READ || state->op == TLS_OP_CHUNK)) {
                TLSStream *tls = state->tls;
                /* For CHUNK, only read what was requested.
                 * For READ, read up to 64KB. */
                int capacity;
                if (state->op == TLS_OP_CHUNK) {
                    capacity = state->bytes_requested - state->user_buf->count;
                    if (capacity <= 0) {
                        /* Already have enough data */
                        janet_schedule(fiber, janet_wrap_buffer(state->user_buf));
                        fiber->ev_state = NULL;
                        janet_async_end(fiber);
                        return;
                    }
                } else {
                    capacity = state->bytes_requested - state->user_buf->count;
                    if (capacity <= 0) {
                        capacity = 65536; /* Read in 64KB chunks if no limit */
                    }
                }

                janet_buffer_ensure(state->user_buf, state->user_buf->count + capacity,
                                    2);

                int ret = SSL_read(
                              tls->ssl, state->user_buf->data + state->user_buf->count, capacity);
                if (ret > 0) {
                    state->user_buf->count += ret;
                    /* Return successfully read data */
                    janet_schedule(fiber, janet_wrap_buffer(state->user_buf));
                    fiber->ev_state = NULL;
                    janet_async_end(fiber);
                    return;
                } else {
                    /* Check if there's a real error vs just EOF */
                    int ssl_err = SSL_get_error(tls->ssl, ret);
                    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                        /* Clean shutdown - return what we have or nil */
                        Janet result = (state->user_buf->count > 0)
                                       ? janet_wrap_buffer(state->user_buf)
                                       : janet_wrap_nil();
                        janet_schedule(fiber, result);
                        fiber->ev_state = NULL;
                        janet_async_end(fiber);
                        return;
                    } else if (ssl_err == SSL_ERROR_SYSCALL &&
                               (errno == 0 || errno == ECONNRESET)) {
                        /* Connection reset - return what we have or nil */
                        Janet result = (state->user_buf->count > 0)
                                       ? janet_wrap_buffer(state->user_buf)
                                       : janet_wrap_nil();
                        janet_schedule(fiber, result);
                        fiber->ev_state = NULL;
                        janet_async_end(fiber);
                        return;
                    } else if (ssl_err == SSL_ERROR_SSL) {
                        /* TLS protocol error - propagate as error */
                        janet_cancel(fiber, janet_cstringv(get_ssl_error_string()));
                        fiber->ev_state = NULL;
                        janet_async_end(fiber);
                        return;
                    } else if (state->user_buf->count > 0) {
                        /* Some data was read before error - return it */
                        janet_schedule(fiber, janet_wrap_buffer(state->user_buf));
                        fiber->ev_state = NULL;
                        janet_async_end(fiber);
                        return;
                    }
                    /* No data and error - fall through to connection closed */
                }
            }
            /* Fall through for non-read operations or read failures */
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((fallthrough));
#endif
        case JANET_ASYNC_EVENT_CLOSE:
        case JANET_ASYNC_EVENT_ERR:
            /* Connection closed or error */
            if (state) {
                janet_cancel(fiber, janet_cstringv("Connection closed"));
                fiber->ev_state = NULL;
                janet_async_end(fiber);
            }
            break;

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
