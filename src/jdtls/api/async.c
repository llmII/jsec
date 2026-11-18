/*
 * client/async.c - Async callbacks for DTLS client operations
 *
 * Handles async state machine for handshake, read, write, and close.
 */

#include "../internal.h"
#include <string.h>

/*
 * =============================================================================
 * Async Callbacks for Client Operations
 * =============================================================================
 */



/*
 * Helper: Flush wbio - use shared helper from internal.h
 * This wrapper maintains the local function name for minimal diff in callers.
 */
#define dtls_client_flush_wbio(client) dtls_client_flush_wbio_to_peer(client)

/* Flight-timer flush: a retransmitted flight in wbio goes out to the
 * peer over the client's transport (no-op on the Unix dgram-BIO path,
 * where DTLSv1_handle_timeout writes the socket directly). */
static void dtls_client_flight_flush(void *owner, JanetStream *transport) {
    (void)transport;
    dtls_client_flush_wbio_to_peer((DTLSClient *)owner);
}

static int dtls_client_cancel_socket_error(JanetFiber *fiber,
                                           DTLSClientAsyncState *state,
                                           int only_if_pending) {
    char msg[JSEC_IO_ERROR_BUFSIZE];
    int has_err = jutils_format_socket_error(msg, sizeof(msg), "DTLS:IO",
                                             fiber->ev_stream);
    if (only_if_pending && !has_err) {
        return 0;
    }
    if (state && state->client) {
        state->client->state = DTLS_STATE_ERROR;
    }
    janet_cancel(fiber, janet_cstringv(msg));
    janet_async_end(fiber);
    return 1;
}

void dtls_client_async_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    DTLSClientAsyncState *state = (DTLSClientAsyncState *)fiber->ev_state;

    /* State may be NULL after mode switch (it was stolen) */
    if (!state && event != JANET_ASYNC_EVENT_DEINIT) {
        return;
    }

    switch (event) {
        case JANET_ASYNC_EVENT_INIT:
#ifdef JANET_WINDOWS
            /* Windows IOCP with memory BIOs:
             * - If want_write: Flush wbio via WSASendTo, then wait for recv
             * - Else: Start WSARecvFrom to receive UDP datagram into recv_buf
             */
            if (state && state->client && state->client->transport) {
                DTLSClient *client = state->client;
                JanetStream *stream = client->transport;

                /* First flush any pending wbio data */
                dtls_client_flush_wbio(client);

                /* Now start async receive */
                memset(&state->overlapped, 0, sizeof(WSAOVERLAPPED));
                state->wsa_flags = 0;
                state->bytes_received = 0;
                state->wsa_buf.buf = (char *)state->recv_buf;
                state->wsa_buf.len = sizeof(state->recv_buf);

                int status =
                    WSARecv((SOCKET)stream->handle, &state->wsa_buf, 1,
                            &state->bytes_received, &state->wsa_flags,
                            &state->overlapped, NULL);

                if (status == SOCKET_ERROR &&
                    WSAGetLastError() != WSA_IO_PENDING) {
                    janet_cancel(fiber, janet_cstringv("WSARecv failed"));
                    janet_async_end(fiber);
                    return;
                }
                janet_async_in_flight(fiber);
            }
            break;
#else
            /* Unix: Flush any pending wbio data (e.g., ClientHello) before
             * waiting for READ events */
            if (state && state->client) {
                dtls_client_flush_wbio(state->client);
            }
            break;
#endif
        case JANET_ASYNC_EVENT_DEINIT:
            /* Real teardown (state was not stolen for a mode switch):
             * retire the handshake flight timer with the registration. */
            if (state) {
                dtls_flight_timer_disarm(&state->client->flight_timer, 0);
            }
            break;

        case JANET_ASYNC_EVENT_MARK:
            if (state) {
                janet_mark(janet_wrap_abstract(state->client));
                if (state->buffer) {
                    janet_mark(janet_wrap_buffer(state->buffer));
                }
                if (state->op == CLIENT_OP_WRITE) {
                    janet_mark(state->write_src);
                }
            }
            break;

        case JANET_ASYNC_EVENT_CLOSE:
        case JANET_ASYNC_EVENT_HUP:
            /* On HUP, inspect SO_ERROR first so a transport error (e.g.
             * ECONNREFUSED/ECONNRESET on kqueue/poll) surfaces under
             * [DTLS:IO] rather than resolving nil as clean EOF. */
            if (event == JANET_ASYNC_EVENT_HUP &&
                dtls_client_cancel_socket_error(fiber, state, 1)) {
                return;
            }
            /* A parked dtls/read is a reader: a local close schedules nil
             * for it (core ev.c:2473-2476) instead of cancelling it.
             * Write- and handshake-class operations are cancelled with
             * the handle-specialized message. */
            if (state && state->op == CLIENT_OP_READ) {
                janet_schedule(fiber, janet_wrap_nil());
            } else {
                janet_cancel(
                    fiber, janet_cstringv("[DTLS:IO] DTLS client is closed"));
            }
            janet_async_end(fiber);
            return;

        case JANET_ASYNC_EVENT_ERR:
            /* A genuine socket error raises under the DTLS category with
             * the OS reason - never nil, never a hardcoded string. */
            dtls_client_cancel_socket_error(fiber, state, 0);
            return;

#ifdef JANET_WINDOWS
        case JANET_ASYNC_EVENT_COMPLETE:
        case JANET_ASYNC_EVENT_FAILED: {
            /* Windows IOCP: Receive completed with actual data - write to
             * rbio */
            DTLSClient *client = state->client;
            DWORD bytes_transferred;
            DWORD flags;
            BOOL success = WSAGetOverlappedResult(
                (SOCKET)client->transport->handle, &state->overlapped,
                &bytes_transferred, FALSE, &flags);

            if (!success || bytes_transferred == 0) {
                /* No data received - start another receive */
                memset(&state->overlapped, 0, sizeof(WSAOVERLAPPED));
                state->wsa_flags = 0;
                state->bytes_received = 0;
                state->wsa_buf.buf = (char *)state->recv_buf;
                state->wsa_buf.len = sizeof(state->recv_buf);

                int status =
                    WSARecv((SOCKET)client->transport->handle,
                            &state->wsa_buf, 1, &state->bytes_received,
                            &state->wsa_flags, &state->overlapped, NULL);
                if (status == SOCKET_ERROR &&
                    WSAGetLastError() != WSA_IO_PENDING) {
                    janet_cancel(fiber,
                                 janet_cstringv("WSARecv restart failed"));
                    janet_async_end(fiber);
                    return;
                }
                janet_async_in_flight(fiber);
                return;
            }

            /* Write received UDP data to rbio for SSL to process */
            BIO_write(client->rbio, state->recv_buf, (int)bytes_transferred);

            /* Fall through to process SSL operation */
        }
#endif
        case JANET_ASYNC_EVENT_READ:
        case JANET_ASYNC_EVENT_WRITE: {
            DTLSClient *client = state->client;

            DTLSResult result = DTLS_RESULT_ERROR;
            Janet retval = janet_wrap_nil();
            int32_t nwritten = 0;
            int sock_err = 0;
            int close_transport = 0;
            const char *op_name = "DTLS";

            switch (state->op) {
                case CLIENT_OP_HANDSHAKE:
                    op_name = "Handshake";
                    result = dtls_do_handshake_ex(client->ssl, &sock_err);
                    if (result == DTLS_RESULT_OK) {
                        client->state = DTLS_STATE_ESTABLISHED;
                        /* Record handshake completion time if tracking
                         * enabled */
                        if (client->flags & JDTLS_CLIENT_TRACK_HANDSHAKE) {
                            clock_gettime(CLOCK_MONOTONIC,
                                          &client->ts_handshake);
                        }
                        retval = janet_wrap_abstract(client);
                    }
                    break;

                case CLIENT_OP_READ: {
                    op_name = "Read";
                    int32_t before = state->buffer->count;
                    int32_t remaining =
                        state->nbytes -
                        (state->buffer->count - state->buf_start);
                    if (remaining <= 0) {
                        /* Nothing left to request: complete with the
                         * buffer and never issue SSL_read(..., 0),
                         * which would read as EOF. */
                        retval = janet_wrap_buffer(state->buffer);
                        result = DTLS_RESULT_OK;
                        break;
                    }
                    result = dtls_do_read_ex(client->ssl, state->buffer,
                                             remaining, &sock_err);
                    if (result == DTLS_RESULT_UNEXPECTED_EOF) {
                        /* A truncation raises below - it must never
                         * look like a clean end of data */
                    } else {
                        if (state->buffer->count > before) {
                            /* For datagrams, return after first
                             * successful read */
                            retval = janet_wrap_buffer(state->buffer);
                            result = DTLS_RESULT_OK;
                        }
                        if (result == DTLS_RESULT_EOF) {
                            /* Clean EOF: what this call appended or nil */
                            retval = state->buffer->count > state->buf_start
                                         ? janet_wrap_buffer(state->buffer)
                                         : janet_wrap_nil();
                            result = DTLS_RESULT_OK;
                        }
                    }
                    break;
                }

                case CLIENT_OP_WRITE: {
                    op_name = "Write";
                    JanetByteView view =
                        janet_getbytes(&state->write_src, 0);
                    if (view.len != state->write_len) {
                        janet_cancel(
                            fiber, janet_cstringv(
                                       "write source changed during write"));
                        janet_async_end(fiber);
                        return;
                    }
                    result = dtls_do_write_ex(client->ssl, view.bytes,
                                              view.len, &nwritten, &sock_err);
                    if (result == DTLS_RESULT_OK) {
                        retval = janet_wrap_nil();
                    }
                    break;
                }

                case CLIENT_OP_CLOSE:
                    op_name = "Shutdown";
                    result = dtls_do_shutdown_ex(client->ssl, &sock_err);
                    if (result == DTLS_RESULT_OK ||
                        result == DTLS_RESULT_EOF ||
                        result == DTLS_RESULT_UNEXPECTED_EOF) {
                        client->flags |= JDTLS_CLIENT_CLOSED;
                        client->state = DTLS_STATE_CLOSED;
                        /* The transport close is deferred past the
                         * completion below: closing it here let its
                         * close event reach this still-registered
                         * listener and cancel the completing fiber
                         * with "stream error" */
                        close_transport = 1;
                        retval = janet_wrap_nil();
                        result = DTLS_RESULT_OK;
                    }
                    break;
            }

            /* Flush any data SSL wrote to wbio - handshake responses, etc */
            dtls_client_flush_wbio(client);

            /* Handle result */
            switch (result) {
                case DTLS_RESULT_OK: {
                    JanetStream *transport = client->transport;
                    janet_schedule(fiber, retval);
                    janet_async_end(fiber);
                    if (close_transport && transport) {
                        janet_stream_close(transport);
                    }
                    break;
                }

                case DTLS_RESULT_WANT_READ: {
                    /* Need to switch async modes - end current, start new */
                    DTLSClientAsyncState *saved = state;
                    saved->want_write = 0; /* Update for next INIT */
                    fiber->ev_state = NULL;
                    janet_async_end(fiber);
                    janet_async_start_fiber(
                        fiber, client->transport, JANET_ASYNC_LISTEN_READ,
                        dtls_client_async_callback, saved);
                    /* Handshake pending on WANT_READ: arm the DTLS
                     * flight timer so a lost flight is retransmitted
                     * even when no peer datagram arrives. */
                    if (state->op == CLIENT_OP_HANDSHAKE) {
                        dtls_flight_timer_arm(&client->flight_timer,
                                              client->ssl, client,
                                              client->transport,
                                              dtls_client_flight_flush);
                    }
                    break;
                }

                case DTLS_RESULT_WANT_WRITE: {
                    DTLSClientAsyncState *saved = state;
                    saved->want_write = 1; /* Update for next INIT */
                    fiber->ev_state = NULL;
                    janet_async_end(fiber);
                    janet_async_start_fiber(
                        fiber, client->transport, JANET_ASYNC_LISTEN_WRITE,
                        dtls_client_async_callback, saved);
                    break;
                }

                case DTLS_RESULT_EOF:
                    client->state = DTLS_STATE_CLOSED;
                    if (state->op == CLIENT_OP_WRITE) {
                        /* Peer closed with the write's bytes unwritten:
                         * fail the write like tls/write and Janet's
                         * ev/write / net/write instead of completing
                         * nil */
                        char msg[256];
                        snprintf(msg, sizeof(msg),
                                 "[DTLS:IO] Write error: connection closed "
                                 "with %d of %d bytes unwritten",
                                 (int)(state->write_len - nwritten),
                                 (int)state->write_len);
                        janet_cancel(fiber, janet_cstringv(msg));
                        janet_async_end(fiber);
                    } else {
                        janet_schedule(fiber, janet_wrap_nil());
                        janet_async_end(fiber);
                    }
                    break;

                case DTLS_RESULT_UNEXPECTED_EOF:
                    if (state->op == CLIENT_OP_WRITE) {
                        /* Peer closed without close_notify and the
                         * write's bytes are unwritten: the write fails
                         * like tls/write and Janet's ev/write /
                         * net/write - read surfaces own the truncation
                         * raise */
                        client->state = DTLS_STATE_CLOSED;
                        char msg[256];
                        snprintf(msg, sizeof(msg),
                                 "[DTLS:IO] Write error: connection closed "
                                 "with %d of %d bytes unwritten",
                                 (int)(state->write_len - nwritten),
                                 (int)state->write_len);
                        janet_cancel(fiber, janet_cstringv(msg));
                        janet_async_end(fiber);
                    } else {
                        /* A truncation raises the one documented error -
                         * it must never look like a clean end of data */
                        client->state = DTLS_STATE_ERROR;
                        janet_cancel(fiber,
                                     janet_cstringv(JSEC_UNEXPECTED_EOF_ERROR));
                        janet_async_end(fiber);
                    }
                    break;

                case DTLS_RESULT_ERROR: {
                    char buf[JSEC_IO_ERROR_BUFSIZE];
                    dtls_format_io_error(buf, sizeof(buf), op_name, sock_err,
                                         fiber->ev_stream);
                    client->state = DTLS_STATE_ERROR;
                    janet_cancel(fiber, janet_cstringv(buf));
                    janet_async_end(fiber);
                    break;
                }
            }
            break;
        }

        default:
            break;
    }
}

/*
 * Internal: Start handshake, returns true if completed synchronously.
 * If returns false, async operation was started and caller should return nil.
 */
int dtls_client_start_handshake(DTLSClient *client) {
    client->state = DTLS_STATE_HANDSHAKING;

    /* Initial attempt */
    DTLSResult result = dtls_do_handshake(client->ssl);
    if (result == DTLS_RESULT_OK) {
        client->state = DTLS_STATE_ESTABLISHED;
        /* Record handshake completion time if tracking enabled */
        if (client->flags & JDTLS_CLIENT_TRACK_HANDSHAKE) {
            clock_gettime(CLOCK_MONOTONIC, &client->ts_handshake);
        }
        return 1; /* Completed synchronously */
    }

    if (result == DTLS_RESULT_ERROR ||
        result == DTLS_RESULT_UNEXPECTED_EOF) {
        client->state = DTLS_STATE_ERROR;
        dtls_panic_ssl("DTLS handshake failed");
    }

    /* Need to wait - start async */
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    if (!state) {
        dtls_panic_io("out of memory");
    }
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->op = CLIENT_OP_HANDSHAKE;
    state->want_write = (result == DTLS_RESULT_WANT_WRITE) ? 1 : 0;

    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    /* Handshake pending on WANT_READ: arm the DTLS flight timer so a
     * lost flight is retransmitted even when no peer datagram arrives. */
    if (result == DTLS_RESULT_WANT_READ) {
        dtls_flight_timer_arm(&client->flight_timer, client->ssl, client,
                              client->transport, dtls_client_flight_flush);
    }
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
    return 0; /* Async started, caller should return nil */
}

/* Helper to create and start async read */
void dtls_client_start_async_read(DTLSClient *client, JanetBuffer *buf,
                                  int32_t nbytes, int32_t buf_start,
                                  int mode, double timeout) {
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    if (!state) {
        dtls_panic_io("out of memory");
    }
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->buffer = buf;
    state->nbytes = nbytes;
    state->buf_start = buf_start;
    state->op = CLIENT_OP_READ;
    state->want_write = (mode == JANET_ASYNC_LISTEN_WRITE) ? 1 : 0;
    /* Arm once here, at initial suspension: the deadline is absolute
     * from the call, so the WANT_READ/WANT_WRITE mode-switches in the
     * callback must not re-arm it. */
    if (timeout >= 0) {
        janet_addtimeout(timeout);
    }
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
}

/* Helper to create and start async write */
void dtls_client_start_async_write(DTLSClient *client, Janet src, int mode,
                                   double timeout) {
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    if (!state) {
        dtls_panic_io("out of memory");
    }
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->write_src = src;
    state->write_len = janet_getbytes(&state->write_src, 0).len;
    state->op = CLIENT_OP_WRITE;
    state->want_write = (mode == JANET_ASYNC_LISTEN_WRITE) ? 1 : 0;
    /* Arm once here, at initial suspension: the deadline is absolute
     * from the call, so the WANT_READ/WANT_WRITE mode-switches in the
     * callback must not re-arm it. */
    if (timeout >= 0) {
        janet_addtimeout(timeout);
    }
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
}

/* Helper to create and start async close */
void dtls_client_start_async_close(DTLSClient *client, int mode) {
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    if (!state) {
        dtls_panic_io("out of memory");
    }
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->op = CLIENT_OP_CLOSE;
    state->want_write = (mode == JANET_ASYNC_LISTEN_WRITE) ? 1 : 0;
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
}
