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

typedef struct {
#ifdef JANET_WINDOWS
    /* Windows IOCP: WSAOVERLAPPED MUST be first field for pointer matching */
    WSAOVERLAPPED overlapped;
    WSABUF wsa_buf;
    DWORD wsa_flags;
    uint8_t recv_buf[65536]; /* Buffer for WSARecvFrom - max UDP datagram */
    DWORD bytes_received;
#endif
    DTLSClient *client;
    JanetBuffer *buffer;      /* For read */
    JanetByteView write_data; /* For write */
    int32_t nbytes;           /* For read */
    enum {
        CLIENT_OP_HANDSHAKE,
        CLIENT_OP_READ,
        CLIENT_OP_WRITE,
        CLIENT_OP_CLOSE
    } op;
    int want_write; /* Track if we're waiting for write vs read */
} DTLSClientAsyncState;

/*
 * Helper: Flush any pending data from wbio to the socket via sendto
 * Returns bytes sent, 0 if nothing to send, or -1 on error.
 */
static ssize_t dtls_client_flush_wbio(DTLSClient *client) {
    /* When using dgram BIO (Unix), wbio is NULL - dgram handles I/O directly
     */
    if (!client->wbio) {
        return 0;
    }

    size_t pending = BIO_ctrl_pending(client->wbio);
    if (pending == 0) {
        return 0;
    }

    uint8_t *buf = janet_malloc(pending);
    if (!buf) {
        return -1;
    }

    int n = BIO_read(client->wbio, buf, (int)pending);
    ssize_t sent = 0;

    if (n > 0) {
        sent = sendto((jsec_socket_t)client->transport->handle,
                      (const char *)buf, (size_t)n, 0,
                      (struct sockaddr *)&client->peer_addr.addr,
                      client->peer_addr.addrlen);
    }

    janet_free(buf);
    return sent;
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
                    fiber->ev_state = NULL;
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
            /* Nothing to do */
            break;

        case JANET_ASYNC_EVENT_MARK:
            if (state) {
                janet_mark(janet_wrap_abstract(state->client));
                if (state->buffer) {
                    janet_mark(janet_wrap_buffer(state->buffer));
                }
            }
            break;

        case JANET_ASYNC_EVENT_CLOSE:
        case JANET_ASYNC_EVENT_ERR:
        case JANET_ASYNC_EVENT_HUP:
            if (state && state->client) {
                state->client->state = DTLS_STATE_ERROR;
            }
            janet_cancel(fiber, janet_cstringv("stream error"));
            janet_async_end(fiber);
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

            switch (state->op) {
                case CLIENT_OP_HANDSHAKE:
                    result = dtls_do_handshake(client->ssl);
                    if (result == DTLS_RESULT_OK) {
                        client->state = DTLS_STATE_ESTABLISHED;
                        /* Record handshake completion time if tracking
                         * enabled */
                        if (client->track_handshake_time) {
                            clock_gettime(CLOCK_MONOTONIC,
                                          &client->ts_handshake);
                        }
                        retval = janet_wrap_abstract(client);
                    }
                    break;

                case CLIENT_OP_READ: {
                    int32_t nread = 0;
                    result = dtls_do_read(
                        client->ssl,
                        state->buffer->data + state->buffer->count,
                        state->nbytes - state->buffer->count, &nread);
                    if (nread > 0) {
                        state->buffer->count += nread;
                        /* For datagrams, return after first successful read
                         */
                        retval = janet_wrap_buffer(state->buffer);
                        result = DTLS_RESULT_OK;
                    }
                    if (result == DTLS_RESULT_EOF) {
                        /* Return what we have or nil */
                        retval = state->buffer->count > 0
                                     ? janet_wrap_buffer(state->buffer)
                                     : janet_wrap_nil();
                        result = DTLS_RESULT_OK;
                    }
                    break;
                }

                case CLIENT_OP_WRITE: {
                    int32_t nwritten = 0;
                    result =
                        dtls_do_write(client->ssl, state->write_data.bytes,
                                      state->write_data.len, &nwritten);
                    if (result == DTLS_RESULT_OK) {
                        retval = janet_wrap_integer(nwritten);
                    }
                    break;
                }

                case CLIENT_OP_CLOSE:
                    result = dtls_do_shutdown(client->ssl);
                    if (result == DTLS_RESULT_OK ||
                        result == DTLS_RESULT_EOF) {
                        client->closed = 1;
                        client->state = DTLS_STATE_CLOSED;
                        /* Close transport after successful shutdown */
                        if (client->transport) {
                            janet_stream_close(client->transport);
                        }
                        retval = janet_wrap_nil();
                        result = DTLS_RESULT_OK;
                    }
                    break;
            }

            /* Flush any data SSL wrote to wbio - handshake responses, etc */
            dtls_client_flush_wbio(client);

            /* Handle result */
            switch (result) {
                case DTLS_RESULT_OK:
                    janet_schedule(fiber, retval);
                    janet_async_end(fiber);
                    break;

                case DTLS_RESULT_WANT_READ: {
                    /* Need to switch async modes - end current, start new */
                    DTLSClientAsyncState *saved = state;
                    saved->want_write = 0; /* Update for next INIT */
                    fiber->ev_state = NULL;
                    janet_async_end(fiber);
                    janet_async_start_fiber(
                        fiber, client->transport, JANET_ASYNC_LISTEN_READ,
                        dtls_client_async_callback, saved);
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
                    janet_schedule(fiber, janet_wrap_nil());
                    janet_async_end(fiber);
                    break;

                case DTLS_RESULT_ERROR: {
                    char buf[256];
                    unsigned long err = ERR_get_error();
                    if (err) {
                        ERR_error_string_n(err, buf, sizeof(buf));
                    } else {
                        snprintf(buf, sizeof(buf), "SSL error");
                    }
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
        if (client->track_handshake_time) {
            clock_gettime(CLOCK_MONOTONIC, &client->ts_handshake);
        }
        return 1; /* Completed synchronously */
    }

    if (result == DTLS_RESULT_ERROR) {
        client->state = DTLS_STATE_ERROR;
        dtls_panic_ssl("DTLS handshake failed");
    }

    /* Need to wait - start async */
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->op = CLIENT_OP_HANDSHAKE;
    state->want_write = (result == DTLS_RESULT_WANT_WRITE) ? 1 : 0;

    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
    return 0; /* Async started, caller should return nil */
}

/* Helper to create and start async read */
void dtls_client_start_async_read(DTLSClient *client, JanetBuffer *buf,
                                  int32_t nbytes, int mode) {
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->buffer = buf;
    state->nbytes = nbytes;
    state->op = CLIENT_OP_READ;
    state->want_write = (mode == JANET_ASYNC_LISTEN_WRITE) ? 1 : 0;
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
}

/* Helper to create and start async write */
void dtls_client_start_async_write(DTLSClient *client, JanetByteView data,
                                   int mode) {
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->write_data = data;
    state->op = CLIENT_OP_WRITE;
    state->want_write = (mode == JANET_ASYNC_LISTEN_WRITE) ? 1 : 0;
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
}

/* Helper to create and start async close */
void dtls_client_start_async_close(DTLSClient *client, int mode) {
    DTLSClientAsyncState *state = janet_malloc(sizeof(DTLSClientAsyncState));
    memset(state, 0, sizeof(DTLSClientAsyncState));
    state->client = client;
    state->op = CLIENT_OP_CLOSE;
    state->want_write = (mode == JANET_ASYNC_LISTEN_WRITE) ? 1 : 0;
    janet_async_start(client->transport, mode, dtls_client_async_callback,
                      state);
}
