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

void dtls_client_async_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    DTLSClientAsyncState *state = (DTLSClientAsyncState *)fiber->ev_state;

    /* State may be NULL after mode switch (it was stolen) */
    if (!state && event != JANET_ASYNC_EVENT_DEINIT) {
        return;
    }

    switch (event) {
        case JANET_ASYNC_EVENT_INIT:
#ifdef JANET_WINDOWS
            /* Windows IOCP: Start zero-byte WSARecv/WSASend as readiness
             * probe. DTLS client socket is connected via connect(), so
             * WSARecv/WSASend should work the same as TCP. */
            if (state && state->client && state->client->transport) {
                JanetStream *stream = state->client->transport;
                memset(&state->overlapped, 0, sizeof(WSAOVERLAPPED));
                state->wsa_buf.len = 0;
                state->wsa_buf.buf = NULL;
                state->wsa_flags = 0;

                int status;
                if (state->want_write) {
                    fprintf(stderr,
                            "[DTLS] INIT: Starting zero-byte WSASend\n");
                    status = WSASend((SOCKET)stream->handle, &state->wsa_buf,
                                     1, NULL, 0, &state->overlapped, NULL);
                } else {
                    fprintf(stderr,
                            "[DTLS] INIT: Starting zero-byte WSARecv\n");
                    status = WSARecv((SOCKET)stream->handle, &state->wsa_buf,
                                     1, NULL, &state->wsa_flags,
                                     &state->overlapped, NULL);
                }
                if (status == SOCKET_ERROR &&
                    WSAGetLastError() != WSA_IO_PENDING) {
                    fprintf(stderr, "[DTLS] INIT: WSA error %d\n",
                            WSAGetLastError());
                    janet_cancel(fiber, janet_cstringv("Socket I/O error"));
                    fiber->ev_state = NULL;
                    janet_async_end(fiber);
                    return;
                }
                fprintf(stderr, "[DTLS] INIT: WSA_IO_PENDING, calling "
                                "janet_async_in_flight\n");
                janet_async_in_flight(fiber);
            }
            break;
#else
            /* Unix: Fall through - wait for READ/WRITE events */
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
        case JANET_ASYNC_EVENT_FAILED:
            fprintf(stderr, "[DTLS] COMPLETE/FAILED: event=%d\n", event);
            /* Windows IOCP: Zero-byte probe completed, fall through to
             * READ/WRITE handling */
#endif
        case JANET_ASYNC_EVENT_READ:
        case JANET_ASYNC_EVENT_WRITE: {
            fprintf(stderr, "[DTLS] READ/WRITE handler: op=%d\n", state->op);
            DTLSClient *client = state->client;
            DTLSResult result = DTLS_RESULT_ERROR;
            Janet retval = janet_wrap_nil();

            switch (state->op) {
                case CLIENT_OP_HANDSHAKE:
                    fprintf(stderr, "[DTLS] Calling dtls_do_handshake\n");
                    result = dtls_do_handshake(client->ssl);
                    fprintf(stderr, "[DTLS] dtls_do_handshake returned %d\n",
                            result);
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
