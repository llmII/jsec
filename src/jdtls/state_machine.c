/*
 * state_machine.c - DTLS async I/O state machine
 *
 * This module implements the async I/O state machine for DTLS.
 * It integrates with Janet's event loop via janet_async_start.
 *
 * DTLS State Machine Flow
 * =======================
 *
 * Unlike TLS which uses a stream socket, DTLS uses datagrams.
 * The state machine handles:
 * 1. Handshake (with retransmission timeouts)
 * 2. Data read/write
 * 3. Shutdown
 *
 * Memory BIO Architecture
 * =======================
 * For the server, we use memory BIOs to decouple SSL from the socket:
 *
 *   Network        rbio (mem)        SSL        wbio (mem)        Network
 *   recvfrom() --> BIO_write() --> SSL_read()
 *                                  SSL_write() --> BIO_read() --> sendto()
 *
 * This allows us to:
 * 1. Demultiplex packets by peer address
 * 2. Route data to correct session
 * 3. Handle timeouts and retransmissions
 *
 * For the client with a connected socket, we can use a dgram BIO directly.
 *
 * Timeout Handling
 * ================
 * DTLS has built-in retransmission:
 * - DTLSv1_get_timeout() returns time until next retransmission
 * - DTLSv1_handle_timeout() triggers retransmission
 * We integrate this with Janet's ev/deadline or manual timeout tracking.
 */

#include "internal.h"
#include <errno.h>

/*
 * =============================================================================
 * SSL Result Translation
 * =============================================================================
 */

DTLSResult dtls_ssl_result(SSL *ssl, int ret) {
    if (ret > 0) {
        return DTLS_RESULT_OK;
    }

    int err = SSL_get_error(ssl, ret);
    switch (err) {
        case SSL_ERROR_NONE:
            return DTLS_RESULT_OK;

        case SSL_ERROR_WANT_READ:
            return DTLS_RESULT_WANT_READ;

        case SSL_ERROR_WANT_WRITE:
            return DTLS_RESULT_WANT_WRITE;

        case SSL_ERROR_ZERO_RETURN:
            /* Peer sent close_notify */
            return DTLS_RESULT_EOF;

        case SSL_ERROR_SYSCALL:
            if (ret == 0) {
                /* EOF without close_notify */
                return DTLS_RESULT_EOF;
            }
            /* Fall through to error */
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((fallthrough));
#endif

        case SSL_ERROR_SSL:
        default:
            return DTLS_RESULT_ERROR;
    }
}

/*
 * =============================================================================
 * Basic SSL Operations
 * =============================================================================
 */

DTLSResult dtls_do_handshake(SSL *ssl) {
    int ret = SSL_do_handshake(ssl);
    if (ret == 1) {
        return DTLS_RESULT_OK;
    }
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_read(SSL *ssl, uint8_t *buf, int32_t len,
                        int32_t *out_len) {
    int ret = SSL_read(ssl, buf, len);
    if (ret > 0) {
        *out_len = ret;
        return DTLS_RESULT_OK;
    }
    *out_len = 0;
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_write(SSL *ssl, const uint8_t *buf, int32_t len,
                         int32_t *out_len) {
    int ret = SSL_write(ssl, buf, len);
    if (ret > 0) {
        *out_len = ret;
        return DTLS_RESULT_OK;
    }
    *out_len = 0;
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_shutdown(SSL *ssl) {
    int ret = SSL_shutdown(ssl);
    if (ret == 1) {
        /* Bidirectional shutdown complete */
        return DTLS_RESULT_OK;
    }
    if (ret == 0) {
        /* Sent close_notify, waiting for peer's */
        return DTLS_RESULT_WANT_READ;
    }
    return dtls_ssl_result(ssl, ret);
}

/*
 * =============================================================================
 * Cookie Generation and Verification (DoS Protection)
 * =============================================================================
 *
 * DTLS cookie exchange prevents amplification attacks:
 * 1. Server receives ClientHello
 * 2. Server sends HelloVerifyRequest with cookie
 * 3. Client resends ClientHello with cookie
 * 4. Server verifies cookie, proceeds with handshake
 *
 * Only step 4 allocates full SSL state, preventing resource exhaustion.
 */

/* Secret key for cookie generation (initialized once) */
static uint8_t cookie_secret[32];
static int cookie_secret_initialized = 0;

static void init_cookie_secret(void) {
    if (!cookie_secret_initialized) {
        RAND_bytes(cookie_secret, sizeof(cookie_secret));
        cookie_secret_initialized = 1;
    }
}

/*
 * Generate cookie for DTLS handshake.
 * Called by OpenSSL during HelloVerifyRequest.
 */
int dtls_generate_cookie(SSL *ssl, unsigned char *cookie,
                         unsigned int *cookie_len) {
    init_cookie_secret();

    /* Get peer address from BIO */
    BIO *bio = SSL_get_rbio(ssl);
    if (!bio) {
        return 0;
    }

    /* For dgram BIO, get peer address */
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } peer;

    /* BIO_dgram_get_peer returns address for dgram BIO */
    if (BIO_dgram_get_peer(bio, &peer) <= 0) {
        /* For memory BIO, we can't get peer this way.
         * The session should have stored the peer address. */
        *cookie_len = 0;
        return 0;
    }

    /* Hash: HMAC(secret, peer_address) */
    unsigned int len = 0;
    HMAC(EVP_sha256(), cookie_secret, sizeof(cookie_secret),
         (const unsigned char *)&peer, sizeof(peer), cookie, &len);

    *cookie_len = len;
    return 1;
}

/*
 * Verify cookie from client.
 * Called by OpenSSL during handshake.
 */
int dtls_verify_cookie(SSL *ssl, const unsigned char *cookie,
                       unsigned int cookie_len) {
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len;

    if (dtls_generate_cookie(ssl, expected, &expected_len) == 0) {
        return 0;
    }

    if (cookie_len != expected_len) {
        return 0;
    }

    /* Constant-time comparison */
    return CRYPTO_memcmp(cookie, expected, cookie_len) == 0;
}

/*
 * =============================================================================
 * Async Callback for Janet Event Loop
 * =============================================================================
 *
 * This callback is invoked by Janet's event loop when:
 * - The socket becomes readable (JANET_ASYNC_EVENT_READ)
 * - The socket becomes writable (JANET_ASYNC_EVENT_WRITE)
 * - An error occurs (JANET_ASYNC_EVENT_ERR)
 * - The stream is closed (JANET_ASYNC_EVENT_CLOSE)
 *
 * The callback continues the DTLS operation and either:
 * - Completes successfully (janet_schedule with result)
 * - Fails (janet_cancel with error)
 * - Continues waiting (janet_async_start again)
 */

typedef struct {
    DTLSAsyncState state;
    SSL *ssl;
    JanetStream *transport;
    DTLSState *dtls_state; /* Pointer to update session/client state */
    int is_server;         /* Server uses memory BIO */
    DTLSSession *session;  /* For server: the session being operated on */
    void *owner;           /* DTLSServer or DTLSClient */
} DTLSAsyncData;

static void dtls_async_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    DTLSAsyncData *data = (DTLSAsyncData *)fiber->ev_state;

    switch (event) {
        case JANET_ASYNC_EVENT_INIT:
            /* Nothing to do on init */
            break;

        case JANET_ASYNC_EVENT_MARK:
            /* Mark Janet values we reference */
            if (data->transport) {
                janet_mark(janet_wrap_abstract(data->transport));
            }
            if (data->state.buffer) {
                janet_mark(janet_wrap_buffer(data->state.buffer));
            }
            if (data->owner) {
                janet_mark(janet_wrap_abstract(data->owner));
            }
            break;

        case JANET_ASYNC_EVENT_DEINIT:
            /* Cleanup - state was janet_malloc'd */
            break;

        case JANET_ASYNC_EVENT_CLOSE:
            janet_cancel(fiber, janet_cstringv("stream closed"));
            janet_async_end(fiber);
            break;

        case JANET_ASYNC_EVENT_ERR:
        case JANET_ASYNC_EVENT_HUP:
            janet_cancel(fiber, janet_cstringv("stream error"));
            janet_async_end(fiber);
            break;

        case JANET_ASYNC_EVENT_READ:
        case JANET_ASYNC_EVENT_WRITE: {
            DTLSResult result;
            Janet retval = janet_wrap_nil();

            switch (data->state.op) {
                case DTLS_OP_HANDSHAKE:
                    result = dtls_do_handshake(data->ssl);
                    if (result == DTLS_RESULT_OK) {
                        if (data->dtls_state) {
                            *data->dtls_state = DTLS_STATE_ESTABLISHED;
                        }
                        retval = janet_ckeywordv("ok");
                    }
                    break;

                case DTLS_OP_READ: {
                    int32_t nread = 0;
                    result = dtls_do_read(
                        data->ssl,
                        data->state.buffer->data + data->state.buffer->count,
                        data->state.nbytes - data->state.buffer->count,
                        &nread);
                    if (nread > 0) {
                        data->state.buffer->count += nread;
                    }
                    if (result == DTLS_RESULT_OK ||
                        data->state.buffer->count > 0) {
                        /* Return what we have */
                        retval = janet_wrap_buffer(data->state.buffer);
                        result = DTLS_RESULT_OK;
                    } else if (result == DTLS_RESULT_EOF) {
                        if (data->state.buffer->count > 0) {
                            retval = janet_wrap_buffer(data->state.buffer);
                        }
                        /* EOF with no data = nil */
                    }
                    break;
                }

                case DTLS_OP_WRITE: {
                    int32_t nwritten = 0;
                    result =
                        dtls_do_write(data->ssl, data->state.write_data.bytes,
                                      data->state.write_data.len, &nwritten);
                    if (result == DTLS_RESULT_OK) {
                        retval = janet_wrap_integer(nwritten);
                    }
                    break;
                }

                case DTLS_OP_SHUTDOWN:
                    result = dtls_do_shutdown(data->ssl);
                    if (result == DTLS_RESULT_OK ||
                        result == DTLS_RESULT_EOF) {
                        if (data->dtls_state) {
                            *data->dtls_state = DTLS_STATE_CLOSED;
                        }
                        retval = janet_ckeywordv("ok");
                        result = DTLS_RESULT_OK;
                    }
                    break;

                default:
                    janet_cancel(fiber, janet_cstringv("invalid operation"));
                    janet_async_end(fiber);
                    return;
            }

            /* Handle result */
            switch (result) {
                case DTLS_RESULT_OK:
                    janet_schedule(fiber, retval);
                    janet_async_end(fiber);
                    break;

                case DTLS_RESULT_WANT_READ:
                    janet_async_start(data->transport,
                                      JANET_ASYNC_LISTEN_READ,
                                      dtls_async_callback, data);
                    break;

                case DTLS_RESULT_WANT_WRITE:
                    janet_async_start(data->transport,
                                      JANET_ASYNC_LISTEN_WRITE,
                                      dtls_async_callback, data);
                    break;

                case DTLS_RESULT_EOF:
                    if (data->dtls_state) {
                        *data->dtls_state = DTLS_STATE_CLOSED;
                    }
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
                    if (data->dtls_state) {
                        *data->dtls_state = DTLS_STATE_ERROR;
                    }
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
 * =============================================================================
 * Start Async Operation
 * =============================================================================
 * These functions initiate an async DTLS operation.
 */

/* Start async handshake */
void dtls_async_handshake(JanetStream *transport, SSL *ssl,
                          DTLSState *state_ptr, void *owner) {
    DTLSAsyncData *data = janet_malloc(sizeof(DTLSAsyncData));
    memset(data, 0, sizeof(DTLSAsyncData));

    data->state.op = DTLS_OP_HANDSHAKE;
    data->ssl = ssl;
    data->transport = transport;
    data->dtls_state = state_ptr;
    data->owner = owner;

    /* First try - might complete immediately */
    DTLSResult result = dtls_do_handshake(ssl);
    if (result == DTLS_RESULT_OK) {
        if (state_ptr) *state_ptr = DTLS_STATE_ESTABLISHED;
        janet_free(data);
        return; /* Completed synchronously */
    }

    /* Need to wait */
    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    janet_async_start(transport, mode, dtls_async_callback, data);
}

/* Start async read */
void dtls_async_read(JanetStream *transport, SSL *ssl, int32_t nbytes,
                     double timeout, void *owner) {
    DTLSAsyncData *data = janet_malloc(sizeof(DTLSAsyncData));
    memset(data, 0, sizeof(DTLSAsyncData));

    data->state.op = DTLS_OP_READ;
    data->state.buffer = janet_buffer(nbytes);
    data->state.nbytes = nbytes;
    data->state.timeout = timeout;
    data->ssl = ssl;
    data->transport = transport;
    data->owner = owner;

    /* Try initial read */
    int32_t nread = 0;
    DTLSResult result =
        dtls_do_read(ssl, data->state.buffer->data, nbytes, &nread);
    if (nread > 0) {
        data->state.buffer->count = nread;
    }

    if (result == DTLS_RESULT_OK) {
        /* Completed synchronously - still go through async machinery
         * for consistent behavior. The callback will see the completed
         * state and return the result. */
    }

    /* Wait for data */
    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    janet_async_start(transport, mode, dtls_async_callback, data);
}

/* Start async write */
void dtls_async_write(JanetStream *transport, SSL *ssl,
                      JanetByteView data_view, double timeout, void *owner) {
    DTLSAsyncData *data = janet_malloc(sizeof(DTLSAsyncData));
    memset(data, 0, sizeof(DTLSAsyncData));

    data->state.op = DTLS_OP_WRITE;
    data->state.write_data = data_view;
    data->state.timeout = timeout;
    data->ssl = ssl;
    data->transport = transport;
    data->owner = owner;

    /* Try initial write */
    int32_t nwritten = 0;
    DTLSResult result =
        dtls_do_write(ssl, data_view.bytes, data_view.len, &nwritten);

    if (result == DTLS_RESULT_OK) {
        /* Completed synchronously - still go through async machinery */
    }

    /* Wait for writable */
    int mode = (result == DTLS_RESULT_WANT_READ) ? JANET_ASYNC_LISTEN_READ
                                                 : JANET_ASYNC_LISTEN_WRITE;
    janet_async_start(transport, mode, dtls_async_callback, data);
}

/* Start async shutdown */
void dtls_async_shutdown(JanetStream *transport, SSL *ssl,
                         DTLSState *state_ptr, void *owner) {
    DTLSAsyncData *data = janet_malloc(sizeof(DTLSAsyncData));
    memset(data, 0, sizeof(DTLSAsyncData));

    data->state.op = DTLS_OP_SHUTDOWN;
    data->ssl = ssl;
    data->transport = transport;
    data->dtls_state = state_ptr;
    data->owner = owner;

    /* Try shutdown */
    DTLSResult result = dtls_do_shutdown(ssl);

    if (result == DTLS_RESULT_OK || result == DTLS_RESULT_EOF) {
        if (state_ptr) *state_ptr = DTLS_STATE_CLOSED;
        janet_free(data);
        return;
    }

    /* Wait for peer's close_notify */
    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    janet_async_start(transport, mode, dtls_async_callback, data);
}
