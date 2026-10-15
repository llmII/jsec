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
 * DTLS has built-in retransmission: DTLSv1_get_timeout() returns time
 * until next retransmission, DTLSv1_handle_timeout() triggers it. DTLS
 * flight retransmission is driven by a per-handshake DTLSFlightTimer:
 * while a handshake is pending on WANT_READ, the arm schedules a
 * helper fiber on the same event-loop thread (janet_vm.tq) for the
 * exact interval DTLSv1_get_timeout returns. The wake step calls
 * DTLSv1_handle_timeout, flushes the retransmitted flight in wbio
 * when one goes out, re-arms while OpenSSL still schedules a
 * retransmission, and retires otherwise. Arms live on DTLSClient and
 * DTLSSession and are disarmed before the owner is freed; a
 * GC-finalizer disarm only marks the arm canceled and clears the
 * slot, and the wake step retires the arm when it next runs, so
 * teardown never dereferences the helper fiber after the sweep frees
 * it.
 */

#include "internal.h"
#include <errno.h>
#ifndef JANET_WINDOWS
#include <sys/time.h>
#endif

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
    ERR_clear_error();
    int ret = SSL_do_handshake(ssl);
    if (ret == 1) {
        return DTLS_RESULT_OK;
    }
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_write(SSL *ssl, const uint8_t *buf, int32_t len,
                         int32_t *out_len) {
    ERR_clear_error();
    int ret = SSL_write(ssl, buf, len);
    if (ret > 0) {
        *out_len = ret;
        return DTLS_RESULT_OK;
    }
    *out_len = 0;
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_shutdown(SSL *ssl) {
    ERR_clear_error();
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

/* Secret key for cookie generation (initialized once)
 *
 * Design Note: There are two separate cookie generators in jsec DTLS:
 *   1. dtls_generate_cookie (this file) - Used by DTLSv1_listen path
 *   2. server_generate_cookie (server.c) - Used by DTLSServer path
 *
 * Both generate cookies using HMAC(secret, peer_address) for DoS protection.
 * Separate secrets are intentional:
 *   - state_machine.c handles low-level async operations
 *   - server.c handles the DTLSServer abstraction
 *   - Each module manages its own secret lifecycle
 *
 * This is a security feature: even if one secret is compromised, the other
 * remains independent. Both secrets are generated via RAND_bytes at first
 * use.
 */
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
    memset(&peer, 0, sizeof(peer));

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
#ifdef JANET_WINDOWS
    /* Windows IOCP: WSAOVERLAPPED MUST be first field for pointer matching */
    WSAOVERLAPPED overlapped;
    WSABUF wsa_buf;
    DWORD wsa_flags;
    uint8_t recv_buf[65536]; /* Buffer for WSARecv - max UDP datagram */
    DWORD bytes_received;
#endif
    DTLSAsyncState state;
    SSL *ssl;
    JanetStream *transport;
    DTLSState *dtls_state; /* Pointer to update session/client state */
    int is_server;         /* Server uses memory BIO */
    DTLSSession *session;  /* For server: the session being operated on */
    void *owner;           /* DTLSServer or DTLSClient */
    int want_write;        /* Track if we're waiting for write vs read */
} DTLSAsyncData;

/*
 * Helper: Flush any pending data from client wbio to the socket via sendto
 * Only applies to client (is_server=0), server has its own send_dtls_packet.
 * Uses shared helper from internal.h.
 */
static ssize_t dtls_async_flush_wbio(DTLSAsyncData *data) {
    if (data->is_server || !data->owner) {
        return 0; /* Server handles its own send */
    }
    return dtls_client_flush_wbio_to_peer((DTLSClient *)data->owner);
}

static void dtls_async_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    DTLSAsyncData *data = (DTLSAsyncData *)fiber->ev_state;

    switch (event) {
        case JANET_ASYNC_EVENT_INIT:
#ifdef JANET_WINDOWS
            /* Windows IOCP with memory BIOs:
             * - First flush any pending wbio data
             * - Then start WSARecv to receive UDP datagram into recv_buf
             */
            if (data && data->transport) {
                /* Flush pending wbio data (for client) */
                dtls_async_flush_wbio(data);

                /* Start async receive */
                memset(&data->overlapped, 0, sizeof(WSAOVERLAPPED));
                data->wsa_flags = 0;
                data->bytes_received = 0;
                data->wsa_buf.buf = (char *)data->recv_buf;
                data->wsa_buf.len = sizeof(data->recv_buf);

                int status =
                    WSARecv((SOCKET)data->transport->handle, &data->wsa_buf,
                            1, &data->bytes_received, &data->wsa_flags,
                            &data->overlapped, NULL);

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
            dtls_async_flush_wbio(data);
            break;
#endif

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

#ifdef JANET_WINDOWS
        case JANET_ASYNC_EVENT_COMPLETE:
        case JANET_ASYNC_EVENT_FAILED: {
            /* Windows IOCP: Receive completed - write data to rbio for client
             */
            if (!data->is_server && data->owner) {
                DTLSClient *client = (DTLSClient *)data->owner;
                DWORD bytes_transferred;
                DWORD flags;
                BOOL success = WSAGetOverlappedResult(
                    (SOCKET)data->transport->handle, &data->overlapped,
                    &bytes_transferred, FALSE, &flags);

                if (success && bytes_transferred > 0) {
                    /* Write received UDP data to client's rbio */
                    BIO_write(client->rbio, data->recv_buf,
                              (int)bytes_transferred);
                } else {
                    /* No data - restart receive */
                    memset(&data->overlapped, 0, sizeof(WSAOVERLAPPED));
                    data->wsa_flags = 0;
                    data->bytes_received = 0;
                    data->wsa_buf.buf = (char *)data->recv_buf;
                    data->wsa_buf.len = sizeof(data->recv_buf);

                    int status =
                        WSARecv((SOCKET)data->transport->handle,
                                &data->wsa_buf, 1, &data->bytes_received,
                                &data->wsa_flags, &data->overlapped, NULL);
                    if (status == SOCKET_ERROR &&
                        WSAGetLastError() != WSA_IO_PENDING) {
                        janet_cancel(
                            fiber, janet_cstringv("WSARecv restart failed"));
                        janet_async_end(fiber);
                        return;
                    }
                    janet_async_in_flight(fiber);
                    return;
                }
            }
            /* Fall through to process SSL operation */
        }
#endif
        case JANET_ASYNC_EVENT_READ:
        case JANET_ASYNC_EVENT_WRITE: {
            /* Note: Server handled by server.c, client dgram BIO handles I/O
             * directly */

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
                    result = dtls_do_read(
                        data->ssl, data->state.buffer,
                        data->state.nbytes -
                            (data->state.buffer->count -
                             data->state.buf_start));
                    if (result == DTLS_RESULT_OK ||
                        data->state.buffer->count > data->state.buf_start) {
                        /* Return what we have */
                        retval = janet_wrap_buffer(data->state.buffer);
                        result = DTLS_RESULT_OK;
                    } else if (result == DTLS_RESULT_EOF) {
                        if (data->state.buffer->count > data->state.buf_start) {
                            retval = janet_wrap_buffer(data->state.buffer);
                        }
                        /* EOF with no data this call = nil */
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

            /* Flush any data SSL wrote to wbio (for client) */
            dtls_async_flush_wbio(data);

            /* Handle result */
            switch (result) {
                case DTLS_RESULT_OK:
                    janet_schedule(fiber, retval);
                    janet_async_end(fiber);
                    break;

                case DTLS_RESULT_WANT_READ:
                    data->want_write = 0;
                    janet_async_start(data->transport,
                                      JANET_ASYNC_LISTEN_READ,
                                      dtls_async_callback, data);
                    break;

                case DTLS_RESULT_WANT_WRITE:
                    data->want_write = 1;
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
    data->want_write = (result == DTLS_RESULT_WANT_WRITE) ? 1 : 0;
    janet_async_start(transport, mode, dtls_async_callback, data);
}

/* Start async read */
void dtls_async_read(JanetStream *transport, SSL *ssl, int32_t nbytes,
                     double timeout, void *owner) {
    DTLSAsyncData *data = janet_malloc(sizeof(DTLSAsyncData));
    memset(data, 0, sizeof(DTLSAsyncData));

    data->state.op = DTLS_OP_READ;
    data->state.buffer = janet_buffer(0);
    data->state.nbytes = nbytes;
    data->state.buf_start = data->state.buffer->count;
    data->state.timeout = timeout;
    data->ssl = ssl;
    data->transport = transport;
    data->owner = owner;

    /* Try initial read */
    DTLSResult result = dtls_do_read(ssl, data->state.buffer, nbytes);

    if (result == DTLS_RESULT_OK) {
        /* Completed synchronously - still go through async machinery
         * for consistent behavior. The callback will see the completed
         * state and return the result. */
    }

    /* Wait for data */
    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    data->want_write = (result == DTLS_RESULT_WANT_WRITE) ? 1 : 0;
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
    data->want_write = (mode == JANET_ASYNC_LISTEN_WRITE) ? 1 : 0;
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
    data->want_write = (result == DTLS_RESULT_WANT_WRITE) ? 1 : 0;
    janet_async_start(transport, mode, dtls_async_callback, data);
}

/*
 * =============================================================================
 * DTLS Flight Timer (Handshake Retransmission)
 * =============================================================================
 * The Timeout Handling note at the top of this file describes the
 * integration with DTLSv1_get_timeout() and DTLSv1_handle_timeout():
 * while a DTLS handshake is pending on SSL_ERROR_WANT_READ, query the
 * flight timer and, when it fires before a peer datagram arrives, drive
 * the retransmission and flush the flight in wbio to the UDP socket.
 *
 * Each arm runs a helper fiber on the same event-loop thread, sleeping
 * out the exact flight interval as one timeout on the event loop's
 * min-heap - no worker thread and no sleep-polling. The fiber boot
 * body is a Janet source function compiled once at module load and
 * rooted in module-level state: two calls of one step function - the
 * first step suspends on janet_sleep_await, the resume continues in
 * the body and the second step drives the retransmission tick.
 * Disarming wakes the fiber with a zero-duration schedule so it
 * retires the arm immediately; a GC
 * finalizer cannot schedule and may run after the teardown sweep has
 * freed the fiber, so that path only marks the arm canceled and lets
 * the wake step retire it. A canceled arm is released without touching
 * owner state. Retransmission ticks never touch the parked caller
 * fiber, so the caller's overall handshake deadline stays
 * janet_addtimeout's domain and keeps failing the call with "timeout"
 * exactly as before.
 */

struct DTLSFlightTimer {
    SSL *ssl;
    void *owner;
    JanetStream *transport;
    DTLSFlightFlushFn flush;
    DTLSFlightTimer **slot; /* owner's arm pointer; NULLed on retire */
    JanetFiber *fiber;      /* two-step helper fiber, one per arm */
    double seconds;         /* flight interval the fiber sleeps out */
    int phase;              /* 0: sleep step pending, 1: wake step pending */
    int canceled;
};

/* Janet core marks a fiber parked on the event loop with
 * JANET_FIBER_EV_FLAG_SUSPENDED (core fiber.h, bit 17), paired with one
 * janet_ev_inc_refcount that the resume path releases. */
#define DTLS_FIBER_EV_SUSPENDED (1 << 17)

/* Pre-marking the helper fiber with JANET_FIBER_FLAG_ROOT (core
 * fiber.h, bit 18) keeps janet_schedule_general from inserting a row
 * in the scheduler task tracking table for this internal fiber. */
#define DTLS_FIBER_EV_ROOT (1 << 18)

/* Helper fiber boot body: (fn [arm step] (step arm) (step arm) nil).
 * The step function is passed in as an argument; the trailing nil
 * keeps both step calls out of tail position, so the body is exactly
 * call, call, return around the sleep: the first call is the sleep
 * step (janet_sleep_await suspends the fiber inside the step call and
 * the resume continues in the body), the second call is the wake
 * step. Compiled once at module load below and rooted in module-level
 * state so the GC can never collect it while arms exist; compiling a
 * Janet source helper instead of hand-packed boot bytecode keeps the
 * body independent of the bytecode format, which a hand-packed body
 * would break against silently the day that format changes. */
#define DTLS_FLIGHT_TIMER_BODY_SOURCE \
    "(fn [arm step] (step arm) (step arm) nil)"

static Janet dtls_flight_timer_step(int32_t argc, Janet *argv);

static JanetFunction *dtls_flight_timer_body = NULL;

void jdtls_flight_timer_init(JanetTable *env) {
    Janet out;
    if (dtls_flight_timer_body) {
        return; /* compiled exactly once; re-entry is a no-op */
    }
    if (janet_dostring(env, DTLS_FLIGHT_TIMER_BODY_SOURCE,
                       "jdtls-flight-timer-body", &out) ||
            !janet_checktype(out, JANET_FUNCTION)) {
        janet_panic("could not compile DTLS flight timer helper body");
    }
    dtls_flight_timer_body = janet_unwrap_function(out);
    janet_gcroot(out);
}

/* Unroot what the arm kept alive and free it. The owner's slot is
 * already clear, so the arm is unreachable from its owner here. */
static void dtls_flight_timer_release(DTLSFlightTimer *arm) {
    janet_gcunroot(janet_wrap_fiber(arm->fiber));
    janet_gcunroot(janet_wrap_abstract(arm->transport));
    janet_free(arm);
}

/* Retire an arm whose helper fiber must never run again: bumping
 * sched_id makes janet_loop1 drop the stale timeout entry and skip a
 * queued resume without waking the fiber, and clearing the suspended
 * flag releases the event-loop refcount the park took. */
static void dtls_flight_timer_retire_in_place(DTLSFlightTimer *arm) {
    JanetFiber *fiber = arm->fiber;
    fiber->sched_id++;
    if (fiber->gc.flags & DTLS_FIBER_EV_SUSPENDED) {
        fiber->gc.flags &= ~DTLS_FIBER_EV_SUSPENDED;
        janet_ev_dec_refcount();
    }
    dtls_flight_timer_release(arm);
}

/* One step of the helper fiber body. The first step sleeps out the
 * flight interval (janet_sleep_await suspends the fiber and never
 * returns here - the resume continues in the body); the second step
 * runs the retransmission tick and retires the arm. When the arm is
 * canceled the tick is skipped entirely - the retire path touches
 * only the arm's own fiber and transport roots, never owner state. */
static Janet dtls_flight_timer_step(int32_t argc, Janet *argv) {
    DTLSFlightTimer *arm;
    janet_fixarity(argc, 1);
    arm = (DTLSFlightTimer *)janet_getpointer(argv, 0);
    if (arm->phase == 0) {
        arm->phase = 1;
        if (!arm->canceled) {
            janet_sleep_await(arm->seconds);
        }
        return janet_wrap_nil();
    }
    if (!arm->canceled && *arm->slot == arm) {
        struct timeval tv;
        int rc;
        /* Detach first: teardown during the tick must not reach the
         * arm while it is driving the retransmission. */
        *arm->slot = NULL;
        rc = DTLSv1_handle_timeout(arm->ssl);
        if (rc > 0 && arm->flush) {
            arm->flush(arm->owner, arm->transport);
        }
        /* Re-arm while OpenSSL still schedules a retransmission. */
        if (DTLSv1_get_timeout(arm->ssl, &tv) == 1) {
            double seconds =
                (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
            /* A zero remaining interval means handle_timeout did not
             * reset the flight timer; retire instead of spinning on it. */
            if (seconds > 0.0) {
                dtls_flight_timer_arm(arm->slot, arm->ssl, arm->owner,
                                      arm->transport, arm->flush);
            }
        }
    }
    dtls_flight_timer_release(arm);
    return janet_wrap_nil();
}

void dtls_flight_timer_arm(DTLSFlightTimer **slot, SSL *ssl, void *owner,
                           JanetStream *transport, DTLSFlightFlushFn flush) {
    DTLSFlightTimer *arm;
    JanetFiber *fiber;
    Janet fiber_args[2];
    struct timeval tv;
    /* Only a handshake with a retransmission scheduled needs a timer. */
    if (DTLSv1_get_timeout(ssl, &tv) != 1) {
        dtls_flight_timer_disarm(slot, 0);
        return;
    }
    dtls_flight_timer_disarm(slot, 0);
    arm = (DTLSFlightTimer *)janet_malloc(sizeof(DTLSFlightTimer));
    if (!arm) {
        return; /* OOM: handshake continues without retransmission */
    }
    arm->ssl = ssl;
    arm->owner = owner;
    arm->transport = transport;
    arm->flush = flush;
    arm->slot = slot;
    arm->seconds = (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    arm->phase = 0;
    arm->canceled = 0;
    if (!dtls_flight_timer_body) {
        /* Helper body missing (module init never compiled it): keep the
         * handshake running without retransmission, like the OOM case. */
        janet_free(arm);
        return;
    }
    fiber_args[0] = janet_wrap_pointer(arm);
    fiber_args[1] = janet_wrap_cfunction(dtls_flight_timer_step);
    fiber = janet_fiber(dtls_flight_timer_body, 16, 2, fiber_args);
    if (!fiber) {
        janet_free(arm);
        return;
    }
    arm->fiber = fiber;
    janet_gcroot(janet_wrap_fiber(fiber));
    janet_gcroot(janet_wrap_abstract(transport));
    *slot = arm;
    /* Mark the helper fiber as a task fiber before the first
     * schedule: janet_schedule_general only records fibers that are
     * not yet JANET_FIBER_FLAG_ROOT (core fiber flag bit 18), so the
     * scheduler task table never gets a row for this internal fiber
     * and a later in-place cancel cannot leave a stale row behind. */
    fiber->gc.flags |= DTLS_FIBER_EV_ROOT;
    janet_schedule(fiber, janet_wrap_nil());
}

void dtls_flight_timer_disarm(DTLSFlightTimer **slot, int in_gc) {
    DTLSFlightTimer *arm = *slot;
    JanetFiber *fiber;
    if (!arm) {
        return;
    }
    *slot = NULL;
    arm->canceled = 1;
    if (in_gc) {
        /* A GC finalizer runs during a sweep, where even janet_schedule
         * is unsafe (it may grow the scheduler spawn queue), and at
         * process teardown the sweep has already freed the helper
         * fiber's GC block. Never touch the fiber here: only mark the
         * arm canceled and clear the slot. The wake step retires the
         * arm at its next run - the arm's gcroot keeps the fiber alive
         * through a normal sweep, and a parked fiber's timeout keeps
         * the event loop running until the wake fires. At real teardown
         * the wake never runs and the arm goes away with the process. */
        return;
    }
    fiber = arm->fiber;
    if (janet_fiber_status(fiber) == JANET_STATUS_ALIVE) {
        /* Mid-tick: the running wake step retires the arm. */
        return;
    }
    if (!janet_fiber_can_resume(fiber)) {
        /* A fiber that cannot resume would never notice a wake: retire
         * in place instead. */
        dtls_flight_timer_retire_in_place(arm);
        return;
    }
    /* Zero-duration wake: the helper fiber retires the arm at once. */
    janet_schedule(fiber, janet_wrap_nil());
}
