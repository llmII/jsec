/*
 * error.c - SSL error handling utilities
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <stdarg.h>

/*
 * Recorded cause of the last cert-loading or security-option validation
 * failure. The helpers (load_cert_chain_mem, load_ca_mem,
 * add_trusted_cert, apply_security_options) never raise: they record a
 * human-readable cause here and return 0, so callers can free what they
 * own and raise with the cause after releasing any held lock (never
 * across a held ctx_cache_lock).
 */
static JANET_THREAD_LOCAL char cert_load_error_buf[2048];

void jutils_cert_load_error_clear(void) {
    cert_load_error_buf[0] = '\0';
}

void jutils_cert_load_errorf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
    vsnprintf(cert_load_error_buf, sizeof(cert_load_error_buf), fmt, ap);
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    va_end(ap);
}

const char *jutils_cert_load_error(void) {
    if (cert_load_error_buf[0] != '\0') return cert_load_error_buf;
    return get_ssl_error_string();
}

/*
 * Get human-readable SSL error string.
 *
 * NOTE: Returns pointer to thread-local static buffer. The returned string
 * is only valid until the next call to this function from the same thread.
 * Use immediately or copy if needed across multiple calls.
 *
 * Reports every queued error, separated. When no error is queued, reports
 * the recorded helper failure detail (if any) so a raise never reports an
 * empty cause while a recorded detail exists; "No SSL error" only when
 * both are empty.
 */
static JANET_THREAD_LOCAL char error_buf[2048];

const char *get_ssl_error_string(void) {
    size_t used = 0;
    unsigned long err = ERR_get_error();
    if (err == 0) {
        if (cert_load_error_buf[0] != '\0') return cert_load_error_buf;
        return "No SSL error";
    }
    while (err != 0) {
        char one[JSEC_STRERROR_BUFSIZE];
        int n;
        ERR_error_string_n(err, one, sizeof(one));
        n = snprintf(error_buf + used, sizeof(error_buf) - used, "%s%s",
                     used == 0 ? "" : "; ", one);
        if (n < 0 || (size_t)n >= sizeof(error_buf) - used) {
            used = sizeof(error_buf) - 1;
            error_buf[used] = '\0';
        } else {
            used += (size_t)n;
        }
        err = ERR_get_error();
    }
    return error_buf;
}

/*
 * True when the error queue holds the OpenSSL 3.x shape of an unexpected
 * EOF (a transport EOF that arrived without close_notify): SSL_ERROR_SSL
 * with reason SSL_R_UNEXPECTED_EOF_WHILE_READING. OpenSSL 1.1.1 and
 * LibreSSL report the same condition as SSL_ERROR_SYSCALL with ret 0 and
 * no queue entry; callers classify that shape from the ret/errno pair and
 * raise JSEC_UNEXPECTED_EOF_ERROR for both. Peek only - the queue is left
 * for the caller to consume or clear.
 */
int jutils_is_unexpected_eof(void) {
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    unsigned long err = ERR_peek_error();
    return err != 0 && ERR_GET_REASON(err) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
#else
    return 0;
#endif
}

int jutils_pending_socket_error(JanetStream *stream) {
    int res = 0;
    socklen_t size = (socklen_t)sizeof(res);
    if (!stream || stream->handle == JANET_HANDLE_NONE) {
        return 0;
    }
    int r = jsec_socket_getsockopt((jsec_socket_t)stream->handle, SOL_SOCKET,
                                   SO_ERROR, &res, &size);
    return (r == 0 && res != 0) ? res : 0;
}

int jutils_format_socket_error(char *buf, size_t buflen, const char *category,
                               JanetStream *stream) {
    int err = jutils_pending_socket_error(stream);
    if (err != 0) {
        snprintf(buf, buflen, "[%s] socket error: %s", category,
                 jsec_socket_strerror(err));
        return 1;
    }
    snprintf(buf, buflen, "[%s] socket error", category);
    return 0;
}

#ifdef JANET_WINDOWS
int jutils_overlapped_error(JanetStream *stream, WSAOVERLAPPED *ov) {
    int err = 0;
    if (stream && stream->handle != JANET_HANDLE_NONE && ov) {
        DWORD bytes = 0;
        DWORD flags = 0;
        if (!WSAGetOverlappedResult((SOCKET)stream->handle, ov, &bytes, FALSE,
                                    &flags)) {
            err = WSAGetLastError();
        }
    }
    if (err == 0) {
        err = jutils_pending_socket_error(stream);
    }
    return err;
}

void jutils_format_overlapped_error(char *buf, size_t buflen,
                                    const char *category, JanetStream *stream,
                                    WSAOVERLAPPED *ov) {
    int err = jutils_overlapped_error(stream, ov);
    if (err != 0) {
        snprintf(buf, buflen, "[%s] socket error: %s", category,
                 jsec_socket_strerror(err));
    } else {
        snprintf(buf, buflen, "[%s] socket error", category);
    }
}

void jutils_win_cancel_overlapped(JanetFiber *fiber, JanetStream *stream,
                                  WSAOVERLAPPED *ov, uint8_t *flags,
                                  uint8_t in_flight_bit) {
    if (flags && (*flags & in_flight_bit)) {
        if (stream && stream->handle != JANET_HANDLE_NONE && ov) {
            CancelIoEx((HANDLE)stream->handle, ov);
        }
        jsec_clear_u8_flag(*flags, in_flight_bit);
    }
    if (fiber && (fiber->flags & 1) && fiber->ev_state == (void *)ov) {
        fiber->ev_state = NULL;
    }
}

typedef struct {
    SOCKET sock;
    JanetStream *stream;
    JanetFiber *fiber;
    void *ctx;
    void **slot;
    JsecWinPollResumeFn resume_fn;
    short events;
    uint8_t owns_close;
    volatile LONG cancelled;
} JsecWinPollWait;

static JanetEVGenericMessage
jutils_win_poll_subr(JanetEVGenericMessage args) {
    JsecWinPollWait *wait = (JsecWinPollWait *)args.argp;
    while (InterlockedCompareExchange(&wait->cancelled, 0, 0) == 0) {
        WSAPOLLFD pfd;
        pfd.fd = wait->sock;
        pfd.events = wait->events;
        pfd.revents = 0;
        int r = WSAPoll(&pfd, 1, 20);
        if (r != 0) {
            args.tag = r;
            return args;
        }
    }
    args.tag = 0;
    return args;
}

static void jutils_win_poll_cb(JanetEVGenericMessage args) {
    JsecWinPollWait *wait = (JsecWinPollWait *)args.argp;
    JanetFiber *fiber = wait->fiber;
    JanetStream *stream = wait->stream;
    void *ctx = wait->ctx;
    void **slot = wait->slot;
    JsecWinPollResumeFn resume_fn = wait->resume_fn;
    int cancelled = (InterlockedCompareExchange(&wait->cancelled, 0, 0) != 0);

    if (wait->owns_close) {
        if (stream->flags & JANET_STREAM_CLOSED) {
            closesocket(wait->sock);
        } else {
            stream->flags &= ~JANET_STREAM_NOT_CLOSEABLE;
        }
    }

    janet_gcunroot(janet_wrap_abstract(stream));
    janet_gcunroot(janet_wrap_fiber(fiber));

    if (!cancelled && fiber->ev_state == ctx) {
        if (slot && *slot == wait) {
            *slot = NULL;
        }
        janet_free(wait);
        resume_fn(fiber, ctx);
        return;
    }

    janet_free(wait);
}

int jutils_win_poll_start(JanetStream *stream, JanetFiber *fiber,
                          short events, void *ctx, void **slot,
                          JsecWinPollResumeFn resume_fn) {
    JsecWinPollWait *wait = janet_malloc(sizeof(JsecWinPollWait));
    if (!wait) {
        return -1;
    }
    wait->sock = (SOCKET)stream->handle;
    wait->stream = stream;
    wait->fiber = fiber;
    wait->ctx = ctx;
    wait->slot = slot;
    wait->resume_fn = resume_fn;
    wait->events = events;
    wait->owns_close =
        ((stream->flags & JANET_STREAM_NOT_CLOSEABLE) == 0) ? 1 : 0;
    wait->cancelled = 0;
    if (wait->owns_close) {
        stream->flags |= JANET_STREAM_NOT_CLOSEABLE;
    }
    if (slot) {
        *slot = wait;
    }
    janet_gcroot(janet_wrap_fiber(fiber));
    janet_gcroot(janet_wrap_abstract(stream));
    JanetEVGenericMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.argp = wait;
    janet_ev_threaded_call(jutils_win_poll_subr, msg, jutils_win_poll_cb);
    return 0;
}

void jutils_win_poll_cancel(void **slot) {
    if (slot && *slot) {
        JsecWinPollWait *wait = (JsecWinPollWait *)(*slot);
        InterlockedExchange(&wait->cancelled, 1);
        *slot = NULL;
    }
}
#endif
