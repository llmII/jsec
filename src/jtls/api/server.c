/*
 * server.c - TLS server functions
 *
 * This file implements server-side connection functions:
 * - accept-loop - Continuously accept TLS connections
 * - server - Create a TLS server listener
 * - listen - Create a TCP/Unix listener
 * - accept - Accept a single TLS connection
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"
#include <math.h>
#ifndef JANET_WINDOWS
#include <sys/un.h>
#include <time.h>
#endif

/*============================================================================
 * ACCEPT ERROR BACK-OFF
 *============================================================================
 * Brief pause taken after a hard accept error before returning to the
 * event loop. A persistent failure (EMFILE/ENFILE/EBADF) leaves the
 * listener readable, so retrying without a pause busy-loops the event
 * callback and starves every other fiber in the process.
 */
static void tls_accept_backoff(void) {
#ifdef JANET_WINDOWS
    Sleep(1);
#else
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000L; /* 1 ms */
    nanosleep(&ts, NULL);
#endif
}

/*============================================================================
 * ACCEPT-LOOP - Continuously accept TLS connections
 *============================================================================
 * (accept-loop listener context handler)
 *
 * Continuously accept connections on a listener, wrap with TLS,
 * and call handler for each. Blocks until listener is closed.
 * Returns the listener stream.
 *
 * This is the TLS equivalent of net/accept-loop.
 */

/* Accept state boolean flags (packed into uint8_t flags) */
#define JTLS_ACCEPT_OWNS_CTX (1U << 0)
#define JTLS_ACCEPT_TCP_NODELAY (1U << 1)
#define JTLS_ACCEPT_TRACK_HANDSHAKE (1U << 2)
#define JTLS_ACCEPT_IO_IN_FLIGHT (1U << 3)

/* State for TLS accept loop - level triggered to handle multiple connections
 */
typedef struct {
#ifdef JANET_WINDOWS
    /* Windows IOCP: WSAOVERLAPPED MUST be first field for pointer matching */
    WSAOVERLAPPED overlapped;
    uint32_t iocp_bytes;  /* Reserved for JanetOverlapped byte count slot */
    SOCKET accept_socket; /* Pre-created socket for AcceptEx */
#endif
    SSL_CTX *ctx;
    JanetFunction *handler;
    int32_t read_buffer_size;
    int32_t write_buffer_size;
    uint8_t flags; /* Bitmask of JTLS_ACCEPT_* */
#ifdef JANET_WINDOWS
    char accept_buf[2 * (sizeof(SOCKADDR_STORAGE) + 16)]; /* Address buffer */
#endif
} TLSAcceptLoopState;

#ifdef JANET_WINDOWS
/* Query listener socket family so AcceptEx creates a matching v4/v6 socket.
 */
static int jtls_win_listener_family(SOCKET lsock) {
    struct sockaddr_storage ss;
    int len = (int)sizeof(ss);
    if (getsockname(lsock, (struct sockaddr *)&ss, &len) == 0 &&
        (ss.ss_family == AF_INET || ss.ss_family == AF_INET6)) {
        return ss.ss_family;
    }
    return AF_INET;
}

/* Start an AcceptEx operation and keep fiber in-flight on both sync &
 * pending.
 */
static int jtls_win_start_acceptex(SOCKET lsock, WSAOVERLAPPED *ov,
                                   char *accept_buf, SOCKET *out_sock,
                                   uint8_t *flags, JanetFiber *fiber) {
    if (lsock == INVALID_SOCKET) {
        return -1;
    }
    int family = jtls_win_listener_family(lsock);
    SOCKET asock =
        jsec_win_overlapped_socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (asock == INVALID_SOCKET) {
        return -1;
    }

    memset(ov, 0, sizeof(WSAOVERLAPPED));
    memset(accept_buf, 0, 2 * (sizeof(SOCKADDR_STORAGE) + 16));
    *out_sock = asock;

    int socksize = (int)(sizeof(SOCKADDR_STORAGE) + 16);
    BOOL result = AcceptEx(lsock, asock, accept_buf, 0, (DWORD)socksize,
                           (DWORD)socksize, NULL, ov);
    if (!result) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            closesocket(asock);
            *out_sock = INVALID_SOCKET;
            WSASetLastError(err);
            return -1;
        }
    }
    /* IOCP posts a completion packet on both synchronous TRUE and
     * WSA_IO_PENDING. */
    janet_async_in_flight(fiber);
    if (flags) {
        jsec_set_u8_flag(*flags, JTLS_ACCEPT_IO_IN_FLIGHT);
    }
    return 0;
}

/* Complete AcceptEx: bind accept context, set non-blocking, wrap JanetStream.
 */
static JanetStream *jtls_win_finish_acceptex(SOCKET lsock,
                                             SOCKET *accept_sock) {
    SOCKET s = *accept_sock;
    *accept_sock = INVALID_SOCKET;
    if (s == INVALID_SOCKET) {
        return NULL;
    }
    if (setsockopt(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&lsock,
                   sizeof(lsock)) != 0) {
        closesocket(s);
        return NULL;
    }
    unsigned long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
    return janet_stream((JanetHandle)s,
                        JANET_STREAM_SOCKET | JANET_STREAM_READABLE |
                            JANET_STREAM_WRITABLE,
                        NULL);
}
#endif

/* Async callback for TLS accept loop */
static void tls_accept_loop_spawn_client(JanetFiber *fiber,
                                         TLSAcceptLoopState *state,
                                         JanetStream *client_stream) {
    SSL_CTX_up_ref(state->ctx);
    TLSStream *tls =
        jtls_setup_stream(client_stream, state->ctx, 1, 1,
                          state->read_buffer_size, state->write_buffer_size,
                          (state->flags & JTLS_ACCEPT_TCP_NODELAY) != 0,
                          (state->flags & JTLS_ACCEPT_TRACK_HANDSHAKE) != 0);

    Janet tls_val = janet_wrap_abstract(tls);
    JanetFiber *handler_fiber = janet_fiber(state->handler, 64, 1, &tls_val);
    handler_fiber->supervisor_channel = fiber->supervisor_channel;
    janet_schedule(handler_fiber, janet_wrap_nil());
}

static void tls_accept_loop_callback(JanetFiber *fiber,
                                     JanetAsyncEvent event) {
    JanetStream *listener = fiber->ev_stream;
    TLSAcceptLoopState *state = (TLSAcceptLoopState *)fiber->ev_state;

    switch (event) {
        default:
            break;

        case JANET_ASYNC_EVENT_MARK:
            /* Mark the handler function */
            if (state && state->handler) {
                janet_mark(janet_wrap_function(state->handler));
            }
            break;

        case JANET_ASYNC_EVENT_DEINIT:
            if (state) {
                if ((state->flags & JTLS_ACCEPT_OWNS_CTX) && state->ctx) {
                    SSL_CTX_free(state->ctx);
                    state->ctx = NULL;
                    jsec_clear_u8_flag(state->flags, JTLS_ACCEPT_OWNS_CTX);
                }
#ifdef JANET_WINDOWS
                jutils_win_cancel_overlapped(
                    fiber, listener, &state->overlapped, &state->flags,
                    JTLS_ACCEPT_IO_IN_FLIGHT);
                if (state->accept_socket != INVALID_SOCKET) {
                    closesocket(state->accept_socket);
                    state->accept_socket = INVALID_SOCKET;
                }
#endif
            }
            break;

        case JANET_ASYNC_EVENT_CLOSE:
            /* Return the listener stream on close */
            janet_schedule(fiber, janet_wrap_abstract(listener));
            janet_async_end(fiber);
            return;

#ifdef JANET_WINDOWS
        case JANET_ASYNC_EVENT_INIT:
            /* Windows: Start AcceptEx operation */
            if (jtls_win_start_acceptex((SOCKET)listener->handle,
                                        &state->overlapped, state->accept_buf,
                                        &state->accept_socket, &state->flags,
                                        fiber) < 0) {
                char errbuf[JSEC_IO_ERROR_BUFSIZE];
                snprintf(errbuf, sizeof(errbuf),
                         "[TLS:IO] Failed to start AcceptEx: %s",
                         jsec_socket_strerror(WSAGetLastError()));
                janet_cancel(fiber, janet_cstringv(errbuf));
                janet_async_end(fiber);
                return;
            }
            break;

        case JANET_ASYNC_EVENT_FAILED: {
            jsec_clear_u8_flag(state->flags, JTLS_ACCEPT_IO_IN_FLIGHT);
            if (state->accept_socket != INVALID_SOCKET) {
                closesocket(state->accept_socket);
                state->accept_socket = INVALID_SOCKET;
            }
            int err = jutils_overlapped_error(listener, &state->overlapped);
            if (err == WSA_OPERATION_ABORTED ||
                err == ERROR_OPERATION_ABORTED) {
                return;
            }
            if (err == WSAECONNRESET || err == WSAECONNABORTED ||
                err == WSAENETRESET) {
                if (jtls_win_start_acceptex(
                        (SOCKET)listener->handle, &state->overlapped,
                        state->accept_buf, &state->accept_socket,
                        &state->flags, fiber) < 0) {
                    char errbuf[JSEC_IO_ERROR_BUFSIZE];
                    snprintf(errbuf, sizeof(errbuf),
                             "[TLS:IO] Failed to restart AcceptEx: %s",
                             jsec_socket_strerror(WSAGetLastError()));
                    janet_cancel(fiber, janet_cstringv(errbuf));
                    janet_async_end(fiber);
                    return;
                }
                break;
            }
            char errbuf[JSEC_IO_ERROR_BUFSIZE];
            snprintf(errbuf, sizeof(errbuf), "[TLS:IO] Accept failed: %s",
                     jsec_socket_strerror(err));
            janet_cancel(fiber, janet_cstringv(errbuf));
            janet_async_end(fiber);
            return;
        }

        case JANET_ASYNC_EVENT_COMPLETE: {
            jsec_clear_u8_flag(state->flags, JTLS_ACCEPT_IO_IN_FLIGHT);
            /* Windows: AcceptEx completed - process the accepted connection
             */
            SOCKET lsock = (SOCKET)listener->handle;
            JanetStream *client_stream =
                jtls_win_finish_acceptex(lsock, &state->accept_socket);
            if (!client_stream) {
                /* Try again */
                if (jtls_win_start_acceptex(
                        lsock, &state->overlapped, state->accept_buf,
                        &state->accept_socket, &state->flags, fiber) < 0) {
                    janet_cancel(
                        fiber, janet_cstringv("Failed to restart AcceptEx"));
                    janet_async_end(fiber);
                    return;
                }
                break;
            }

            tls_accept_loop_spawn_client(fiber, state, client_stream);

            /* Start next AcceptEx */
            if (jtls_win_start_acceptex(
                    lsock, &state->overlapped, state->accept_buf,
                    &state->accept_socket, &state->flags, fiber) < 0) {
                janet_cancel(fiber,
                             janet_cstringv("Failed to restart AcceptEx"));
                janet_async_end(fiber);
                return;
            }
            break;
        }
#else
        /* Unix: Use epoll/kqueue readiness notification */
        case JANET_ASYNC_EVENT_INIT:
        case JANET_ASYNC_EVENT_READ: {
            /* Try to accept connections - level triggered so we may get
             * multiple */
            while (1) {
                jsec_socket_t client_fd =
                    jsec_accept4(listener->handle, NULL, NULL,
                                 JSEC_SOCK_NONBLOCK | JSEC_SOCK_CLOEXEC);
                if (client_fd < 0) {
                    int sock_err = jsec_socket_errno;
                    if (sock_err == JSEC_EAGAIN ||
                        sock_err == JSEC_EWOULDBLOCK) {
                        /* No more connections ready - wait for next event */
                        break;
                    }
                    if (sock_err == JSEC_EINTR) {
                        /* Interrupted by signal - retry accept */
                        continue;
                    }
                    if (sock_err == JSEC_ECONNABORTED) {
                        /* Client closed before accept - drain next */
                        continue;
                    }
                    /* Other accept error - back off briefly and stop
                     * draining, matching Janet core's accept handling.
                     * Continuing here spins inside the event callback on
                     * persistent errors like EMFILE/ENFILE/EBADF. */
                    tls_accept_backoff();
                    break;
                }

                /* Create stream for client socket */
                JanetStream *client_stream =
                    janet_stream(client_fd,
                                 JANET_STREAM_SOCKET | JANET_STREAM_READABLE |
                                     JANET_STREAM_WRITABLE,
                                 NULL);
                tls_accept_loop_spawn_client(fiber, state, client_stream);
            }
            break;
        }
#endif
    }
}

Janet cfun_accept_loop(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    JanetStream *listener = janet_getabstract(argv, 0, &janet_stream_type);
    JanetFunction *handler = janet_getfunction(argv, 2);

    if (handler->def->min_arity < 1) {
        tls_panic_param("handler function must take at least 1 argument");
    }

    /* Second arg can be TLSContext or options table */
    SSL_CTX *ctx = NULL;
    int owns_ctx = 0;

    if (janet_checkabstract(argv[1], jutils_get_context_type())) {
        TLSContext *tls_ctx =
            janet_getabstract(argv, 1, jutils_get_context_type());
        if (tls_ctx->is_dtls) {
            tls_panic_config("cannot use DTLS context for TLS connection");
        }
        ctx = tls_ctx->ctx;
        SSL_CTX_up_ref(ctx);
        owns_ctx = 1;
    } else if (janet_checktype(argv[1], JANET_TABLE) ||
               janet_checktype(argv[1], JANET_STRUCT)) {
        Janet cert = janet_get(argv[1], janet_ckeywordv("cert"));
        Janet key = janet_get(argv[1], janet_ckeywordv("key"));
        Janet security_opts = janet_get(argv[1], janet_ckeywordv("security"));
        Janet alpn_opt = janet_get(argv[1], janet_ckeywordv("alpn"));

        ctx = jtls_create_server_ctx(cert, key, security_opts, alpn_opt, 1);
        if (!ctx) {
            tls_panic_ssl("failed to create server context");
        }
        owns_ctx = 1;
    } else {
        tls_panic_config(
            "accept-loop requires a TLS context or options table");
    }

    /* Parse buffer options */
    int32_t read_buffer_size = DEFAULT_TLS_BUFFER_SIZE;
    int32_t write_buffer_size = JSEC_DEFAULT_WRITE_BUFFER_SIZE;
    jtls_parse_buffer_opts(argv[1], &read_buffer_size, &write_buffer_size);

    /* Parse tcp-nodelay option (default: enabled) */
    int tcp_nodelay = 1;
    if (janet_checktype(argv[1], JANET_TABLE) ||
        janet_checktype(argv[1], JANET_STRUCT)) {
        Janet nodelay_opt =
            janet_get(argv[1], janet_ckeywordv("tcp-nodelay"));
        if (!janet_checktype(nodelay_opt, JANET_NIL)) {
            tcp_nodelay = janet_truthy(nodelay_opt);
        }
    }

    /* Parse handshake-timing option (default: disabled) */
    int track_handshake_time = 0;
    if (janet_checktype(argv[1], JANET_TABLE) ||
        janet_checktype(argv[1], JANET_STRUCT)) {
        Janet timing_opt =
            janet_get(argv[1], janet_ckeywordv("handshake-timing"));
        if (!janet_checktype(timing_opt, JANET_NIL)) {
            track_handshake_time = janet_truthy(timing_opt);
        }
    }

    /* Create state for accept loop */
    TLSAcceptLoopState *state = janet_malloc(sizeof(TLSAcceptLoopState));
    if (!state) {
        tls_panic_io("out of memory");
    }
    memset(state, 0, sizeof(TLSAcceptLoopState));
#ifdef JANET_WINDOWS
    state->accept_socket = INVALID_SOCKET;
#endif
    state->ctx = ctx;
    state->handler = handler;
    state->read_buffer_size = read_buffer_size;
    state->write_buffer_size = write_buffer_size;
    state->flags = (owns_ctx ? JTLS_ACCEPT_OWNS_CTX : 0) |
                   (tcp_nodelay ? JTLS_ACCEPT_TCP_NODELAY : 0) |
                   (track_handshake_time ? JTLS_ACCEPT_TRACK_HANDSHAKE : 0);

    /* Use level-triggered mode to handle multiple connections */
    janet_stream_level_triggered(listener);

    /* Start accept loop */
    janet_async_start(listener, JANET_ASYNC_LISTEN_READ,
                      tls_accept_loop_callback, state);

    janet_panic("unreachable");
}

/*============================================================================
 * SERVER - Create a TLS server listener
 *============================================================================
 * (server host port &opt opts)
 *
 * Create a TLS server listener. Returns the listener stream.
 * Use with accept-loop in an ev/go fiber for continuous accepting:
 *
 *   (def server (tls/server "127.0.0.1" "8443" {:cert ... :key ...}))
 *   (ev/go (fn [] (tls/accept-loop server ctx handler)))
 *
 * Or use net/listen + tls/accept for more control.
 */
Janet cfun_server(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    /* Just create a listener - same as listen, pass all args through */
    return cfun_listen(argc, argv);
}

/* Method table for the raw listener JanetStream returned by cfun_listen.
 * The default Janet stream method table lacks :localname and :accept, so
 * the listener gets its own table: :localname works via cfun_localname's
 * core/stream dispatch, and :accept / :accept-loop wrap with TLS. */
#ifdef JANET_WINDOWS
/* Local forwarders avoid MSVC C4232 on dllimport function pointers in a
 * file-scope static const initializer. */
static Janet jtls_listener_stream_close(int32_t argc, Janet *argv) {
    return janet_cfun_stream_close(argc, argv);
}
static Janet jtls_listener_stream_read(int32_t argc, Janet *argv) {
    return janet_cfun_stream_read(argc, argv);
}
static Janet jtls_listener_stream_chunk(int32_t argc, Janet *argv) {
    return janet_cfun_stream_chunk(argc, argv);
}
static Janet jtls_listener_stream_write(int32_t argc, Janet *argv) {
    return janet_cfun_stream_write(argc, argv);
}
#define JTLS_STREAM_CLOSE_FN jtls_listener_stream_close
#define JTLS_STREAM_READ_FN jtls_listener_stream_read
#define JTLS_STREAM_CHUNK_FN jtls_listener_stream_chunk
#define JTLS_STREAM_WRITE_FN jtls_listener_stream_write
#else
#define JTLS_STREAM_CLOSE_FN janet_cfun_stream_close
#define JTLS_STREAM_READ_FN janet_cfun_stream_read
#define JTLS_STREAM_CHUNK_FN janet_cfun_stream_chunk
#define JTLS_STREAM_WRITE_FN janet_cfun_stream_write
#endif

static const JanetMethod tls_listener_methods[] = {
    {"close", JTLS_STREAM_CLOSE_FN},   {"localname", cfun_localname},
    {"read", JTLS_STREAM_READ_FN},     {"chunk", JTLS_STREAM_CHUNK_FN},
    {"write", JTLS_STREAM_WRITE_FN},   {"accept", cfun_accept},
    {"accept-loop", cfun_accept_loop}, {NULL, NULL}};

/*============================================================================
 * LISTEN - Create a TCP/Unix listener for TLS server
 *============================================================================
 * (listen host port &opt opts)      - TCP listener
 * (listen :unix path &opt opts)     - Unix socket listener
 *
 * Create a listening socket. Returns a Janet stream that can be used with
 * net/localname and accept.
 */
Janet cfun_listen(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    /* Check for unix socket mode: (listen :unix path &opt opts) */
    int is_unix =
        janet_checktype(argv[0], JANET_KEYWORD) &&
        !strcmp((const char *)janet_unwrap_keyword(argv[0]), "unix");

    const char *host = NULL;
    const char *port = NULL;
    const char *unix_path = NULL;

    if (is_unix) {
        unix_path = janet_getcstring(argv, 1);
    } else {
        host = janet_getcstring(argv, 0);
        /* Handle port as string or integer (like Janet's net/listen) */
        if (janet_checktype(argv[1], JANET_NUMBER)) {
            port = (const char *)janet_to_string(argv[1]);
        } else {
            port = janet_getcstring(argv, 1);
        }
    }

    /* Default backlog, can be overridden by opts table */
    int backlog = 1024;

    /* Check for optional opts table */
    if (argc >= 3 && janet_checktype(argv[2], JANET_TABLE)) {
        JanetTable *opts = janet_unwrap_table(argv[2]);
        Janet backlog_val = janet_table_get(opts, janet_ckeywordv("backlog"));
        if (!janet_checktype(backlog_val, JANET_NIL)) {
            backlog = janet_getinteger(&backlog_val, 0);
            if (backlog < 1) backlog = 1;
            if (backlog > 65535) backlog = 65535;
        }
    } else if (argc >= 3 && janet_checktype(argv[2], JANET_STRUCT)) {
        JanetStruct opts = janet_unwrap_struct(argv[2]);
        Janet backlog_val =
            janet_struct_get(opts, janet_ckeywordv("backlog"));
        if (!janet_checktype(backlog_val, JANET_NIL)) {
            backlog = janet_getinteger(&backlog_val, 0);
            if (backlog < 1) backlog = 1;
            if (backlog > 65535) backlog = 65535;
        }
    } else if (argc >= 3 && !janet_checktype(argv[2], JANET_NIL)) {
        tls_panic_param("options must be a table or struct");
    }

    jsec_socket_t fd = JSEC_INVALID_SOCKET;

#ifndef JANET_WINDOWS
    if (is_unix) {
        /* Unix socket listener */
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path) - 1);

        socklen_t addrlen = sizeof(addr);

        /* Support Linux abstract namespace sockets (start with @) */
#ifdef JANET_LINUX
        if (unix_path[0] == '@') {
            addr.sun_path[0] = '\0';
            addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                  strlen(unix_path));
        }
#endif

        /* Leave any pre-existing path in place: matching Janet's
         * net/listen, bind must fail EADDRINUSE on an occupied path
         * rather than unlinking it first. */

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd == -1) {
            tls_panic_socket("could not create unix socket");
        }

        if (bind(fd, (struct sockaddr *)&addr, addrlen) != 0) {
            jsec_close_socket(fd);
            jsec_panic(JSEC_MOD_TLS, "SOCKET",
                       "could not bind to unix socket %s: %s", unix_path,
                       jsec_strerror(errno));
        }
    } else
#endif
    {
        /* TCP listener */
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        struct addrinfo *ai = NULL;
        int status = getaddrinfo(host, port, &hints, &ai);
        if (status != 0) {
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "getaddrinfo failed: %s",
                       gai_strerror(status));
        }

        struct addrinfo *rp;
        for (rp = ai; rp != NULL; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == JSEC_INVALID_SOCKET) continue;

#ifndef JANET_WINDOWS
            /* On Windows SO_REUSEADDR permits active port hijacking instead
             * of TIME_WAIT reuse alone; leave default exclusive bind
             * semantics. */
            int enable = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
#ifdef SO_REUSEPORT
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int));
#endif
#endif

            if (bind(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
                break;
            }
            jsec_close_socket(fd);
            fd = JSEC_INVALID_SOCKET;
        }
        freeaddrinfo(ai);

        if (fd == JSEC_INVALID_SOCKET) {
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "failed to bind to %s:%s",
                       host, port);
        }
    }

    if (listen(fd, backlog) < 0) {
        jsec_close_socket(fd);
        tls_panic_socket("listen failed");
    }

    /* Set non-blocking */
    jsec_socket_set_nonblock(fd);

    /* Return a Janet stream */
    return janet_wrap_abstract(janet_stream(
        (JanetHandle)fd, JANET_STREAM_SOCKET | JANET_STREAM_ACCEPTABLE,
        tls_listener_methods));
}

/*============================================================================
 * ACCEPT - Accept a TLS connection
 *============================================================================
 * (accept listener context &opt timeout)
 *
 * Accept a TCP connection and wrap it with TLS. Returns immediately after
 * TCP accept - the TLS handshake happens lazily on first read/write.
 */

/* State for async TLS accept operation */
typedef struct {
#ifdef JANET_WINDOWS
    /* Windows IOCP: WSAOVERLAPPED MUST be first field for pointer matching */
    WSAOVERLAPPED overlapped;
    uint32_t iocp_bytes;  /* Reserved for JanetOverlapped byte count slot */
    SOCKET accept_socket; /* Pre-created socket for AcceptEx */
#endif
    SSL_CTX *ctx;
    int32_t read_buffer_size;
    int32_t write_buffer_size;
    uint8_t flags; /* Bitmask of JTLS_ACCEPT_* */
#ifdef JANET_WINDOWS
    char accept_buf[2 * (sizeof(SOCKADDR_STORAGE) + 16)]; /* Address buffer */
#endif
} TLSAcceptState;

static void tls_accept_finish_client(JanetFiber *fiber, TLSAcceptState *state,
                                     JanetStream *client_stream) {
    TLSStream *tls =
        jtls_setup_stream(client_stream, state->ctx, 1,
                          (state->flags & JTLS_ACCEPT_OWNS_CTX) != 0,
                          state->read_buffer_size, state->write_buffer_size,
                          (state->flags & JTLS_ACCEPT_TCP_NODELAY) != 0,
                          (state->flags & JTLS_ACCEPT_TRACK_HANDSHAKE) != 0);

    jsec_clear_u8_flag(state->flags, JTLS_ACCEPT_OWNS_CTX);
    janet_schedule(fiber, janet_wrap_abstract(tls));
    janet_async_end(fiber);
}

/* Async callback for TLS accept - just handles TCP accept */
static void tls_accept_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    JanetStream *listener = fiber->ev_stream;
    TLSAcceptState *state = (TLSAcceptState *)fiber->ev_state;

    switch (event) {
        default:
            break;

        case JANET_ASYNC_EVENT_MARK:
            /* Nothing to mark - ctx is not a Janet value */
            break;

        case JANET_ASYNC_EVENT_DEINIT:
            /* Every terminal path ends here through janet_async_end. A
             * cancelled (ev/cancel) or timed-out accept never reaches the
             * success path, so release a still-owned context; successful
             * accepts transfer ownership to the TLS stream first and leave
             * owns_ctx cleared. */
            if (state && (state->flags & JTLS_ACCEPT_OWNS_CTX) &&
                state->ctx) {
                SSL_CTX_free(state->ctx);
                state->ctx = NULL;
                jsec_clear_u8_flag(state->flags, JTLS_ACCEPT_OWNS_CTX);
            }
#ifdef JANET_WINDOWS
            if (state) {
                jutils_win_cancel_overlapped(
                    fiber, listener, &state->overlapped, &state->flags,
                    JTLS_ACCEPT_IO_IN_FLIGHT);
                if (state->accept_socket != INVALID_SOCKET) {
                    closesocket(state->accept_socket);
                    state->accept_socket = INVALID_SOCKET;
                }
            }
#endif
            break;

        case JANET_ASYNC_EVENT_CLOSE:
            janet_schedule(fiber, janet_wrap_nil());
            janet_async_end(fiber);
            return;

#ifdef JANET_WINDOWS
        case JANET_ASYNC_EVENT_INIT:
            /* Windows: Start AcceptEx operation */
            if (jtls_win_start_acceptex((SOCKET)listener->handle,
                                        &state->overlapped, state->accept_buf,
                                        &state->accept_socket, &state->flags,
                                        fiber) < 0) {
                char errbuf[JSEC_IO_ERROR_BUFSIZE];
                snprintf(errbuf, sizeof(errbuf),
                         "[TLS:IO] Failed to start AcceptEx: %s",
                         jsec_socket_strerror(WSAGetLastError()));
                janet_cancel(fiber, janet_cstringv(errbuf));
                janet_async_end(fiber);
                return;
            }
            break;

        case JANET_ASYNC_EVENT_FAILED: {
            jsec_clear_u8_flag(state->flags, JTLS_ACCEPT_IO_IN_FLIGHT);
            if (state->accept_socket != INVALID_SOCKET) {
                closesocket(state->accept_socket);
                state->accept_socket = INVALID_SOCKET;
            }
            int err = jutils_overlapped_error(listener, &state->overlapped);
            if (err == WSA_OPERATION_ABORTED ||
                err == ERROR_OPERATION_ABORTED) {
                return;
            }
            char errbuf[JSEC_IO_ERROR_BUFSIZE];
            snprintf(errbuf, sizeof(errbuf), "[TLS:IO] Accept failed: %s",
                     jsec_socket_strerror(err));
            janet_cancel(fiber, janet_cstringv(errbuf));
            janet_async_end(fiber);
            return;
        }

        case JANET_ASYNC_EVENT_COMPLETE: {
            jsec_clear_u8_flag(state->flags, JTLS_ACCEPT_IO_IN_FLIGHT);
            /* Windows: AcceptEx completed - process the accepted connection
             */
            SOCKET lsock = (SOCKET)listener->handle;
            JanetStream *client_stream =
                jtls_win_finish_acceptex(lsock, &state->accept_socket);
            if (!client_stream) {
                janet_cancel(
                    fiber, janet_cstringv("Failed to update accept context"));
                janet_async_end(fiber);
                return;
            }

            tls_accept_finish_client(fiber, state, client_stream);
            return;
        }
#else
        /* Unix: Use epoll/kqueue readiness notification */
        case JANET_ASYNC_EVENT_INIT:
        case JANET_ASYNC_EVENT_READ: {
            /* Try to accept a TCP connection */
            jsec_socket_t client_fd =
                jsec_accept4(listener->handle, NULL, NULL,
                             JSEC_SOCK_NONBLOCK | JSEC_SOCK_CLOEXEC);
            if (client_fd >= 0) {
                /* Create stream for client socket */
                JanetStream *client_stream =
                    janet_stream(client_fd,
                                 JANET_STREAM_SOCKET | JANET_STREAM_READABLE |
                                     JANET_STREAM_WRITABLE,
                                 NULL);
                tls_accept_finish_client(fiber, state, client_stream);
                return;
            } else {
                int sock_err = jsec_socket_errno;
                if (sock_err == JSEC_EINTR || sock_err == JSEC_ECONNABORTED) {
                    /* Transient event - keep waiting for a valid connection
                     */
                    break;
                }
                if (sock_err != JSEC_EAGAIN && sock_err != JSEC_EWOULDBLOCK) {
                    /* Real error */
                    janet_cancel(fiber, janet_cstringv(
                                            jsec_socket_strerror(sock_err)));
                    janet_async_end(fiber);
                    return;
                }
            }
            /* EAGAIN - continue waiting for TCP accept */
            break;
        }
#endif
    }
}

Janet cfun_accept(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    JanetStream *listener = janet_getabstract(argv, 0, &janet_stream_type);

    /* Second arg can be TLSContext or options table */
    SSL_CTX *ctx = NULL;
    int owns_ctx = 0;

    if (janet_checkabstract(argv[1], jutils_get_context_type())) {
        TLSContext *tls_ctx =
            janet_getabstract(argv, 1, jutils_get_context_type());
        if (tls_ctx->is_dtls) {
            tls_panic_config("cannot use DTLS context for TLS connection");
        }
        ctx = tls_ctx->ctx;
        SSL_CTX_up_ref(ctx);
        owns_ctx = 1;
    } else if (janet_checktype(argv[1], JANET_TABLE) ||
               janet_checktype(argv[1], JANET_STRUCT)) {
        Janet cert = janet_get(argv[1], janet_ckeywordv("cert"));
        Janet key = janet_get(argv[1], janet_ckeywordv("key"));
        Janet security_opts = janet_get(argv[1], janet_ckeywordv("security"));
        Janet alpn_opt = janet_get(argv[1], janet_ckeywordv("alpn"));

        ctx = jtls_create_server_ctx(cert, key, security_opts, alpn_opt, 1);
        if (!ctx) {
            tls_panic_ssl("failed to create server context");
        }
        owns_ctx = 1;
    } else {
        tls_panic_config("accept requires a TLS context or options table");
    }

    /* Parse buffer options */
    int32_t read_buffer_size = DEFAULT_TLS_BUFFER_SIZE;
    int32_t write_buffer_size = JSEC_DEFAULT_WRITE_BUFFER_SIZE;
    jtls_parse_buffer_opts(argv[1], &read_buffer_size, &write_buffer_size);

    /* Parse tcp-nodelay option (default: enabled) */
    int tcp_nodelay = 1;
    if (janet_checktype(argv[1], JANET_TABLE) ||
        janet_checktype(argv[1], JANET_STRUCT)) {
        Janet nodelay_opt =
            janet_get(argv[1], janet_ckeywordv("tcp-nodelay"));
        if (!janet_checktype(nodelay_opt, JANET_NIL)) {
            tcp_nodelay = janet_truthy(nodelay_opt);
        }
    }

    /* Parse handshake-timing option (default: disabled) */
    int track_handshake_time = 0;
    if (janet_checktype(argv[1], JANET_TABLE) ||
        janet_checktype(argv[1], JANET_STRUCT)) {
        Janet timing_opt =
            janet_get(argv[1], janet_ckeywordv("handshake-timing"));
        if (!janet_checktype(timing_opt, JANET_NIL)) {
            track_handshake_time = janet_truthy(timing_opt);
        }
    }

    /* Create state for async accept */
    TLSAcceptState *state = janet_malloc(sizeof(TLSAcceptState));
    if (!state) {
        tls_panic_io("out of memory");
    }
    memset(state, 0, sizeof(TLSAcceptState));
#ifdef JANET_WINDOWS
    state->accept_socket = INVALID_SOCKET;
#endif
    state->ctx = ctx;
    state->read_buffer_size = read_buffer_size;
    state->write_buffer_size = write_buffer_size;
    state->flags = (owns_ctx ? JTLS_ACCEPT_OWNS_CTX : 0) |
                   (tcp_nodelay ? JTLS_ACCEPT_TCP_NODELAY : 0) |
                   (track_handshake_time ? JTLS_ACCEPT_TRACK_HANDSHAKE : 0);

    /* Optional timeout: arm like timed Janet I/O (net/accept, ev/read) so
     * the fiber raises "timeout" when the deadline expires. */
    double to = janet_optnumber(argv, argc, 2, INFINITY);
    if (isinf(to) == 0) janet_addtimeout(to);

    /* Start async accept operation */
    janet_async_start(listener, JANET_ASYNC_LISTEN_READ, tls_accept_callback,
                      state);

    /* This never returns - fiber is suspended until accept completes */
    janet_panic("unreachable");
}
