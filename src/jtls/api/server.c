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

#ifdef __linux__
#define _GNU_SOURCE  /* For accept4 */
#endif

#include "../jtls_internal.h"
#include <sys/un.h>

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

/* State for TLS accept loop - level triggered to handle multiple connections */
typedef struct {
    SSL_CTX *ctx;
    int owns_ctx;
    JanetFunction *handler;
    int32_t buffer_size;
    int tcp_nodelay;
    int track_handshake_time;
} TLSAcceptLoopState;

/* Async callback for TLS accept loop */
static void tls_accept_loop_callback(JanetFiber *fiber, JanetAsyncEvent event) {
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

        case JANET_ASYNC_EVENT_CLOSE:
            if (state && state->owns_ctx && state->ctx) {
                SSL_CTX_free(state->ctx);
            }
            /* Return the listener stream on close */
            janet_schedule(fiber, janet_wrap_abstract(listener));
            janet_async_end(fiber);
            return;

        case JANET_ASYNC_EVENT_INIT:
        case JANET_ASYNC_EVENT_READ: {
            /* Try to accept connections - level triggered so we may get multiple */
            while (1) {
#ifdef __linux__
                int client_fd = accept4(listener->handle, NULL, NULL, SOCK_CLOEXEC);
#else
                int client_fd = accept(listener->handle, NULL, NULL);
#endif
                if (client_fd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        /* No more connections ready - wait for next event */
                        break;
                    }
                    /* Other error - continue trying */
                    continue;
                }

                /* Got a connection - set non-blocking */
                int flags = fcntl(client_fd, F_GETFL, 0);
                if (flags != -1) {
                    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
                }
#ifndef __linux__
                flags = fcntl(client_fd, F_GETFD, 0);
                if (flags != -1) {
                    fcntl(client_fd, F_SETFD, flags | FD_CLOEXEC);
                }
#endif
                /* Create stream for client socket */
                JanetStream *client_stream = janet_stream(client_fd, JANET_STREAM_SOCKET |
                                                          JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

                /* Create TLS stream - handshake happens lazily on first I/O */
                /* We need to up_ref the ctx since it's shared across connections */
                SSL_CTX_up_ref(state->ctx);
                TLSStream *tls = jtls_setup_stream(client_stream, state->ctx, 1, 1, 
                                                   state->buffer_size, state->tcp_nodelay,
                                                   state->track_handshake_time);

                /* Spawn a fiber to handle this connection */
                Janet tls_val = janet_wrap_abstract(tls);
                JanetFiber *handler_fiber = janet_fiber(state->handler, 64, 1, &tls_val);
                handler_fiber->supervisor_channel = fiber->supervisor_channel;
                janet_schedule(handler_fiber, janet_wrap_nil());
            }
            break;
        }
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

    if (janet_checkabstract(argv[1], &tls_context_type)) {
        TLSContext *tls_ctx = janet_getabstract(argv, 1, &tls_context_type);
        ctx = tls_ctx->ctx;
        SSL_CTX_up_ref(ctx);
        owns_ctx = 1;
    } else if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
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
        tls_panic_config("accept-loop requires a TLS context or options table");
    }

    /* Parse buffer-size option */
    int32_t buffer_size = DEFAULT_TLS_BUFFER_SIZE;
    if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
        Janet buf_size_opt = janet_get(argv[1], janet_ckeywordv("buffer-size"));
        if (!janet_checktype(buf_size_opt, JANET_NIL)) {
            if (janet_checktype(buf_size_opt, JANET_NUMBER)) {
                int32_t size = (int32_t)janet_unwrap_integer(buf_size_opt);
                if (size < MIN_TLS_BUFFER_SIZE) size = MIN_TLS_BUFFER_SIZE;
                if (size > MAX_TLS_BUFFER_SIZE) size = MAX_TLS_BUFFER_SIZE;
                buffer_size = size;
            }
        }
    }

    /* Parse tcp-nodelay option (default: enabled) */
    int tcp_nodelay = 1;
    if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
        Janet nodelay_opt = janet_get(argv[1], janet_ckeywordv("tcp-nodelay"));
        if (!janet_checktype(nodelay_opt, JANET_NIL)) {
            tcp_nodelay = janet_truthy(nodelay_opt);
        }
    }

    /* Parse handshake-timing option (default: disabled) */
    int track_handshake_time = 0;
    if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
        Janet timing_opt = janet_get(argv[1], janet_ckeywordv("handshake-timing"));
        if (!janet_checktype(timing_opt, JANET_NIL)) {
            track_handshake_time = janet_truthy(timing_opt);
        }
    }

    /* Create state for accept loop */
    TLSAcceptLoopState *state = janet_malloc(sizeof(TLSAcceptLoopState));
    state->ctx = ctx;
    state->owns_ctx = owns_ctx;
    state->handler = handler;
    state->buffer_size = buffer_size;
    state->tcp_nodelay = tcp_nodelay;
    state->track_handshake_time = track_handshake_time;

    /* Use level-triggered mode to handle multiple connections */
    janet_stream_level_triggered(listener);

    /* Start accept loop */
    janet_async_start(listener, JANET_ASYNC_LISTEN_READ, tls_accept_loop_callback, state);

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
    int is_unix = janet_checktype(argv[0], JANET_KEYWORD) &&
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
        Janet backlog_val = janet_struct_get(opts, janet_ckeywordv("backlog"));
        if (!janet_checktype(backlog_val, JANET_NIL)) {
            backlog = janet_getinteger(&backlog_val, 0);
            if (backlog < 1) backlog = 1;
            if (backlog > 65535) backlog = 65535;
        }
    }

    int fd = -1;
    
    if (is_unix) {
        /* Unix socket listener */
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path) - 1);
        
        socklen_t addrlen = sizeof(addr);
        
        /* Support Linux abstract namespace sockets (start with @) */
#ifdef __linux__
        if (unix_path[0] == '@') {
            addr.sun_path[0] = '\0';
            addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(unix_path));
        }
#endif
        
        /* Remove existing socket file (if not abstract) */
        if (unix_path[0] != '@') {
            unlink(unix_path);
        }
        
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd == -1) {
            tls_panic_socket("could not create unix socket");
        }
        
        if (bind(fd, (struct sockaddr *)&addr, addrlen) != 0) {
            close(fd);
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "could not bind to unix socket %s: %s", unix_path, strerror(errno));
        }
    } else {
        /* TCP listener */
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        struct addrinfo *ai = NULL;
        int status = getaddrinfo(host, port, &hints, &ai);
        if (status != 0) {
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "getaddrinfo failed: %s", gai_strerror(status));
        }

        struct addrinfo *rp;
        for (rp = ai; rp != NULL; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == -1) continue;

            int enable = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
#ifdef SO_REUSEPORT
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int));
#endif

            if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                break;
            }
            close(fd);
            fd = -1;
        }
        freeaddrinfo(ai);

        if (fd == -1) {
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "failed to bind to %s:%s", host, port);
        }
    }

    if (listen(fd, backlog) < 0) {
        close(fd);
        tls_panic_socket("listen failed");
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Return a Janet stream */
    return janet_wrap_abstract(janet_stream(fd, JANET_STREAM_SOCKET | JANET_STREAM_ACCEPTABLE, NULL));
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
    SSL_CTX *ctx;
    int owns_ctx;
    int32_t buffer_size;
    int tcp_nodelay;
    int track_handshake_time;
} TLSAcceptState;

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

        case JANET_ASYNC_EVENT_CLOSE:
            if (state && state->owns_ctx && state->ctx) {
                SSL_CTX_free(state->ctx);
            }
            janet_schedule(fiber, janet_wrap_nil());
            janet_async_end(fiber);
            return;

        case JANET_ASYNC_EVENT_INIT:
        case JANET_ASYNC_EVENT_READ: {
            /* Try to accept a TCP connection */
#ifdef __linux__
            int client_fd = accept4(listener->handle, NULL, NULL, SOCK_CLOEXEC);
#else
            int client_fd = accept(listener->handle, NULL, NULL);
#endif
            if (client_fd >= 0) {
                /* Got a connection - set non-blocking */
                int flags = fcntl(client_fd, F_GETFL, 0);
                if (flags != -1) {
                    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
                }
#ifndef __linux__
                flags = fcntl(client_fd, F_GETFD, 0);
                if (flags != -1) {
                    fcntl(client_fd, F_SETFD, flags | FD_CLOEXEC);
                }
#endif
                /* Create stream for client socket */
                JanetStream *client_stream = janet_stream(client_fd, JANET_STREAM_SOCKET |
                                                          JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

                /* Create TLS stream - handshake will happen on first I/O */
                TLSStream *tls = jtls_setup_stream(client_stream, state->ctx, 1, 
                                                   state->owns_ctx, state->buffer_size,
                                                   state->tcp_nodelay, state->track_handshake_time);
                
                /* Ownership transferred to TLS stream */
                state->owns_ctx = 0;

                /* Return the TLS stream - handshake happens lazily */
                janet_schedule(fiber, janet_wrap_abstract(tls));
                janet_async_end(fiber);
                return;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                /* Real error */
                if (state->owns_ctx && state->ctx) {
                    SSL_CTX_free(state->ctx);
                }
                janet_cancel(fiber, janet_cstringv(strerror(errno)));
                janet_async_end(fiber);
                return;
            }
            /* EAGAIN - continue waiting for TCP accept */
            break;
        }
    }
}

Janet cfun_accept(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    JanetStream *listener = janet_getabstract(argv, 0, &janet_stream_type);
    
    /* Second arg can be TLSContext or options table */
    SSL_CTX *ctx = NULL;
    int owns_ctx = 0;
    
    if (janet_checkabstract(argv[1], &tls_context_type)) {
        TLSContext *tls_ctx = janet_getabstract(argv, 1, &tls_context_type);
        ctx = tls_ctx->ctx;
        SSL_CTX_up_ref(ctx);
        owns_ctx = 1;
    } else if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
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

    /* Parse buffer-size option */
    int32_t buffer_size = DEFAULT_TLS_BUFFER_SIZE;
    if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
        Janet buf_size_opt = janet_get(argv[1], janet_ckeywordv("buffer-size"));
        if (!janet_checktype(buf_size_opt, JANET_NIL)) {
            if (janet_checktype(buf_size_opt, JANET_NUMBER)) {
                int32_t size = (int32_t)janet_unwrap_integer(buf_size_opt);
                if (size < MIN_TLS_BUFFER_SIZE) size = MIN_TLS_BUFFER_SIZE;
                if (size > MAX_TLS_BUFFER_SIZE) size = MAX_TLS_BUFFER_SIZE;
                buffer_size = size;
            }
        }
    }

    /* Parse tcp-nodelay option (default: enabled) */
    int tcp_nodelay = 1;
    if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
        Janet nodelay_opt = janet_get(argv[1], janet_ckeywordv("tcp-nodelay"));
        if (!janet_checktype(nodelay_opt, JANET_NIL)) {
            tcp_nodelay = janet_truthy(nodelay_opt);
        }
    }

    /* Parse handshake-timing option (default: disabled) */
    int track_handshake_time = 0;
    if (janet_checktype(argv[1], JANET_TABLE) || janet_checktype(argv[1], JANET_STRUCT)) {
        Janet timing_opt = janet_get(argv[1], janet_ckeywordv("handshake-timing"));
        if (!janet_checktype(timing_opt, JANET_NIL)) {
            track_handshake_time = janet_truthy(timing_opt);
        }
    }

    /* Create state for async accept */
    TLSAcceptState *state = janet_malloc(sizeof(TLSAcceptState));
    state->ctx = ctx;
    state->owns_ctx = owns_ctx;
    state->buffer_size = buffer_size;
    state->tcp_nodelay = tcp_nodelay;
    state->track_handshake_time = track_handshake_time;

    /* Start async accept operation */
    janet_async_start(listener, JANET_ASYNC_LISTEN_READ, tls_accept_callback, state);

    /* This never returns - fiber is suspended until accept completes */
    janet_panic("unreachable");
}
