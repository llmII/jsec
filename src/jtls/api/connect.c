/*
 * connect.c - TLS connection establishment functions
 *
 * This file implements client-side connection functions:
 * - wrap/upgrade - Wrap existing streams with TLS
 * - connect - Create new TLS client connections
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "../internal.h"
#include <sys/un.h>

/*============================================================================
 * WRAP - Wrap an existing stream with TLS
 *============================================================================
 * (wrap stream &opt config options)
 *
 * Wrap an existing Janet stream (TCP/Unix socket) with TLS.
 *
 * Client mode:
 *   (wrap stream hostname)
 *   (wrap stream hostname {:verify true})
 *   (wrap stream {:hostname "example.com" :verify false})
 *
 * Server mode:
 *   (wrap stream {:cert "cert.pem" :key "key.pem"})
 *
 * With pre-created context:
 *   (wrap stream context)
 *   (wrap stream context "hostname")
 */
Janet cfun_wrap(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 4);

    JanetStream *transport = NULL;
    if (!janet_checktype(argv[0], JANET_NIL)) {
        transport = janet_getabstract(argv, 0, &janet_stream_type);
    }

    const char *hostname = NULL;
    const char *verify_hostname = NULL;  /* Hostname for certificate verification (can differ from SNI) */
    int is_server = 0;
    int verify = 1;
    int owns_ctx = 1;
    int32_t buffer_size = DEFAULT_TLS_BUFFER_SIZE;

    SSL_CTX *ctx = NULL;
    Janet security_opts = janet_wrap_nil();
    Janet alpn_opt = janet_wrap_nil();
    Janet session_opt = janet_wrap_nil();
    Janet opts = janet_wrap_nil();

    /* Check if argv[1] is a TLSContext */
    if (argc >= 2 && janet_checktype(argv[1], JANET_ABSTRACT) &&
        janet_checkabstract(argv[1], &tls_context_type)) {
        TLSContext *tls_ctx = (TLSContext *)janet_getabstract(argv, 1,
                                                              &tls_context_type);
        ctx = tls_ctx->ctx;
        SSL_CTX_up_ref(ctx);
        owns_ctx = 1;

        if (argc >= 3) {
            if (janet_checktype(argv[2], JANET_STRING)) {
                hostname = janet_getcstring(argv, 2);
                is_server = 0;
                if (argc >= 4) opts = argv[3];
            } else {
                opts = argv[2];
                is_server = 1;
                if (!janet_checktype(opts, JANET_NIL)) {
                    Janet hn = janet_get(opts, janet_ckeywordv("hostname"));
                    if (janet_checktype(hn, JANET_STRING)) {
                        hostname = (const char *)janet_unwrap_string(hn);
                        is_server = 0;
                    }
                }
            }
        } else {
            is_server = 1;
        }
        goto common_setup;
    }

    /* Determine mode from options */
    if (argc >= 2 && (janet_checktype(argv[1], JANET_TABLE) ||
                      janet_checktype(argv[1], JANET_STRUCT))) {
        Janet cert = janet_get(argv[1], janet_ckeywordv("cert"));
        Janet key = janet_get(argv[1], janet_ckeywordv("key"));

        if (!janet_checktype(cert, JANET_NIL) && !janet_checktype(key, JANET_NIL)) {
            /* Server mode */
            is_server = 1;
            opts = argv[1];
            security_opts = janet_get(opts, janet_ckeywordv("security"));
            alpn_opt = janet_get(opts, janet_ckeywordv("alpn"));

            ctx = jtls_create_server_ctx(cert, key, security_opts, alpn_opt, 1);
            if (!ctx) {
                tls_panic_ssl("failed to create server context");
            }
            
            /* Handle server-side client certificate verification (mTLS) */
            Janet verify_opt = janet_get(opts, janet_ckeywordv("verify"));
            if (janet_truthy(verify_opt)) {
                /* Require client certificate */
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
                
                /* Handle :trusted-cert option for trusting specific client certs */
                Janet trusted_cert = janet_get(opts, janet_ckeywordv("trusted-cert"));
                if (!janet_checktype(trusted_cert, JANET_NIL)) {
                    if (!jtls_add_trusted_cert(ctx, trusted_cert)) {
                        SSL_CTX_free(ctx);
                        tls_panic_ssl("failed to add trusted certificate");
                    }
                }
                
                /* Handle :ca option for CA file path */
                Janet ca_opt = janet_get(opts, janet_ckeywordv("ca"));
                if (janet_checktype(ca_opt, JANET_STRING)) {
                    const char *ca_path = (const char *)janet_unwrap_string(ca_opt);
                    if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) <= 0) {
                        SSL_CTX_free(ctx);
                        tls_panic_config("failed to load CA file: %s", ca_path);
                    }
                }
            }
        } else {
            /* Client mode with options table */
            opts = argv[1];
            goto client_setup;
        }
    } else {
        /* Client mode with hostname string */
        if (argc >= 2 && janet_checktype(argv[1], JANET_STRING)) {
            hostname = janet_getcstring(argv, 1);
            if (argc >= 3) opts = argv[2];
        }

client_setup:
        if (!janet_checktype(opts, JANET_NIL)) {
            /* Check for pre-built context first */
            Janet context_opt = janet_get(opts, janet_ckeywordv("context"));
            if (!janet_checktype(context_opt, JANET_NIL)) {
                if (janet_checkabstract(context_opt, &tls_context_type)) {
                    TLSContext *tls_ctx = (TLSContext *)janet_unwrap_abstract(context_opt);
                    ctx = tls_ctx->ctx;
                    SSL_CTX_up_ref(ctx);
                    owns_ctx = 1;
                    
                    /* Still need hostname for SNI */
                    Janet hn = janet_get(opts, janet_ckeywordv("hostname"));
                    if (janet_checktype(hn, JANET_STRING)) {
                        hostname = (const char *)janet_unwrap_string(hn);
                    }
                    
                    /* Check if context was created with verification */
                    verify = (SSL_CTX_get_verify_mode(ctx) & SSL_VERIFY_PEER) != 0;
                    
                    goto common_setup;
                }
            }
            
            Janet verify_opt = janet_get(opts, janet_ckeywordv("verify"));
            if (!janet_checktype(verify_opt, JANET_NIL)) {
                verify = janet_truthy(verify_opt);
            }
            security_opts = janet_get(opts, janet_ckeywordv("security"));
            alpn_opt = janet_get(opts, janet_ckeywordv("alpn"));
            session_opt = janet_get(opts, janet_ckeywordv("session"));

            if (!hostname) {
                Janet hn = janet_get(opts, janet_ckeywordv("hostname"));
                if (janet_checktype(hn, JANET_STRING)) {
                    hostname = (const char *)janet_unwrap_string(hn);
                }
            }
            
            /* :verify-hostname option allows verifying cert against a different hostname than SNI
             * Useful for: connecting to IP addresses with hostname certs, CDNs, load balancers */
            Janet vh = janet_get(opts, janet_ckeywordv("verify-hostname"));
            if (janet_checktype(vh, JANET_STRING)) {
                verify_hostname = (const char *)janet_unwrap_string(vh);
            }
        }

        ctx = jtls_create_client_ctx(verify, security_opts);
        if (!ctx) {
            tls_panic_ssl("failed to create client context");
        }

        /* Handle :trusted-cert option for certificate pinning */
        if (!janet_checktype(opts, JANET_NIL)) {
            Janet trusted_cert = janet_get(opts, janet_ckeywordv("trusted-cert"));
            if (!janet_checktype(trusted_cert, JANET_NIL)) {
                if (!jtls_add_trusted_cert(ctx, trusted_cert)) {
                    SSL_CTX_free(ctx);
                    tls_panic_ssl("failed to add trusted certificate");
                }
            }
            
            /* Handle client certificate for mTLS (client providing cert to server) */
            Janet client_cert = janet_get(opts, janet_ckeywordv("cert"));
            Janet client_key = janet_get(opts, janet_ckeywordv("key"));
            if (!janet_checktype(client_cert, JANET_NIL) && !janet_checktype(client_key, JANET_NIL)) {
                /* Load client certificate */
                if (!jutils_load_cert(ctx, client_cert)) {
                    SSL_CTX_free(ctx);
                    tls_panic_ssl("failed to load client certificate");
                }
                
                /* Load client private key */
                if (!jutils_load_key(ctx, client_key)) {
                    SSL_CTX_free(ctx);
                    tls_panic_ssl("failed to load client private key");
                }
                
                /* Verify key matches certificate */
                if (SSL_CTX_check_private_key(ctx) != 1) {
                    SSL_CTX_free(ctx);
                    tls_panic_ssl("client certificate and private key do not match");
                }
            }
        }
    }

common_setup:
    /* Parse buffer-size option */
    if (!janet_checktype(opts, JANET_NIL)) {
        Janet buf_size_opt = janet_get(opts, janet_ckeywordv("buffer-size"));
        if (!janet_checktype(buf_size_opt, JANET_NIL)) {
            if (!janet_checktype(buf_size_opt, JANET_NUMBER)) {
                tls_panic_param("buffer-size must be a number");
            }
            int32_t size = (int32_t)janet_unwrap_integer(buf_size_opt);
            if (size < MIN_TLS_BUFFER_SIZE) size = MIN_TLS_BUFFER_SIZE;
            if (size > MAX_TLS_BUFFER_SIZE) size = MAX_TLS_BUFFER_SIZE;
            buffer_size = size;
        }

        if (janet_checktype(session_opt, JANET_NIL)) {
            session_opt = janet_get(opts, janet_ckeywordv("session"));
        }
        if (janet_checktype(alpn_opt, JANET_NIL)) {
            alpn_opt = janet_get(opts, janet_ckeywordv("alpn"));
        }
    }

    /* Parse tcp-nodelay option (default: enabled) */
    int tcp_nodelay = 1;
    if (!janet_checktype(opts, JANET_NIL)) {
        Janet nodelay_opt = janet_get(opts, janet_ckeywordv("tcp-nodelay"));
        if (!janet_checktype(nodelay_opt, JANET_NIL)) {
            tcp_nodelay = janet_truthy(nodelay_opt);
        }
    }

    /* Parse handshake-timing option (default: disabled) */
    int track_handshake_time = 0;
    if (!janet_checktype(opts, JANET_NIL)) {
        Janet timing_opt = janet_get(opts, janet_ckeywordv("handshake-timing"));
        if (!janet_checktype(timing_opt, JANET_NIL)) {
            track_handshake_time = janet_truthy(timing_opt);
        }
    }

    /* Create the TLS stream */
    TLSStream *tls = jtls_setup_stream(transport, ctx, is_server, owns_ctx, buffer_size, tcp_nodelay, track_handshake_time);

    /* Set SNI hostname for client */
    if (hostname && !is_server) {
        SSL_set_tlsext_host_name(tls->ssl, hostname);
        /* Enable hostname verification for security
         * Use verify_hostname if provided, otherwise use hostname (SNI) */
        if (verify) {
            const char *host_to_verify = verify_hostname ? verify_hostname : hostname;
            SSL_set_hostflags(tls->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (!SSL_set1_host(tls->ssl, host_to_verify)) {
                tls_panic_verify("failed to set hostname verification for %s", host_to_verify);
            }
        }
    } else if (verify_hostname && verify && !is_server) {
        /* verify_hostname without hostname - just set hostname verification */
        SSL_set_hostflags(tls->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (!SSL_set1_host(tls->ssl, verify_hostname)) {
            tls_panic_verify("failed to set hostname verification for %s", verify_hostname);
        }
    }

    /* Set ALPN for client */
    if (!is_server && !janet_checktype(alpn_opt, JANET_NIL)) {
        unsigned int wire_len;
        unsigned char *wire = jtls_array_to_alpn_wire(alpn_opt, &wire_len);
        if (wire) {
            if (SSL_set_alpn_protos(tls->ssl, wire, wire_len) != 0) {
                janet_free(wire);
                tls_panic_ssl("failed to set ALPN protocols");
            }
            janet_free(wire);
        } else {
            tls_panic_param("invalid ALPN protocols");
        }
    }

    /* Set session for resumption (client) */
    if (!is_server && !janet_checktype(session_opt, JANET_NIL)) {
        JanetByteView session_data;
        if (janet_checktype(session_opt, JANET_STRING)) {
            session_data.bytes = janet_unwrap_string(session_opt);
            session_data.len = janet_string_length(janet_unwrap_string(session_opt));
        } else if (janet_checktype(session_opt, JANET_BUFFER)) {
            JanetBuffer *buf = janet_unwrap_buffer(session_opt);
            session_data.bytes = buf->data;
            session_data.len = buf->count;
        } else {
            session_data.bytes = NULL;
            session_data.len = 0;
        }

        if (session_data.bytes && session_data.len > 0) {
            const unsigned char *der_ptr = session_data.bytes;
            SSL_SESSION *session = d2i_SSL_SESSION(NULL, &der_ptr, session_data.len);
            if (session) {
                SSL_set_session(tls->ssl, session);
                SSL_SESSION_free(session);
            }
        }
    }

    /*
     * Start handshake immediately for wrap/upgrade.
     * This ensures that verification errors are raised at wrap time,
     * not lazily on first I/O.
     *
     * For connect(), the handshake happens during the async callback,
     * so errors are properly propagated.
     *
     * Use write_state for handshake since it's not concurrent with I/O.
     */
    TLSState *state = &tls->write_state;
    memset(state, 0, sizeof(TLSState));
    state->tls = tls;
    state->op = TLS_OP_HANDSHAKE;

    if (jtls_attempt_io(janet_current_fiber(), state, 0)) {
        return janet_wrap_abstract(tls);
    }

    /* If no transport (manual mode), return stream even if handshake incomplete */
    if (!tls->transport) {
        return janet_wrap_abstract(tls);
    }

    return janet_wrap_nil();
}

/*============================================================================
 * UPGRADE - Upgrade existing connection to TLS (STARTTLS)
 *============================================================================
 * (upgrade stream &opt config options)
 *
 * This is an alias for wrap, used for STARTTLS-style upgrades.
 */
Janet cfun_upgrade(int32_t argc, Janet *argv) {
    return cfun_wrap(argc, argv);
}

/*============================================================================
 * CONNECT - Create a TLS client connection
 *============================================================================
 * (connect host port &opt opts)
 *
 * Connect to a TLS server. Creates the TCP connection asynchronously,
 * then wraps it with TLS.
 *
 * The TCP connection uses non-blocking connect with async completion,
 * matching Janet's net/connect behavior.
 */

/* State for async TLS connect operation */
typedef struct {
    char *hostname;              /* Hostname for SNI (owned, must free) */
    Janet opts;                  /* TLS options (must mark for GC) */
} TLSConnectState;

/* Async callback for TCP connect phase */
static void tls_connect_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    JanetStream *stream = fiber->ev_stream;
    TLSConnectState *state = (TLSConnectState *)fiber->ev_state;

    switch (event) {
        default:
            break;

        case JANET_ASYNC_EVENT_MARK:
            if (state) janet_mark(state->opts);
            break;

        case JANET_ASYNC_EVENT_DEINIT:
            /* Janet will free fiber->ev_state (the state struct) automatically.
             * We only need to free the hostname string if it wasn't already freed. */
            if (state && state->hostname) {
                janet_free(state->hostname);
            }
            return;

        case JANET_ASYNC_EVENT_CLOSE:
            janet_cancel(fiber, janet_cstringv("stream closed"));
            janet_async_end(fiber);
            return;

#ifndef JANET_WINDOWS
        case JANET_ASYNC_EVENT_INIT:
            /* On non-Windows, wait for actual event before checking */
            return;
#endif

        case JANET_ASYNC_EVENT_ERR:
        case JANET_ASYNC_EVENT_HUP:
        case JANET_ASYNC_EVENT_WRITE: {
            /* Check if connect succeeded via SO_ERROR */
            int res = 0;
            socklen_t size = sizeof(res);
            int r = getsockopt(stream->handle, SOL_SOCKET, SO_ERROR, &res, &size);

            if (r != 0 || res != 0) {
                /* Connect failed */
                janet_cancel(fiber, janet_cstringv(res ? strerror(res) : "connect failed"));
                stream->flags |= JANET_STREAM_TOCLOSE;
                janet_async_end(fiber);
                return;
            }

            /* TCP connect succeeded - now set up TLS */
            /* Extract state data - Janet will free the state struct in janet_async_end */
            char *hostname = state->hostname;
            Janet opts = state->opts;
            state->hostname = NULL;  /* Prevent double-free of hostname in DEINIT */

            /* Check if a pre-created context was provided */
            SSL_CTX *ctx = NULL;
            int owns_ctx = 1;
            int verify = 1;
            
            if (!janet_checktype(opts, JANET_NIL)) {
                Janet context_opt = janet_get(opts, janet_ckeywordv("context"));
                if (janet_checktype(context_opt, JANET_ABSTRACT) &&
                    janet_checkabstract(context_opt, &tls_context_type)) {
                    TLSContext *tls_ctx = (TLSContext *)janet_unwrap_abstract(context_opt);
                    ctx = tls_ctx->ctx;
                    SSL_CTX_up_ref(ctx);
                    owns_ctx = 1;
                }
                
                Janet v = janet_get(opts, janet_ckeywordv("verify"));
                if (!janet_checktype(v, JANET_NIL)) {
                    verify = janet_truthy(v);
                }
            }
            
            /* Create context if not provided */
            if (!ctx) {
                Janet security_opts = janet_wrap_nil();
                if (!janet_checktype(opts, JANET_NIL)) {
                    security_opts = janet_get(opts, janet_ckeywordv("security"));
                }
                
                ctx = jtls_create_client_ctx(verify, security_opts);
                if (!ctx) {
                    janet_free(hostname);
                    janet_cancel(fiber, janet_cstringv("failed to create SSL context"));
                    janet_async_end(fiber);
                    return;
                }
                
                /* Handle trusted-cert option (only when creating new context) */
                if (!janet_checktype(opts, JANET_NIL)) {
                    Janet trusted_cert = janet_get(opts, janet_ckeywordv("trusted-cert"));
                    if (!janet_checktype(trusted_cert, JANET_NIL)) {
                        if (!jtls_add_trusted_cert(ctx, trusted_cert)) {
                            SSL_CTX_free(ctx);
                            janet_free(hostname);
                            janet_cancel(fiber, janet_cstringv("failed to add trusted certificate"));
                            janet_async_end(fiber);
                            return;
                        }
                    }
                }
            }
            
            /* Parse buffer-size option */
            int32_t buffer_size = DEFAULT_TLS_BUFFER_SIZE;
            if (!janet_checktype(opts, JANET_NIL)) {
                Janet buf_size_opt = janet_get(opts, janet_ckeywordv("buffer-size"));
                if (!janet_checktype(buf_size_opt, JANET_NIL)) {
                    if (janet_checktype(buf_size_opt, JANET_NUMBER)) {
                        int32_t buf_sz = (int32_t)janet_unwrap_integer(buf_size_opt);
                        if (buf_sz < MIN_TLS_BUFFER_SIZE) buf_sz = MIN_TLS_BUFFER_SIZE;
                        if (buf_sz > MAX_TLS_BUFFER_SIZE) buf_sz = MAX_TLS_BUFFER_SIZE;
                        buffer_size = buf_sz;
                    }
                }
            }
            
            /* Parse tcp-nodelay option (default: enabled) */
            int tcp_nodelay = 1;
            if (!janet_checktype(opts, JANET_NIL)) {
                Janet nodelay_opt = janet_get(opts, janet_ckeywordv("tcp-nodelay"));
                if (!janet_checktype(nodelay_opt, JANET_NIL)) {
                    tcp_nodelay = janet_truthy(nodelay_opt);
                }
            }
            
            /* Parse handshake-timing option (default: disabled) */
            int track_handshake_time = 0;
            if (!janet_checktype(opts, JANET_NIL)) {
                Janet timing_opt = janet_get(opts, janet_ckeywordv("handshake-timing"));
                if (!janet_checktype(timing_opt, JANET_NIL)) {
                    track_handshake_time = janet_truthy(timing_opt);
                }
            }
            
            /* Create TLS stream - handshake happens on first I/O */
            TLSStream *tls = jtls_setup_stream(stream, ctx, 0, owns_ctx, buffer_size, tcp_nodelay, track_handshake_time);
            
            /* Check for :hostname option to override SNI (allows connecting by IP but using hostname for SNI) */
            const char *sni_hostname = hostname;
            const char *verify_host = NULL;
            if (!janet_checktype(opts, JANET_NIL)) {
                Janet hostname_opt = janet_get(opts, janet_ckeywordv("hostname"));
                if (janet_checktype(hostname_opt, JANET_STRING)) {
                    sni_hostname = (const char *)janet_unwrap_string(hostname_opt);
                }
                /* Check for :verify-hostname to override certificate hostname verification */
                Janet verify_hostname_opt = janet_get(opts, janet_ckeywordv("verify-hostname"));
                if (janet_checktype(verify_hostname_opt, JANET_STRING)) {
                    verify_host = (const char *)janet_unwrap_string(verify_hostname_opt);
                }
            }
            
            /* Set SNI hostname */
            if (sni_hostname) {
                SSL_set_tlsext_host_name(tls->ssl, sni_hostname);
            }
            
            /* Set hostname verification - use verify-hostname if specified, otherwise use SNI hostname */
            if (verify) {
                const char *cert_verify_host = verify_host ? verify_host : sni_hostname;
                if (cert_verify_host) {
                    SSL_set_hostflags(tls->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                    SSL_set1_host(tls->ssl, cert_verify_host);
                }
            }
            
            /* Free hostname */
            janet_free(hostname);

            /* Schedule fiber with result - handshake will happen on first I/O */
            janet_schedule(fiber, janet_wrap_abstract(tls));
            janet_async_end(fiber);
            return;
        }
    }
}

Janet cfun_connect(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    /* Check for unix socket mode: (connect :unix path &opt opts) */
    int is_unix = janet_checktype(argv[0], JANET_KEYWORD) &&
                  !strcmp((const char *)janet_unwrap_keyword(argv[0]), "unix");
    
    const char *host;
    const char *port = NULL;
    const char *unix_path = NULL;
    Janet opts = janet_wrap_nil();
    
    if (is_unix) {
        /* Unix socket mode */
        unix_path = janet_getcstring(argv, 1);
        host = "localhost";  /* For SNI, not used in connection */
        if (argc >= 3) opts = argv[2];
    } else {
        /* TCP mode */
        host = janet_getcstring(argv, 0);
        /* Handle port as string or integer (like Janet's net/connect) */
        if (janet_checktype(argv[1], JANET_NUMBER)) {
            port = (const char *)janet_to_string(argv[1]);
        } else {
            port = janet_getcstring(argv, 1);
        }
        if (argc >= 3) opts = argv[2];
    }

    int fd = -1;
    int status;
    
    if (is_unix) {
        /* Unix socket connection */
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path) - 1);
        
        /* Support Linux abstract namespace sockets (start with @) */
#ifdef __linux__
        if (unix_path[0] == '@') {
            addr.sun_path[0] = '\0';
        }
#endif
        
#ifdef __linux__
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd != -1) {
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            flags = fcntl(fd, F_GETFD, 0);
            if (flags != -1) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
#endif
        if (fd == -1) {
            tls_panic_socket("could not create unix socket");
        }
        
        socklen_t addrlen = sizeof(addr);
#ifdef __linux__
        if (unix_path[0] == '@') {
            addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(unix_path));
        }
#endif
        
        do {
            status = connect(fd, (struct sockaddr *)&addr, addrlen);
        } while (status == -1 && errno == EINTR);
        
        if (status == 0) {
            /* Connected immediately */
            JanetStream *stream = janet_stream(fd, JANET_STREAM_SOCKET |
                JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

            /* Wrap with TLS - use hostname from opts if provided, else "localhost" */
            const char *sni_host = host;
            if (!janet_checktype(opts, JANET_NIL)) {
                JanetTable *opts_tbl = NULL;
                JanetStruct opts_struct = NULL;
                if (janet_checktype(opts, JANET_TABLE)) {
                    opts_tbl = janet_unwrap_table(opts);
                    Janet hostname_val = janet_table_get(opts_tbl, janet_ckeywordv("hostname"));
                    if (janet_checktype(hostname_val, JANET_STRING)) {
                        sni_host = (const char *)janet_unwrap_string(hostname_val);
                    }
                } else if (janet_checktype(opts, JANET_STRUCT)) {
                    opts_struct = janet_unwrap_struct(opts);
                    Janet hostname_val = janet_struct_get(opts_struct, janet_ckeywordv("hostname"));
                    if (janet_checktype(hostname_val, JANET_STRING)) {
                        sni_host = (const char *)janet_unwrap_string(hostname_val);
                    }
                }
            }
            
            Janet wrap_args[3];
            wrap_args[0] = janet_wrap_abstract(stream);
            wrap_args[1] = janet_cstringv(sni_host);
            wrap_args[2] = opts;

            return cfun_wrap(3, wrap_args);
        } else if (errno != EINPROGRESS) {
            close(fd);
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "could not connect to unix socket %s: %s", unix_path, strerror(errno));
        }
        /* else EINPROGRESS - fall through to async handling */
    } else {
        /* TCP connection - DNS resolution (blocking, same as Janet's net/connect) */
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo *ai = NULL;
        status = getaddrinfo(host, port, &hints, &ai);
        if (status != 0) {
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "could not get address info: %s", gai_strerror(status));
        }

        /* Try addresses until we get one that starts connecting */
        struct addrinfo *rp;
        for (rp = ai; rp != NULL; rp = rp->ai_next) {
            /* Create socket with non-blocking from the start */
#ifdef __linux__
            fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, rp->ai_protocol);
#else
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd != -1) {
                int flags = fcntl(fd, F_GETFL, 0);
                if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                flags = fcntl(fd, F_GETFD, 0);
                if (flags != -1) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
            }
#endif
            if (fd == -1) continue;

            /* Attempt non-blocking connect */
            do {
                status = connect(fd, rp->ai_addr, rp->ai_addrlen);
            } while (status == -1 && errno == EINTR);

            if (status == 0) {
                /* Connected immediately (rare, but possible on localhost) */
                freeaddrinfo(ai);
                
                JanetStream *stream = janet_stream(fd, JANET_STREAM_SOCKET |
                    JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

                /* Wrap with TLS synchronously */
                Janet wrap_args[3];
                wrap_args[0] = janet_wrap_abstract(stream);
                wrap_args[1] = janet_cstringv(host);
                wrap_args[2] = opts;

                return cfun_wrap(3, wrap_args);
            } else if (errno == EINPROGRESS) {
                /* Connection in progress - normal async case */
                break;
            } else {
                /* This address failed immediately, try next */
                close(fd);
                fd = -1;
            }
        }
        freeaddrinfo(ai);
    }

    if (fd == -1) {
        if (is_unix) {
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "could not connect to unix socket %s", unix_path);
        } else {
            jsec_panic(JSEC_MOD_TLS, "SOCKET", "could not connect to %s:%s", host, port);
        }
    }

    /* Create stream for async connect completion */
    JanetStream *stream = janet_stream(fd, JANET_STREAM_SOCKET |
        JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

    /* Create state for async callback */
    TLSConnectState *state = janet_malloc(sizeof(TLSConnectState));
    if (!state) {
        janet_stream_close(stream);
        tls_panic_config("failed to allocate TLS connect state");
    }
    size_t host_len = strlen(host);
    state->hostname = janet_malloc(host_len + 1);
    if (!state->hostname) {
        janet_free(state);
        janet_stream_close(stream);
        tls_panic_config("failed to allocate hostname buffer");
    }
    memcpy(state->hostname, host, host_len + 1);
    state->opts = opts;

    /* Start async wait for connect completion */
    janet_async_start(stream, JANET_ASYNC_LISTEN_WRITE, tls_connect_callback, state);

    /* Fiber is suspended - this should not return */
    janet_panic("unreachable");
}
