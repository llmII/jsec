/*
 * server.c - DTLS server implementation
 *
 * Provides UDP-style API for DTLS servers:
 *   dtls/listen    - Create server bound to address
 *   dtls/recv-from - Receive from any peer, returns [data addr]
 *   dtls/send-to   - Send to specific peer
 *
 * Architecture:
 * - Single UDP socket receives all datagrams
 * - Connection table maps peer addresses to SSL sessions
 * - New peers go through cookie exchange (DoS protection)
 * - Sessions timeout after inactivity
 *
 * This matches Janet's net/recv-from and net/send-to conventions.
 */

#include "internal.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* MSG_DONTWAIT may not be available on all platforms.
 * Since our sockets are already non-blocking, we can use 0 as fallback. */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/*
 * Send pending data from session's write BIO to peer.
 * Returns bytes sent, or -1 on error.
 * This consolidates the repeated sendto() pattern.
 */
static ssize_t send_dtls_packet(JanetStream *transport,
                                DTLSSession *session) {
    size_t pending = BIO_ctrl_pending(session->wbio);
    if (pending == 0) {
        return 0;
    }

    uint8_t *send_buf = janet_malloc(pending);
    if (!send_buf) {
        return -1;
    }

    int send_len = BIO_read(session->wbio, send_buf, (int)pending);
    ssize_t sent = 0;

    if (send_len > 0) {
        sent = sendto(transport->handle, send_buf, (size_t)send_len, 0,
                      (struct sockaddr *)&session->peer_addr.addr,
                      session->peer_addr.addrlen);
    }

    janet_free(send_buf);
    return sent;
}

/*
 * =============================================================================
 * DTLSServer Abstract Type
 * =============================================================================
 */

static int dtls_server_gc(void *p, size_t s) {
    (void)s;
    DTLSServer *server = (DTLSServer *)p;

    /* Free all sessions */
    for (int i = 0; i < DTLS_SESSION_TABLE_SIZE; i++) {
        DTLSSession *session = server->sessions[i];
        while (session) {
            DTLSSession *next = session->next;
            dtls_session_free(session);
            session = next;
        }
        server->sessions[i] = NULL;
    }

    if (server->ctx) {
        SSL_CTX_free(server->ctx);
        server->ctx = NULL;
    }

    /* Transport is GC managed */
    return 0;
}

static int dtls_server_mark(void *p, size_t s) {
    (void)s;
    DTLSServer *server = (DTLSServer *)p;

    if (server->transport) {
        janet_mark(janet_wrap_abstract(server->transport));
    }

    return 0;
}

/* Forward declarations for server methods */
static Janet cfun_dtls_recv_from(int32_t argc, Janet *argv);
static Janet cfun_dtls_send_to(int32_t argc, Janet *argv);
static Janet cfun_dtls_close_server(int32_t argc, Janet *argv);
static Janet cfun_dtls_server_localname(int32_t argc, Janet *argv);

/* Method table for DTLSServer - matches Janet's UDP pattern */
const JanetMethod dtls_server_methods[] = {
    {"recv-from", cfun_dtls_recv_from},
    {"send-to", cfun_dtls_send_to},
    {"close", cfun_dtls_close_server},
    {"localname", cfun_dtls_server_localname},
    {NULL, NULL}
};

/* Method dispatch using janet_getmethod like TLS does */
static int dtls_server_get(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD)) return 0;
    return janet_getmethod(janet_unwrap_keyword(key), dtls_server_methods, out);
}

const JanetAbstractType dtls_server_type = {
    "jsec/dtls-server",
    dtls_server_gc,
    dtls_server_mark,
    dtls_server_get,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    JANET_ATEND_HASH
};

/*
 * =============================================================================
 * Cookie Callbacks for OpenSSL
 * =============================================================================
 */

/* Generate stateless cookie based on client address */
static int server_generate_cookie(SSL *ssl, unsigned char *cookie,
                                  unsigned int *cookie_len) {
    /* Get peer address from BIO */
    BIO *bio = SSL_get_rbio(ssl);
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } peer;
    socklen_t peerlen = sizeof(peer);

    /* For memory BIO, peer address should be stored in ex_data */
    DTLSAddress *addr = SSL_get_ex_data(ssl, 0);
    if (addr) {
        memcpy(&peer, &addr->addr, addr->addrlen);
        peerlen = addr->addrlen;
    } else if (BIO_dgram_get_peer(bio, &peer) <= 0) {
        /* Can't determine peer - generate random cookie */
        RAND_bytes(cookie, 32);
        *cookie_len = 32;
        return 1;
    }

    /* Simple HMAC of peer address */
    static unsigned char secret[32];
    static int secret_init = 0;
    if (!secret_init) {
        RAND_bytes(secret, sizeof(secret));
        secret_init = 1;
    }

    unsigned int len = 0;
    HMAC(EVP_sha256(), secret, sizeof(secret),
         (unsigned char *)&peer, peerlen, cookie, &len);
    *cookie_len = len;
    return 1;
}

static int server_verify_cookie(SSL *ssl, const unsigned char *cookie,
                                unsigned int cookie_len) {
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len;

    if (!server_generate_cookie(ssl, expected, &expected_len)) {
        return 0;
    }

    if (cookie_len != expected_len) {
        return 0;
    }

    return CRYPTO_memcmp(cookie, expected, cookie_len) == 0;
}

/*
 * =============================================================================
 * Server Creation
 * =============================================================================
 */

/*
 * (dtls/listen host port &opt opts)
 *
 * Create a DTLS server listening on the specified address.
 * Returns a DTLSServer object.
 *
 * Options:
 *   :cert - Server certificate (required)
 *   :key - Server private key (required)
 *   :verify - Require client certificates (default false)
 *   :ca - CA certificates for client verification
 *   :session-timeout - Session timeout in seconds (default 300)
 */
static Janet cfun_dtls_listen(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    const char *host = janet_getcstring(argv, 0);
    int port;

    if (janet_checktype(argv[1], JANET_STRING)) {
        const char *port_str = (const char *)janet_unwrap_string(argv[1]);
        char *endptr;
        long port_val = strtol(port_str, &endptr, 10);
        if (*endptr != '\0' || port_val < 0 || port_val > 65535) {
            dtls_panic_param("invalid port: %s", port_str);
        }
        port = (int)port_val;
    } else {
        port = janet_getinteger(argv, 1);
    }

    Janet opts = argc > 2 ? argv[2] : janet_wrap_nil();

    /* Create UDP socket */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        dtls_panic_socket("failed to create socket");
    }

    /* Set socket options */
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (strcmp(host, "0.0.0.0") == 0 || strlen(host) == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        dtls_panic_param("invalid address: %s", host);
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        dtls_panic_socket("bind failed");
    }

    /* Wrap as Janet stream */
    JanetStream *transport = janet_stream(fd,
                                          JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

    /* Create DTLS server */
    DTLSServer *server = janet_abstract(&dtls_server_type, sizeof(DTLSServer));
    memset(server, 0, sizeof(DTLSServer));

    /* Initialize embedded JanetStream for method dispatch */
    server->stream.handle =
        JANET_HANDLE_NONE;  /* We don't own the handle directly */
    server->stream.flags = JANET_STREAM_READABLE | JANET_STREAM_WRITABLE;
    server->stream.methods = dtls_server_methods;

    server->transport = transport;
    server->session_timeout = DTLS_SESSION_TIMEOUT;

    /* Get session timeout from options */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet t = janet_get(opts, janet_ckeywordv("session-timeout"));
        if (!janet_checktype(t, JANET_NIL)) {
            server->session_timeout = janet_unwrap_number(t);
        }
    }

    /* Create SSL context */
    server->ctx = SSL_CTX_new(DTLS_server_method());
    if (!server->ctx) {
        dtls_panic_ssl("failed to create SSL context");
    }

    /* Enable session resumption */
    static const unsigned char sid_ctx[] = "jsec-dtls-server";
    SSL_CTX_set_session_id_context(server->ctx, sid_ctx, sizeof(sid_ctx) - 1);

    /* Set cookie callbacks */
    SSL_CTX_set_cookie_generate_cb(server->ctx, server_generate_cookie);
    SSL_CTX_set_cookie_verify_cb(server->ctx, server_verify_cookie);

    /* Apply security options */
    Janet security = janet_wrap_nil();
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        security = janet_get(opts, janet_ckeywordv("security"));
    }
    apply_security_options(server->ctx, security, 1);  /* is_dtls = 1 */

    /* Load certificate and key (required for server) */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet cert = janet_get(opts, janet_ckeywordv("cert"));
        Janet key = janet_get(opts, janet_ckeywordv("key"));

        if (janet_checktype(cert, JANET_NIL) || janet_checktype(key, JANET_NIL)) {
            dtls_panic_config("dtls/listen requires :cert and :key options");
        }

        /* Load certificate */
        if (!jutils_load_cert(server->ctx, cert)) {
            dtls_panic_ssl("failed to load certificate");
        }

        /* Load private key */
        if (!jutils_load_key(server->ctx, key)) {
            dtls_panic_ssl("failed to load private key");
        }

        /* Verify key matches certificate */
        if (!SSL_CTX_check_private_key(server->ctx)) {
            dtls_panic_ssl("private key does not match certificate");
        }

        /* Client verification */
        Janet verify = janet_get(opts, janet_ckeywordv("verify"));
        if (janet_truthy(verify)) {
            SSL_CTX_set_verify(server->ctx,
                               SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               NULL);

            /* Handle :trusted-cert option for trusting specific client certs */
            Janet trusted_cert = janet_get(opts, janet_ckeywordv("trusted-cert"));
            if (!janet_checktype(trusted_cert, JANET_NIL)) {
                if (!add_trusted_cert(server->ctx, trusted_cert)) {
                    SSL_CTX_free(server->ctx);
                    server->ctx = NULL;
                    dtls_panic_ssl("failed to add trusted certificate");
                }
            }

            /* Handle :ca option for CA file path */
            Janet ca = janet_get(opts, janet_ckeywordv("ca"));
            if (!janet_checktype(ca, JANET_NIL)) {
                if (!jutils_load_ca(server->ctx, ca)) {
                    dtls_panic_ssl("failed to load CA certificates");
                }
            }
        }
    } else {
        dtls_panic_config("dtls/listen requires options with :cert and :key");
    }

    return janet_wrap_abstract(server);
}

/*
 * =============================================================================
 * Async State for recv-from
 * =============================================================================
 */

typedef struct {
    DTLSServer *server;
    JanetBuffer *buffer;
    int32_t nbytes;
    double timeout;
} DTLSRecvFromState;

/*
 * Process received datagram, demultiplex to session.
 *
 * State transitions:
 *   New peer      -> Create session, start handshake
 *   Handshaking   -> Continue handshake, send response if needed
 *   Established   -> Read application data
 *   Peer closes   -> Send close_notify, remove session
 *
 * Returns:
 *   - Address abstract type on success (data appended to out_buf)
 *   - nil if handshake in progress or no data yet
 *
 * This matches Janet's net/recv-from convention: returns address,
 * data is placed in the provided buffer.
 */
static Janet process_datagram(DTLSServer *server, uint8_t *data, int datalen,
                              DTLSAddress *peer_addr, JanetBuffer *out_buf) {
    /* Look up or create session for this peer */
    DTLSSession *session = dtls_server_get_session(server, peer_addr);

    if (!session) {
        /* New connection - create session */
        session = dtls_server_create_session(server, peer_addr);
        if (!session) {
            return janet_wrap_nil();  /* Out of memory or other error */
        }
        /* Store peer address in SSL ex_data for cookie generation */
        SSL_set_ex_data(session->ssl, 0, &session->peer_addr);
    }

    /* Feed incoming data to SSL via memory BIO */
    if (BIO_write(session->rbio, data, datalen) <= 0) {
        return janet_wrap_nil();
    }

    session->last_activity = get_current_time();

    /* Handle handshake if not yet established */
    if (session->state == DTLS_STATE_IDLE ||
        session->state == DTLS_STATE_HANDSHAKING) {
        session->state = DTLS_STATE_HANDSHAKING;
        int ret = SSL_do_handshake(session->ssl);

        if (ret == 1) {
            session->state = DTLS_STATE_ESTABLISHED;
        } else {
            int err = SSL_get_error(session->ssl, ret);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                /* Handshake failed - clean up */
                dtls_server_remove_session(server, peer_addr);
                return janet_wrap_nil();
            }
        }

        /* Send any handshake response data */
        send_dtls_packet(server->transport, session);

        if (session->state != DTLS_STATE_ESTABLISHED) {
            return janet_wrap_nil();  /* Handshake still in progress */
        }
        /* Fall through - handshake complete, may have application data */
    }

    /* Read application data from established session */
    if (session->state == DTLS_STATE_ESTABLISHED) {
        int nread = SSL_read(session->ssl, out_buf->data + out_buf->count,
                             out_buf->capacity - out_buf->count);

        if (nread > 0) {
            out_buf->count += nread;
            /* Return address (data is in buffer per Janet convention) */
            DTLSAddress *ret_addr = janet_abstract(&dtls_address_type,
                                                   sizeof(DTLSAddress));
            memcpy(ret_addr, peer_addr, sizeof(DTLSAddress));
            return janet_wrap_abstract(ret_addr);
        }

        /* Handle peer close */
        if (SSL_get_error(session->ssl, nread) == SSL_ERROR_ZERO_RETURN) {
            SSL_shutdown(session->ssl);
            send_dtls_packet(server->transport, session);  /* Send close_notify */
            dtls_server_remove_session(server, peer_addr);
        }
    }

    return janet_wrap_nil();
}

/*
 * Async callback for recv-from operation.
 *
 * State transitions:
 *   INIT     -> Ready to receive, waiting for READ event
 *   READ     -> Process datagram(s), return data or re-register
 *   MARK     -> Mark GC roots during collection
 *   CLOSE/ERR/HUP -> Cancel operation, clean up
 *   DEINIT   -> Final cleanup (state may be NULL)
 *
 * The callback processes all available datagrams in a loop to handle
 * the case where session resumption causes handshake + app data to
 * arrive in rapid succession.
 */
static void dtls_recv_from_callback(JanetFiber *fiber,
                                    JanetAsyncEvent event) {
    DTLSRecvFromState *state = (DTLSRecvFromState *)fiber->ev_state;

    /* State may be NULL after mode switch (stolen for re-registration) */
    if (!state && event != JANET_ASYNC_EVENT_DEINIT) {
        return;
    }

    switch (event) {
        case JANET_ASYNC_EVENT_DEINIT:
            break;

        case JANET_ASYNC_EVENT_MARK:
            if (state) {
                janet_mark(janet_wrap_abstract(state->server));
                if (state->buffer) {
                    janet_mark(janet_wrap_buffer(state->buffer));
                }
            }
            break;

        case JANET_ASYNC_EVENT_CLOSE:
        case JANET_ASYNC_EVENT_ERR:
        case JANET_ASYNC_EVENT_HUP:
            janet_cancel(fiber, janet_cstringv("server closed"));
            janet_async_end(fiber);
            return;

        case JANET_ASYNC_EVENT_INIT:
        case JANET_ASYNC_EVENT_READ: {
                DTLSServer *server = state->server;

                /* Process all available datagrams */
                while (1) {
                    uint8_t recv_buf[65536];
                    DTLSAddress peer_addr;
                    peer_addr.addrlen = sizeof(peer_addr.addr);

                    ssize_t n = recvfrom(server->transport->handle, recv_buf, sizeof(recv_buf),
                                         MSG_DONTWAIT,
                                         (struct sockaddr *)&peer_addr.addr, &peer_addr.addrlen);

                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            /* No more data available - just return and wait for
                             * the next READ event. The fiber is already registered
                             * for JANET_ASYNC_LISTEN_READ. */
                            break;  /* Exit loop, stay registered */
                        }
                        janet_cancel(fiber, janet_cstringv(strerror(errno)));
                        janet_async_end(fiber);
                        return;
                    }

                    /* Cleanup expired sessions periodically */
                    dtls_server_cleanup_expired(server, get_current_time());

                    /* Process datagram - may be handshake or app data */
                    Janet result = process_datagram(server, recv_buf, (int)n, &peer_addr,
                                                    state->buffer);

                    if (janet_checktype(result, JANET_ABSTRACT)) {
                        /* Got application data - return to caller */
                        janet_schedule(fiber, result);
                        janet_async_end(fiber);
                        return;
                    }
                    /* Handshake packet processed - check for more */
                }
                break;
            }

        default:
            break;
    }
}

/*
 * (dtls/recv-from server nbytes buf &opt timeout-or-opts)
 *
 * Receive a datagram from any peer.
 * Returns the peer address (data is placed in buf).
 * This matches Janet's net/recv-from convention.
 *
 * The last optional argument can be:
 *   - A number (timeout in seconds)
 *   - A table/struct with :timeout key
 */
static Janet cfun_dtls_recv_from(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);

    DTLSServer *server = janet_getabstract(argv, 0, &dtls_server_type);
    int32_t nbytes = janet_getinteger(argv, 1);
    JanetBuffer *buf = janet_getbuffer(argv, 2);

    if (server->closed) {
        return janet_wrap_nil();
    }

    /* Ensure buffer capacity */
    janet_buffer_ensure(buf, buf->count + nbytes, 2);

    /* Get timeout - can be number or table/struct with :timeout */
    double timeout = -1;
    if (argc > 3 && !janet_checktype(argv[3], JANET_NIL)) {
        if (janet_checktype(argv[3], JANET_NUMBER)) {
            timeout = janet_unwrap_number(argv[3]);
        } else if (janet_checktype(argv[3], JANET_TABLE) ||
                   janet_checktype(argv[3], JANET_STRUCT)) {
            Janet t = janet_get(argv[3], janet_ckeywordv("timeout"));
            if (!janet_checktype(t, JANET_NIL)) {
                timeout = janet_unwrap_number(t);
            }
        }
    }

    /* Add timeout if specified */
    if (timeout >= 0) {
        janet_addtimeout(timeout);
    }

    /* Start async receive */
    DTLSRecvFromState *state = janet_malloc(sizeof(DTLSRecvFromState));
    state->server = server;
    state->buffer = buf;
    state->nbytes = nbytes;
    state->timeout = timeout;

    janet_async_start(server->transport, JANET_ASYNC_LISTEN_READ,
                      dtls_recv_from_callback, state);

    return janet_wrap_nil();  /* Will be replaced by async result */
}

/*
 * (dtls/send-to server addr data &opt timeout)
 *
 * Send a datagram to a specific peer.
 * The peer must have an established session (from previous recv-from).
 */
static Janet cfun_dtls_send_to(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);

    DTLSServer *server = janet_getabstract(argv, 0, &dtls_server_type);
    DTLSAddress *addr = janet_getabstract(argv, 1, &dtls_address_type);
    JanetByteView data = janet_getbytes(argv, 2);

    if (server->closed) {
        dtls_panic_io("server is closed");
    }

    /* Look up session */
    DTLSSession *session = dtls_server_get_session(server, addr);
    if (!session) {
        dtls_panic_io("no session for peer address");
    }

    if (session->state != DTLS_STATE_ESTABLISHED) {
        dtls_panic_io("session not established");
    }

    /* Encrypt data via SSL */
    int ret = SSL_write(session->ssl, data.bytes, data.len);
    if (ret <= 0) {
        dtls_panic_ssl("SSL_write failed");
    }

    /* Send encrypted data to peer */
    ssize_t sent = send_dtls_packet(server->transport, session);
    if (sent < 0) {
        dtls_panic_socket("sendto failed");
    }

    session->last_activity = get_current_time();

    return janet_wrap_abstract(server);
}

/*
 * (dtls/close-server server &opt force)
 *
 * Close the DTLS server and all sessions.
 * If force is true, skip sending close_notify alerts.
 * Otherwise, sends close_notify to all established sessions (best effort, non-blocking).
 */
static Janet cfun_dtls_close_server(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    DTLSServer *server = janet_getabstract(argv, 0, &dtls_server_type);
    int force = argc > 1 && janet_truthy(argv[1]);

    if (server->closed) {
        return janet_wrap_nil();
    }

    server->closed = 1;

    /* Close all sessions - send close_notify unless forced */
    for (int i = 0; i < DTLS_SESSION_TABLE_SIZE; i++) {
        DTLSSession *session = server->sessions[i];
        while (session) {
            DTLSSession *next = session->next;
            if (session->state == DTLS_STATE_ESTABLISHED && !force) {
                /* Send close_notify (non-blocking, best effort) */
                SSL_shutdown(session->ssl);
                send_dtls_packet(server->transport, session);
            }
            dtls_session_free(session);
            session = next;
        }
        server->sessions[i] = NULL;
    }
    server->session_count = 0;

    /* Close transport */
    if (server->transport) {
        janet_stream_close(server->transport);
    }

    return janet_wrap_nil();
}

/*
 * (dtls/localname server)
 *
 * Get the local address the server is bound to.
 */
static Janet cfun_dtls_server_localname(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    DTLSServer *server = janet_getabstract(argv, 0, &dtls_server_type);

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    if (getsockname(server->transport->handle, (struct sockaddr *)&addr,
                    &addrlen) < 0) {
        dtls_panic_socket("getsockname failed");
    }

    /* Create address tuple like Janet's net/localname */
    char host[INET6_ADDRSTRLEN];
    uint16_t port = 0;

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
        port = ntohs(sin->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
        port = ntohs(sin6->sin6_port);
    } else {
        dtls_panic_param("unknown address family");
    }

    /* Return [host port] tuple */
    Janet *tuple = janet_tuple_begin(2);
    tuple[0] = janet_cstringv(host);
    tuple[1] = janet_wrap_integer(port);
    return janet_wrap_tuple(janet_tuple_end(tuple));
}

/*
 * Method dispatch
 */
/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

static const JanetReg server_cfuns[] = {
    {
        "listen", cfun_dtls_listen,
        "(dtls/listen host port &opt opts)\n\n"
        "Create a DTLS server listening on the specified address.\n"
        "Returns a DTLSServer object.\n\n"
        "Options:\n"
        "  :cert - Server certificate (required)\n"
        "  :key - Server private key (required)\n"
        "  :verify - Require client certificates (default false)\n"
        "  :ca - CA certificates for client verification\n"
        "  :session-timeout - Session timeout in seconds (default 300)"
    },
    {
        "recv-from", cfun_dtls_recv_from,
        "(dtls/recv-from server nbytes buf &opt timeout-or-opts)\n\n"
        "Receive a datagram from any peer.\n"
        "Returns the peer address. Data is placed in buf.\n"
        "Handles handshakes transparently - only returns when application data is ready.\n"
        "The last arg can be a number (timeout) or table/struct with :timeout key.\n"
        "Matches Janet's net/recv-from convention."
    },
    {
        "send-to", cfun_dtls_send_to,
        "(dtls/send-to server addr data &opt timeout)\n\n"
        "Send a datagram to a specific peer.\n"
        "The peer must have an established session."
    },
    {
        "close-server", cfun_dtls_close_server,
        "(dtls/close-server server &opt force)\n\n"
        "Close the DTLS server and all sessions.\n"
        "Sends close_notify to all established sessions unless force is true.\n"
        "Close notifications are non-blocking (best effort)."
    },
    {
        "localname", cfun_dtls_server_localname,
        "(dtls/localname server)\n\n"
        "Get the local address the server is bound to.\n"
        "Returns [host port] tuple."
    },
    {NULL, NULL, NULL}
};

void jdtls_register_server(JanetTable *env) {
    janet_register_abstract_type(&dtls_server_type);
    janet_cfuns(env, "jsec/dtls", server_cfuns);
}
