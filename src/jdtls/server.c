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
#include <math.h>
#include <string.h>
#include <fcntl.h>
#ifndef JANET_WINDOWS
#include <unistd.h>
#endif

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
 * Record sequence alignment for sessions admitted through the cookie
 * gate (RFC 6347 section 4.2.1).
 *
 * The verified resend that admits a session carries the wire record
 * sequence its epoch-0 stream has reached - 1 in a single-round
 * exchange, larger when a multi-round cookie exchange advanced the
 * client's counter - and the initial ServerHello MUST echo that
 * number. The session's own write counter restarts at 1 (the
 * discarded in-session HelloVerifyRequest consumed sequence 0), so
 * outbound epoch-0 record headers are rewritten with the constant
 * offset established at admit time. Epoch-0 handshake records carry
 * no MAC over the header and the handshake hashes cover message
 * bodies only, so the rewrite is integrity-neutral. Epoch-1 records
 * (MAC/AEAD over the sequence number) are never touched, and neither
 * is handshake message_seq.
 */
static void server_align_outbound_records(DTLSSession *session, uint8_t *data,
                                          int len) {
    int o = 0;
    if (session->rec_seq_off == 0) {
        return;
    }
    while (o + 13 <= len) {
        int rl = (data[o + 11] << 8) | data[o + 12];
        int end = o + 13 + rl;
        int epoch;
        if (end > len) {
            end = len;
        }
        epoch = (data[o + 3] << 8) | data[o + 4];
        if (epoch == 0) {
            uint64_t rs = 0;
            int i;
            for (i = 5; i < 11; i++) {
                rs = (rs << 8) | data[o + i];
            }
            rs = (rs + session->rec_seq_off) & 0xffffffffffffULL;
            for (i = 10; i >= 5; i--) {
                data[o + i] = (uint8_t)(rs & 0xff);
                rs >>= 8;
            }
        }
        o = end;
    }
}

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
        server_align_outbound_records(session, send_buf, send_len);
        sent = sendto((jsec_socket_t)transport->handle,
                      (const char *)send_buf, (size_t)send_len, 0,
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
    {NULL, NULL}};

/* Method dispatch using janet_getmethod like TLS does */
static int dtls_server_get(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD)) return 0;
    return janet_getmethod(janet_unwrap_keyword(key), dtls_server_methods,
                           out);
}

const JanetAbstractType dtls_server_type = {"jsec/dtls-server",
                                            dtls_server_gc,
                                            dtls_server_mark,
                                            dtls_server_get,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            JANET_ATEND_HASH};

/*
 * =============================================================================
 * Cookie Generation and Verification (DoS protection)
 * =============================================================================
 * A cookie is the canonical endpoint identity of the peer (family, port,
 * address, scope_id - the identity src/jdtls/address.c compares and
 * hashes, never raw sockaddr bytes) followed by an HMAC of those fields
 * under a per-process secret. The HMAC binds the full identity; a resend
 * verifies when the HMAC holds and the cookie's bound family, address
 * and scope match the presenting datagram, so a client whose source port
 * rebinds between flights still passes.
 */

/* Dedicated SSL ex_data index for the peer DTLSAddress. Reserved
 * index 0 belongs to SSL_set_app_data and must not be clobbered. */
static int dtls_peer_addr_ex_index = -1;

static unsigned char server_cookie_secret[32];
static int server_cookie_secret_ready = 0;

static int server_cookie_init_secret(void) {
    if (!server_cookie_secret_ready) {
        if (RAND_bytes(server_cookie_secret,
                       sizeof(server_cookie_secret)) != 1) {
            return 0;
        }
        server_cookie_secret_ready = 1;
    }
    return 1;
}

/* Serialize the canonical endpoint identity fields of addr (family,
 * port, address, scope_id) into out. Returns the serialized length, or
 * 0 when the family has no canonical identity. */
static size_t server_cookie_identity(const DTLSAddress *addr,
                                     unsigned char *out) {
    uint32_t fam = htonl((uint32_t)addr->addr.ss_family);
    size_t n = 0;
    memcpy(out + n, &fam, sizeof(fam));
    n += sizeof(fam);
    if (addr->addr.ss_family == AF_INET) {
        const struct sockaddr_in *sin =
            (const struct sockaddr_in *)&addr->addr;
        memcpy(out + n, &sin->sin_port, sizeof(sin->sin_port));
        n += sizeof(sin->sin_port);
        memcpy(out + n, &sin->sin_addr, sizeof(sin->sin_addr));
        n += sizeof(sin->sin_addr);
        return n;
    }
    if (addr->addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 =
            (const struct sockaddr_in6 *)&addr->addr;
        memcpy(out + n, &sin6->sin6_port, sizeof(sin6->sin6_port));
        n += sizeof(sin6->sin6_port);
        memcpy(out + n, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
        n += sizeof(sin6->sin6_addr);
        memcpy(out + n, &sin6->sin6_scope_id, sizeof(sin6->sin6_scope_id));
        n += sizeof(sin6->sin6_scope_id);
        return n;
    }
    return 0;
}

/* Generate a cookie for the peer: identity fields then HMAC. Returns 0
 * when the identity cannot be canonicalized or the RNG or HMAC fails,
 * so no cookie is emitted from an uninitialized secret or partial
 * buffer. */
static int server_cookie_generate(const DTLSAddress *addr,
                                  unsigned char *cookie,
                                  unsigned int *cookie_len) {
    unsigned char identity[32];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    size_t id_len;

    *cookie_len = 0;
    id_len = server_cookie_identity(addr, identity);
    if (id_len == 0 || id_len + 32 > 255) {
        return 0;
    }
    if (!server_cookie_init_secret()) {
        return 0;
    }
    if (HMAC(EVP_sha256(), server_cookie_secret,
             (int)sizeof(server_cookie_secret), identity, id_len, mac,
             &mac_len) == NULL) {
        return 0;
    }
    if (mac_len != 32) {
        return 0;
    }
    memcpy(cookie, identity, id_len);
    memcpy(cookie + id_len, mac, mac_len);
    *cookie_len = (unsigned int)id_len + mac_len;
    return 1;
}

/* Verify a cookie presented by the peer. The HMAC must cover the
 * identity carried in the cookie, and that identity must match the
 * presenting datagram on family, address and scope_id. */
static int server_cookie_verify(const DTLSAddress *addr,
                                const unsigned char *cookie,
                                unsigned int cookie_len) {
    unsigned char identity[32];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    uint32_t fam;
    size_t id_len, n;

    if (cookie_len < 4 + 32) {
        return 0;
    }
    memcpy(&fam, cookie, sizeof(fam));
    fam = ntohl(fam);
    if (fam == (uint32_t)AF_INET) {
        id_len = 4 + 2 + 4;
    } else if (fam == (uint32_t)AF_INET6) {
        id_len = 4 + 2 + 16 + 4;
    } else {
        return 0;
    }
    if ((size_t)cookie_len != id_len + 32) {
        return 0;
    }
    if (!server_cookie_init_secret()) {
        return 0;
    }
    if (HMAC(EVP_sha256(), server_cookie_secret,
             (int)sizeof(server_cookie_secret), cookie, id_len, mac,
             &mac_len) == NULL) {
        return 0;
    }
    if (mac_len != 32) {
        return 0;
    }
    if (CRYPTO_memcmp(mac, cookie + id_len, 32) != 0) {
        return 0;
    }
    n = server_cookie_identity(addr, identity);
    if (n != id_len || memcmp(identity, cookie, 4) != 0) {
        return 0;
    }
    return memcmp(identity + 6, cookie + 6, id_len - 6) == 0;
}

/* Generate stateless cookie based on client address */
static int server_generate_cookie(SSL *ssl, unsigned char *cookie,
                                  unsigned int *cookie_len) {
    /* For memory BIO, peer address is stored in ex_data */
    DTLSAddress *addr = SSL_get_ex_data(ssl, dtls_peer_addr_ex_index);
    if (addr) {
        return server_cookie_generate(addr, cookie, cookie_len);
    }

    /* Get peer address from BIO */
    BIO *bio = SSL_get_rbio(ssl);
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } peer;
    DTLSAddress peer_addr;
    memset(&peer, 0, sizeof(peer));
    if (bio && BIO_dgram_get_peer(bio, &peer) > 0) {
        memset(&peer_addr, 0, sizeof(peer_addr));
        memcpy(&peer_addr.addr, &peer, sizeof(peer_addr.addr));
        if (peer.ss.ss_family == AF_INET) {
            peer_addr.addrlen = (socklen_t)sizeof(peer.s4);
        } else if (peer.ss.ss_family == AF_INET6) {
            peer_addr.addrlen = (socklen_t)sizeof(peer.s6);
        } else {
            peer_addr.addrlen = (socklen_t)sizeof(peer);
        }
        return server_cookie_generate(&peer_addr, cookie, cookie_len);
    }

    /* Can't determine peer - generate random cookie */
    *cookie_len = 0;
    if (RAND_bytes(cookie, 32) != 1) {
        return 0;
    }
    *cookie_len = 32;
    return 1;
}

static int server_verify_cookie(SSL *ssl, const unsigned char *cookie,
                                unsigned int cookie_len) {
    /* For memory BIO, peer address is stored in ex_data */
    DTLSAddress *addr = SSL_get_ex_data(ssl, dtls_peer_addr_ex_index);
    if (!addr) {
        return 0;
    }
    return server_cookie_verify(addr, cookie, cookie_len);
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

    /* Bind */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)(uint16_t)port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *ai = NULL;
    const char *node = strlen(host) == 0 ? "0.0.0.0" : host;
    if (getaddrinfo(node, port_str, &hints, &ai) != 0) {
        dtls_panic_param("invalid address: %s", host);
    }

    jsec_socket_t fd = JSEC_INVALID_SOCKET;

    struct addrinfo *rp;
    for (rp = ai; rp != NULL; rp = rp->ai_next) {
        /* Create UDP socket - must use WSA_FLAG_OVERLAPPED on Windows for
         * IOCP */
#ifdef JANET_WINDOWS
        fd = WSASocketW(rp->ai_family, rp->ai_socktype, rp->ai_protocol,
                        NULL, 0, WSA_FLAG_OVERLAPPED);
#else
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
        if (fd == JSEC_INVALID_SOCKET) continue;

        /* Set socket options */
        int yes = 1;
#ifdef JANET_WINDOWS
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes,
                   sizeof(yes));
#else
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

        /* Set non-blocking */
#ifdef JANET_WINDOWS
        unsigned long mode = 1;
        ioctlsocket(fd, FIONBIO, &mode);
#else
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

        if (bind(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;

        jsec_close_socket(fd);
        fd = JSEC_INVALID_SOCKET;
    }
    freeaddrinfo(ai);

    if (fd == JSEC_INVALID_SOCKET) {
        dtls_panic_socket("bind failed");
    }

    /* Wrap as Janet stream */
    JanetStream *transport = janet_stream(
        (JanetHandle)fd, JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

    /* Create DTLS server */
    DTLSServer *server =
        janet_abstract(&dtls_server_type, sizeof(DTLSServer));
    memset(server, 0, sizeof(DTLSServer));

    /* Initialize embedded JanetStream for method dispatch */
    server->stream.handle =
        JANET_HANDLE_NONE; /* We don't own the handle directly */
    server->stream.flags = JANET_STREAM_READABLE | JANET_STREAM_WRITABLE;
    server->stream.methods = dtls_server_methods;

    server->transport = transport;
    server->session_timeout = DTLS_SESSION_TIMEOUT;

    /* Get session timeout from options */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet t = janet_get(opts, janet_ckeywordv("session-timeout"));
        if (!janet_checktype(t, JANET_NIL)) {
            if (!janet_checktype(t, JANET_NUMBER)) {
                dtls_panic_param("invalid :session-timeout %v: expected a "
                                 "finite non-negative number of seconds", t);
            }
            double timeout = janet_unwrap_number(t);
            if (!isfinite(timeout) || timeout < 0.0) {
                dtls_panic_param("invalid :session-timeout %v: expected a "
                                 "finite non-negative number of seconds", t);
            }
            server->session_timeout = timeout;
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
    if (!apply_security_options(server->ctx, security, 1)) {
        SSL_CTX_free(server->ctx);
        server->ctx = NULL;
        dtls_panic_ssl("failed to apply security options");
    }

    /* Load certificate and key (required for server) */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet cert = janet_get(opts, janet_ckeywordv("cert"));
        Janet key = janet_get(opts, janet_ckeywordv("key"));

        if (janet_checktype(cert, JANET_NIL) ||
            janet_checktype(key, JANET_NIL)) {
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
            SSL_CTX_set_verify(
                server->ctx,
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

            /* Handle :trusted-cert option for trusting specific client certs
             */
            Janet trusted_cert =
                janet_get(opts, janet_ckeywordv("trusted-cert"));
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
#ifdef JANET_WINDOWS
    /* Windows IOCP: WSAOVERLAPPED MUST be first field for pointer matching */
    WSAOVERLAPPED overlapped;
    WSABUF wsa_buf;
    DWORD wsa_flags;
    uint8_t recv_buf[65536];           /* Buffer for received datagram */
    struct sockaddr_storage peer_addr; /* Peer address from recvfrom */
    int peer_addrlen;
    DWORD bytes_received;
#endif
    DTLSServer *server;
    JanetBuffer *buffer;
    int32_t nbytes;
    double timeout;
} DTLSRecvFromState;

/*
 * =============================================================================
 * Pre-Session Cookie Gate (RFC 6347 section 4.2.1)
 * =============================================================================
 * First contact is handled statelessly, ahead of session creation: a
 * cookie-less ClientHello is answered with a HelloVerifyRequest
 * carrying a cookie and no session state, and only a resend whose
 * cookie verifies is admitted to the session handshake. Unverified
 * spoofed ClientHellos therefore allocate zero DTLSServerSession
 * entries.
 */

/* Locate the cookie field of the ClientHello carried as the first
 * handshake message of the datagram's first record. On success returns
 * 1 and sets *cookie_off / *cookie_len (0 for an empty cookie field);
 * returns 0 when the datagram is not a parseable first-fragment
 * ClientHello. */
static int server_client_hello_cookie(const uint8_t *data, int datalen,
                                      int *cookie_off, int *cookie_len) {
    unsigned int rec_len;
    int rec_end, sid_len, off;

    if (datalen < 61 || data[0] != 0x16) {
        return 0;
    }
    if (data[13] != 1) {
        return 0;
    }
    if (data[19] != 0 || data[20] != 0 || data[21] != 0) {
        return 0; /* Not the first fragment of the message */
    }
    rec_len = ((unsigned int)data[11] << 8) | (unsigned int)data[12];
    rec_end = 13 + (int)rec_len;
    if (rec_end > datalen) {
        rec_end = datalen;
    }
    sid_len = data[59];
    off = 60 + sid_len;
    if (off + 1 > rec_end) {
        return 0;
    }
    *cookie_len = data[off];
    if (off + 1 + *cookie_len > rec_end) {
        return 0;
    }
    *cookie_off = off + 1;
    return 1;
}

/* Answer a datagram with a HelloVerifyRequest carrying cookie. The
 * request mirrors the hello's record and message versions and creates
 * no session state. */
static void server_send_hello_verify(DTLSServer *server,
                                     const DTLSAddress *peer,
                                     const uint8_t *data, int datalen,
                                     const unsigned char *cookie,
                                     unsigned int cookie_len) {
    uint8_t out[128];
    unsigned int body_len = 3 + cookie_len;
    unsigned int rec_len = 12 + body_len;
    ssize_t sent;

    if ((int)sizeof(out) < 28 + (int)cookie_len) {
        return;
    }
    memset(out, 0, sizeof(out));
    out[0] = 0x16;
    out[1] = data[1];
    out[2] = data[2];
    memcpy(out + 5, data + 5, 6); /* RFC 6347: echo the hello record seq */
    out[11] = (uint8_t)(rec_len >> 8);
    out[12] = (uint8_t)(rec_len & 0xff);
    out[13] = 3; /* hello_verify_request */
    out[14] = (uint8_t)(body_len >> 16);
    out[15] = (uint8_t)((body_len >> 8) & 0xff);
    out[16] = (uint8_t)(body_len & 0xff);
    out[22] = out[14];
    out[23] = out[15];
    out[24] = out[16];
    out[25] = data[25];
    out[26] = data[26];
    out[27] = (uint8_t)cookie_len;
    memcpy(out + 28, cookie, cookie_len);

    sent = sendto((jsec_socket_t)server->transport->handle,
                  (const char *)out, 28 + cookie_len, 0,
                  (struct sockaddr *)&peer->addr, peer->addrlen);
    (void)sent;
    (void)datalen;
}

/* Returns 1 when the datagram is admitted to the session handshake,
 * 0 when it was answered statelessly with a HelloVerifyRequest or
 * dropped. */
static int dtls_server_cookie_gate(DTLSServer *server, const uint8_t *data,
                                   int datalen, const DTLSAddress *peer) {
    unsigned char cookie[96];
    unsigned int cookie_len;
    int cookie_off, echo_len;

    if (!server_client_hello_cookie(data, datalen, &cookie_off, &echo_len)) {
        return 0;
    }
    if (echo_len > 0 && server_cookie_verify(peer, data + cookie_off,
                                             (unsigned int)echo_len)) {
        return 1; /* Verified resend - admit to the session handshake */
    }
    if (!server_cookie_generate(peer, cookie, &cookie_len)) {
        return 0;
    }
    server_send_hello_verify(server, peer, data, datalen, cookie, cookie_len);
    return 0;
}

static int server_synth_client_hello(const uint8_t *data, int datalen,
                                     uint8_t *out, int *out_len) {
    unsigned int rec_len, msg_len, frag_len;
    int cookie_off, cookie_len, drop;

    if (!server_client_hello_cookie(data, datalen, &cookie_off, &cookie_len)) {
        return 0;
    }
    rec_len = ((unsigned int)data[11] << 8) | (unsigned int)data[12];
    msg_len = ((unsigned int)data[14] << 16) | ((unsigned int)data[15] << 8) |
              (unsigned int)data[16];
    frag_len = ((unsigned int)data[22] << 16) | ((unsigned int)data[23] << 8) |
               (unsigned int)data[24];
    if ((int)rec_len + 13 != datalen || msg_len != frag_len ||
        frag_len != rec_len - 12) {
        return 0;
    }
    drop = cookie_len + 1;
    memcpy(out, data, (size_t)(cookie_off - 1));
    memcpy(out + cookie_off - 1, data + cookie_off + cookie_len,
           (size_t)(datalen - cookie_off - cookie_len));
    memset(out + 5, 0, 6);
    out[11] = (uint8_t)((rec_len - (unsigned int)drop) >> 8);
    out[12] = (uint8_t)((rec_len - (unsigned int)drop) & 0xff);
    out[14] = (uint8_t)(((msg_len - (unsigned int)drop) >> 16) & 0xff);
    out[15] = (uint8_t)(((msg_len - (unsigned int)drop) >> 8) & 0xff);
    out[16] = (uint8_t)((msg_len - (unsigned int)drop) & 0xff);
    out[17] = 0;
    out[18] = 0;
    out[22] = out[14];
    out[23] = out[15];
    out[24] = out[16];
    *out_len = datalen - drop;
    return 1;
}

static void server_drain_wbio(DTLSSession *session) {
    uint8_t sink[512];
    while (BIO_read(session->wbio, sink, (int)sizeof(sink)) > 0) {
    }
}

static int dtls_server_admit_resend(DTLSSession *session, const uint8_t *data,
                                    int datalen) {
    uint8_t *synth;
    int synth_len = 0;
    BIO_ADDR *peer;
    int ret;

    /* Record sequence alignment: read the verified resend's wire
     * record sequence (bytes 5..10, big-endian; epoch at bytes 3..4)
     * and advance the session's epoch-0 write counter to it, so the
     * ServerHello flight echoes that number on the wire. The write
     * counter restarts at 1 for this session (the discarded
     * in-session HelloVerifyRequest consumed sequence 0), so the
     * alignment offset is wire_seq - 1. Zero offset keeps the
     * single-round case byte-identical. */
    if (datalen >= 11 && ((data[3] << 8) | data[4]) == 0) {
        uint64_t wire_seq = 0;
        int i;
        for (i = 5; i < 11; i++) {
            wire_seq = (wire_seq << 8) | data[i];
        }
        session->rec_seq_off = wire_seq - 1;
    }

    synth = (uint8_t *)janet_malloc((size_t)datalen);
    if (!synth) {
        return 0;
    }
    peer = BIO_ADDR_new();
    if (!peer) {
        janet_free(synth);
        return 0;
    }
    if (!server_synth_client_hello(data, datalen, synth, &synth_len) ||
        BIO_write(session->rbio, synth, synth_len) <= 0) {
        janet_free(synth);
        BIO_ADDR_free(peer);
        return 0;
    }
    janet_free(synth);
    ERR_clear_error();
    ret = DTLSv1_listen(session->ssl, peer);
    if (ret != 0) {
        BIO_ADDR_free(peer);
        server_drain_wbio(session);
        return 0;
    }
    server_drain_wbio(session);
    synth = (uint8_t *)janet_malloc((size_t)datalen);
    if (!synth) {
        BIO_ADDR_free(peer);
        return 0;
    }
    memcpy(synth, data, (size_t)datalen);
    memset(synth + 5, 0, 5);
    synth[10] = 1;
    synth[17] = 0;
    synth[18] = 1;
    if (BIO_write(session->rbio, synth, datalen) <= 0) {
        janet_free(synth);
        BIO_ADDR_free(peer);
        return 0;
    }
    janet_free(synth);
    ERR_clear_error();
    ret = DTLSv1_listen(session->ssl, peer);
    BIO_ADDR_free(peer);
    if (ret != 1) {
        server_drain_wbio(session);
        return 0;
    }
    return 1;
}

/*
 * Process received datagram, demultiplex to session.
 *
 * State transitions:
 *   New peer      -> Cookie gate, then create session
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

    int fresh = 0;

    if (!session) {
        /* New connection - run the stateless cookie gate before any
         * session state is allocated */
        if (!dtls_server_cookie_gate(server, data, datalen, peer_addr)) {
            return janet_wrap_nil();
        }
        session = dtls_server_create_session(server, peer_addr);
        if (!session) {
            return janet_wrap_nil(); /* Out of memory or other error */
        }
        session->cookie_verified = 1;
        /* Store peer address in SSL ex_data for cookie generation */
        SSL_set_ex_data(session->ssl, dtls_peer_addr_ex_index,
                        &session->peer_addr);
        if (!dtls_server_admit_resend(session, data, datalen)) {
            dtls_server_remove_session(server, peer_addr);
            return janet_wrap_nil();
        }
        fresh = 1;
    }

    /* Feed incoming data to SSL via memory BIO (the verified resend is
     * already consumed by dtls_server_admit_resend) */
    if (!fresh && BIO_write(session->rbio, data, datalen) <= 0) {
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
                ERR_clear_error();
                /* Handshake failed - clean up */
                dtls_server_remove_session(server, peer_addr);
                return janet_wrap_nil();
            }
        }

        /* Send any handshake response data */
        send_dtls_packet(server->transport, session);

        if (session->state != DTLS_STATE_ESTABLISHED) {
            return janet_wrap_nil(); /* Handshake still in progress */
        }
        /* Fall through - handshake complete, may have application data */
    }

    /* Read application data from established session, sized from the
     * datagram: SSL_peek runs before any buffer growth (nothing is
     * reserved with no data available), and once a decrypted datagram is
     * pending its exact size drives the growth and the read, so a
     * datagram of any size is delivered intact. */
    if (session->state == DTLS_STATE_ESTABLISHED) {
        uint8_t dummy;
        ERR_clear_error();
        int ret = SSL_peek(session->ssl, &dummy, 1);
        if (ret > 0) {
            int32_t avail = (int32_t)SSL_pending(session->ssl);
            if (avail < 1) avail = 1;
            janet_buffer_extra(out_buf, avail);
            ERR_clear_error();
            ret = SSL_read(session->ssl, out_buf->data + out_buf->count, avail);
            if (ret > 0) {
                out_buf->count += ret;
                /* Return address (data is in buffer per Janet convention) */
                DTLSAddress *ret_addr =
                    janet_abstract(&dtls_address_type, sizeof(DTLSAddress));
                memcpy(ret_addr, peer_addr, sizeof(DTLSAddress));
                return janet_wrap_abstract(ret_addr);
            }
        }

        /* Handle peer close */
        if (SSL_get_error(session->ssl, ret) == SSL_ERROR_ZERO_RETURN) {
            SSL_shutdown(session->ssl);
            send_dtls_packet(server->transport,
                             session); /* Send close_notify */
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

#ifdef JANET_WINDOWS
/* Forward declare callback for helper */
static void dtls_recv_from_callback(JanetFiber *fiber, JanetAsyncEvent event);
/* Start an async WSARecvFrom operation for Windows IOCP */
static int dtls_start_wsa_recvfrom(DTLSRecvFromState *state,
                                   JanetFiber *fiber) {
    DTLSServer *server = state->server;

    /* Reset overlapped struct */
    memset(&state->overlapped, 0, sizeof(WSAOVERLAPPED));
    state->wsa_flags = 0;
    memset(&state->peer_addr, 0, sizeof(state->peer_addr));
    state->peer_addrlen = sizeof(state->peer_addr);
    state->bytes_received = 0;

    /* Set up buffer */
    state->wsa_buf.buf = (char *)state->recv_buf;
    state->wsa_buf.len = sizeof(state->recv_buf);

    int result =
        WSARecvFrom((SOCKET)server->transport->handle, &state->wsa_buf, 1,
                    &state->bytes_received, &state->wsa_flags,
                    (struct sockaddr *)&state->peer_addr,
                    &state->peer_addrlen, &state->overlapped, NULL);

    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            /* Async recv started */
            janet_async_in_flight(fiber);
            return 0;
        }
        /* Real error */
        return -1;
    }
    /* Completed synchronously (rare) - will be handled in COMPLETE */
    return 0;
}
#endif

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

#ifdef JANET_WINDOWS
        case JANET_ASYNC_EVENT_INIT:
            /* Windows: Start async WSARecvFrom */
            if (dtls_start_wsa_recvfrom(state, fiber) < 0) {
                janet_cancel(fiber, janet_cstringv("WSARecvFrom failed"));
                janet_async_end(fiber);
                return;
            }
            break;

        case JANET_ASYNC_EVENT_COMPLETE:
        case JANET_ASYNC_EVENT_FAILED: {
            DTLSServer *server = state->server;

            /* Get the number of bytes received from GetQueuedCompletionStatus
             */
            DWORD bytes_transferred;
            DWORD flags;
            BOOL success = WSAGetOverlappedResult(
                (SOCKET)server->transport->handle, &state->overlapped,
                &bytes_transferred, FALSE, &flags);

            if (!success || bytes_transferred == 0) {
                /* Try to start another receive */
                if (dtls_start_wsa_recvfrom(state, fiber) < 0) {
                    janet_cancel(
                        fiber, janet_cstringv("WSARecvFrom restart failed"));
                    janet_async_end(fiber);
                    return;
                }
                break;
            }

            /* Cleanup expired sessions periodically */
            dtls_server_cleanup_expired(server, get_current_time());

            /* Process datagram - may be handshake or app data */
            DTLSAddress peer_addr;
            memcpy(&peer_addr.addr, &state->peer_addr,
                   sizeof(peer_addr.addr));
            peer_addr.addrlen = state->peer_addrlen;

            Janet result = process_datagram(server, state->recv_buf,
                                            (int)bytes_transferred,
                                            &peer_addr, state->buffer);

            if (janet_checktype(result, JANET_ABSTRACT)) {
                /* Got application data - return to caller */
                janet_schedule(fiber, result);
                janet_async_end(fiber);
                return;
            }

            /* Handshake packet processed - start next recv */
            if (dtls_start_wsa_recvfrom(state, fiber) < 0) {
                janet_cancel(fiber,
                             janet_cstringv("WSARecvFrom restart failed"));
                janet_async_end(fiber);
                return;
            }
            break;
        }
#else
        /* Unix: Use epoll/kqueue readiness notification */
        case JANET_ASYNC_EVENT_INIT:
        case JANET_ASYNC_EVENT_READ: {
            DTLSServer *server = state->server;

            /* Process all available datagrams */
            while (1) {
                uint8_t recv_buf[65536];
                DTLSAddress peer_addr;
                memset(&peer_addr, 0, sizeof(peer_addr));
                peer_addr.addrlen = sizeof(peer_addr.addr);

                ssize_t n = recvfrom((jsec_socket_t)server->transport->handle,
                                     recv_buf, sizeof(recv_buf), MSG_DONTWAIT,
                                     (struct sockaddr *)&peer_addr.addr,
                                     &peer_addr.addrlen);

                if (n < 0) {
                    int sock_err = jsec_socket_errno;
                    if (sock_err == JSEC_EAGAIN ||
                        sock_err == JSEC_EWOULDBLOCK) {
                        /* No more data available - just return and wait for
                         * the next READ event. The fiber is already
                         * registered for JANET_ASYNC_LISTEN_READ. */
                        break; /* Exit loop, stay registered */
                    }
                    janet_cancel(fiber, janet_cstringv(
                                            jsec_socket_strerror(sock_err)));
                    janet_async_end(fiber);
                    return;
                }

                /* Cleanup expired sessions periodically */
                dtls_server_cleanup_expired(server, get_current_time());

                /* Process datagram - may be handshake or app data */
                Janet result = process_datagram(server, recv_buf, (int)n,
                                                &peer_addr, state->buffer);

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
#endif

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

    /* No pre-allocation: process_datagram grows buf by the datagram's
     * own decrypted size, so nothing is reserved before data arrives */

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

    return janet_wrap_nil(); /* Will be replaced by async result */
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
 * Otherwise, sends close_notify to all established sessions (best effort,
 * non-blocking).
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
    memset(&addr, 0, sizeof(addr));
    socklen_t addrlen = sizeof(addr);

    if (getsockname((jsec_socket_t)server->transport->handle,
                    (struct sockaddr *)&addr, &addrlen) < 0) {
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
 * (dtls/localname client-or-server)
 *
 * One module entry for the dtls/localname name, dispatching on the
 * abstract type of its argument: a DTLSClient returns its local
 * address as a DTLSAddress, a DTLSServer returns the address it is
 * bound to as a [host port] tuple. Any other argument raises a type
 * error naming both accepted types.
 */
static Janet cfun_dtls_localname_dispatch(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    if (janet_checkabstract(argv[0], &dtls_client_type)) {
        return cfun_dtls_localname(argc, argv);
    }
    if (janet_checkabstract(argv[0], &dtls_server_type)) {
        return cfun_dtls_server_localname(argc, argv);
    }
    janet_panicf("bad slot #%d, expected %s or %s, got %v", 0,
                 dtls_client_type.name, dtls_server_type.name, argv[0]);
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
    {"listen", cfun_dtls_listen,
     "(dtls/listen host port &opt opts)\n\n"
     "Create a DTLS server listening on the specified address.\n"
     "Returns a DTLSServer object.\n\n"
     "Options:\n"
     "  :cert - Server certificate (required)\n"
     "  :key - Server private key (required)\n"
     "  :verify - Require client certificates (default false)\n"
     "  :ca - CA certificates for client verification\n"
     "  :session-timeout - Session timeout in seconds (default 300)"},
    {"recv-from", cfun_dtls_recv_from,
     "(dtls/recv-from server nbytes buf &opt timeout-or-opts)\n\n"
     "Receive a datagram from any peer.\n"
     "Returns the peer address. Data is placed in buf.\n"
     "Handles handshakes transparently - only returns when application data "
     "is ready.\n"
     "The last arg can be a number (timeout) or table/struct with :timeout "
     "key.\n"
     "Matches Janet's net/recv-from convention."},
    {"send-to", cfun_dtls_send_to,
     "(dtls/send-to server addr data &opt timeout)\n\n"
     "Send a datagram to a specific peer.\n"
     "The peer must have an established session."},
    {"close-server", cfun_dtls_close_server,
     "(dtls/close-server server &opt force)\n\n"
     "Close the DTLS server and all sessions.\n"
     "Sends close_notify to all established sessions unless force is true.\n"
     "Close notifications are non-blocking (best effort)."},
    {"localname", cfun_dtls_localname_dispatch,
     "(dtls/localname client-or-server)\n\n"
     "Get the local address as a DTLSAddress (client), or the local\n"
     "address the server is bound to as a [host port] tuple (server)."},
    {NULL, NULL, NULL}};

void jdtls_register_server(JanetTable *env) {
    janet_register_abstract_type(&dtls_server_type);
    dtls_peer_addr_ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    janet_cfuns(env, "jsec/dtls", server_cfuns);
}
