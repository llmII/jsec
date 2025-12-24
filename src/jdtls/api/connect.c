/*
 * client/connect.c - DTLS client connection establishment
 *
 * Provides dtls/connect for creating 1:1 DTLS client connections.
 */

#include "../internal.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <openssl/x509v3.h>

/* External declarations */
extern const JanetMethod dtls_client_methods[];
extern void dtls_client_async_callback(JanetFiber *fiber,
                                       JanetAsyncEvent event);
extern int dtls_client_start_handshake(DTLSClient *client);

/*
 * (dtls/connect host port &opt opts)
 *
 * Create a DTLS client connection.
 * Options:
 *   :cert - Client certificate (for mutual TLS)
 *   :key - Client private key
 *   :verify - Verify server certificate (default true)
 *   :ca - CA certificate or path
 *   :alpn - ALPN protocols
 *   :sni - Server name for SNI (defaults to host)
 */
Janet cfun_dtls_connect(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    const char *host = janet_getcstring(argv, 0);
    int port;

    /* Port can be string or integer */
    if (janet_checktype(argv[1], JANET_STRING)) {
        port = atoi((const char *)janet_unwrap_string(argv[1]));
    } else {
        port = janet_getinteger(argv, 1);
    }

    /* Parse options */
    Janet opts = argc > 2 ? argv[2] : janet_wrap_nil();
    int verify = 1;  /* Default: verify server */
    const char *sni = host;
    const char *verify_hostname =
        NULL;  /* Hostname for certificate verification (can differ from SNI) */
    int track_handshake_time = 0;
    DTLSContext *shared_ctx = NULL;  /* Shared context from :context option */

    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet v = janet_get(opts, janet_ckeywordv("verify"));
        if (!janet_checktype(v, JANET_NIL)) {
            verify = janet_truthy(v);
        }

        Janet s = janet_get(opts, janet_ckeywordv("sni"));
        if (janet_checktype(s, JANET_STRING)) {
            sni = (const char *)janet_unwrap_string(s);
        }

        /* :verify-hostname option allows verifying cert against a different hostname than SNI */
        Janet vh = janet_get(opts, janet_ckeywordv("verify-hostname"));
        if (janet_checktype(vh, JANET_STRING)) {
            verify_hostname = (const char *)janet_unwrap_string(vh);
        }

        /* :handshake-timing option enables timing measurement */
        Janet ht = janet_get(opts, janet_ckeywordv("handshake-timing"));
        if (!janet_checktype(ht, JANET_NIL)) {
            track_handshake_time = janet_truthy(ht);
        }

        /* :context option allows reusing a DTLSContext (SSLContext) */
        Janet ctx_opt = janet_get(opts, janet_ckeywordv("context"));
        if (janet_checktype(ctx_opt, JANET_ABSTRACT)) {
            shared_ctx = janet_getabstract(&ctx_opt, 0, &dtls_context_type);
            /* Verify it's a DTLS context, not TLS */
            if (!shared_ctx->is_dtls) {
                dtls_panic_config("cannot use TLS context for DTLS connection");
            }
        }
    }

    /* Create UDP socket and connect */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        dtls_panic_socket("failed to create socket");
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Resolve and connect */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        dtls_panic_param("invalid address: %s", host);
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
        errno != EINPROGRESS) {
        close(fd);
        dtls_panic_socket("connect failed");
    }

    /* Wrap as Janet stream */
    JanetStream *transport = janet_stream(fd,
                                          JANET_STREAM_READABLE | JANET_STREAM_WRITABLE, NULL);

    /* Create DTLS client */
    DTLSClient *client = janet_abstract(&dtls_client_type, sizeof(DTLSClient));
    memset(client, 0, sizeof(DTLSClient));

    /* Initialize embedded JanetStream for method dispatch */
    client->stream.handle =
        JANET_HANDLE_NONE;  /* We don't own the handle directly */
    client->stream.flags = JANET_STREAM_READABLE | JANET_STREAM_WRITABLE;
    client->stream.methods = dtls_client_methods;

    client->transport = transport;
    client->state = DTLS_STATE_IDLE;
    client->is_server = 0;  /* dtls/connect is always client */

    /* Initialize handshake timing if enabled */
    client->track_handshake_time = track_handshake_time;
    if (track_handshake_time) {
        clock_gettime(CLOCK_MONOTONIC, &client->ts_connect);
    }

    /* Store peer address */
    client->peer_addr.addr.ss_family = AF_INET;
    memcpy(&client->peer_addr.addr, &addr, sizeof(addr));
    client->peer_addr.addrlen = sizeof(addr);

    /* Create or use existing SSL context */
    if (shared_ctx) {
        /* Use shared context - don't free on GC */
        client->ctx = shared_ctx->ctx;
        client->owns_ctx = 0;
    } else {
        /* Create new context - free on GC */
        client->ctx = SSL_CTX_new(DTLS_client_method());
        if (!client->ctx) {
            dtls_panic_ssl("failed to create SSL context");
        }
        client->owns_ctx = 1;

        /* Apply security options from jshared */
        Janet security = janet_wrap_nil();
        if (janet_checktype(opts, JANET_TABLE) ||
            janet_checktype(opts, JANET_STRUCT)) {
            security = janet_get(opts, janet_ckeywordv("security"));
        }
        apply_security_options(client->ctx, security, 1);  /* 1 = is_dtls */

        /* Load certificates if provided */
        if (janet_checktype(opts, JANET_TABLE) ||
            janet_checktype(opts, JANET_STRUCT)) {
            Janet cert = janet_get(opts, janet_ckeywordv("cert"));
            Janet key = janet_get(opts, janet_ckeywordv("key"));
            Janet ca = janet_get(opts, janet_ckeywordv("ca"));

            /* Load credentials - panics on failure with descriptive error */
            jutils_load_credentials(client->ctx, cert, key, ca);

            /* Trust specific certificate (for self-signed certs) */
            Janet trusted = janet_get(opts, janet_ckeywordv("trusted-cert"));
            if (!janet_checktype(trusted, JANET_NIL)) {
                if (!add_trusted_cert(client->ctx, trusted)) {
                    dtls_panic_ssl("failed to add trusted certificate");
                }
            }
        }

        /* Set verification mode */
        if (verify) {
            SSL_CTX_set_verify(client->ctx, SSL_VERIFY_PEER, NULL);
            /* Only load default verify paths if no trusted cert was provided */
            if (janet_checktype(opts, JANET_TABLE) ||
                janet_checktype(opts, JANET_STRUCT)) {
                Janet trusted = janet_get(opts, janet_ckeywordv("trusted-cert"));
                if (janet_checktype(trusted, JANET_NIL)) {
                    SSL_CTX_set_default_verify_paths(client->ctx);
                }
            } else {
                SSL_CTX_set_default_verify_paths(client->ctx);
            }
        } else {
            SSL_CTX_set_verify(client->ctx, SSL_VERIFY_NONE, NULL);
        }
    }

    /* Create SSL object */
    client->ssl = SSL_new(client->ctx);
    if (!client->ssl) {
        /* Clean up ctx if we own it */
        if (client->owns_ctx && client->ctx) {
            SSL_CTX_free(client->ctx);
            client->ctx = NULL;
            client->owns_ctx = 0;
        }
        dtls_panic_ssl("failed to create SSL object");
    }

    /* Set SNI hostname */
    SSL_set_tlsext_host_name(client->ssl, sni);

    /* Set hostname for certificate verification
     * Use verify_hostname if provided, otherwise use sni */
    if (verify) {
        const char *host_to_verify = verify_hostname ? verify_hostname : sni;
        SSL_set_hostflags(client->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        SSL_set1_host(client->ssl, host_to_verify);
    }

    /* Session resumption */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet session_data = janet_get(opts, janet_ckeywordv("session"));
        if (janet_checktype(session_data, JANET_BUFFER)) {
            JanetBuffer *buf = janet_unwrap_buffer(session_data);
            const unsigned char *p = buf->data;
            SSL_SESSION *session = d2i_SSL_SESSION(NULL, &p, buf->count);
            if (session) {
                SSL_set_session(client->ssl, session);
                SSL_SESSION_free(session);
            }
        }
    }

    /* Create dgram BIO for connected socket */
    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!bio) {
        dtls_panic_ssl("failed to create BIO");
    }

    /* Set peer address on BIO */
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addr);

    /* Set non-blocking */
    BIO_set_nbio(bio, 1);

    /* Attach to SSL */
    SSL_set_bio(client->ssl, bio, bio);

    /* Set connect state and start handshake */
    SSL_set_connect_state(client->ssl);

    if (dtls_client_start_handshake(client)) {
        /* Handshake completed synchronously */
        return janet_wrap_abstract(client);
    }

    /* Async handshake in progress - async callback will schedule result */
    return janet_wrap_nil();
}
