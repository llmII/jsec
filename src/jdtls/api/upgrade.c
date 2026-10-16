/*
 * client/upgrade.c - DTLS upgrade for existing UDP sockets
 *
 * Provides dtls/upgrade for wrapping connected UDP sockets with DTLS.
 */

#include "../internal.h"
#include <string.h>
#include <fcntl.h>
#ifndef JANET_WINDOWS
#include <unistd.h>
#endif
#include <time.h>
#include <openssl/x509v3.h>

/* External declarations */
extern const JanetMethod dtls_client_methods[];
extern int dtls_client_start_handshake(DTLSClient *client);

/*
 * (dtls/upgrade transport &opt opts)
 *
 * Upgrade an existing UDP socket to DTLS. The transport must be a connected
 * UDP socket (created with net/connect :datagram).
 *
 * Options:
 *   :cert - Client certificate (for mutual TLS)
 *   :key - Client private key
 *   :verify - Verify peer certificate (default true)
 *   :ca - CA certificate path
 *   :hostname - Client name for SNI and certificate verification
 *     (:sni is reserved for the server virtual-host map)
 *   :session - Session data for resumption
 *   :server - If true, act as server (default: client)
 *   :trusted-cert - Trust specific certificate (for self-signed)
 *   :verify-hostname - Hostname for cert verification (can differ from
 *     :hostname)
 */
Janet cfun_dtls_upgrade(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    /* Get the UDP transport */
    JanetStream *transport = janet_getabstract(argv, 0, &janet_stream_type);

    /* Parse options */
    Janet opts = argc > 1 ? argv[1] : janet_wrap_nil();
    int verify = 1;
    int is_server = 0;
    int track_handshake_time = 0;

    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet v = janet_get(opts, janet_ckeywordv("verify"));
        if (!janet_checktype(v, JANET_NIL)) {
            verify = janet_truthy(v);
        }

        Janet srv = janet_get(opts, janet_ckeywordv("server"));
        if (janet_truthy(srv)) {
            is_server = 1;
        }

        if (!is_server) {
            Janet sni = janet_get(opts, janet_ckeywordv("sni"));
            if (!janet_checktype(sni, JANET_NIL)) {
                dtls_panic_param(
                    ":sni is server-side only (the server virtual-host "
                    "map on tls/new-context); use :hostname for the "
                    "client name");
            }
        }

        /* :handshake-timing option enables timing measurement */
        Janet ht = janet_get(opts, janet_ckeywordv("handshake-timing"));
        if (!janet_checktype(ht, JANET_NIL)) {
            track_handshake_time = janet_truthy(ht);
        }

        /* :session accepts nil (absent/no-op) or a byte string or buffer;
         * anything else raises before any SSL_CTX or SSL is allocated
         * (PNB-08 cleanup safety). */
        Janet session = janet_get(opts, janet_ckeywordv("session"));
        if (!janet_checktype(session, JANET_NIL) &&
            !janet_checktype(session, JANET_STRING) &&
            !janet_checktype(session, JANET_BUFFER)) {
            dtls_panic_param("session must be a byte string or buffer");
        }
    } else if (!janet_checktype(opts, JANET_NIL)) {
        dtls_panic_param("options must be a table or struct");
    }

    /* Get the file descriptor from the stream */
    jsec_socket_t fd = (jsec_socket_t)transport->handle;
    if (fd == JSEC_INVALID_SOCKET) {
        dtls_panic_io("invalid transport stream");
    }

    /* Get peer address from socket */
    struct sockaddr_storage peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    socklen_t peer_len = sizeof(peer_addr);
    if (getpeername(fd, (struct sockaddr *)&peer_addr, &peer_len) < 0) {
        dtls_panic_socket(
            "failed to get peer address (socket may not be connected)");
    }

    /* Create DTLS client */
    DTLSClient *client =
        janet_abstract(&dtls_client_type, sizeof(DTLSClient));
    memset(client, 0, sizeof(DTLSClient));

    /* Initialize embedded JanetStream for method dispatch */
    client->stream.handle = JANET_HANDLE_NONE;
    client->stream.flags = JANET_STREAM_READABLE | JANET_STREAM_WRITABLE;
    client->stream.methods = dtls_client_methods;

    client->transport = transport;
    client->state = DTLS_STATE_IDLE;
    client->is_server = is_server; /* Set based on :server option */

    /* Initialize handshake timing if enabled */
    client->track_handshake_time = track_handshake_time;
    if (track_handshake_time) {
        clock_gettime(CLOCK_MONOTONIC, &client->ts_connect);
    }

    /* Store peer address */
    memcpy(&client->peer_addr.addr, &peer_addr, peer_len);
    client->peer_addr.addrlen = peer_len;

    /* Extract and validate :security before any SSL_CTX exists
     * or ctx_cache_lock is taken (never longjmp past cleanup) */
    Janet security = janet_wrap_nil();
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        security = janet_get(opts, janet_ckeywordv("security"));
    }
    jutils_validate_security_options(security);

    /* Create SSL context */
    if (is_server) {
        client->ctx = SSL_CTX_new(DTLS_server_method());
    } else {
        client->ctx = SSL_CTX_new(DTLS_client_method());
    }
    if (!client->ctx) {
        dtls_panic_ssl("failed to create SSL context");
    }
    client->owns_ctx = 1;

    /* Apply security options */
    if (!apply_security_options(client->ctx, security, 1,
                                is_server)) { /* is_dtls = 1 */
        SSL_CTX_free(client->ctx);
        client->ctx = NULL;
        client->owns_ctx = 0;
        dtls_panic_ssl("failed to apply security options");
    }

    /* Load certificates if provided */
    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet cert = janet_get(opts, janet_ckeywordv("cert"));
        Janet key = janet_get(opts, janet_ckeywordv("key"));
        Janet ca = janet_get(opts, janet_ckeywordv("ca"));

        /* Load credentials - panics on failure with descriptive error */
        jutils_load_credentials(client->ctx, cert, key, ca);

        /* Trust specific certificate */
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
        /* Only load default paths if we don't have a trusted cert */
        Janet trusted = janet_get(opts, janet_ckeywordv("trusted-cert"));
        if (janet_checktype(trusted, JANET_NIL) &&
            SSL_CTX_set_default_verify_paths(client->ctx) != 1) {
            SSL_CTX_free(client->ctx);
            client->ctx = NULL;
            client->owns_ctx = 0;
            dtls_panic_ssl("failed to load default verify paths");
        }
    } else {
        SSL_CTX_set_verify(client->ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Create SSL object */
    client->ssl = SSL_new(client->ctx);
    if (!client->ssl) {
        /* ctx was already set on client, need to clean up */
        SSL_CTX_free(client->ctx);
        client->ctx = NULL;
        client->owns_ctx = 0;
        dtls_panic_ssl("failed to create SSL object");
    }

    /* Client name ranking (:hostname only - there is no positional host
     * here), SNI, certificate name verification and :session attachment:
     * one shared setup for every entry point (D-01) */
    if (!is_server) {
        const char *fail =
            jutils_client_setup(client->ssl, opts, NULL, verify);
        if (fail) {
            dtls_panic_verify("client SSL setup failed in %s", fail);
        }
    }

#ifdef JANET_WINDOWS
    /* Windows IOCP: Use memory BIOs for decoupled I/O
     * - rbio: We write received UDP data here, SSL reads from it
     * - wbio: SSL writes encrypted data here, we sendto() from it
     */
    client->rbio = BIO_new(BIO_s_mem());
    client->wbio = BIO_new(BIO_s_mem());
    if (!client->rbio || !client->wbio) {
        if (client->rbio) BIO_free(client->rbio);
        if (client->wbio) BIO_free(client->wbio);
        dtls_panic_ssl("failed to create memory BIOs");
    }

    /* Set non-blocking mode on memory BIOs */
    BIO_set_nbio(client->rbio, 1);
    BIO_set_nbio(client->wbio, 1);

    /* Attach BIOs to SSL - SSL takes ownership */
    SSL_set_bio(client->ssl, client->rbio, client->wbio);
#else
    /* Unix: Use dgram BIO for direct socket I/O.
     * OpenSSL handles socket I/O directly through the dgram BIO. */
    client->rbio = NULL;
    client->wbio = NULL;

    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!bio) {
        dtls_panic_ssl("failed to create BIO");
    }

    /* Set peer address on BIO (required for dgram BIO to know destination) */
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer_addr);

    /* Set non-blocking */
    BIO_set_nbio(bio, 1);

    /* Attach to SSL */
    SSL_set_bio(client->ssl, bio, bio);
#endif

    /* Set mode */
    if (is_server) {
        SSL_set_accept_state(client->ssl);
    } else {
        SSL_set_connect_state(client->ssl);
    }

    /* Start handshake */
    if (dtls_client_start_handshake(client)) {
        return janet_wrap_abstract(client);
    }

    return janet_wrap_nil();
}
