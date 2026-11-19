/*
 * client/close.c - DTLS client shutdown and close operations
 */

#include "../internal.h"
#include <string.h>

/* External declarations */
extern void dtls_client_start_async_close(DTLSClient *client, int mode);

/*
 * (dtls/shutdown client &opt mode)
 *
 * Perform DTLS shutdown without closing the underlying socket.
 * Useful for transitioning back to raw UDP.
 * Mode can be :rd, :wr, or :rdwr (default).
 */
Janet cfun_dtls_shutdown(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl || (client->flags & JDTLS_CLIENT_CLOSED)) {
        return janet_wrap_nil();
    }

    /* Send close_notify but don't close socket */
    int ret = SSL_shutdown(client->ssl);
    if (ret < 0) {
        int err = SSL_get_error(client->ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            dtls_panic_ssl("DTLS shutdown failed");
        }
    }

    /* Flush the alert out of wbio when close_notify landed there */
    dtls_client_flush_wbio_to_peer(client);

    /* Mark as shutdown but not closed - socket still usable for raw UDP */
    client->state = DTLS_STATE_SHUTDOWN;

    return janet_wrap_nil();
}

/*
 * (dtls/close client &opt force)
 *
 * Close DTLS client connection with a unidirectional shutdown.
 * Sends close_notify alert unless force is true and returns nil once
 * the alert is generated and flushed - the peer's answering alert is
 * never awaited (over UDP it may not arrive).
 */
Janet cfun_dtls_close(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);
    int force = argc > 1 && janet_truthy(argv[1]);

    if (client->flags & JDTLS_CLIENT_CLOSED) {
        return janet_wrap_nil();
    }

    /* For force close or non-established state, skip SSL shutdown */
    if (force || client->state != DTLS_STATE_ESTABLISHED) {
        client->flags |= JDTLS_CLIENT_CLOSED;
        client->state = DTLS_STATE_CLOSED;
        if (client->transport) {
            janet_stream_close(client->transport);
        }
        return janet_wrap_nil();
    }

    /* Unidirectional shutdown: generate close_notify, flush it to the
     * peer, then finish locally. A UDP peer's answering alert may never
     * arrive, so it is never awaited. */
    client->state = DTLS_STATE_SHUTDOWN;

    /* Send close_notify */
    ERR_clear_error();
    int ret = SSL_shutdown(client->ssl);
    dtls_client_flush_wbio_to_peer(client);

    if (ret >= 0) {
        /* close_notify generated (ret 0: sent, awaiting the peer's;
         * ret 1: bidirectional done) - the local close is complete */
        client->flags |= JDTLS_CLIENT_CLOSED;
        client->state = DTLS_STATE_CLOSED;
        if (client->transport) {
            janet_stream_close(client->transport);
        }
        return janet_wrap_nil();
    }

    /* The alert is not generated yet or the shutdown failed */
    DTLSResult result = dtls_ssl_result(client->ssl, ret);
    if (result == DTLS_RESULT_OK || result == DTLS_RESULT_EOF ||
        result == DTLS_RESULT_UNEXPECTED_EOF) {
        /* Shutdown complete or the peer already closed: a peer close
         * without close_notify still completes the close; read
         * surfaces own the truncation raise */
        client->flags |= JDTLS_CLIENT_CLOSED;
        client->state = DTLS_STATE_CLOSED;
        if (client->transport) {
            janet_stream_close(client->transport);
        }
        return janet_wrap_nil();
    }
    if (result == DTLS_RESULT_ERROR) {
        dtls_panic_ssl("DTLS shutdown failed");
    }

    /* An alert that cannot be generated yet finishes through the
     * async close (defense-in-depth for a WANT_WRITE arm) */
    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    dtls_client_start_async_close(client, mode);
    return janet_wrap_nil(); /* Will complete async */
}
