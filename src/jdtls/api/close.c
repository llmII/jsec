/*
 * client/close.c - DTLS client shutdown and close operations
 */

#include "../jdtls_internal.h"
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
    
    if (!client->ssl || client->closed) {
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
    
    /* Mark as shutdown but not closed - socket still usable for raw UDP */
    client->state = DTLS_STATE_SHUTDOWN;
    
    return janet_wrap_nil();
}

/*
 * (dtls/close client &opt force)
 *
 * Close DTLS client connection with proper RFC-compliant shutdown.
 * Sends close_notify alert unless force is true.
 * This is async - waits for peer's close_notify response.
 */
Janet cfun_dtls_close(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);
    int force = argc > 1 && janet_truthy(argv[1]);
    
    if (client->closed) {
        return janet_wrap_nil();
    }
    
    /* For force close or non-established state, skip SSL shutdown */
    if (force || client->state != DTLS_STATE_ESTABLISHED) {
        client->closed = 1;
        client->state = DTLS_STATE_CLOSED;
        if (client->transport) {
            janet_stream_close(client->transport);
        }
        return janet_wrap_nil();
    }
    
    /* RFC-compliant: Send close_notify and wait for peer's */
    client->state = DTLS_STATE_SHUTDOWN;
    
    /* Try initial shutdown */
    DTLSResult result = dtls_do_shutdown(client->ssl);
    
    if (result == DTLS_RESULT_OK || result == DTLS_RESULT_EOF) {
        /* Shutdown complete */
        client->closed = 1;
        client->state = DTLS_STATE_CLOSED;
        if (client->transport) {
            janet_stream_close(client->transport);
        }
        return janet_wrap_nil();
    }
    
    /* Need to wait for peer's close_notify */
    int mode = (result == DTLS_RESULT_WANT_WRITE)
               ? JANET_ASYNC_LISTEN_WRITE
               : JANET_ASYNC_LISTEN_READ;
    dtls_client_start_async_close(client, mode);
    return janet_wrap_nil();  /* Will complete async */
}
