/*
 * state_machine.c - DTLS async I/O state machine
 *
 * This module implements the async I/O state machine for DTLS.
 * It integrates with Janet's event loop via janet_async_start.
 *
 * DTLS State Machine Flow
 * =======================
 *
 * Unlike TLS which uses a stream socket, DTLS uses datagrams.
 * The state machine handles:
 * 1. Handshake (with retransmission timeouts)
 * 2. Data read/write
 * 3. Shutdown
 *
 * Memory BIO Architecture
 * =======================
 * For the server, we use memory BIOs to decouple SSL from the socket:
 *
 *   Network        rbio (mem)        SSL        wbio (mem)        Network
 *   recvfrom() --> BIO_write() --> SSL_read()
 *                                  SSL_write() --> BIO_read() --> sendto()
 *
 * This allows us to:
 * 1. Demultiplex packets by peer address
 * 2. Route data to correct session
 * 3. Handle timeouts and retransmissions
 *
 * For the client with a connected socket, we can use a dgram BIO directly.
 *
 * Timeout Handling
 * ================
 * DTLS has built-in retransmission:
 * - DTLSv1_get_timeout() returns time until next retransmission
 * - DTLSv1_handle_timeout() triggers retransmission
 * We integrate this with Janet's ev/deadline or manual timeout tracking.
 */

#include "internal.h"
#include <errno.h>

/*
 * =============================================================================
 * SSL Result Translation
 * =============================================================================
 */

DTLSResult dtls_ssl_result(SSL *ssl, int ret) {
    if (ret > 0) {
        return DTLS_RESULT_OK;
    }

    int err = SSL_get_error(ssl, ret);
    switch (err) {
        case SSL_ERROR_NONE:
            return DTLS_RESULT_OK;

        case SSL_ERROR_WANT_READ:
            return DTLS_RESULT_WANT_READ;

        case SSL_ERROR_WANT_WRITE:
            return DTLS_RESULT_WANT_WRITE;

        case SSL_ERROR_ZERO_RETURN:
            /* Peer sent close_notify */
            return DTLS_RESULT_EOF;

        case SSL_ERROR_SYSCALL:
            if (ret == 0) {
                /* EOF without close_notify */
                return DTLS_RESULT_EOF;
            }
            /* Fall through to error */
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((fallthrough));
#endif

        case SSL_ERROR_SSL:
        default:
            return DTLS_RESULT_ERROR;
    }
}

/*
 * =============================================================================
 * Basic SSL Operations
 * =============================================================================
 */

DTLSResult dtls_do_handshake(SSL *ssl) {
    ERR_clear_error();
    int ret = SSL_do_handshake(ssl);
    if (ret == 1) {
        return DTLS_RESULT_OK;
    }
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_write(SSL *ssl, const uint8_t *buf, int32_t len,
                         int32_t *out_len) {
    ERR_clear_error();
    int ret = SSL_write(ssl, buf, len);
    if (ret > 0) {
        *out_len = ret;
        return DTLS_RESULT_OK;
    }
    *out_len = 0;
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_shutdown(SSL *ssl) {
    ERR_clear_error();
    int ret = SSL_shutdown(ssl);
    if (ret == 1) {
        /* Bidirectional shutdown complete */
        return DTLS_RESULT_OK;
    }
    if (ret == 0) {
        /* Sent close_notify, waiting for peer's */
        return DTLS_RESULT_WANT_READ;
    }
    return dtls_ssl_result(ssl, ret);
}

