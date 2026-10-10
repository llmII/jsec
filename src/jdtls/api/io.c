/*
 * client/io.c - DTLS client I/O operations (read, write, chunk)
 */

#include "../internal.h"
#include <string.h>

/* External declarations */
extern void dtls_client_start_async_read(DTLSClient *client, JanetBuffer *buf,
                                         int32_t nbytes, int mode);
extern void dtls_client_start_async_write(DTLSClient *client,
                                          JanetByteView data, int mode);

/*
 * dtls_do_read - read one datagram into buf, sized from the datagram.
 *
 * SSL_peek runs before any buffer growth: with no decrypted datagram
 * available the buffer grows by nothing. Once one is available,
 * SSL_pending reports its exact size and the buffer grows by exactly
 * what the read consumes, so a datagram of any size is delivered intact
 * and capacity tracks data, not the request.
 */
DTLSResult dtls_do_read(SSL *ssl, JanetBuffer *buf, int32_t n) {
    uint8_t dummy;
    ERR_clear_error();
    int pk = SSL_peek(ssl, &dummy, 1);
    if (pk <= 0) {
        return dtls_ssl_result(ssl, pk);
    }
    int32_t avail = (int32_t)SSL_pending(ssl);
    if (avail < 1) avail = 1;
    int32_t to_read = (n < 0 || n > avail) ? avail : n;
    janet_buffer_extra(buf, to_read);
    ERR_clear_error();
    int ret = SSL_read(ssl, buf->data + buf->count, to_read);
    if (ret > 0) {
        buf->count += ret;
        return DTLS_RESULT_OK;
    }
    return dtls_ssl_result(ssl, ret);
}

/*
 * (dtls/read client n &opt buf timeout)
 *
 * Read up to n bytes from DTLS client.
 * For datagrams, returns after first complete datagram received.
 */
Janet cfun_dtls_read(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 4);

    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);
    int32_t n = janet_getinteger(argv, 1);

    if (client->closed || client->state == DTLS_STATE_CLOSED) {
        return janet_wrap_nil();
    }

    if (client->state != DTLS_STATE_ESTABLISHED) {
        dtls_panic_io("DTLS client not connected");
    }

    /* Get or create buffer; an omitted user buffer starts at capacity 0
     * so nothing is reserved before SSL_peek succeeds */
    JanetBuffer *buf = janet_optbuffer(argv, argc, 2, 0);

    /* Try initial read */
    int32_t before = buf->count;
    DTLSResult result = dtls_do_read(client->ssl, buf, n);

    if (buf->count > before) {
        return janet_wrap_buffer(buf);
    }

    if (result == DTLS_RESULT_EOF) {
        return buf->count > 0 ? janet_wrap_buffer(buf) : janet_wrap_nil();
    }

    /* Need to wait */
    int mode = (result == DTLS_RESULT_WANT_WRITE) ? JANET_ASYNC_LISTEN_WRITE
                                                  : JANET_ASYNC_LISTEN_READ;
    dtls_client_start_async_read(client, buf, n, mode);
    return janet_wrap_nil(); /* Will be replaced by async result */
}

/*
 * (dtls/write client data &opt timeout)
 *
 * Write data to DTLS client.
 * Data should fit in a single datagram (typically < 64KB).
 */
Janet cfun_dtls_write(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);
    JanetByteView data = janet_getbytes(argv, 1);

    if (client->closed || client->state == DTLS_STATE_CLOSED) {
        dtls_panic_io("DTLS client is closed");
    }

    if (client->state != DTLS_STATE_ESTABLISHED) {
        dtls_panic_io("DTLS client not connected");
    }

    /* Try initial write */
    int32_t nwritten = 0;
    DTLSResult result =
        dtls_do_write(client->ssl, data.bytes, data.len, &nwritten);

    if (result == DTLS_RESULT_OK) {
        return janet_wrap_integer(nwritten);
    }

    /* Need to wait */
    int mode = (result == DTLS_RESULT_WANT_READ) ? JANET_ASYNC_LISTEN_READ
                                                 : JANET_ASYNC_LISTEN_WRITE;
    dtls_client_start_async_write(client, data, mode);
    return janet_wrap_nil(); /* Will be replaced by async result */
}

/*
 * (dtls/chunk client n &opt buf timeout)
 *
 * Read exactly n bytes from DTLS client.
 * Unlike read, will not return early if less than n bytes are available.
 * Returns buffer with exactly n bytes, or what's available on EOF.
 *
 * Note: For DTLS datagrams, this delegates to read since each SSL_read
 * returns a complete datagram. The "chunk" semantics make less sense
 * for datagrams but we provide it for API consistency with TLS.
 */
Janet cfun_dtls_chunk(int32_t argc, Janet *argv) {
    /* For DTLS, chunk just delegates to read since datagrams are atomic */
    return cfun_dtls_read(argc, argv);
}
