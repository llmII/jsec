/*
 * client/io.c - DTLS client I/O operations (read, write, chunk)
 */

#include "../internal.h"
#include <string.h>

/* External declarations */
extern void dtls_client_start_async_read(DTLSClient *client, JanetBuffer *buf, int32_t nbytes, int mode);
extern void dtls_client_start_async_write(DTLSClient *client, JanetByteView data, int mode);

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
    
    /* Get or create buffer */
    JanetBuffer *buf;
    if (argc > 2 && janet_checktype(argv[2], JANET_BUFFER)) {
        buf = janet_getbuffer(argv, 2);
        janet_buffer_ensure(buf, buf->count + n, 2);
    } else {
        buf = janet_buffer(n);
    }
    
    /* Try initial read */
    int32_t nread = 0;
    DTLSResult result = dtls_do_read(client->ssl, buf->data + buf->count, n, &nread);
    
    if (nread > 0) {
        buf->count += nread;
        return janet_wrap_buffer(buf);
    }
    
    if (result == DTLS_RESULT_EOF) {
        return buf->count > 0 ? janet_wrap_buffer(buf) : janet_wrap_nil();
    }
    
    /* Need to wait */
    int mode = (result == DTLS_RESULT_WANT_WRITE)
               ? JANET_ASYNC_LISTEN_WRITE
               : JANET_ASYNC_LISTEN_READ;
    dtls_client_start_async_read(client, buf, n, mode);
    return janet_wrap_nil();  /* Will be replaced by async result */
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
    DTLSResult result = dtls_do_write(client->ssl, data.bytes, data.len, &nwritten);
    
    if (result == DTLS_RESULT_OK) {
        return janet_wrap_integer(nwritten);
    }
    
    /* Need to wait */
    int mode = (result == DTLS_RESULT_WANT_READ)
               ? JANET_ASYNC_LISTEN_READ
               : JANET_ASYNC_LISTEN_WRITE;
    dtls_client_start_async_write(client, data, mode);
    return janet_wrap_nil();  /* Will be replaced by async result */
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
