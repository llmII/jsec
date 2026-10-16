/*
 * error.c - SSL error handling utilities
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"

/*
 * Get human-readable SSL error string.
 *
 * NOTE: Returns pointer to thread-local static buffer. The returned string
 * is only valid until the next call to this function from the same thread.
 * Use immediately or copy if needed across multiple calls.
 */
static JANET_THREAD_LOCAL char error_buf[512];

const char *get_ssl_error_string(void) {
    unsigned long err = ERR_get_error();
    if (err == 0) return "No SSL error";
    ERR_error_string_n(err, error_buf, sizeof(error_buf));
    ERR_clear_error();
    return error_buf;
}

/*
 * True when the error queue holds the OpenSSL 3.x shape of an unexpected
 * EOF (a transport EOF that arrived without close_notify): SSL_ERROR_SSL
 * with reason SSL_R_UNEXPECTED_EOF_WHILE_READING. OpenSSL 1.1.1 and
 * LibreSSL report the same condition as SSL_ERROR_SYSCALL with ret 0 and
 * no queue entry; callers classify that shape from the ret/errno pair and
 * raise JSEC_UNEXPECTED_EOF_ERROR for both. Peek only - the queue is left
 * for the caller to consume or clear.
 */
int jutils_is_unexpected_eof(void) {
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    unsigned long err = ERR_peek_error();
    return err != 0 && ERR_GET_REASON(err) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
#else
    return 0;
#endif
}
