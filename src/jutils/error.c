/*
 * error.c - SSL error handling utilities
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <stdarg.h>

/*
 * Recorded cause of the last cert-loading or security-option validation
 * failure. The helpers (load_cert_chain_mem, load_ca_mem,
 * add_trusted_cert, apply_security_options) never raise: they record a
 * human-readable cause here and return 0, so callers can free what they
 * own and raise with the cause after releasing any held lock (never
 * across a held ctx_cache_lock).
 */
static JANET_THREAD_LOCAL char cert_load_error_buf[2048];

void jutils_cert_load_error_clear(void) { cert_load_error_buf[0] = '\0'; }

void jutils_cert_load_errorf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cert_load_error_buf, sizeof(cert_load_error_buf), fmt, ap);
    va_end(ap);
}

const char *jutils_cert_load_error(void) {
    if (cert_load_error_buf[0] != '\0') return cert_load_error_buf;
    return get_ssl_error_string();
}

/*
 * Get human-readable SSL error string.
 *
 * NOTE: Returns pointer to thread-local static buffer. The returned string
 * is only valid until the next call to this function from the same thread.
 * Use immediately or copy if needed across multiple calls.
 *
 * Reports every queued error, separated. When no error is queued, reports
 * the recorded helper failure detail (if any) so a raise never reports an
 * empty cause while a recorded detail exists; "No SSL error" only when
 * both are empty.
 */
static JANET_THREAD_LOCAL char error_buf[2048];

const char *get_ssl_error_string(void) {
    size_t used = 0;
    unsigned long err = ERR_get_error();
    if (err == 0) {
        if (cert_load_error_buf[0] != '\0') return cert_load_error_buf;
        return "No SSL error";
    }
    while (err != 0) {
        char one[256];
        int n;
        ERR_error_string_n(err, one, sizeof(one));
        n = snprintf(error_buf + used, sizeof(error_buf) - used, "%s%s",
                     used == 0 ? "" : "; ", one);
        if (n < 0 || (size_t)n >= sizeof(error_buf) - used) {
            used = sizeof(error_buf) - 1;
            error_buf[used] = '\0';
        } else {
            used += (size_t)n;
        }
        err = ERR_get_error();
    }
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
