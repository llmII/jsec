/*
 * session.c - TLS session management functions
 *
 * This file implements session management:
 * - session-reused? - Check if session was resumed
 * - get-session - Export session for resumption
 * - set-session - Import session for resumption
 * - renegotiate - Trigger TLS renegotiation (TLS 1.2)
 * - key-update - Trigger key update (TLS 1.3)
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"

/*============================================================================
 * HELPER: Check handshake completion
 *============================================================================*/
static void check_handshake(TLSStream *tls) {
    if (tls->conn_state != TLS_CONN_READY && tls->ssl && SSL_is_init_finished(tls->ssl)) {
        tls->conn_state = TLS_CONN_READY;
        if (tls->track_handshake_time && 
            tls->ts_handshake.tv_sec == 0 && tls->ts_handshake.tv_nsec == 0) {
            clock_gettime(CLOCK_MONOTONIC, &tls->ts_handshake);
        }
    }
}

/*============================================================================
 * SESSION-REUSED? - Check if session was resumed
 *============================================================================
 */
Janet cfun_session_reused(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    check_handshake(tls);
    if (!tls->ssl || tls->conn_state != TLS_CONN_READY) {
        return janet_wrap_boolean(0);
    }

    return janet_wrap_boolean(SSL_session_reused(tls->ssl));
}

/*============================================================================
 * GET-SESSION - Export session for resumption
 *============================================================================
 */
Janet cfun_get_session(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    check_handshake(tls);
    if (!tls->ssl || tls->conn_state != TLS_CONN_READY) {
        return janet_wrap_nil();
    }

    SSL_SESSION *session = SSL_get1_session(tls->ssl);
    if (!session) {
        return janet_wrap_nil();
    }

    unsigned char *der_buf = NULL;
    int der_len = i2d_SSL_SESSION(session, &der_buf);
    SSL_SESSION_free(session);

    if (der_len <= 0 || !der_buf) {
        return janet_wrap_nil();
    }

    Janet result = janet_wrap_string(janet_string(der_buf, der_len));
    OPENSSL_free(der_buf);
    return result;
}

/*============================================================================
 * SET-SESSION - Import session for resumption
 *============================================================================
 */
Janet cfun_set_session(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);
    JanetByteView session_data = janet_getbytes(argv, 1);

    if (!tls->ssl) {
        tls_panic_io("stream not initialized");
    }

    if (tls->conn_state == TLS_CONN_READY) {
        tls_panic_io("cannot set session after handshake");
    }

    const unsigned char *der_ptr = session_data.bytes;
    SSL_SESSION *session = d2i_SSL_SESSION(NULL, &der_ptr, session_data.len);

    if (!session) {
        tls_panic_ssl("failed to deserialize session");
    }

    int ret = SSL_set_session(tls->ssl, session);
    SSL_SESSION_free(session);

    if (ret != 1) {
        tls_panic_ssl("failed to set session");
    }

    return janet_wrap_nil();
}

/*============================================================================
 * RENEGOTIATE - Trigger TLS renegotiation (TLS 1.2 and earlier)
 *============================================================================
 */
Janet cfun_renegotiate(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    if (!tls->ssl) tls_panic_io("stream not initialized");

    int ret = SSL_renegotiate(tls->ssl);
    if (ret == 1) return janet_ckeywordv("ok");

    tls_panic_ssl("renegotiation failed");
    return janet_wrap_nil();
}

/*============================================================================
 * KEY-UPDATE - Trigger TLS key update (TLS 1.3)
 *============================================================================
 */
Janet cfun_key_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    if (!tls->ssl) tls_panic_io("stream not initialized");

    int ret = SSL_key_update(tls->ssl, SSL_KEY_UPDATE_REQUESTED);
    if (ret == 1) return janet_ckeywordv("ok");

    tls_panic_ssl("key update failed");
    return janet_wrap_nil();
}
