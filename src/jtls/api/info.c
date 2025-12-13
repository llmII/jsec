/*
 * info.c - TLS connection information functions
 *
 * This file implements connection info functions:
 * - get-version - Get TLS protocol version
 * - get-cipher - Get negotiated cipher suite
 * - get-cipher-bits - Get cipher strength in bits
 * - get-connection-info - Get detailed connection information
 * - get-handshake-time - Get handshake duration
 * - localname - Get local address/port
 * - peername - Get remote peer's address/port
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../jtls_internal.h"
#include <arpa/inet.h>
#include <sys/un.h>

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
 * GET-VERSION - Get TLS protocol version
 *============================================================================
 */
Janet cfun_get_version(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    check_handshake(tls);
    if (!tls->ssl || tls->conn_state != TLS_CONN_READY) {
        return janet_wrap_nil();
    }

    const char *version = SSL_get_version(tls->ssl);
    return janet_cstringv(version);
}

/*============================================================================
 * GET-CIPHER - Get negotiated cipher suite
 *============================================================================
 */
Janet cfun_get_cipher(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    check_handshake(tls);
    if (!tls->ssl || tls->conn_state != TLS_CONN_READY) {
        return janet_wrap_nil();
    }

    const char *cipher = SSL_get_cipher_name(tls->ssl);
    if (!cipher) return janet_wrap_nil();
    return janet_cstringv(cipher);
}

/*============================================================================
 * GET-CIPHER-BITS - Get cipher strength in bits
 *============================================================================
 */
Janet cfun_get_cipher_bits(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    check_handshake(tls);
    if (!tls->ssl || tls->conn_state != TLS_CONN_READY) {
        return janet_wrap_nil();
    }

    const SSL_CIPHER *cipher = SSL_get_current_cipher(tls->ssl);
    if (!cipher) return janet_wrap_nil();

    int bits = SSL_CIPHER_get_bits(cipher, NULL);
    return janet_wrap_integer(bits);
}

/*============================================================================
 * GET-CONNECTION-INFO - Get detailed connection information
 *============================================================================
 */
Janet cfun_get_connection_info(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    check_handshake(tls);
    if (!tls->ssl || tls->conn_state != TLS_CONN_READY) {
        return janet_wrap_nil();
    }

    const SSL_CIPHER *cipher = SSL_get_current_cipher(tls->ssl);
    JanetKV *st = janet_struct_begin(8);

    /* TLS version */
    const char *version = SSL_get_version(tls->ssl);
    janet_struct_put(st, janet_ckeywordv("version"), janet_cstringv(version));

    /* Protocol version number */
    int proto_version = SSL_version(tls->ssl);
    janet_struct_put(st, janet_ckeywordv("protocol-version"),
                     janet_wrap_integer(proto_version));

    if (cipher) {
        const char *cipher_name = SSL_CIPHER_get_name(cipher);
        if (cipher_name) {
            janet_struct_put(st, janet_ckeywordv("cipher"), janet_cstringv(cipher_name));
        }

        int bits = SSL_CIPHER_get_bits(cipher, NULL);
        janet_struct_put(st, janet_ckeywordv("cipher-bits"), janet_wrap_integer(bits));

        const char *cipher_version = SSL_CIPHER_get_version(cipher);
        if (cipher_version) {
            janet_struct_put(st, janet_ckeywordv("cipher-version"),
                             janet_cstringv(cipher_version));
        }

        char buf[256];
        const char *desc = SSL_CIPHER_description(cipher, buf, sizeof(buf));
        if (desc) {
            janet_struct_put(st, janet_ckeywordv("cipher-description"),
                             janet_cstringv(desc));
        }
    }

    /* ALPN */
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(tls->ssl, &alpn, &alpn_len);
    if (alpn && alpn_len > 0) {
        janet_struct_put(st, janet_ckeywordv("alpn"),
                         janet_wrap_string(janet_string(alpn, (int32_t)alpn_len)));
    }

    /* SNI */
    const char *servername = SSL_get_servername(tls->ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        janet_struct_put(st, janet_ckeywordv("server-name"),
                         janet_cstringv(servername));
    }

    return janet_wrap_struct(janet_struct_end(st));
}

/*============================================================================
 * GET-HANDSHAKE-TIME - Get handshake duration in seconds
 *============================================================================
 * Returns the time spent in TLS handshake as a floating-point number of
 * seconds, or nil if handshake timing isn't enabled or handshake hasn't
 * completed yet.
 * Uses CLOCK_MONOTONIC for accurate timing that isn't affected by system
 * time adjustments.
 */
Janet cfun_get_handshake_time(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    /* Return nil if timing is disabled */
    if (!tls->track_handshake_time) {
        return janet_wrap_nil();
    }

    /* Check if handshake has completed (ts_handshake will be non-zero) */
    if (tls->ts_handshake.tv_sec == 0 && tls->ts_handshake.tv_nsec == 0) {
        return janet_wrap_nil();
    }

    /* Calculate duration: handshake_time - connect_time */
    double duration = (double)(tls->ts_handshake.tv_sec - tls->ts_connect.tv_sec);
    duration += (double)(tls->ts_handshake.tv_nsec - tls->ts_connect.tv_nsec) / 1e9;

    return janet_wrap_number(duration);
}

/*============================================================================
 * HELPER: Convert sockaddr to Janet tuple
 *============================================================================
 * Returns (host port) for IPv4/IPv6 or (path) for Unix sockets.
 * Based on pattern from Janet's net.c (Copyright Calvin Rose & contributors, MIT License)
 */
static Janet sockaddr_to_tuple(const struct sockaddr_storage *ss) {
    char buffer[INET6_ADDRSTRLEN + 1];
    
    switch (ss->ss_family) {
        case AF_INET: {
            const struct sockaddr_in *sai = (const struct sockaddr_in *)ss;
            if (!inet_ntop(AF_INET, &(sai->sin_addr), buffer, sizeof(buffer))) {
                tls_panic_io("unable to decode ipv4 host address");
            }
            Janet pair[2] = {janet_cstringv(buffer), janet_wrap_integer(ntohs(sai->sin_port))};
            return janet_wrap_tuple(janet_tuple_n(pair, 2));
        }
        case AF_INET6: {
            const struct sockaddr_in6 *sai6 = (const struct sockaddr_in6 *)ss;
            if (!inet_ntop(AF_INET6, &(sai6->sin6_addr), buffer, sizeof(buffer))) {
                tls_panic_io("unable to decode ipv6 host address");
            }
            Janet pair[2] = {janet_cstringv(buffer), janet_wrap_integer(ntohs(sai6->sin6_port))};
            return janet_wrap_tuple(janet_tuple_n(pair, 2));
        }
        case AF_UNIX: {
            const struct sockaddr_un *sun = (const struct sockaddr_un *)ss;
            Janet pathname;
            if (sun->sun_path[0] == '\0') {
                /* Abstract socket - replace null with @ */
                char abuf[sizeof(sun->sun_path) + 1];
                memcpy(abuf, sun->sun_path, sizeof(sun->sun_path));
                abuf[0] = '@';
                pathname = janet_cstringv(abuf);
            } else {
                pathname = janet_cstringv(sun->sun_path);
            }
            return janet_wrap_tuple(janet_tuple_n(&pathname, 1));
        }
        default:
            tls_panic_param("unknown address family");
    }
}

/*============================================================================
 * LOCALNAME - Get local address/port
 *============================================================================
 * (:localname stream)
 *
 * Get the local address and port as a tuple (host port).
 * For Unix sockets, returns (path).
 */
Janet cfun_localname(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);
    
    if (!tls->transport || (tls->transport->flags & JANET_STREAM_CLOSED)) {
        tls_panic_io("stream closed");
    }
    
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    memset(&ss, 0, slen);
    
    if (getsockname(tls->transport->handle, (struct sockaddr *)&ss, &slen)) {
        tls_panic_socket("failed to get localname");
    }
    
    return sockaddr_to_tuple(&ss);
}

/*============================================================================
 * PEERNAME - Get remote peer's address/port
 *============================================================================
 * (:peername stream)
 *
 * Get the remote peer's address and port as a tuple (host port).
 * For Unix sockets, returns (path).
 */
Janet cfun_peername(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);
    
    if (!tls->transport || (tls->transport->flags & JANET_STREAM_CLOSED)) {
        tls_panic_io("stream closed");
    }
    
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    memset(&ss, 0, slen);
    
    if (getpeername(tls->transport->handle, (struct sockaddr *)&ss, &slen)) {
        tls_panic_socket("failed to get peername");
    }
    
    return sockaddr_to_tuple(&ss);
}
