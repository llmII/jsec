/*
 * info.c - TLS connection information functions
 *
 * This file implements connection info functions:
 * - get-version - Get TLS protocol version
 * - get-cipher - Get negotiated cipher suite
 * - get-cipher-bits - Get cipher strength in bits
 * - get-connection-info - Get detailed connection information
 * - get-handshake-time - Get handshake duration
 * - get-peer-cert - Get peer certificate as X.509 DER
 * - localname - Get local address/port
 * - peername - Get remote peer's address/port
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"
#ifndef JANET_WINDOWS
#include <arpa/inet.h>
#endif
#ifndef JANET_WINDOWS
#include <sys/un.h>
#endif

/*============================================================================
 * HELPER: Check handshake completion
 *============================================================================*/
static void check_handshake(TLSStream *tls) {
    if (tls->conn_state != TLS_CONN_READY && tls->ssl &&
        SSL_is_init_finished(tls->ssl)) {
        tls->conn_state = TLS_CONN_READY;
        if (tls->track_handshake_time && tls->ts_handshake.tv_sec == 0 &&
            tls->ts_handshake.tv_nsec == 0) {
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
            janet_struct_put(st, janet_ckeywordv("cipher"),
                             janet_cstringv(cipher_name));
        }

        int bits = SSL_CIPHER_get_bits(cipher, NULL);
        janet_struct_put(st, janet_ckeywordv("cipher-bits"),
                         janet_wrap_integer(bits));

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
        janet_struct_put(
            st, janet_ckeywordv("alpn"),
            janet_wrap_string(janet_string(alpn, (int32_t)alpn_len)));
    }

    /* SNI */
    const char *servername =
        SSL_get_servername(tls->ssl, TLSEXT_NAMETYPE_host_name);
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
    double duration =
        (double)(tls->ts_handshake.tv_sec - tls->ts_connect.tv_sec);
    duration +=
        (double)(tls->ts_handshake.tv_nsec - tls->ts_connect.tv_nsec) / 1e9;

    return janet_wrap_number(duration);
}

/*============================================================================
 * GET-PEER-CERT - Get peer certificate as X.509 DER
 *============================================================================
 * (get-peer-cert stream)
 *
 * Export the peer certificate as an immutable Janet string holding the
 * X.509 DER encoding.
 *
 * Parameters:
 *   stream - TLS stream (live, after handshake)
 *
 * Returns:
 *   Immutable byte string of the peer certificate's X.509 DER encoding,
 *   or nil when there is no peer certificate (before the handshake
 *   completes or when the peer presented none).
 *
 * The two-pass i2d_X509 shape writes the DER encoding directly into
 * janet_string_begin's staging region - no intermediate buffer copy.
 * Serialization failure is a real failure and raises. The OpenSSL error
 * queue is drained on every exit so a silent nil cannot re-dirty it.
 */
Janet cfun_get_peer_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    TLSStream *tls = janet_getabstract(argv, 0, &tls_stream_type);

    if (tls->stream.flags & JANET_STREAM_CLOSED) {
        tls_panic_io("stream closed");
    }

    check_handshake(tls);

    /* nil is a documented absence of a peer certificate, never a failure
     * signal: before the handshake completes there is not one yet. */
    if (!tls->ssl || !SSL_is_init_finished(tls->ssl)) {
        return janet_wrap_nil();
    }

    ERR_clear_error();
    X509 *cert = SSL_get_peer_certificate(tls->ssl);
    if (!cert) {
        ERR_clear_error();
        return janet_wrap_nil();
    }

    /* Two-pass i2d: probe the length, then write in place */
    int der_len = i2d_X509(cert, NULL);
    if (der_len <= 0) {
        X509_free(cert);
        tls_panic_ssl("failed to encode peer certificate");
    }

    uint8_t *der = janet_string_begin((int32_t)der_len);
    unsigned char *p = der;
    if (i2d_X509(cert, &p) != der_len) {
        X509_free(cert);
        tls_panic_ssl("failed to encode peer certificate");
    }
    X509_free(cert);

    ERR_clear_error();
    return janet_wrap_string(janet_string_end(der));
}

/*============================================================================
 * HELPER: Convert sockaddr to Janet tuple
 *============================================================================
 * Returns (host port) for IPv4/IPv6 or (path) for Unix sockets.
 * Based on pattern from Janet's net.c (Copyright Calvin Rose & contributors,
 * MIT License)
 */
static Janet sockaddr_to_tuple(const struct sockaddr_storage *ss) {
    char buffer[INET6_ADDRSTRLEN + 1];

    switch (ss->ss_family) {
        case AF_INET: {
            const struct sockaddr_in *sai = (const struct sockaddr_in *)ss;
            if (!inet_ntop(AF_INET, &(sai->sin_addr), buffer,
                           sizeof(buffer))) {
                tls_panic_io("unable to decode ipv4 host address");
            }
            Janet pair[2] = {janet_cstringv(buffer),
                             janet_wrap_integer(ntohs(sai->sin_port))};
            return janet_wrap_tuple(janet_tuple_n(pair, 2));
        }
        case AF_INET6: {
            const struct sockaddr_in6 *sai6 = (const struct sockaddr_in6 *)ss;
            if (!inet_ntop(AF_INET6, &(sai6->sin6_addr), buffer,
                           sizeof(buffer))) {
                tls_panic_io("unable to decode ipv6 host address");
            }
            Janet pair[2] = {janet_cstringv(buffer),
                             janet_wrap_integer(ntohs(sai6->sin6_port))};
            return janet_wrap_tuple(janet_tuple_n(pair, 2));
        }
#ifndef JANET_WINDOWS
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
#endif
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
 * Accepts a jsec/tls-stream TLSStream or a core/stream JanetStream that
 * is a socket, so the raw listener returned by tls/listen also works.
 */
Janet cfun_localname(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    jsec_socket_t fd = JSEC_INVALID_SOCKET;

    if (janet_checkabstract(argv[0], &tls_stream_type)) {
        TLSStream *tls = (TLSStream *)janet_unwrap_abstract(argv[0]);

        if (!tls->transport ||
            (tls->transport->flags & JANET_STREAM_CLOSED)) {
            tls_panic_io("stream closed");
        }

        if (!(tls->transport->flags & JANET_STREAM_SOCKET)) {
            tls_panic_socket("underlying transport is not a socket");
        }

        fd = (jsec_socket_t)tls->transport->handle;
    } else if (janet_checkabstract(argv[0], &janet_stream_type)) {
        JanetStream *js = (JanetStream *)janet_unwrap_abstract(argv[0]);

        if (js->flags & JANET_STREAM_CLOSED) {
            tls_panic_io("stream closed");
        }

        if (!(js->flags & JANET_STREAM_SOCKET)) {
            tls_panic_socket("stream is not a socket");
        }

        fd = (jsec_socket_t)js->handle;
    } else {
        tls_panic_param(
            "bad slot #0, expected jsec/tls-stream or core/stream, got %v",
            argv[0]);
    }

    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    memset(&ss, 0, slen);

    if (getsockname(fd, (struct sockaddr *)&ss, &slen) < 0) {
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

    if (getpeername((jsec_socket_t)tls->transport->handle,
                    (struct sockaddr *)&ss, &slen)) {
        tls_panic_socket("failed to get peername");
    }

    return sockaddr_to_tuple(&ss);
}
