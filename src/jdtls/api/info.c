/*
 * client/info.c - DTLS client connection information functions
 *
 * Provides getters for version, cipher, session, peer info, the peer
 * certificate DER export (get-peer-cert), etc.
 */

#include "../internal.h"
#include <string.h>
#include <time.h>
#include <openssl/x509v3.h>

/*
 * (dtls/get-version client)
 *
 * Get the DTLS protocol version string (e.g., "DTLSv1.2").
 */
Janet cfun_dtls_get_version(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl || client->state != DTLS_STATE_ESTABLISHED) {
        return janet_wrap_nil();
    }

    const char *version = SSL_get_version(client->ssl);
    return version ? janet_cstringv(version) : janet_wrap_nil();
}

/*
 * (dtls/get-cipher client)
 *
 * Get the cipher suite name.
 */
Janet cfun_dtls_get_cipher(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl || client->state != DTLS_STATE_ESTABLISHED) {
        return janet_wrap_nil();
    }

    const char *cipher = SSL_get_cipher(client->ssl);
    return cipher ? janet_cstringv(cipher) : janet_wrap_nil();
}

/*
 * (dtls/get-cipher-bits client)
 *
 * Get the cipher strength in bits.
 */
Janet cfun_dtls_get_cipher_bits(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl || client->state != DTLS_STATE_ESTABLISHED) {
        return janet_wrap_nil();
    }

    int bits = SSL_get_cipher_bits(client->ssl, NULL);
    return janet_wrap_integer(bits);
}

/*
 * (dtls/get-connection-info client)
 *
 * Get all connection info as a struct.
 */
Janet cfun_dtls_get_connection_info(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl || client->state != DTLS_STATE_ESTABLISHED) {
        return janet_wrap_nil();
    }

    JanetKV *kv = janet_struct_begin(4);

    const char *version = SSL_get_version(client->ssl);
    janet_struct_put(kv, janet_ckeywordv("version"),
                     version ? janet_cstringv(version) : janet_wrap_nil());

    const char *cipher = SSL_get_cipher(client->ssl);
    janet_struct_put(kv, janet_ckeywordv("cipher"),
                     cipher ? janet_cstringv(cipher) : janet_wrap_nil());

    int bits = SSL_get_cipher_bits(client->ssl, NULL);
    janet_struct_put(kv, janet_ckeywordv("cipher-bits"),
                     janet_wrap_integer(bits));

    /* ALPN protocol if negotiated */
    const unsigned char *alpn;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(client->ssl, &alpn, &alpn_len);
    if (alpn && alpn_len > 0) {
        janet_struct_put(kv, janet_ckeywordv("alpn"),
                         janet_stringv(alpn, alpn_len));
    } else {
        janet_struct_put(kv, janet_ckeywordv("alpn"), janet_wrap_nil());
    }

    return janet_wrap_struct(janet_struct_end(kv));
}

/*
 * (dtls/session-reused? client)
 *
 * Check if the session was reused from a previous connection.
 */
Janet cfun_dtls_session_reused(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl) {
        return janet_wrap_false();
    }

    return janet_wrap_boolean(SSL_session_reused(client->ssl));
}

/*
 * (dtls/get-session client)
 *
 * Get the session data for resumption.
 * Returns an immutable byte string containing the serialized session,
 * or nil if not available.
 */
Janet cfun_dtls_get_session(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl || client->state != DTLS_STATE_ESTABLISHED) {
        return janet_wrap_nil();
    }

    SSL_SESSION *session = SSL_get1_session(client->ssl);
    if (!session) {
        return janet_wrap_nil();
    }

    /* Serialize session to DER */
    int len = i2d_SSL_SESSION(session, NULL);
    if (len <= 0) {
        SSL_SESSION_free(session);
        return janet_wrap_nil();
    }

    uint8_t *str = janet_string_begin(len);
    unsigned char *p = str;
    i2d_SSL_SESSION(session, &p);

    SSL_SESSION_free(session);
    return janet_wrap_string(janet_string_end(str));
}

/*
 * (dtls/localname client)
 *
 * Get the local address as a DTLSAddress.
 */
Janet cfun_dtls_localname(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->transport) {
        return janet_wrap_nil();
    }

    jsec_socket_t fd = (jsec_socket_t)client->transport->handle;
    if (fd == JSEC_INVALID_SOCKET) {
        return janet_wrap_nil();
    }

    DTLSAddress local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.addrlen = sizeof(local_addr.addr);

    if (getsockname(fd, (struct sockaddr *)&local_addr.addr,
                    &local_addr.addrlen) < 0) {
        return janet_wrap_nil();
    }

    return dtls_address_wrap(&local_addr);
}

/*
 * (dtls/peername client)
 *
 * Get the peer's address as a DTLSAddress.
 */
Janet cfun_dtls_peername(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    return dtls_address_wrap(&client->peer_addr);
}

/*
 * (dtls/set-session client session-data)
 *
 * Set session data for resumption before connect.
 * The session-data should be a byte string or buffer from a previous
 * dtls/get-session call.
 * Returns nil on success, matching tls/set-session. Raises when the
 * session data does not parse or cannot be attached, draining the
 * OpenSSL error queue.
 */
Janet cfun_dtls_set_session(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl) {
        dtls_panic_io("stream not initialized");
    }

    JanetByteView bytes = janet_getbytes(argv, 1);

    /* Deserialize session from DER */
    const unsigned char *p = bytes.bytes;
    SSL_SESSION *session =
        (bytes.bytes && bytes.len > 0) ? d2i_SSL_SESSION(NULL, &p, bytes.len)
                                       : NULL;
    if (!session) {
        dtls_panic_ssl("failed to parse session data");
    }

    int ret = SSL_set_session(client->ssl, session);
    SSL_SESSION_free(session);

    if (ret != 1) {
        dtls_panic_ssl("failed to set session");
    }

    return janet_wrap_nil();
}

/*
 * (dtls/trust-cert client cert-pem)
 *
 * Trust a specific certificate for this connection.
 * Useful for self-signed certificates or certificate pinning.
 * The cert-pem should be a string/buffer containing PEM-encoded certificate.
 */
Janet cfun_dtls_trust_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (!client->ssl || !client->ctx) {
        dtls_panic_io("invalid DTLS client");
    }

    JanetByteView cert_pem = janet_getbytes(argv, 1);

    /* Create BIO from PEM data */
    BIO *bio = BIO_new_mem_buf(cert_pem.bytes, (int)cert_pem.len);
    if (!bio) {
        dtls_panic_ssl("failed to create BIO for certificate");
    }

    /* Parse certificate */
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) {
        dtls_panic_ssl("failed to parse PEM certificate");
    }

    /* Get or create cert store and add the certificate */
    X509_STORE *store = SSL_CTX_get_cert_store(client->ctx);
    if (!store) {
        X509_free(cert);
        dtls_panic_ssl("failed to get certificate store");
    }

    int result = X509_STORE_add_cert(store, cert);
    X509_free(cert);

    if (result != 1) {
        /* Might already be in store, not necessarily an error */
        unsigned long err = ERR_peek_last_error();
        if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
            dtls_panic_ssl("failed to add certificate to store");
        }
        ERR_clear_error();
    }

    return janet_wrap_nil();
}

/*
 * (:handshake-time client)
 *
 * Get handshake duration in seconds. Returns nil if:
 * - Handshake timing was not enabled
 * - Handshake not yet complete
 */
Janet cfun_dtls_get_handshake_time(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    /* Return nil if tracking not enabled */
    if (!client->track_handshake_time) {
        return janet_wrap_nil();
    }

    /* Return nil if handshake not complete */
    if (client->ts_handshake.tv_sec == 0 &&
        client->ts_handshake.tv_nsec == 0) {
        return janet_wrap_nil();
    }

    /* Calculate duration: handshake_time - connect_time */
    double duration =
        (double)(client->ts_handshake.tv_sec - client->ts_connect.tv_sec) +
        (double)(client->ts_handshake.tv_nsec - client->ts_connect.tv_nsec) /
            1e9;

    return janet_wrap_number(duration);
}

/*============================================================================
 * GET-PEER-CERT - Get peer certificate as X.509 DER
 *============================================================================
 * (get-peer-cert client)
 *
 * Export the peer certificate as an immutable Janet string holding the
 * X.509 DER encoding.
 *
 * Parameters:
 *   client - DTLS client stream (live, after handshake)
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
Janet cfun_dtls_get_peer_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSClient *client = janet_getabstract(argv, 0, &dtls_client_type);

    if (client->closed || client->state == DTLS_STATE_CLOSED ||
        (client->transport &&
         (client->transport->flags & JANET_STREAM_CLOSED))) {
        dtls_panic_io("stream closed");
    }

    /* nil is a documented absence of a peer certificate, never a failure
     * signal: before the handshake completes there is not one yet. */
    if (!client->ssl || !SSL_is_init_finished(client->ssl)) {
        return janet_wrap_nil();
    }

    ERR_clear_error();
    X509 *cert = SSL_get_peer_certificate(client->ssl);
    if (!cert) {
        ERR_clear_error();
        return janet_wrap_nil();
    }

    /* Two-pass i2d: probe the length, then write in place */
    int der_len = i2d_X509(cert, NULL);
    if (der_len <= 0) {
        X509_free(cert);
        dtls_panic_ssl("failed to encode peer certificate");
    }

    uint8_t *der = janet_string_begin((int32_t)der_len);
    unsigned char *p = der;
    if (i2d_X509(cert, &p) != der_len) {
        X509_free(cert);
        dtls_panic_ssl("failed to encode peer certificate");
    }
    X509_free(cert);

    ERR_clear_error();
    return janet_wrap_string(janet_string_end(der));
}
