/*
 * jutils/client_name.c - unified client SSL name and session setup
 *
 * One implementation of the client-side connection name work (D-01):
 * client-name ranking, the SNI extension, certificate name verification
 * binding, and :session attachment - with every OpenSSL return checked -
 * shared by tls/connect, tls/wrap (and its tls/upgrade alias),
 * dtls/connect and dtls/upgrade.
 *
 * Author: jsec project
 * License: ISC
 */

#include "internal.h"
#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <openssl/x509v3.h>

/* An IP literal is not a DNS name: verification matches it through
 * iPAddress SANs, and RFC 6066 section 3 forbids literal addresses in
 * the server_name extension. */
static int host_is_ip_literal(const char *host) {
    struct in_addr a4;
    struct in6_addr a6;
    if (!host) return 0;
    return inet_pton(AF_INET, host, &a4) == 1 ||
           inet_pton(AF_INET6, host, &a6) == 1;
}

const char *jutils_client_setup(SSL *ssl, Janet opts,
                                const char *positional_host, int verify) {
    const char *client_name = positional_host;
    const char *verify_name = NULL;

    /* The :hostname option wins over the positional host; the :sni key is
     * the server virtual-host map on tls/new-context and never a client
     * name. */
    if (!janet_checktype(opts, JANET_NIL)) {
        Janet hn = janet_get(opts, janet_ckeywordv("hostname"));
        if (janet_checktype(hn, JANET_STRING)) {
            client_name = (const char *)janet_unwrap_string(hn);
        }
        Janet vh = janet_get(opts, janet_ckeywordv("verify-hostname"));
        if (janet_checktype(vh, JANET_STRING)) {
            verify_name = (const char *)janet_unwrap_string(vh);
        }
    }
    if (!verify_name) {
        verify_name = client_name;
    }

    /* SNI extension - IP literals send no server_name at all */
    if (client_name && !host_is_ip_literal(client_name)) {
        if (!SSL_set_tlsext_host_name(ssl, client_name)) {
            return "SSL_set_tlsext_host_name";
        }
    }

    /* Certificate name verification */
    if (verify && verify_name) {
        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (host_is_ip_literal(verify_name)) {
            if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),
                                               verify_name)) {
                return "X509_VERIFY_PARAM_set1_ip_asc";
            }
        } else if (!SSL_set1_host(ssl, verify_name)) {
            return "SSL_set1_host";
        }
    }

    /* :session resumption bytes - attach only when the caller validated
     * the option shape; deserialize/attach failure semantics stay with the
     * :session audit, not here */
    if (!janet_checktype(opts, JANET_NIL)) {
        Janet session_opt = janet_get(opts, janet_ckeywordv("session"));
        const uint8_t *bytes;
        int32_t len;
        if (janet_bytes_view(session_opt, &bytes, &len) && len > 0) {
            const unsigned char *p = bytes;
            SSL_SESSION *session = d2i_SSL_SESSION(NULL, &p, len);
            if (session) {
                SSL_set_session(ssl, session);
                SSL_SESSION_free(session);
            }
        }
    }

    return NULL;
}
