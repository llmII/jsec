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

    /* :session resumption bytes - attach with the :session audit
     * contract: an explicit non-nil :session that is not a byte string,
     * fails to deserialize, or fails to attach is reported through the
     * returned string (never silently ignored), and the caller raises it
     * under its own module family with the OpenSSL queue drained. */
    if (!janet_checktype(opts, JANET_NIL)) {
        Janet session_opt = janet_get(opts, janet_ckeywordv("session"));
        if (!janet_checktype(session_opt, JANET_NIL)) {
            const uint8_t *bytes;
            int32_t len;
            if (!janet_bytes_view(session_opt, &bytes, &len)) {
                return "session must be a byte string or buffer";
            }
            const unsigned char *p = bytes;
            SSL_SESSION *session =
                (len > 0) ? d2i_SSL_SESSION(NULL, &p, len) : NULL;
            if (!session) {
                return "failed to parse session data";
            }
            int ret = SSL_set_session(ssl, session);
            SSL_SESSION_free(session);
            if (ret != 1) {
                return "failed to set session";
            }
        }
    }

    return NULL;
}

/*
 * Raise a jutils_client_setup failure under the caller's module family.
 * The three :session audit strings raise with their ruled categories and
 * messages ([mod:PARAM] / [mod:SSL] with the OpenSSL queue drained through
 * get_ssl_error_string); every other failure names an OpenSSL call and
 * raises the caller's verify message, as before.
 */
void jutils_raise_client_setup(const char *fail, const char *mod) {
    if (!strcmp(fail, "session must be a byte string or buffer")) {
        janet_panicf("[%s:PARAM] session must be a byte string or buffer",
                     mod);
    }
    if (!strcmp(fail, "failed to parse session data")) {
        janet_panicf("[%s:SSL] failed to parse session data: %s", mod,
                     get_ssl_error_string());
    }
    if (!strcmp(fail, "failed to set session")) {
        janet_panicf("[%s:SSL] failed to set session: %s", mod,
                     get_ssl_error_string());
    }
    janet_panicf("[%s:VERIFY] client SSL setup failed in %s", mod, fail);
}
