/*
 * alpn.c - ALPN (Application-Layer Protocol Negotiation) handling
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"

/*============================================================================
 * ALPN WIRE FORMAT CONVERSION
 *============================================================================
 * Convert a Janet array of protocol strings to ALPN wire format.
 *
 * Wire format is: [len1][proto1][len2][proto2]...
 * Each protocol is prefixed with its length as a single byte.
 *
 * Example: ["h2", "http/1.1"] becomes: \x02h2\x08http/1.1
 */
unsigned char *jtls_array_to_alpn_wire(Janet array, unsigned int *out_len) {
    if (!janet_checktype(array, JANET_ARRAY) &&
        !janet_checktype(array, JANET_TUPLE)) {
        return NULL;
    }

    const Janet *vals;
    int32_t len;
    janet_indexed_view(array, &vals, &len);

    /* First pass: calculate total length */
    size_t total_len = 0;
    for (int32_t i = 0; i < len; i++) {
        if (!janet_checktype(vals[i], JANET_STRING)) return NULL;
        int32_t slen = janet_string_length(janet_unwrap_string(vals[i]));
        if (slen > 255) return NULL;  /* ALPN protocol name limit */
        total_len += 1 + (size_t)slen;
    }

    if (total_len == 0 || total_len > 65535) return NULL;

    unsigned char *wire = janet_malloc(total_len);
    if (!wire) return NULL;

    /* Second pass: fill buffer */
    unsigned char *p = wire;
    for (int32_t i = 0; i < len; i++) {
        const uint8_t *str = janet_unwrap_string(vals[i]);
        int32_t slen = janet_string_length(str);
        *p++ = (unsigned char)slen;
        memcpy(p, str, (size_t)slen);
        p += slen;
    }

    *out_len = (unsigned int)total_len;
    return wire;
}

/*============================================================================
 * ALPN SELECTION CALLBACK
 *============================================================================
 * Called by OpenSSL during handshake to select the ALPN protocol.
 * Matches client's preference list against server's supported protocols.
 */
int jtls_alpn_select_cb(SSL *ssl, const unsigned char **out,
                        unsigned char *outlen, const unsigned char *in,
                        unsigned int inlen, void *arg) {
    (void)ssl;
    ALPNConfig *conf = (ALPNConfig *)arg;

    if (!conf || !conf->wire) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* SSL_select_next_proto has an unfortunate API that takes non-const out */
    unsigned char *selected = NULL;
    if (SSL_select_next_proto(&selected, outlen,
                              conf->wire, conf->len,
                              in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    *out = selected;
    return SSL_TLSEXT_ERR_OK;
}

/* Free callback for ALPN ex_data */
void jtls_alpn_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                       int idx, long argl, void *argp) {
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    if (ptr) {
        ALPNConfig *conf = (ALPNConfig *)ptr;
        if (conf->wire) free(conf->wire);
        free(conf);
    }
}
