/*
 * sni.c - SNI (Server Name Indication) handling
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"

/*============================================================================
 * SNI CALLBACK
 *============================================================================
 * Called by OpenSSL when client sends SNI hostname.
 * Looks up the hostname in our SNI mapping and switches SSL_CTX if found.
 */
int jtls_sni_callback(SSL *ssl, int *ad, void *arg) {
    (void)ad;
    SNIData *data = (SNIData *)arg;
    const char *servername =
        SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (!servername) return SSL_TLSEXT_ERR_NOACK;

    for (int i = 0; i < data->count; i++) {
        if (strcmp(servername, data->hostnames[i]) == 0) {
            if (SSL_set_SSL_CTX(ssl, data->contexts[i]) == NULL) {
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            /* Pin the per-vhost session ID context on the connection so a
             * session for one vhost cannot resume for another. */
            unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
            unsigned int sid_len = 0;
            if (jtls_sid_ctx_for_ctx(data->contexts[i], sid_ctx, &sid_len)) {
                SSL_set_session_id_context(ssl, sid_ctx, sid_len);
            }
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_NOACK;
}

/*============================================================================
 * CLIENT HELLO CALLBACK
 *============================================================================
 * Called by OpenSSL while processing the ClientHello, before session lookup
 * and creation stamp the session ID context.  The servername callback runs
 * after that, so the SNI path also sets the per-vhost session ID context
 * here to keep session resumption scoped per virtual host.
 */
int jtls_client_hello_cb(SSL *ssl, int *al, void *arg) {
    (void)al;
    SNIData *data = (SNIData *)arg;
    if (!data) return SSL_CLIENT_HELLO_SUCCESS;

    const unsigned char *ext = NULL;
    size_t ext_len = 0;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &ext,
                                   &ext_len) ||
        !ext) {
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    /* server_name payload: 2-byte list length, then per entry a 1-byte
     * name type (0 = host_name), 2-byte name length, and the name. */
    if (ext_len < 5 || ext[2] != 0x00) return SSL_CLIENT_HELLO_SUCCESS;
    size_t name_len = ((size_t)ext[3] << 8) | (size_t)ext[4];
    if (name_len == 0 || name_len != ext_len - 5) {
        return SSL_CLIENT_HELLO_SUCCESS;
    }
    const unsigned char *name = ext + 5;

    for (int i = 0; i < data->count; i++) {
        const char *host = data->hostnames[i];
        if (host && strlen(host) == name_len &&
            memcmp(host, name, name_len) == 0) {
            unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
            unsigned int sid_len = 0;
            if (jtls_sid_ctx_for_ctx(data->contexts[i], sid_ctx, &sid_len)) {
                SSL_set_session_id_context(ssl, sid_ctx, sid_len);
            }
            break;
        }
    }
    return SSL_CLIENT_HELLO_SUCCESS;
}

/* Free callback for SNI ex_data */
void jtls_sni_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
                      long argl, void *argp) {
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    if (ptr) {
        SNIData *data = (SNIData *)ptr;
        for (int i = 0; i < data->count; i++) {
            if (data->hostnames[i]) free(data->hostnames[i]);
            if (data->contexts[i]) SSL_CTX_free(data->contexts[i]);
        }
        if (data->hostnames) free(data->hostnames);
        if (data->contexts) free(data->contexts);
        free(data);
    }
}
