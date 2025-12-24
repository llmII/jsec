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
            SSL_set_SSL_CTX(ssl, data->contexts[i]);
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_NOACK;
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
