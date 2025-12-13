/*
 * ocsp.c - OCSP (Online Certificate Status Protocol) stapling
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../jtls_internal.h"

/*============================================================================
 * OCSP STATUS CALLBACK
 *============================================================================
 * Called by OpenSSL to get OCSP response for stapling.
 */
int jtls_ocsp_status_cb(SSL *ssl, void *arg) {
    (void)arg;
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    OCSPData *ocsp = SSL_CTX_get_ex_data(ctx, ocsp_idx);

    if (ocsp && ocsp->data) {
        /* OpenSSL takes ownership, so we must copy */
        unsigned char *p = OPENSSL_malloc((size_t)ocsp->len);
        if (p) {
            memcpy(p, ocsp->data, (size_t)ocsp->len);
            SSL_set_tlsext_status_ocsp_resp(ssl, p, ocsp->len);
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_NOACK;
}

/* Free callback for OCSP ex_data */
void jtls_ocsp_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                       int idx, long argl, void *argp) {
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    if (ptr) {
        OCSPData *data = (OCSPData *)ptr;
        if (data->data) free(data->data);
        free(data);
    }
}
