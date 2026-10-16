/*
 * ocsp.c - OCSP (Online Certificate Status Protocol) stapling
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"

/*============================================================================
 * OCSP STATUS CALLBACK
 *============================================================================
 * Called by OpenSSL to get OCSP response for stapling.
 *
 * The response normally lives on the active context. SNI switches the
 * connection to a per-name context that may carry none of its own, so
 * the arg - the initial context, set on SNI child contexts - provides
 * the response in that case.
 */
int jtls_ocsp_status_cb(SSL *ssl, void *arg) {
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    OCSPData *ocsp = SSL_CTX_get_ex_data(ctx, ocsp_idx);
    if (!ocsp && arg) {
        ocsp = SSL_CTX_get_ex_data((SSL_CTX *)arg, ocsp_idx);
    }

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

/*============================================================================
 * STORE OCSP RESPONSE
 *============================================================================
 * Copy a DER OCSP response onto a context's stapling slot, replacing
 * any response already stored there.
 */
int jtls_store_ocsp_response(SSL_CTX *ctx, const unsigned char *data,
                             int len) {
    OCSPData *ocsp = malloc(sizeof(OCSPData));
    if (!ocsp) return 0;

    ocsp->len = len;
    ocsp->data = malloc((size_t)len);
    if (!ocsp->data) {
        free(ocsp);
        return 0;
    }
    memcpy(ocsp->data, data, (size_t)len);

    OCSPData *old_data = SSL_CTX_get_ex_data(ctx, ocsp_idx);
    if (old_data) {
        if (old_data->data) free(old_data->data);
        free(old_data);
    }

    if (!SSL_CTX_set_ex_data(ctx, ocsp_idx, ocsp)) {
        free(ocsp->data);
        free(ocsp);
        return 0;
    }
    return 1;
}

/* Free callback for OCSP ex_data */
void jtls_ocsp_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
                       long argl, void *argp) {
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    if (ptr) {
        OCSPData *data = (OCSPData *)ptr;
        if (data->data) free(data->data);
        free(data);
    }
}
