/*
 * api_context.c - TLS context management API functions
 *
 * This file implements context management functions:
 * - new-context - Create a reusable TLS context
 * - set-ocsp-response - Set OCSP response for stapling
 * - trust-cert - Add certificate to trusted store
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../internal.h"

/*============================================================================
 * NEW-CONTEXT - Create a reusable TLS context
 *============================================================================
 */
Janet cfun_new_context(int32_t argc, Janet *argv) {
    janet_arity(argc, 0, 1);

    int is_server = 0;
    Janet opts = janet_wrap_nil();
    if (argc > 0) opts = argv[0];

    SSL_CTX *ctx = NULL;

    if (janet_checktype(opts, JANET_TABLE) ||
        janet_checktype(opts, JANET_STRUCT)) {
        Janet cert = janet_get(opts, janet_ckeywordv("cert"));
        Janet key = janet_get(opts, janet_ckeywordv("key"));

        int has_cert = !janet_checktype(cert, JANET_NIL);
        int has_key = !janet_checktype(key, JANET_NIL);

        /* Validate: cert and key must be provided together */
        if (has_cert != has_key) {
            janet_panicf(
                "[TLS:CFG] :cert and :key must be provided together");
        }

        if (has_cert && has_key) {
            is_server = 1;
        }
    }

    if (is_server) {
        Janet cert = janet_get(opts, janet_ckeywordv("cert"));
        Janet key = janet_get(opts, janet_ckeywordv("key"));
        Janet security_opts = janet_get(opts, janet_ckeywordv("security"));
        Janet alpn_opt = janet_get(opts, janet_ckeywordv("alpn"));
        Janet sni_opt = janet_get(opts, janet_ckeywordv("sni"));

        int use_cache = janet_checktype(sni_opt, JANET_NIL);

        ctx = jtls_create_server_ctx(cert, key, security_opts, alpn_opt,
                                     use_cache);
        if (!ctx) {
            tls_panic_ssl("failed to create server context");
        }

        /* Handle SNI */
        if (!janet_checktype(sni_opt, JANET_NIL)) {
            if (!janet_checktype(sni_opt, JANET_TABLE) &&
                !janet_checktype(sni_opt, JANET_STRUCT)) {
                SSL_CTX_free(ctx);
                tls_panic_config("sni option must be a table or struct");
            }

            const JanetKV *kvs = NULL;
            int32_t len = 0;
            int32_t cap = 0;
            janet_dictionary_view(sni_opt, &kvs, &len, &cap);

            SNIData *data = malloc(sizeof(SNIData));
            memset(data, 0, sizeof(SNIData));
            data->count = len;
            data->hostnames = malloc(sizeof(char *) * (size_t)len);
            data->contexts = malloc(sizeof(SSL_CTX *) * (size_t)len);

            int idx = 0;
            for (int32_t i = 0; i < cap; i++) {
                if (!janet_checktype(kvs[i].key, JANET_NIL)) {
                    const char *hostname =
                        (const char *)janet_unwrap_string(kvs[i].key);
                    Janet sub_opts = kvs[i].value;

                    Janet sub_cert =
                        janet_get(sub_opts, janet_ckeywordv("cert"));
                    Janet sub_key =
                        janet_get(sub_opts, janet_ckeywordv("key"));
                    Janet sub_sec =
                        janet_get(sub_opts, janet_ckeywordv("security"));
                    Janet sub_alpn =
                        janet_get(sub_opts, janet_ckeywordv("alpn"));

                    SSL_CTX *sub_ctx = jtls_create_server_ctx(
                        sub_cert, sub_key, sub_sec, sub_alpn, 1);
                    if (!sub_ctx) {
                        for (int j = 0; j < idx; j++) {
                            free(data->hostnames[j]);
                            SSL_CTX_free(data->contexts[j]);
                        }
                        free(data->hostnames);
                        free(data->contexts);
                        free(data);
                        SSL_CTX_free(ctx);
                        tls_panic_config(
                            "failed to create SNI context for %s", hostname);
                    }

                    data->hostnames[idx] = strdup(hostname);
                    data->contexts[idx] = sub_ctx;
                    idx++;
                }
            }

            if (!SSL_CTX_set_ex_data(ctx, sni_idx, data)) {
                for (int j = 0; j < idx; j++) {
                    free(data->hostnames[j]);
                    SSL_CTX_free(data->contexts[j]);
                }
                free(data->hostnames);
                free(data->contexts);
                free(data);
                SSL_CTX_free(ctx);
                tls_panic_ssl("failed to set SNI data");
            }
            SSL_CTX_set_tlsext_servername_callback(ctx, jtls_sni_callback);
            SSL_CTX_set_tlsext_servername_arg(ctx, data);
        }
    } else {
        int verify = 1;
        Janet verify_opt = janet_get(opts, janet_ckeywordv("verify"));
        if (!janet_checktype(verify_opt, JANET_NIL)) {
            verify = janet_truthy(verify_opt);
        }
        Janet security_opts = janet_get(opts, janet_ckeywordv("security"));

        ctx = jtls_create_client_ctx(verify, security_opts);
        if (!ctx) {
            tls_panic_ssl("failed to create client context");
        }
    }

    TLSContext *tls_ctx =
        (TLSContext *)janet_abstract(&tls_context_type, sizeof(TLSContext));
    tls_ctx->ctx = ctx;
    tls_ctx->is_dtls = 0; /* This is a TLS context */
    return janet_wrap_abstract(tls_ctx);
}

/*============================================================================
 * SET-OCSP-RESPONSE - Set OCSP response for stapling
 *============================================================================
 */
Janet cfun_set_ocsp_response(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    TLSContext *tls_ctx = janet_getabstract(argv, 0, &tls_context_type);
    JanetByteView response = janet_getbytes(argv, 1);

    OCSPData *data = malloc(sizeof(OCSPData));
    if (!data) tls_panic_config("out of memory");

    data->len = response.len;
    data->data = malloc((size_t)response.len);
    if (!data->data) {
        free(data);
        tls_panic_config("out of memory");
    }
    memcpy(data->data, response.bytes, (size_t)response.len);

    OCSPData *old_data = SSL_CTX_get_ex_data(tls_ctx->ctx, ocsp_idx);
    if (old_data) {
        if (old_data->data) free(old_data->data);
        free(old_data);
    }

    if (!SSL_CTX_set_ex_data(tls_ctx->ctx, ocsp_idx, data)) {
        free(data->data);
        free(data);
        tls_panic_ssl("failed to set OCSP data");
    }

    return janet_wrap_nil();
}

/*============================================================================
 * TRUST-CERT - Add a certificate to trusted store
 *============================================================================
 * (trust-cert context cert-pem)
 *
 * Add a certificate to the context's trusted store for verification.
 * This allows verifying against specific certificates without a full CA
 * chain. Useful for certificate pinning or self-signed cert verification.
 *
 * Example:
 *   (def ctx (tls/new-context {:verify true}))
 *   (tls/trust-cert ctx server-cert-pem)
 *   (tls/connect "localhost" 8443 {:context ctx})
 */
Janet cfun_trust_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    TLSContext *tls_ctx = janet_getabstract(argv, 0, &tls_context_type);

    if (!jtls_add_trusted_cert(tls_ctx->ctx, argv[1])) {
        tls_panic_ssl("failed to add trusted certificate");
    }

    return janet_wrap_nil();
}
