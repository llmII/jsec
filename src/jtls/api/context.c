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
 * HELPER: EXTRACT OCSP RESPONSE BYTES
 *============================================================================
 * Read a DER OCSP response option (byte string or buffer).
 */
static int extract_ocsp_response(Janet value, const unsigned char **out_data,
                                 int32_t *out_len) {
    if (janet_checktype(value, JANET_STRING)) {
        const uint8_t *s = janet_unwrap_string(value);
        *out_data = s;
        *out_len = janet_string_length(s);
        return 1;
    } else if (janet_checktype(value, JANET_BUFFER)) {
        JanetBuffer *b = janet_unwrap_buffer(value);
        *out_data = b->data;
        *out_len = b->count;
        return 1;
    }
    return 0;
}

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

        /* A top-level :ocsp-response staples on this context and is the
         * response per-name contexts fall back to when they carry none
         * of their own */
        Janet ocsp_resp = janet_get(opts, janet_ckeywordv("ocsp-response"));
        if (!janet_checktype(ocsp_resp, JANET_NIL)) {
            const unsigned char *resp_data = NULL;
            int32_t resp_len = 0;
            if (!extract_ocsp_response(ocsp_resp, &resp_data, &resp_len)) {
                SSL_CTX_free(ctx);
                tls_panic_config(
                    ":ocsp-response must be a string or buffer");
            }
            if (!jtls_store_ocsp_response(ctx, resp_data, resp_len)) {
                SSL_CTX_free(ctx);
                tls_panic_config("out of memory");
            }
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

            int parent_ocsp_stapling = 0;
            Janet parent_ocsp_opt =
                janet_get(security_opts, janet_ckeywordv("ocsp-stapling"));
            if (!janet_checktype(parent_ocsp_opt, JANET_NIL)) {
                parent_ocsp_stapling = janet_truthy(parent_ocsp_opt);
            }

            int idx = 0;
            for (int32_t i = 0; i < cap; i++) {
                if (!janet_checktype(kvs[i].key, JANET_NIL)) {
                    if (!janet_checktypes(kvs[i].key,
                                          JANET_TFLAG_STRING |
                                              JANET_TFLAG_KEYWORD |
                                              JANET_TFLAG_SYMBOL)) {
                        for (int j = 0; j < idx; j++) {
                            free(data->hostnames[j]);
                            SSL_CTX_free(data->contexts[j]);
                        }
                        free(data->hostnames);
                        free(data->contexts);
                        free(data);
                        SSL_CTX_free(ctx);
                        tls_panic_config(
                            "sni map key must be a string, keyword, or "
                            "symbol, got %v",
                            kvs[i].key);
                    }
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
                    Janet sub_ocsp_resp =
                        janet_get(sub_opts, janet_ckeywordv("ocsp-response"));

                    const unsigned char *resp_data = NULL;
                    int32_t resp_len = 0;
                    int has_ocsp_resp =
                        !janet_checktype(sub_ocsp_resp, JANET_NIL);
                    if (has_ocsp_resp && !extract_ocsp_response(
                                             sub_ocsp_resp, &resp_data,
                                             &resp_len)) {
                        for (int j = 0; j < idx; j++) {
                            free(data->hostnames[j]);
                            SSL_CTX_free(data->contexts[j]);
                        }
                        free(data->hostnames);
                        free(data->contexts);
                        free(data);
                        SSL_CTX_free(ctx);
                        tls_panic_config(
                            ":ocsp-response must be a string or buffer");
                    }

                    /* Each name keeps a context of its own: the shared
                     * context cache would otherwise let one name's
                     * staple and one parent's fallback leak to another */
                    SSL_CTX *sub_ctx = jtls_create_server_ctx(
                        sub_cert, sub_key, sub_sec, sub_alpn, 0);
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

                    if (has_ocsp_resp &&
                        !jtls_store_ocsp_response(sub_ctx, resp_data,
                                                  resp_len)) {
                        SSL_CTX_free(sub_ctx);
                        for (int j = 0; j < idx; j++) {
                            free(data->hostnames[j]);
                            SSL_CTX_free(data->contexts[j]);
                        }
                        free(data->hostnames);
                        free(data->contexts);
                        free(data);
                        SSL_CTX_free(ctx);
                        tls_panic_config("out of memory");
                    }

                    /* Stapling: a name's handshakes serve its own
                     * response and otherwise the initial context's, so
                     * the status arg carries the initial context; a name
                     * without its own :ocsp-stapling setting inherits the
                     * status callback from the parent options */
                    Janet sub_ocsp_stapling = janet_get(
                        sub_sec, janet_ckeywordv("ocsp-stapling"));
                    if (janet_checktype(sub_ocsp_stapling, JANET_NIL) &&
                        parent_ocsp_stapling) {
                        SSL_CTX_set_tlsext_status_cb(sub_ctx,
                                                     jtls_ocsp_status_cb);
                    }
                    SSL_CTX_set_tlsext_status_arg(sub_ctx, ctx);

                    data->hostnames[idx] = jsec_strdup(hostname);
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
            SSL_CTX_set_client_hello_cb(ctx, jtls_client_hello_cb, data);
        }
    } else {
        int verify = 1;
        Janet verify_opt = janet_get(opts, janet_ckeywordv("verify"));
        if (!janet_checktype(verify_opt, JANET_NIL)) {
            verify = janet_truthy(verify_opt);
        }
        Janet security_opts = janet_get(opts, janet_ckeywordv("security"));
        Janet ca_opt = janet_get(opts, janet_ckeywordv("ca"));

        ctx = jtls_create_client_ctx(verify, security_opts, ca_opt);
        if (!ctx) {
            tls_panic_ssl("failed to create client context");
        }

        /* Trust specific certificate (:trusted-cert) */
        Janet trusted_cert =
            janet_get(opts, janet_ckeywordv("trusted-cert"));
        if (!janet_checktype(trusted_cert, JANET_NIL)) {
            if (!jtls_add_trusted_cert(ctx, trusted_cert)) {
                SSL_CTX_free(ctx);
                tls_panic_ssl("failed to add trusted certificate");
            }
        }

        /* Cipher suites (:ciphers) */
        Janet ciphers = janet_get(opts, janet_ckeywordv("ciphers"));
        if (!janet_checktype(ciphers, JANET_NIL)) {
            if (!janet_checktype(ciphers, JANET_STRING)) {
                SSL_CTX_free(ctx);
                tls_panic_param("ciphers must be a string");
            }
            const char *cipher_str =
                (const char *)janet_unwrap_string(ciphers);
            if (SSL_CTX_set_cipher_list(ctx, cipher_str) != 1) {
                SSL_CTX_free(ctx);
                tls_panic_config("failed to set ciphers: %s", cipher_str);
            }
        }

        /* Top-level :ocsp-stapling opts in status requests on the wire */
        Janet ocsp_opt = janet_get(opts, janet_ckeywordv("ocsp-stapling"));
        if (!janet_checktype(ocsp_opt, JANET_NIL) && janet_truthy(ocsp_opt)) {
            SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);
        }
    }

    TLSContext *tls_ctx = (TLSContext *)janet_abstract(
        jutils_get_context_type(), sizeof(TLSContext));
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
    TLSContext *tls_ctx =
        janet_getabstract(argv, 0, jutils_get_context_type());
    JanetByteView response = janet_getbytes(argv, 1);

    if (!jtls_store_ocsp_response(tls_ctx->ctx, response.bytes,
                                  response.len)) {
        tls_panic_config("out of memory");
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
    TLSContext *tls_ctx =
        janet_getabstract(argv, 0, jutils_get_context_type());

    if (!jtls_add_trusted_cert(tls_ctx->ctx, argv[1])) {
        tls_panic_ssl("failed to add trusted certificate");
    }

    return janet_wrap_nil();
}
