/*
 * server.c - Server SSL context creation
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../jtls_internal.h"

/*============================================================================
 * HELPER: EXTRACT CREDENTIAL DATA
 *============================================================================
 * Extract certificate/key data from Janet value (string path or buffer/PEM).
 */
static int extract_credential(Janet value, const char **out_path,
                              const unsigned char **out_data, int *out_len) {
    *out_path = NULL;
    *out_data = NULL;
    *out_len = 0;

    if (janet_checktype(value, JANET_STRING)) {
        const uint8_t *s = janet_unwrap_string(value);
        if (strstr((const char *)s, "-----BEGIN")) {
            *out_data = s;
            *out_len = janet_string_length(s);
        } else {
            *out_path = (const char *)s;
        }
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
 * HELPER: APPLY SESSION OPTIONS
 *============================================================================
 * Configure session cache, tickets, OCSP stapling from security options.
 */
static void apply_session_options(SSL_CTX *ctx, Janet security_opts) {
    /* Handle session cache option - default enabled for server */
    int session_cache = 1;
    if (janet_checktype(security_opts, JANET_TABLE)) {
        JanetTable *opts_table = janet_unwrap_table(security_opts);
        Janet cache_opt = janet_table_get(opts_table,
                                          janet_ckeywordv("session-cache"));
        if (!janet_checktype(cache_opt, JANET_NIL)) {
            session_cache = janet_truthy(cache_opt);
        }
    }
    SSL_CTX_set_session_cache_mode(ctx, session_cache ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_OFF);

    /* Handle session tickets */
    int tickets = 1;
    if (janet_checktype(security_opts, JANET_TABLE)) {
        JanetTable *opts_table = janet_unwrap_table(security_opts);
        Janet ticket_opt = janet_table_get(opts_table,
                                           janet_ckeywordv("session-tickets"));
        if (!janet_checktype(ticket_opt, JANET_NIL)) {
            tickets = janet_truthy(ticket_opt);
        }
    }
    if (!tickets) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }

    /* Handle OCSP stapling option */
    int ocsp_stapling = 0;
    if (janet_checktype(security_opts, JANET_TABLE)) {
        JanetTable *opts_table = janet_unwrap_table(security_opts);
        Janet ocsp_opt = janet_table_get(opts_table, janet_ckeywordv("ocsp-stapling"));
        if (!janet_checktype(ocsp_opt, JANET_NIL)) {
            ocsp_stapling = janet_truthy(ocsp_opt);
        }
    }
    if (ocsp_stapling) {
        SSL_CTX_set_tlsext_status_cb(ctx, jtls_ocsp_status_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, NULL);
    }

    /* Get cache size from security options */
    long cache_size = 1000;
    if (janet_checktype(security_opts, JANET_TABLE)) {
        JanetTable *opts_table = janet_unwrap_table(security_opts);
        Janet size_opt = janet_table_get(opts_table,
                                         janet_ckeywordv("session-cache-size"));
        if (janet_checktype(size_opt, JANET_NUMBER)) {
            cache_size = (long)janet_unwrap_number(size_opt);
            if (cache_size < 0) cache_size = 1000;
        }
    }
    SSL_CTX_sess_set_cache_size(ctx, cache_size);

    /* Set session ID context for resumption */
    const unsigned char session_id_ctx[] = "jsec_server";
    SSL_CTX_set_session_id_context(ctx, session_id_ctx, sizeof(session_id_ctx) - 1);
}

/*============================================================================
 * HELPER: CHECK CACHE HIT
 *============================================================================
 * Check if cached context matches current parameters.
 */
static int check_cache_hit(const char *cert_path, const char *key_path,
                           const unsigned char *cert_data, int cert_len,
                           const unsigned char *key_data, int key_len,
                           unsigned char *alpn_wire, unsigned int alpn_len) {
    /* Check file-based credentials */
    if (cert_path && key_path &&
        server_ctx_cache.cert_path &&
        server_ctx_cache.key_path &&
        strcmp(server_ctx_cache.cert_path, cert_path) == 0 &&
        strcmp(server_ctx_cache.key_path, key_path) == 0) {

        if (server_ctx_cache.alpn_len == alpn_len) {
            if (alpn_len == 0) {
                return 1;
            } else if (server_ctx_cache.alpn_wire && alpn_wire &&
                       memcmp(server_ctx_cache.alpn_wire, alpn_wire, alpn_len) == 0) {
                return 1;
            }
        }
    }

    /* Check memory-based credentials */
    if (cert_data && key_data &&
        server_ctx_cache.cert_data &&
        server_ctx_cache.key_data &&
        cert_len == server_ctx_cache.cert_len &&
        key_len == server_ctx_cache.key_len &&
        memcmp(cert_data, server_ctx_cache.cert_data, (size_t)cert_len) == 0 &&
        memcmp(key_data, server_ctx_cache.key_data, (size_t)key_len) == 0) {

        if (server_ctx_cache.alpn_len == alpn_len) {
            if (alpn_len == 0) {
                return 1;
            } else if (server_ctx_cache.alpn_wire && alpn_wire &&
                       memcmp(server_ctx_cache.alpn_wire, alpn_wire, alpn_len) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

/*============================================================================
 * HELPER: UPDATE CACHE
 *============================================================================
 * Store context and credentials in cache.
 */
static void update_cache(SSL_CTX *ctx, const char *cert_path, const char *key_path,
                         const unsigned char *cert_data, int cert_len,
                         const unsigned char *key_data, int key_len) {
    /* Free old cache data */
    if (server_ctx_cache.ctx && server_ctx_cache.ctx != ctx) {
        SSL_CTX_free(server_ctx_cache.ctx);
    }
    if (server_ctx_cache.cert_path) {
        free(server_ctx_cache.cert_path);
        server_ctx_cache.cert_path = NULL;
    }
    if (server_ctx_cache.key_path) {
        free(server_ctx_cache.key_path);
        server_ctx_cache.key_path = NULL;
    }
    if (server_ctx_cache.cert_data) {
        free(server_ctx_cache.cert_data);
        server_ctx_cache.cert_data = NULL;
        server_ctx_cache.cert_len = 0;
    }
    if (server_ctx_cache.key_data) {
        free(server_ctx_cache.key_data);
        server_ctx_cache.key_data = NULL;
        server_ctx_cache.key_len = 0;
    }
    if (server_ctx_cache.alpn_wire) {
        free(server_ctx_cache.alpn_wire);
        server_ctx_cache.alpn_wire = NULL;
        server_ctx_cache.alpn_len = 0;
    }

    server_ctx_cache.ctx = ctx;

    /* Store file paths if using file-based certs */
    if (cert_path && key_path) {
        char *new_cert_path = strdup(cert_path);
        char *new_key_path = strdup(key_path);
        if (new_cert_path && new_key_path) {
            server_ctx_cache.cert_path = new_cert_path;
            server_ctx_cache.key_path = new_key_path;
        } else {
            free(new_cert_path);
            free(new_key_path);
        }
    } else if (cert_data && key_data) {
        unsigned char *new_cert_data = malloc((size_t)cert_len);
        unsigned char *new_key_data = malloc((size_t)key_len);
        if (new_cert_data && new_key_data) {
            memcpy(new_cert_data, cert_data, (size_t)cert_len);
            memcpy(new_key_data, key_data, (size_t)key_len);
            server_ctx_cache.cert_data = new_cert_data;
            server_ctx_cache.cert_len = cert_len;
            server_ctx_cache.key_data = new_key_data;
            server_ctx_cache.key_len = key_len;
        } else {
            free(new_cert_data);
            free(new_key_data);
        }
    }

    /* Store ALPN for cache key comparison */
    ALPNConfig *conf = SSL_CTX_get_ex_data(ctx, alpn_idx);
    if (conf && conf->wire) {
        unsigned char *new_alpn = malloc(conf->len);
        if (new_alpn) {
            memcpy(new_alpn, conf->wire, conf->len);
            server_ctx_cache.alpn_wire = new_alpn;
            server_ctx_cache.alpn_len = conf->len;
        }
    }

    SSL_CTX_up_ref(ctx);
}

/*============================================================================
 * CREATE SERVER CONTEXT
 *============================================================================
 * Create an SSL_CTX for server connections.
 *
 * Parameters:
 *   cert          - Certificate (file path or PEM buffer)
 *   key           - Private key (file path or PEM buffer)
 *   security_opts - Janet table with security options
 *   alpn_opt      - ALPN protocols to support
 *   use_cache     - Whether to use/update the context cache
 */
SSL_CTX *jtls_create_server_ctx(Janet cert, Janet key, Janet security_opts,
                                Janet alpn_opt, int use_cache) {
    janet_os_mutex_lock(ctx_cache_lock);

    const char *cert_path = NULL;
    const char *key_path = NULL;
    const unsigned char *cert_data = NULL;
    int cert_len = 0;
    const unsigned char *key_data = NULL;
    int key_len = 0;
    unsigned char *alpn_wire = NULL;
    unsigned int alpn_len = 0;
    SSL_CTX *ctx = NULL;

    /* Extract credentials */
    if (!extract_credential(cert, &cert_path, &cert_data, &cert_len)) {
        janet_os_mutex_unlock(ctx_cache_lock);
        return NULL;
    }
    if (!extract_credential(key, &key_path, &key_data, &key_len)) {
        janet_os_mutex_unlock(ctx_cache_lock);
        return NULL;
    }

    /* Process ALPN */
    if (!janet_checktype(alpn_opt, JANET_NIL)) {
        alpn_wire = jtls_array_to_alpn_wire(alpn_opt, &alpn_len);
        if (!alpn_wire) {
            janet_os_mutex_unlock(ctx_cache_lock);
            tls_panic_param("invalid ALPN protocols");
        }
    }

    /* Check cache for matching context */
    if (use_cache && server_ctx_cache.ctx) {
        if (check_cache_hit(cert_path, key_path, cert_data, cert_len,
                            key_data, key_len, alpn_wire, alpn_len)) {
            if (alpn_wire) free(alpn_wire);
            SSL_CTX *ret_ctx = server_ctx_cache.ctx;
            SSL_CTX_up_ref(ret_ctx);
            janet_os_mutex_unlock(ctx_cache_lock);
            return ret_ctx;
        }
    }

    /* Create new context */
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        if (alpn_wire) free(alpn_wire);
        janet_os_mutex_unlock(ctx_cache_lock);
        return NULL;
    }

    /* Load certificate */
    if (cert_path) {
        if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
            goto error;
        }
    } else {
        if (!load_cert_chain_mem(ctx, cert_data, cert_len)) {
            goto error;
        }
    }

    /* Load private key */
    if (key_path) {
        if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
            goto error;
        }
    } else {
        if (!load_key_mem(ctx, key_data, key_len)) {
            goto error;
        }
    }

    /* Verify key matches certificate */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        goto error;
    }

    /* Apply security options */
    if (!apply_security_options(ctx, security_opts, 0)) {
        goto error;
    }

    /* Disable renegotiation by default */
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);

    /* Setup ALPN */
    if (alpn_wire) {
        ALPNConfig *conf = malloc(sizeof(ALPNConfig));
        if (!conf) {
            goto error;
        }
        conf->wire = alpn_wire;
        conf->len = alpn_len;
        alpn_wire = NULL;  /* Ownership transferred */

        if (!SSL_CTX_set_ex_data(ctx, alpn_idx, conf)) {
            free(conf);
            goto error;
        }
        SSL_CTX_set_alpn_select_cb(ctx, jtls_alpn_select_cb, conf);
    }

    /* Apply session and cache options */
    apply_session_options(ctx, security_opts);

    /* Enable key logging if SSLKEYLOGFILE is set */
    if (keylog_file) {
        SSL_CTX_set_keylog_callback(ctx, jtls_keylog_callback);
    }

    /* Update cache if requested */
    if (use_cache) {
        update_cache(ctx, cert_path, key_path, cert_data, cert_len,
                     key_data, key_len);
    }

    janet_os_mutex_unlock(ctx_cache_lock);
    return ctx;

error:
    if (ctx) SSL_CTX_free(ctx);
    if (alpn_wire) free(alpn_wire);
    janet_os_mutex_unlock(ctx_cache_lock);
    return NULL;
}

/*============================================================================
 * ADD TRUSTED CERTIFICATE
 *============================================================================
 * Add a certificate to the context's trusted store for verification.
 * Delegates to shared implementation in jutils.
 */
int jtls_add_trusted_cert(SSL_CTX *ctx, Janet cert_pem) {
    return add_trusted_cert(ctx, cert_pem);
}
