/*
 * jcert/verify.c - Certificate chain verification
 *
 * Standalone certificate chain validation outside of TLS connection context.
 * Use cases: Certificate validation UI, debugging, audit logging, policy
 * checking.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "../compat.h" /* For LibreSSL/OpenSSL feature detection */
#include "../jutils.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <sys/stat.h>
#ifdef JANET_WINDOWS
#include <io.h>
#else
#include <unistd.h>
#endif

/* True when the trust-directory path names a readable directory. The
 * OpenSSL trust-directory load registers a lazy lookup and reports
 * success for a wrong or unreadable path, so the failure has to be
 * detected here to be raised at all. */
static int trust_dir_usable(const char *path) {
#ifdef JANET_WINDOWS
    struct _stat st;
    if (_stat(path, &st) != 0 || (st.st_mode & _S_IFDIR) == 0) return 0;
    return _access(path, 4) == 0;
#else
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
    return access(path, R_OK) == 0;
#endif
}

/*
 * Load a certificate from PEM data
 */
static X509 *load_cert_from_pem(const uint8_t *data, int32_t len) {
    BIO *bio = BIO_new_mem_buf(data, len);
    if (!bio) return NULL;

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

/*
 * Load multiple certificates from PEM data (chain)
 */
static STACK_OF(X509) *
    load_cert_chain_from_pem(const uint8_t *data, int32_t len) {
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) return NULL;

    BIO *bio = BIO_new_mem_buf(data, len);
    if (!bio) {
        sk_X509_free(chain);
        return NULL;
    }

    X509 *cert;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }

    /* Clear the "no more certs" error */
    ERR_clear_error();

    BIO_free(bio);
    return chain;
}

/*
 * Convert X509 verification error to human-readable message
 */
static const char *get_verify_error_string(int err) {
    return X509_verify_cert_error_string(err);
}

/*
 * Get purpose flag from keyword
 */
static int get_purpose_from_keyword(const char *purpose) {
    if (strcmp(purpose, "server-auth") == 0 ||
        strcmp(purpose, "ssl-server") == 0) {
        return X509_PURPOSE_SSL_SERVER;
    }
    if (strcmp(purpose, "client-auth") == 0 ||
        strcmp(purpose, "ssl-client") == 0) {
        return X509_PURPOSE_SSL_CLIENT;
    }
    // openssl 3.0 doesn't define this, but might get it another way
    if (strcmp(purpose, "code-signing") == 0) {
#ifdef X509_PURPOSE_CODE_SIGN
        return X509_PURPOSE_CODE_SIGN;
#else
        int idx = X509_PURPOSE_get_by_sname("codesign");
        if (idx >= 0) return idx;
        return -1;
#endif
    }
    if (strcmp(purpose, "email-protection") == 0 ||
        strcmp(purpose, "smime-sign") == 0) {
        return X509_PURPOSE_SMIME_SIGN;
    }
    if (strcmp(purpose, "smime-encrypt") == 0) {
        return X509_PURPOSE_SMIME_ENCRYPT;
    }
    if (strcmp(purpose, "timestamp") == 0 ||
        strcmp(purpose, "timestamp-sign") == 0) {
        return X509_PURPOSE_TIMESTAMP_SIGN;
    }
    if (strcmp(purpose, "ocsp-helper") == 0) {
        return X509_PURPOSE_OCSP_HELPER;
    }
    if (strcmp(purpose, "any") == 0) {
        return X509_PURPOSE_ANY;
    }
    return -1; /* Invalid */
}

/*
 * Export X509 to PEM string
 */
static Janet cert_to_pem(X509 *cert) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return janet_wrap_nil();

    PEM_write_bio_X509(bio, cert);

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    Janet result = janet_stringv((const uint8_t *)data, (int32_t)len);
    BIO_free(bio);

    return result;
}

/*
 * Verify certificate chain
 * (cert/verify-chain cert-pem &opt opts)
 * opts:
 *   :chain [<pem> ...] - Intermediate certificates
 *   :trusted [<pem> ...] - Trusted root certificates
 *   :trusted-dir "/path" - Directory of trusted certs
 *   :purpose :server-auth - Certificate purpose
 *   :hostname "example.com" - Verify hostname
 *   :time 1234567890 - Verify at specific time
 *   :check-crl true - Check CRL
 *   :crl <pem> - CRL to check against
 *
 * Returns: {:valid true :chain [<pem> ...]}
 *      or: {:valid false :error "message" :depth 0}
 */
Janet cfun_cert_verify_chain(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    JanetByteView cert_pem = janet_getbytes(argv, 0);

    /* Parse options */
    JanetArray *chain_arr = NULL;
    JanetArray *trusted_arr = NULL;
    const char *trusted_dir = NULL;
    size_t trusted_dir_len = 0;
    const char *purpose_str = NULL;
    const char *hostname = NULL;
    size_t hostname_len = 0;
    time_t verify_time = 0;
    int use_verify_time = 0;
    int check_crl = 0;
    JanetByteView crl_pem = {0};

    if (argc > 1 && !janet_checktype(argv[1], JANET_NIL)) {
        JanetTable *opts = NULL;
        JanetStruct opts_struct = NULL;

        if (janet_checktype(argv[1], JANET_TABLE)) {
            opts = janet_unwrap_table(argv[1]);
        } else if (janet_checktype(argv[1], JANET_STRUCT)) {
            opts_struct = janet_unwrap_struct(argv[1]);
        } else {
            cert_panic_param("options must be a table or struct");
        }

        Janet val;

        /* :chain */
        val = opts ? janet_table_get(opts, janet_ckeywordv("chain"))
                   : janet_struct_get(opts_struct, janet_ckeywordv("chain"));
        if (!janet_checktype(val, JANET_NIL)) {
            if (!janet_checktype(val, JANET_ARRAY) &&
                !janet_checktype(val, JANET_TUPLE)) {
                cert_panic_param(":chain must be an array of PEM strings");
            }
            chain_arr = janet_checktype(val, JANET_ARRAY)
                            ? janet_unwrap_array(val)
                            : NULL;
            /* Handle tuple as well */
            if (!chain_arr) {
                JanetTuple tup = janet_unwrap_tuple(val);
                chain_arr = janet_array(janet_tuple_length(tup));
                for (int32_t i = 0; i < janet_tuple_length(tup); i++) {
                    janet_array_push(chain_arr, tup[i]);
                }
            }
        }

        /* :trusted */
        val = opts
                  ? janet_table_get(opts, janet_ckeywordv("trusted"))
                  : janet_struct_get(opts_struct, janet_ckeywordv("trusted"));
        if (!janet_checktype(val, JANET_NIL)) {
            if (!janet_checktype(val, JANET_ARRAY) &&
                !janet_checktype(val, JANET_TUPLE)) {
                cert_panic_param(":trusted must be an array of PEM strings");
            }
            trusted_arr = janet_checktype(val, JANET_ARRAY)
                              ? janet_unwrap_array(val)
                              : NULL;
            if (!trusted_arr) {
                JanetTuple tup = janet_unwrap_tuple(val);
                trusted_arr = janet_array(janet_tuple_length(tup));
                for (int32_t i = 0; i < janet_tuple_length(tup); i++) {
                    janet_array_push(trusted_arr, tup[i]);
                }
            }
        }

        /* :trusted-dir */
        val = opts ? janet_table_get(opts, janet_ckeywordv("trusted-dir"))
                   : janet_struct_get(opts_struct,
                                      janet_ckeywordv("trusted-dir"));
        if (!janet_checktype(val, JANET_NIL)) {
            JanetByteView bv = janet_getbytes(&val, 0);
            trusted_dir = (const char *)bv.bytes;
            trusted_dir_len = bv.len;
        }

        /* :purpose */
        val = opts
                  ? janet_table_get(opts, janet_ckeywordv("purpose"))
                  : janet_struct_get(opts_struct, janet_ckeywordv("purpose"));
        if (!janet_checktype(val, JANET_NIL)) {
            purpose_str = (const char *)janet_getkeyword(&val, 0);
        }

        /* :hostname */
        val =
            opts ? janet_table_get(opts, janet_ckeywordv("hostname"))
                 : janet_struct_get(opts_struct, janet_ckeywordv("hostname"));
        if (!janet_checktype(val, JANET_NIL)) {
            JanetByteView bv = janet_getbytes(&val, 0);
            hostname = (const char *)bv.bytes;
            hostname_len = bv.len;
        }

        /* :time */
        val = opts ? janet_table_get(opts, janet_ckeywordv("time"))
                   : janet_struct_get(opts_struct, janet_ckeywordv("time"));
        if (!janet_checktype(val, JANET_NIL)) {
            verify_time = (time_t)janet_unwrap_number(val);
            use_verify_time = 1;
        }

        /* :check-crl */
        val = opts ? janet_table_get(opts, janet_ckeywordv("check-crl"))
                   : janet_struct_get(opts_struct,
                                      janet_ckeywordv("check-crl"));
        if (!janet_checktype(val, JANET_NIL)) {
            check_crl = janet_truthy(val);
        }

        /* :crl */
        val = opts ? janet_table_get(opts, janet_ckeywordv("crl"))
                   : janet_struct_get(opts_struct, janet_ckeywordv("crl"));
        if (!janet_checktype(val, JANET_NIL)) {
            crl_pem = janet_getbytes(&val, 0);
            check_crl = 1; /* Implicitly enable CRL check */
        }
    }

    /* Load the certificate to verify */
    X509 *cert = load_cert_from_pem(cert_pem.bytes, cert_pem.len);
    if (!cert) {
        cert_panic_ssl("failed to parse certificate");
    }

    /* Create X509_STORE for trusted certificates */
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        X509_free(cert);
        cert_panic_resource("failed to create certificate store");
    }

    /* Add trusted certificates - an entry that does not parse raises
     * naming it instead of being silently omitted */
    if (trusted_arr) {
        for (int32_t i = 0; i < trusted_arr->count; i++) {
            JanetByteView pem = janet_getbytes(&trusted_arr->data[i], 0);
            X509 *trusted = load_cert_from_pem(pem.bytes, pem.len);
            if (!trusted) {
                X509_STORE_free(store);
                X509_free(cert);
                janet_panicf("[CERT:PARSE] failed to parse :trusted entry "
                             "%d: %s",
                             (int)i, get_ssl_error_string());
            }
            if (!X509_STORE_add_cert(store, trusted)) {
                X509_free(trusted);
                X509_STORE_free(store);
                X509_free(cert);
                janet_panicf("[CERT:SSL] failed to add :trusted entry %d to "
                             "the trust store: %s",
                             (int)i, get_ssl_error_string());
            }
            X509_free(trusted);
        }
        ERR_clear_error();
    }

    /* Load trusted directory if specified - a wrong or unreadable
     * directory raises naming it instead of silently loading zero
     * anchors */
    if (trusted_dir) {
        JanetBuffer *dir_buf = janet_buffer(trusted_dir_len + 1);
        janet_buffer_push_bytes(dir_buf, (const uint8_t *)trusted_dir,
                                trusted_dir_len);
        janet_buffer_push_u8(dir_buf, 0);
        const char *dir_path = (const char *)dir_buf->data;
        if (!trust_dir_usable(dir_path)) {
            X509_STORE_free(store);
            X509_free(cert);
            janet_panicf("[CERT:SSL] failed to load :trusted-dir %s: not a "
                         "readable directory",
                         dir_path);
        }
#if JSEC_HAS_X509_STORE_LOAD_PATH
        int dir_ok = X509_STORE_load_path(store, dir_path);
#else
        /* LibreSSL fallback: use X509_STORE_load_locations */
        int dir_ok = X509_STORE_load_locations(store, NULL, dir_path);
#endif
        if (dir_ok != 1) {
            X509_STORE_free(store);
            X509_free(cert);
            janet_panicf("[CERT:SSL] failed to load :trusted-dir %s: %s",
                         dir_path, get_ssl_error_string());
        }
    }

    /* Add CRL if specified - an unparseable :crl raises instead of being
     * silently dropped so verification cannot blame a missing input */
    if (crl_pem.bytes && crl_pem.len > 0) {
        BIO *crl_bio = BIO_new_mem_buf(crl_pem.bytes, (int)crl_pem.len);
        if (!crl_bio) {
            X509_STORE_free(store);
            X509_free(cert);
            cert_panic_resource("failed to create CRL BIO");
        }
        X509_CRL *crl = PEM_read_bio_X509_CRL(crl_bio, NULL, NULL, NULL);
        BIO_free(crl_bio);
        if (!crl) {
            X509_STORE_free(store);
            X509_free(cert);
            janet_panicf("[CERT:PARSE] failed to parse :crl: %s",
                         get_ssl_error_string());
        }
        if (!X509_STORE_add_crl(store, crl)) {
            X509_CRL_free(crl);
            X509_STORE_free(store);
            X509_free(cert);
            janet_panicf("[CERT:SSL] failed to add :crl to the trust store: "
                         "%s",
                         get_ssl_error_string());
        }
        X509_CRL_free(crl);
    }

    /* Set CRL check flags */
    if (check_crl) {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
                                        X509_V_FLAG_CRL_CHECK_ALL);
    }

    /* Create verification context */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        X509_free(cert);
        cert_panic_resource("failed to create verification context");
    }

    /* Load intermediate chain certificates - an entry that does not
     * parse raises naming it instead of being silently omitted */
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (chain_arr) {
        for (int32_t i = 0; i < chain_arr->count; i++) {
            JanetByteView pem = janet_getbytes(&chain_arr->data[i], 0);
            X509 *intermediate = load_cert_from_pem(pem.bytes, pem.len);
            if (!intermediate) {
                sk_X509_pop_free(chain, X509_free);
                X509_STORE_CTX_free(ctx);
                X509_STORE_free(store);
                X509_free(cert);
                janet_panicf("[CERT:PARSE] failed to parse :chain entry %d: "
                             "%s",
                             (int)i, get_ssl_error_string());
            }
            if (!sk_X509_push(chain, intermediate)) {
                X509_free(intermediate);
                sk_X509_pop_free(chain, X509_free);
                X509_STORE_CTX_free(ctx);
                X509_STORE_free(store);
                X509_free(cert);
                cert_panic_resource("failed to add :chain entry");
            }
        }
        ERR_clear_error();
    }

    /* Initialize context */
    if (!X509_STORE_CTX_init(ctx, store, cert, chain)) {
        sk_X509_pop_free(chain, X509_free);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(cert);
        cert_panic_ssl("failed to initialize verification context");
    }

    /* Set verification time if specified */
    if (use_verify_time) {
        X509_STORE_CTX_set_time(ctx, 0, verify_time);
    }

    /* Set purpose if specified */
    if (purpose_str) {
        int purpose = get_purpose_from_keyword(purpose_str);
        if (purpose < 0) {
            sk_X509_pop_free(chain, X509_free);
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            X509_free(cert);
            cert_panic_param(
                "unknown purpose: %s (supported: server-auth, client-auth, "
                "code-signing, email-protection, timestamp, any)",
                purpose_str);
        }
        if (!X509_STORE_CTX_set_purpose(ctx, purpose)) {
            sk_X509_pop_free(chain, X509_free);
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            X509_free(cert);
            cert_panic_ssl("failed to set verification purpose");
        }
    }

    /* Perform verification */
    int result = X509_verify_cert(ctx);

    JanetTable *ret = janet_table(4);

    if (result == 1) {
        /* Verification succeeded */
        janet_table_put(ret, janet_ckeywordv("valid"), janet_wrap_boolean(1));

        /* If hostname verification requested, do it separately */
        if (hostname) {
            /* OpenSSL 1.1.0+ has X509_check_host */
            JanetBuffer *host_buf = janet_buffer(hostname_len + 1);
            janet_buffer_push_bytes(host_buf, (const uint8_t *)hostname,
                                    hostname_len);
            janet_buffer_push_u8(host_buf, 0);
            if (X509_check_host(cert, (const char *)host_buf->data,
                                hostname_len, 0, NULL) != 1) {
                janet_table_put(ret, janet_ckeywordv("valid"),
                                janet_wrap_boolean(0));
                janet_table_put(ret, janet_ckeywordv("error"),
                                janet_cstringv("hostname mismatch"));
                janet_table_put(ret, janet_ckeywordv("depth"),
                                janet_wrap_integer(0));
            }
        }

        /* Build verified chain */
        if (janet_truthy(janet_table_get(ret, janet_ckeywordv("valid")))) {
            STACK_OF(X509) *verified_chain = X509_STORE_CTX_get0_chain(ctx);
            JanetArray *chain_pems = janet_array(sk_X509_num(verified_chain));
            for (int i = 0; i < sk_X509_num(verified_chain); i++) {
                X509 *c = sk_X509_value(verified_chain, i);
                janet_array_push(chain_pems, cert_to_pem(c));
            }
            janet_table_put(ret, janet_ckeywordv("chain"),
                            janet_wrap_array(chain_pems));
        }
    } else {
        /* Verification failed */
        janet_table_put(ret, janet_ckeywordv("valid"), janet_wrap_boolean(0));

        int err = X509_STORE_CTX_get_error(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);

        janet_table_put(ret, janet_ckeywordv("error"),
                        janet_cstringv(get_verify_error_string(err)));
        janet_table_put(ret, janet_ckeywordv("depth"),
                        janet_wrap_integer(depth));
        janet_table_put(ret, janet_ckeywordv("error-code"),
                        janet_wrap_integer(err));
    }

    /* Cleanup */
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);

    return janet_wrap_table(ret);
}

/*
 * Build certificate chain from cert to trusted root
 * (cert/build-chain cert-pem intermediates trusted)
 * intermediates can be array or single PEM string with multiple certs
 * trusted can be array or single PEM string
 * Returns array of PEM strings from cert to the trusted root. Raises when
 * the walk cannot end at a trusted root - an unreachable issuer, a cycle,
 * or a self-signed certificate outside the trust set - naming the target
 * subject and the depth the walk stopped at; a rootless chain is never
 * returned as success.
 */
Janet cfun_cert_build_chain(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    JanetByteView cert_pem = janet_getbytes(argv, 0);

    /* Load target certificate */
    X509 *cert = load_cert_from_pem(cert_pem.bytes, cert_pem.len);
    if (!cert) {
        cert_panic_ssl("failed to parse certificate");
    }

    /* Load intermediates */
    STACK_OF(X509) *intermediates = sk_X509_new_null();
    if (janet_checktype(argv[1], JANET_ARRAY) ||
        janet_checktype(argv[1], JANET_TUPLE)) {
        JanetView items = janet_getindexed(&argv[1], 0);
        for (int32_t i = 0; i < items.len; i++) {
            JanetByteView pem = janet_getbytes(&items.items[i], 0);
            STACK_OF(X509) *loaded =
                load_cert_chain_from_pem(pem.bytes, pem.len);
            if (loaded) {
                for (int j = 0; j < sk_X509_num(loaded); j++) {
                    sk_X509_push(intermediates, sk_X509_value(loaded, j));
                }
                sk_X509_free(
                    loaded); /* Don't free the certs, just the stack */
            }
        }
    } else {
        JanetByteView pem = janet_getbytes(argv, 1);
        sk_X509_pop_free(intermediates, X509_free);
        intermediates = load_cert_chain_from_pem(pem.bytes, pem.len);
    }

    /* Load trusted roots */
    STACK_OF(X509) *trusted = sk_X509_new_null();
    if (janet_checktype(argv[2], JANET_ARRAY) ||
        janet_checktype(argv[2], JANET_TUPLE)) {
        JanetView items = janet_getindexed(&argv[2], 0);
        for (int32_t i = 0; i < items.len; i++) {
            JanetByteView pem = janet_getbytes(&items.items[i], 0);
            STACK_OF(X509) *loaded =
                load_cert_chain_from_pem(pem.bytes, pem.len);
            if (loaded) {
                for (int j = 0; j < sk_X509_num(loaded); j++) {
                    sk_X509_push(trusted, sk_X509_value(loaded, j));
                }
                sk_X509_free(loaded);
            }
        }
    } else {
        JanetByteView pem = janet_getbytes(argv, 2);
        sk_X509_pop_free(trusted, X509_free);
        trusted = load_cert_chain_from_pem(pem.bytes, pem.len);
    }

    /* Build chain by finding issuers. The walk only succeeds when it
     * ends at a certificate the trust set vouches for; every other stop
     * raises naming the subject and the depth. */
    JanetArray *chain = janet_array(8);
    janet_array_push(chain, cert_to_pem(cert));

    X509 *current = cert;
    int max_depth = 20; /* Prevent infinite loops */
    int depth = 0;
    int anchored = 0;

    for (int i = 0; i < sk_X509_num(trusted); i++) {
        if (X509_cmp(sk_X509_value(trusted, i), cert) == 0) {
            anchored = 1;
            break;
        }
    }

    while (!anchored) {
        if (X509_check_issued(current, current) == X509_V_OK) {
            /* Self-signed outside the trust set: not a trusted root */
            break;
        }
        if (depth >= max_depth) {
            /* Depth bound exhausted without reaching a trusted root */
            break;
        }

        /* Check if current cert's issuer is in trusted set */
        int found = 0;
        for (int i = 0; i < sk_X509_num(trusted); i++) {
            X509 *candidate = sk_X509_value(trusted, i);
            if (X509_check_issued(candidate, current) == X509_V_OK) {
                janet_array_push(chain, cert_to_pem(candidate));
                current = candidate;
                anchored = 1;
                found = 1;
                break;
            }
        }

        if (found) continue;

        /* Check intermediates */
        for (int i = 0; i < sk_X509_num(intermediates); i++) {
            X509 *candidate = sk_X509_value(intermediates, i);
            if (X509_check_issued(candidate, current) == X509_V_OK) {
                janet_array_push(chain, cert_to_pem(candidate));
                current = candidate;
                found = 1;
                break;
            }
        }

        if (!found) {
            break;
        }
        depth++;
    }

    if (!anchored) {
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject,
                          sizeof(subject));
        const char *reason =
            (depth >= max_depth)
                ? "depth bound exhausted before a trusted root"
                : (X509_check_issued(current, current) == X509_V_OK
                       ? "chain ends at a self-signed certificate outside "
                         "the trust set"
                       : "no issuer found for the last certificate");
        sk_X509_pop_free(intermediates, X509_free);
        sk_X509_pop_free(trusted, X509_free);
        X509_free(cert);
        cert_panic_verify(
            "cannot build a chain to a trusted root for %s: %s (walk "
            "stopped after %d certificates)",
            subject, reason, depth + 1);
    }

    /* Cleanup */
    sk_X509_pop_free(intermediates, X509_free);
    sk_X509_pop_free(trusted, X509_free);
    X509_free(cert);

    return janet_wrap_array(chain);
}
