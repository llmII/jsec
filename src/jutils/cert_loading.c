/*
 * cert_loading.c - Certificate, key, and CA loading from memory
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

/*
 * Callback to prevent interactive password prompts in OpenSSL 3.0+
 * Returns 0 to indicate no password available.
 */
int jutils_no_password_cb(char *buf, int size, int rwflag, void *u) {
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)u;
    return 0;
}

/*
 * Callback for password-protected keys that uses userdata if provided.
 * If userdata contains a password string, copies it to buffer and returns
 * length. Otherwise returns 0 to prevent TTY prompting.
 */
int jutils_password_cb(char *buf, int size, int rwflag, void *u) {
    (void)rwflag;
    if (u == NULL) {
        return 0;
    }
    const char *pass = (const char *)u;
    int len = (int)strlen(pass);
    if (len >= size) {
        len = size - 1; /* Leave room for null terminator */
    }
    memcpy(buf, pass, len);
    buf[len] = '\0'; /* Null-terminate for safety */
    return len;
}

/*
 * Load certificate chain from PEM data in memory.
 * Loads the first certificate as the end-entity cert, then any
 * additional certificates as the chain.
 *
 * Returns: 1 on success, 0 on failure
 */
int load_cert_chain_mem(SSL_CTX *ctx, const unsigned char *data, int len) {
    BIO *bio = BIO_new_mem_buf(data, len);
    if (!bio) return 0;

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        return 0;
    }

    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        X509_free(cert);
        BIO_free(bio);
        return 0;
    }
    X509_free(cert);

    /* Load any additional certificates as chain certs */
    X509 *ca;
    while ((ca = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (SSL_CTX_add_extra_chain_cert(ctx, ca) != 1) {
            X509_free(ca);
            BIO_free(bio);
            return 0;
        }
        /* Note: SSL_CTX_add_extra_chain_cert takes ownership, don't free ca
         */
    }

    BIO_free(bio);
    return 1;
}

/*
 * Load private key from PEM data in memory.
 *
 * Returns: 1 on success, 0 on failure
 */
int load_key_mem(SSL_CTX *ctx, const unsigned char *data, int len) {
    BIO *bio = BIO_new_mem_buf(data, len);
    if (!bio) return 0;

    EVP_PKEY *pkey =
        PEM_read_bio_PrivateKey(bio, NULL, jutils_no_password_cb, NULL);
    if (!pkey) {
        BIO_free(bio);
        return 0;
    }

    int ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return ret;
}

/*
 * Load CA certificates from PEM data in memory.
 * Can contain multiple certificates.
 *
 * Returns: 1 on success, 0 on failure
 */
int load_ca_mem(SSL_CTX *ctx, const unsigned char *data, int len) {
    BIO *bio = BIO_new_mem_buf(data, len);
    if (!bio) return 0;

    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        BIO_free(bio);
        return 0;
    }

    X509 *cert;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
    }

    BIO_free(bio);
    return 1;
}

/*
 * Add a trusted certificate to SSL_CTX's certificate store.
 * Used for certificate pinning (trust specific cert without full CA chain).
 *
 * Accepts PEM-encoded certificate as Janet string or buffer.
 * Returns: 1 on success, 0 on failure
 */
int add_trusted_cert(SSL_CTX *ctx, Janet cert_pem) {
    const unsigned char *cert_data = NULL;
    int cert_len = 0;

    /* Extract certificate data from Janet value */
    if (janet_checktype(cert_pem, JANET_STRING)) {
        cert_data = janet_unwrap_string(cert_pem);
        cert_len = janet_string_length(janet_unwrap_string(cert_pem));
    } else if (janet_checktype(cert_pem, JANET_BUFFER)) {
        JanetBuffer *b = janet_unwrap_buffer(cert_pem);
        cert_data = b->data;
        cert_len = b->count;
    } else {
        return 0;
    }

    /* Parse PEM certificate */
    BIO *bio = BIO_new_mem_buf(cert_data, cert_len);
    if (!bio) return 0;

    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!x509) return 0;

    /* Get the certificate store and add the certificate */
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        X509_free(x509);
        return 0;
    }

    int ret = X509_STORE_add_cert(store, x509);
    X509_free(x509);

    return ret == 1;
}

/*
 * Load certificate from Janet value into SSL_CTX.
 * Handles: string (PEM data or file path), buffer (PEM data)
 *
 * Returns: 1 on success, 0 on failure
 */
int jutils_load_cert(SSL_CTX *ctx, Janet cert) {
    if (janet_checktype(cert, JANET_NIL)) return 1; /* Nothing to load */

    if (janet_checktype(cert, JANET_STRING)) {
        const uint8_t *s = janet_unwrap_string(cert);
        if (strstr((const char *)s, "-----BEGIN")) {
            /* PEM data in string */
            return load_cert_chain_mem(ctx, s, janet_string_length(s));
        } else {
            /* File path */
            return SSL_CTX_use_certificate_file(ctx, (const char *)s,
                                                SSL_FILETYPE_PEM) > 0;
        }
    } else if (janet_checktype(cert, JANET_BUFFER)) {
        JanetBuffer *b = janet_unwrap_buffer(cert);
        return load_cert_chain_mem(ctx, b->data, b->count);
    }

    return 0; /* Invalid type */
}

/*
 * Load private key from Janet value into SSL_CTX.
 * Handles: string (PEM data or file path), buffer (PEM data)
 *
 * Returns: 1 on success, 0 on failure
 */
int jutils_load_key(SSL_CTX *ctx, Janet key) {
    if (janet_checktype(key, JANET_NIL)) return 1; /* Nothing to load */

    if (janet_checktype(key, JANET_STRING)) {
        const uint8_t *s = janet_unwrap_string(key);
        if (strstr((const char *)s, "-----BEGIN")) {
            /* PEM data in string */
            return load_key_mem(ctx, s, janet_string_length(s));
        } else {
            /* File path */
            return SSL_CTX_use_PrivateKey_file(ctx, (const char *)s,
                                               SSL_FILETYPE_PEM) > 0;
        }
    } else if (janet_checktype(key, JANET_BUFFER)) {
        JanetBuffer *b = janet_unwrap_buffer(key);
        return load_key_mem(ctx, b->data, b->count);
    }

    return 0; /* Invalid type */
}

/*
 * Load CA certificates from Janet value into SSL_CTX.
 * Handles: string (PEM data or file path), buffer (PEM data)
 *
 * Returns: 1 on success, 0 on failure
 */
int jutils_load_ca(SSL_CTX *ctx, Janet ca) {
    if (janet_checktype(ca, JANET_NIL)) return 1; /* Nothing to load */

    if (janet_checktype(ca, JANET_STRING)) {
        const uint8_t *s = janet_unwrap_string(ca);
        if (strstr((const char *)s, "-----BEGIN")) {
            /* PEM data in string */
            return load_ca_mem(ctx, s, janet_string_length(s));
        } else {
            /* File path */
            return SSL_CTX_load_verify_locations(ctx, (const char *)s, NULL) >
                   0;
        }
    } else if (janet_checktype(ca, JANET_BUFFER)) {
        JanetBuffer *b = janet_unwrap_buffer(ca);
        return load_ca_mem(ctx, b->data, b->count);
    }

    return 0; /* Invalid type */
}

/*
 * Load credentials (cert, key, ca) from Janet values into SSL_CTX.
 * All parameters are optional (pass janet_wrap_nil() to skip).
 * Panics with descriptive error on failure.
 *
 * This consolidates the common pattern of:
 *   if (!jutils_load_cert(ctx, cert)) janet_panic("...");
 *   if (!jutils_load_key(ctx, key)) janet_panic("...");
 *   if (!jutils_load_ca(ctx, ca)) janet_panic("...");
 */
void jutils_load_credentials(SSL_CTX *ctx, Janet cert, Janet key, Janet ca) {
    if (!janet_checktype(cert, JANET_NIL)) {
        if (!jutils_load_cert(ctx, cert)) {
            utils_panic_ssl("failed to load certificate");
        }
    }

    if (!janet_checktype(key, JANET_NIL)) {
        if (!jutils_load_key(ctx, key)) {
            utils_panic_ssl("failed to load private key");
        }
    }

    if (!janet_checktype(ca, JANET_NIL)) {
        if (!jutils_load_ca(ctx, ca)) {
            utils_panic_ssl("failed to load CA certificates");
        }
    }
}

/*
 * Fresh CSPRNG random serial, at least 64 bits of entropy (BN_rand), set
 * directly on the certificate. Auto-generated serials use this; an explicit
 * caller-supplied serial is passed to ASN1_INTEGER_set_int64 by the caller.
 */
int jutils_set_random_serial(X509 *x509) {
    BIGNUM *bn = BN_new();
    if (!bn) return 0;
    int ok = BN_rand(bn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    if (ok) {
        ok = (BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x509)) != NULL);
    }
    BN_free(bn);
    return ok;
}

/*
 * The common name becomes exactly one literal SAN entry: a GENERAL_NAMES
 * structure attached with X509V3_add1_i2d, never spliced into an X509V3
 * config value. a2i_IPADDRESS classifies the single entry (GEN_IPADD vs
 * GEN_DNS).
 */
int jutils_add_common_name_san(X509 *cert, const char *cn) {
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ASN1_OCTET_STRING *ip = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    int ok = 0;

    gens = sk_GENERAL_NAME_new_null();
    gen = GENERAL_NAME_new();
    if (!gens || !gen) goto done;

    ip = a2i_IPADDRESS(cn);
    if (ip) {
        GENERAL_NAME_set0_value(gen, GEN_IPADD, ip);
        ip = NULL;
    } else {
        ASN1_IA5STRING *dns = ASN1_IA5STRING_new();
        if (!dns) goto done;
        if (!ASN1_STRING_set(dns, cn, -1)) {
            ASN1_IA5STRING_free(dns);
            goto done;
        }
        GENERAL_NAME_set0_value(gen, GEN_DNS, dns);
    }

    if (!sk_GENERAL_NAME_push(gens, gen)) goto done;
    gen = NULL;

    exts = sk_X509_EXTENSION_new_null();
    if (!exts) goto done;
    if (!X509V3_add1_i2d(&exts, NID_subject_alt_name, gens, 0,
                         X509V3_ADD_DEFAULT))
        goto done;
    if (!X509_add_ext(cert, sk_X509_EXTENSION_value(exts, 0), -1)) goto done;
    ok = 1;

done:
    if (exts) sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    if (ip) ASN1_OCTET_STRING_free(ip);
    if (gen) GENERAL_NAME_free(gen);
    if (gens) sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return ok;
}
