/*
 * jutils.h - Shared definitions and utilities for jsec
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#ifndef JUTILS_H
#define JUTILS_H

/* Enable POSIX features for clock_gettime, strdup, etc. */
#ifndef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 200809L
#endif

#include <janet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>

/* Debug logging macro - enabled by defining JSEC_DEBUG_VERBOSE
 * Note: JSEC_DEBUG enables debug builds (sanitizers, etc.)
 *       JSEC_DEBUG_VERBOSE enables verbose debug print statements
 * Uses janet_eprintf for proper integration with Janet's I/O system */
#ifdef JSEC_DEBUG_VERBOSE
    #define DEBUG_LOG(...) janet_eprintf("[jsec] " __VA_ARGS__)
#else
    #define DEBUG_LOG(...) do {} while(0)
#endif

/*
 * Helper macro for casting const strings to unsigned char* for OpenSSL APIs.
 * OpenSSL's X509_NAME_add_entry_by_txt and similar functions take unsigned char*
 * but don't modify the data. Janet returns const uint8_t* for strings.
 * This cast is safe because OpenSSL only reads the data.
 */
#define OSSL_STR(s) ((unsigned char *)(uintptr_t)(s))


/*============================================================================
 * PUBLIC API - Utility Functions
 *============================================================================
 */

/* Get SSL error string - returns static buffer, not thread-safe
 * Use immediately or copy if needed across multiple calls. */
const char *get_ssl_error_string(void);

/* Helper to convert Janet string or keyword to C string
 * Returns NULL if the value is neither a string nor keyword. */
const char *janet_to_string_or_keyword(Janet value);

/*============================================================================
 * PUBLIC API - Certificate Loading
 *============================================================================
 */

/*
 * Load certificate from Janet value into SSL_CTX.
 * Accepts: string (PEM data or file path), buffer (PEM data)
 * Returns 1 on success, 0 on failure
 */
int jutils_load_cert(SSL_CTX *ctx, Janet cert);

/*
 * Load private key from Janet value into SSL_CTX.
 * Accepts: string (PEM data or file path), buffer (PEM data)
 * Returns 1 on success, 0 on failure
 */
int jutils_load_key(SSL_CTX *ctx, Janet key);

/*
 * Load CA certificates from Janet value into SSL_CTX.
 * Accepts: string (PEM data or file path), buffer (PEM data)
 * Returns 1 on success, 0 on failure
 */
int jutils_load_ca(SSL_CTX *ctx, Janet ca);

/*
 * Load credentials (cert, key, ca) from Janet values into SSL_CTX.
 * All parameters are optional (pass janet_wrap_nil() to skip).
 * Panics with descriptive error on failure.
 * This is a convenience function that combines jutils_load_cert,
 * jutils_load_key, and jutils_load_ca with consistent error messages.
 */
void jutils_load_credentials(SSL_CTX *ctx, Janet cert, Janet key, Janet ca);

/*============================================================================
 * PUBLIC API - Low-level Memory Loading
 *============================================================================
 * These functions load credentials from memory buffers. They are used
 * internally by the higher-level jutils_load_* functions but are also
 * available for direct use when needed (e.g., server context caching).
 */

/* Load certificate chain from PEM data in memory
 * Returns 1 on success, 0 on failure */
int load_cert_chain_mem(SSL_CTX *ctx, const unsigned char *data, int len);

/* Load private key from PEM data in memory
 * Returns 1 on success, 0 on failure */
int load_key_mem(SSL_CTX *ctx, const unsigned char *data, int len);

/* Load CA certificates from PEM data in memory
 * Returns 1 on success, 0 on failure */
int load_ca_mem(SSL_CTX *ctx, const unsigned char *data, int len);

/*============================================================================
 * PUBLIC API - Security Options
 *============================================================================
 */

/* Apply security options to SSL_CTX
 * Accepts a Janet table with the following optional keys:
 *   :min-version - Minimum TLS/DTLS version (e.g., :TLS1.2, :TLS1.3, :DTLS1.2)
 *   :max-version - Maximum TLS/DTLS version
 *   :ciphers - Cipher suite string (OpenSSL format)
 *   :curves - EC curves for ECDHE (e.g., :prime256v1 or "prime256v1:secp384r1")
 *   :ca-file - CA file path or PEM string/buffer
 *   :ca-path - CA directory path
 */
int apply_security_options(SSL_CTX *ctx, Janet opts, int is_dtls);

/* Add a trusted certificate to SSL_CTX's certificate store
 * Used for certificate pinning (trust specific cert without full CA chain)
 * Accepts PEM-encoded certificate as string or buffer
 */
int add_trusted_cert(SSL_CTX *ctx, Janet cert_pem);

/*============================================================================
 * UNIFIED SSL CONTEXT TYPE
 *============================================================================
 * Unified context type for both TLS and DTLS. The only difference between
 * TLS and DTLS contexts is the SSL_METHOD used during creation.
 *
 * Note: is_server is NOT stored here - that's a connection-level property.
 * A context can be used for either client or server connections.
 */
typedef struct {
    SSL_CTX *ctx;
    int is_dtls;  /* 0 = TLS, 1 = DTLS */
} SSLContext;

/* Unified context abstract type - shared between TLS and DTLS modules */
extern const JanetAbstractType ssl_context_type;

/* GC callback for unified context */
int ssl_context_gc(void *p, size_t s);

/* Get method for unified context */
int ssl_context_get(void *p, Janet key, Janet *out);

/* Method table for SSLContext */
extern const JanetMethod ssl_context_methods[];

/* Initialize the shared context type (call once at module init) */
void jutils_init_context_type(void);

/* Helper to create unified context from options
 * Returns SSLContext* allocated via janet_abstract, or panics on error
 */
SSLContext *jutils_create_context(Janet opts, int is_dtls);

/* Helper to get SSLContext from Janet value */
SSLContext *jutils_get_context(Janet val);

/* Add trusted cert to unified context */
Janet cfun_ssl_context_trust_cert(int32_t argc, Janet *argv);

/* Callback to prevent interactive password prompts in OpenSSL 3.0+
 * Returns 0 to indicate no password available. */
int jutils_no_password_cb(char *buf, int size, int rwflag, void *u);

#endif