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

#include <errno.h>
#include <janet.h>
#include "compat.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * SSL Option Compatibility - must be after ssl.h include
 * SSL_OP_NO_RENEGOTIATION - OpenSSL 1.1.0h+, LibreSSL 2.5.1+
 * Define to 0 if missing so we can use it unconditionally.
 */
#ifndef SSL_OP_NO_RENEGOTIATION
#define SSL_OP_NO_RENEGOTIATION 0
#endif

/* Debug logging macro - enabled by defining JSEC_DEBUG_VERBOSE
 * Note: JSEC_DEBUG enables debug builds (sanitizers, etc.)
 *       JSEC_DEBUG_VERBOSE enables verbose debug print statements
 * Uses janet_eprintf for proper integration with Janet's I/O system */
#ifdef JSEC_DEBUG_VERBOSE
#define DEBUG_LOG(...) janet_eprintf("[jsec] " __VA_ARGS__)
#else
#define DEBUG_LOG(...)                                                       \
    do {                                                                     \
    } while (0)
#endif

/*
 * Helper macro for casting const strings to unsigned char* for OpenSSL APIs.
 * OpenSSL's X509_NAME_add_entry_by_txt and similar functions take unsigned
 * char* but don't modify the data. Janet returns const uint8_t* for strings.
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

/*
 * The one documented error for a peer close without close_notify. A peer
 * that ends the connection without the TLS shutdown alert has truncated
 * the stream: jsec raises this error on every read surface instead of
 * reporting a clean end of data, on every supported TLS library, so a
 * truncated stream can never look like a complete one. It is raised
 * identically for both library shapes of the same condition: the
 * SSL_ERROR_SYSCALL ret-0 surface of OpenSSL 1.1.1 and LibreSSL, and the
 * SSL_ERROR_SSL surface of OpenSSL 3.x.
 */
#define JSEC_UNEXPECTED_EOF_ERROR                                              \
    "unexpected EOF without close_notify: the peer closed the connection "     \
    "without completing the TLS shutdown"

/*
 * True when the OpenSSL error queue holds the OpenSSL 3.x shape of an
 * unexpected EOF: SSL_ERROR_SSL with reason
 * SSL_R_UNEXPECTED_EOF_WHILE_READING. The 1.1.1/LibreSSL shape (SSL_ERROR_
 * SYSCALL with ret 0) carries no queue entry and is classified by the
 * callers from the ret/errno pair instead. Peek only - the queue is left
 * for the caller to consume or clear.
 */
int jutils_is_unexpected_eof(void);

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

/* Set a fresh CSPRNG random serial of at least 64 bits (BN_rand) on the
 * certificate. Returns 1 on success, 0 on failure. */
int jutils_set_random_serial(X509 *x509);

/* Attach exactly one SAN entry for the common name: a GEN_IPADD entry when
 * a2i_IPADDRESS accepts the name, a GEN_DNS entry with the literal bytes
 * otherwise. The name is never parsed as X509V3 config syntax. Returns 1 on
 * success, 0 on failure. */
int jutils_add_common_name_san(X509 *cert, const char *cn);

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
 *   :min-version - Minimum TLS/DTLS version (e.g., :TLS1.2, :TLS1.3,
 * :DTLS1.2) :max-version - Maximum TLS/DTLS version :ciphers - Cipher suite
 * string (OpenSSL format) :curves - EC curves for ECDHE (e.g., :prime256v1 or
 * "prime256v1:secp384r1") :ca-file - CA file path or PEM string/buffer
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
    int is_dtls; /* 0 = TLS, 1 = DTLS */
} SSLContext;

/* Unified context abstract type - shared between TLS and DTLS modules */
extern const JanetAbstractType ssl_context_type;

/* GC callback for unified context */
int ssl_context_gc(void *p, size_t s);

/* Get method for unified context */
int ssl_context_get(void *p, Janet key, Janet *out);

/* Method table for SSLContext */
extern const JanetMethod ssl_context_methods[];

/*
 * Canonical context type object for janet_abstract / janet_getabstract /
 * janet_checkabstract. ssl_context_type is a per-.so copy; only the
 * registered copy carries one identity across module boundaries, so type
 * checks and creation go through this lookup, never through
 * &ssl_context_type.
 */
const JanetAbstractType *jutils_get_context_type(void);

/* Initialize the shared context type (call once at module init) */
void jutils_init_context_type(void);

/* Helper to create unified context from options
 * Returns SSLContext* allocated via janet_abstract, or panics on error
 */
SSLContext *jutils_create_context(Janet opts, int is_dtls);

/* Add trusted cert to unified context */
Janet cfun_ssl_context_trust_cert(int32_t argc, Janet *argv);

/* Callback to prevent interactive password prompts in OpenSSL 3.0+
 * Returns 0 to indicate no password available. */
int jutils_no_password_cb(char *buf, int size, int rwflag, void *u);

/* Callback for password-protected keys that uses userdata if provided.
 * If userdata contains a password string, copies it to buffer.
 * Otherwise returns 0 to prevent TTY prompting. */
int jutils_password_cb(char *buf, int size, int rwflag, void *u);

/*============================================================================
 * STANDARDIZED ERROR SYSTEM
 *============================================================================
 *
 * All errors follow the format: "[MODULE:CATEGORY] message: detail"
 *
 * Modules: TLS, DTLS, CRYPTO, CA, CERT
 * Categories: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY
 *
 * Examples:
 *   [TLS:CONFIG] invalid cipher suite: RC4-MD5
 *   [DTLS:SOCKET] bind failed: address already in use
 *   [CRYPTO:PARAM] output length must be 1-1024, got 2000
 *   [CA:SSL] failed to sign certificate: key mismatch
 */

/* Error categories */
typedef enum {
    JSEC_ERR_CONFIG,   /* Configuration errors (bad options, invalid settings)
                        */
    JSEC_ERR_IO,       /* I/O errors (read/write failures) */
    JSEC_ERR_SSL,      /* OpenSSL operation errors */
    JSEC_ERR_SOCKET,   /* Socket operation errors */
    JSEC_ERR_PARAM,    /* Invalid parameter errors */
    JSEC_ERR_RESOURCE, /* Resource allocation errors */
    JSEC_ERR_VERIFY,   /* Verification failures */
    JSEC_ERR_PARSE     /* Parsing errors */
} JsecErrorCategory;

/* Module names for error prefixes */
#define JSEC_MOD_TLS "TLS"
#define JSEC_MOD_DTLS "DTLS"
#define JSEC_MOD_CRYPTO "CRYPTO"
#define JSEC_MOD_CA "CA"
#define JSEC_MOD_CERT "CERT"
#define JSEC_MOD_UTILS "UTILS"

/* Category names */
static inline const char *jsec_err_category_str(JsecErrorCategory cat) {
    switch (cat) {
        case JSEC_ERR_CONFIG:
            return "CONFIG";
        case JSEC_ERR_IO:
            return "IO";
        case JSEC_ERR_SSL:
            return "SSL";
        case JSEC_ERR_SOCKET:
            return "SOCKET";
        case JSEC_ERR_PARAM:
            return "PARAM";
        case JSEC_ERR_RESOURCE:
            return "RESOURCE";
        case JSEC_ERR_VERIFY:
            return "VERIFY";
        case JSEC_ERR_PARSE:
            return "PARSE";
        default:
            return "UNKNOWN";
    }
}

/*
 * Standardized panic macros
 * Usage: jsec_panic(MOD, CAT, "message", ...)
 *        jsec_panic_ssl(MOD, CAT, "message") - appends SSL error
 *        jsec_panic_errno(MOD, CAT, "message") - appends strerror(errno)
 */

#define jsec_panic(mod, cat, ...)                                            \
    janet_panicf("[" mod ":" cat "] " __VA_ARGS__)

#define jsec_panic_ssl(mod, cat, msg)                                        \
    janet_panicf("[" mod ":" cat "] " msg ": %s", get_ssl_error_string())

#define jsec_panic_errno(mod, cat, msg)                                      \
    janet_panicf("[" mod ":" cat "] " msg ": %s", jsec_strerror(errno))

/* Convenience macros for common patterns */

/* TLS module */
#define tls_panic_config(...) jsec_panic(JSEC_MOD_TLS, "CONFIG", __VA_ARGS__)
#define tls_panic_io(...) jsec_panic(JSEC_MOD_TLS, "IO", __VA_ARGS__)
#define tls_panic_ssl(msg) jsec_panic_ssl(JSEC_MOD_TLS, "SSL", msg)
#define tls_panic_socket(msg) jsec_panic_errno(JSEC_MOD_TLS, "SOCKET", msg)
#define tls_panic_param(...) jsec_panic(JSEC_MOD_TLS, "PARAM", __VA_ARGS__)
#define tls_panic_verify(...) jsec_panic(JSEC_MOD_TLS, "VERIFY", __VA_ARGS__)

/* DTLS module */
#define dtls_panic_config(...)                                               \
    jsec_panic(JSEC_MOD_DTLS, "CONFIG", __VA_ARGS__)
#define dtls_panic_io(...) jsec_panic(JSEC_MOD_DTLS, "IO", __VA_ARGS__)
#define dtls_panic_ssl(msg) jsec_panic_ssl(JSEC_MOD_DTLS, "SSL", msg)
#define dtls_panic_socket(msg) jsec_panic_errno(JSEC_MOD_DTLS, "SOCKET", msg)
#define dtls_panic_param(...) jsec_panic(JSEC_MOD_DTLS, "PARAM", __VA_ARGS__)

/* CRYPTO module */
#define crypto_panic_config(...)                                             \
    jsec_panic(JSEC_MOD_CRYPTO, "CONFIG", __VA_ARGS__)
#define crypto_panic_ssl(msg) jsec_panic_ssl(JSEC_MOD_CRYPTO, "SSL", msg)
#define crypto_panic_param(...)                                              \
    jsec_panic(JSEC_MOD_CRYPTO, "PARAM", __VA_ARGS__)
#define crypto_panic_resource(...)                                           \
    jsec_panic(JSEC_MOD_CRYPTO, "RESOURCE", __VA_ARGS__)
#define crypto_panic_parse(...)                                              \
    jsec_panic(JSEC_MOD_CRYPTO, "PARSE", __VA_ARGS__)

/* CA module */
#define ca_panic_config(...) jsec_panic(JSEC_MOD_CA, "CONFIG", __VA_ARGS__)
#define ca_panic_ssl(msg) jsec_panic_ssl(JSEC_MOD_CA, "SSL", msg)
#define ca_panic_param(...) jsec_panic(JSEC_MOD_CA, "PARAM", __VA_ARGS__)
#define ca_panic_parse(...) jsec_panic(JSEC_MOD_CA, "PARSE", __VA_ARGS__)
#define ca_panic_verify(...) jsec_panic(JSEC_MOD_CA, "VERIFY", __VA_ARGS__)
#define ca_panic_resource(...)                                               \
    jsec_panic(JSEC_MOD_CA, "RESOURCE", __VA_ARGS__)

/* CERT module */
#define cert_panic_config(...)                                               \
    jsec_panic(JSEC_MOD_CERT, "CONFIG", __VA_ARGS__)
#define cert_panic_ssl(msg) jsec_panic_ssl(JSEC_MOD_CERT, "SSL", msg)
#define cert_panic_param(...) jsec_panic(JSEC_MOD_CERT, "PARAM", __VA_ARGS__)
#define cert_panic_parse(msg) jsec_panic_ssl(JSEC_MOD_CERT, "PARSE", msg)
#define cert_panic_resource(...)                                             \
    jsec_panic(JSEC_MOD_CERT, "RESOURCE", __VA_ARGS__)
#define cert_panic_verify(...)                                               \
    jsec_panic(JSEC_MOD_CERT, "VERIFY", __VA_ARGS__)

/* UTILS module */
#define utils_panic_config(...)                                              \
    jsec_panic(JSEC_MOD_UTILS, "CONFIG", __VA_ARGS__)
#define utils_panic_ssl(msg) jsec_panic_ssl(JSEC_MOD_UTILS, "SSL", msg)
#define utils_panic_param(...)                                               \
    jsec_panic(JSEC_MOD_UTILS, "PARAM", __VA_ARGS__)
#define utils_panic_verify(...)                                              \
    jsec_panic(JSEC_MOD_UTILS, "VERIFY", __VA_ARGS__)

#endif