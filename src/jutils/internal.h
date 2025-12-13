/*
 * jutils/internal.h - Internal definitions for jutils implementation
 *
 * This header is for internal use by jutils implementation files only.
 * External modules should include "jutils.h" instead.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#ifndef JUTILS_INTERNAL_H
#define JUTILS_INTERNAL_H

#include "../jutils.h"

/*
 * Standardized Error System
 * =========================
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
    JSEC_ERR_CONFIG,    /* Configuration errors (bad options, invalid settings) */
    JSEC_ERR_IO,        /* I/O errors (read/write failures) */
    JSEC_ERR_SSL,       /* OpenSSL operation errors */
    JSEC_ERR_SOCKET,    /* Socket operation errors */
    JSEC_ERR_PARAM,     /* Invalid parameter errors */
    JSEC_ERR_RESOURCE,  /* Resource allocation errors */
    JSEC_ERR_VERIFY,    /* Verification failures */
    JSEC_ERR_PARSE      /* Parsing errors */
} JsecErrorCategory;

/* Module names for error prefixes */
#define JSEC_MOD_TLS    "TLS"
#define JSEC_MOD_DTLS   "DTLS"
#define JSEC_MOD_CRYPTO "CRYPTO"
#define JSEC_MOD_CA     "CA"
#define JSEC_MOD_CERT   "CERT"
#define JSEC_MOD_UTILS  "UTILS"

/* Category names */
static inline const char *jsec_err_category_str(JsecErrorCategory cat) {
    switch (cat) {
        case JSEC_ERR_CONFIG:   return "CONFIG";
        case JSEC_ERR_IO:       return "IO";
        case JSEC_ERR_SSL:      return "SSL";
        case JSEC_ERR_SOCKET:   return "SOCKET";
        case JSEC_ERR_PARAM:    return "PARAM";
        case JSEC_ERR_RESOURCE: return "RESOURCE";
        case JSEC_ERR_VERIFY:   return "VERIFY";
        case JSEC_ERR_PARSE:    return "PARSE";
        default:                 return "UNKNOWN";
    }
}

/*
 * Standardized panic macros
 * Usage: jsec_panic(MOD, CAT, "message", ...)
 *        jsec_panic_ssl(MOD, CAT, "message") - appends SSL error
 *        jsec_panic_errno(MOD, CAT, "message") - appends strerror(errno)
 */

#define jsec_panic(mod, cat, ...) \
    janet_panicf("[" mod ":" cat "] " __VA_ARGS__)

#define jsec_panic_ssl(mod, cat, msg) \
    janet_panicf("[" mod ":" cat "] " msg ": %s", get_ssl_error_string())

#define jsec_panic_errno(mod, cat, msg) \
    janet_panicf("[" mod ":" cat "] " msg ": %s", strerror(errno))

/* Convenience macros for common patterns */

/* TLS module */
#define tls_panic_config(...)      jsec_panic(JSEC_MOD_TLS, "CONFIG", __VA_ARGS__)
#define tls_panic_io(...)          jsec_panic(JSEC_MOD_TLS, "IO", __VA_ARGS__)
#define tls_panic_ssl(msg)         jsec_panic_ssl(JSEC_MOD_TLS, "SSL", msg)
#define tls_panic_socket(msg)      jsec_panic_errno(JSEC_MOD_TLS, "SOCKET", msg)
#define tls_panic_param(...)       jsec_panic(JSEC_MOD_TLS, "PARAM", __VA_ARGS__)
#define tls_panic_verify(...)      jsec_panic(JSEC_MOD_TLS, "VERIFY", __VA_ARGS__)

/* DTLS module */
#define dtls_panic_config(...)     jsec_panic(JSEC_MOD_DTLS, "CONFIG", __VA_ARGS__)
#define dtls_panic_io(...)         jsec_panic(JSEC_MOD_DTLS, "IO", __VA_ARGS__)
#define dtls_panic_ssl(msg)        jsec_panic_ssl(JSEC_MOD_DTLS, "SSL", msg)
#define dtls_panic_socket(msg)     jsec_panic_errno(JSEC_MOD_DTLS, "SOCKET", msg)
#define dtls_panic_param(...)      jsec_panic(JSEC_MOD_DTLS, "PARAM", __VA_ARGS__)

/* CRYPTO module */
#define crypto_panic_config(...)   jsec_panic(JSEC_MOD_CRYPTO, "CONFIG", __VA_ARGS__)
#define crypto_panic_ssl(msg)      jsec_panic_ssl(JSEC_MOD_CRYPTO, "SSL", msg)
#define crypto_panic_param(...)    jsec_panic(JSEC_MOD_CRYPTO, "PARAM", __VA_ARGS__)
#define crypto_panic_resource(...) jsec_panic(JSEC_MOD_CRYPTO, "RESOURCE", __VA_ARGS__)
#define crypto_panic_parse(...)    jsec_panic(JSEC_MOD_CRYPTO, "PARSE", __VA_ARGS__)

/* CA module */
#define ca_panic_config(...)       jsec_panic(JSEC_MOD_CA, "CONFIG", __VA_ARGS__)
#define ca_panic_ssl(msg)          jsec_panic_ssl(JSEC_MOD_CA, "SSL", msg)
#define ca_panic_param(...)        jsec_panic(JSEC_MOD_CA, "PARAM", __VA_ARGS__)
#define ca_panic_parse(...)        jsec_panic(JSEC_MOD_CA, "PARSE", __VA_ARGS__)
#define ca_panic_verify(...)       jsec_panic(JSEC_MOD_CA, "VERIFY", __VA_ARGS__)
#define ca_panic_resource(...)     jsec_panic(JSEC_MOD_CA, "RESOURCE", __VA_ARGS__)

/* CERT module */
#define cert_panic_config(...)     jsec_panic(JSEC_MOD_CERT, "CONFIG", __VA_ARGS__)
#define cert_panic_ssl(msg)        jsec_panic_ssl(JSEC_MOD_CERT, "SSL", msg)
#define cert_panic_param(...)      jsec_panic(JSEC_MOD_CERT, "PARAM", __VA_ARGS__)
#define cert_panic_parse(msg)      jsec_panic_ssl(JSEC_MOD_CERT, "PARSE", msg)
#define cert_panic_resource(...)   jsec_panic(JSEC_MOD_CERT, "RESOURCE", __VA_ARGS__)
#define cert_panic_verify(...)     jsec_panic(JSEC_MOD_CERT, "VERIFY", __VA_ARGS__)

/* UTILS module */
#define utils_panic_config(...)    jsec_panic(JSEC_MOD_UTILS, "CONFIG", __VA_ARGS__)
#define utils_panic_ssl(msg)       jsec_panic_ssl(JSEC_MOD_UTILS, "SSL", msg)
#define utils_panic_param(...)     jsec_panic(JSEC_MOD_UTILS, "PARAM", __VA_ARGS__)
#define utils_panic_verify(...)    jsec_panic(JSEC_MOD_UTILS, "VERIFY", __VA_ARGS__)

#endif /* JUTILS_INTERNAL_H */
