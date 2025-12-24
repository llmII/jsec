/*
 * jsec compatibility layer for OpenSSL/LibreSSL
 *
 * This header provides detection macros and compatibility shims for
 * differences between OpenSSL 3.0+ and LibreSSL.
 *
 * Inspired by cqueues
 * (https://github.com/wahern/cqueues/blob/master/src/socket.c)
 */

#ifndef JSEC_COMPAT_H
#define JSEC_COMPAT_H

#include <openssl/opensslv.h>

/*
 * Version Macros (following cqueues pattern)
 *
 * OPENSSL_PREREQ(M, m, p) - returns true if OpenSSL version >= M.m.p
 * LIBRESSL_PREREQ(M, m, p) - returns true if LibreSSL version >= M.m.p
 *
 * Only one of these will ever return true (LibreSSL sets
 * LIBRESSL_VERSION_NUMBER, OpenSSL does not).
 */
#ifdef LIBRESSL_VERSION_NUMBER
  #define OPENSSL_PREREQ(M, m, p) (0)
  #define LIBRESSL_PREREQ(M, m, p)                                           \
      (LIBRESSL_VERSION_NUMBER >= (((M) << 28) | ((m) << 20) | ((p) << 12)))
#else
  #define OPENSSL_PREREQ(M, m, p)                                            \
      (OPENSSL_VERSION_NUMBER >= (((M) << 28) | ((m) << 20) | ((p) << 12)))
  #define LIBRESSL_PREREQ(M, m, p) (0)
#endif

/*
 * Backend Detection
 */
#ifdef LIBRESSL_VERSION_NUMBER
  #define JSEC_LIBRESSL 1
  #define JSEC_OPENSSL 0
#else
  #define JSEC_LIBRESSL 0
  #define JSEC_OPENSSL 1
#endif

/*
 * Feature Availability - SSL_CTX_up_ref / SSL_up_ref
 *
 * Available in OpenSSL 1.1.0+ and LibreSSL 2.7.0+
 */
#ifndef HAVE_SSL_CTX_UP_REF
  #define HAVE_SSL_CTX_UP_REF                                                \
      (OPENSSL_PREREQ(1, 1, 0) || LIBRESSL_PREREQ(2, 7, 0))
#endif

#ifndef HAVE_SSL_UP_REF
  #define HAVE_SSL_UP_REF                                                    \
      (OPENSSL_PREREQ(1, 1, 0) || LIBRESSL_PREREQ(2, 7, 0))
#endif

/*
 * Feature Availability - OSSL_PARAM system
 *
 * OpenSSL 3.0 introduced new APIs that LibreSSL doesn't have:
 * - OSSL_PARAM system (core_names.h)
 * - Provider API
 * - EVP_PKEY_get_utf8_string_param() and friends
 */
#define JSEC_HAS_OSSL_PROVIDER OPENSSL_PREREQ(3, 0, 0)
#define JSEC_HAS_OSSL_PARAM OPENSSL_PREREQ(3, 0, 0)

/*
 * Feature Availability - TLS 1.3 Key Update
 *
 * SSL_key_update() and SSL_KEY_UPDATE_REQUESTED are OpenSSL 1.1.1+ only.
 * LibreSSL does not have this API.
 */
#define JSEC_HAS_KEY_UPDATE OPENSSL_PREREQ(1, 1, 1)

/*
 * Feature Availability - X509_STORE_load_path
 *
 * X509_STORE_load_path() is OpenSSL 3.0+ only.
 * LibreSSL has X509_STORE_load_locations() instead.
 */
#define JSEC_HAS_X509_STORE_LOAD_PATH OPENSSL_PREREQ(3, 0, 0)

/*
 * Compatibility Shims
 *
 * For older OpenSSL/LibreSSL that lack SSL_CTX_up_ref / SSL_up_ref
 */
#if !HAVE_SSL_CTX_UP_REF
  #include <openssl/crypto.h>
  #define SSL_CTX_up_ref(ctx)                                                \
      CRYPTO_add(&(ctx)->references, 1, CRYPTO_LOCK_SSL_CTX)
#endif

#if !HAVE_SSL_UP_REF
  #include <openssl/crypto.h>
  #define SSL_up_ref(ssl) CRYPTO_add(&(ssl)->references, 1, CRYPTO_LOCK_SSL)
#endif

#endif /* JSEC_COMPAT_H */
