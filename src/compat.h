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

/* Enable POSIX features before any system includes (clock_gettime, strdup) */
#ifndef _POSIX_C_SOURCE
  #define _POSIX_C_SOURCE 200809L
#endif

#include <janet.h>
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
 * Windows Platform Compatibility - Types and Headers
 * Moved to _WIN32 block below to strictly enforce include order
 */


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

/*
 * =============================================================================
 * Windows Socket Compatibility
 * =============================================================================
 */

#ifdef _WIN32
  /* Winsock2 must be included before windows.h to avoid conflicts */
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mswsock.h> /* For WSA_FLAG_OVERLAPPED, AcceptEx, etc. */
  #include <windows.h>

  /* ssize_t is POSIX, not available on Windows */
  #include <basetsd.h>
typedef SSIZE_T ssize_t;

  /* Windows uses Winsock2 instead of arpa/inet.h */
  #define JSEC_HAS_ARPA_INET 0

  /* clock_gettime is POSIX, provide Windows implementation */
  #include <time.h>
  #include <profileapi.h>

  #ifndef CLOCK_MONOTONIC
    #define CLOCK_MONOTONIC 1
  #endif

static inline int clock_gettime(int clk_id, struct timespec *spec) {
    (void)clk_id; /* Only CLOCK_MONOTONIC supported */
    LARGE_INTEGER count, freq;
    QueryPerformanceCounter(&count);
    QueryPerformanceFrequency(&freq);
    spec->tv_sec = (time_t)(count.QuadPart / freq.QuadPart);
    spec->tv_nsec = (long)((count.QuadPart % freq.QuadPart) * 1000000000LL /
                           freq.QuadPart);
    return 0;
}

  /* Link against Winsock library */
  #pragma comment(lib, "ws2_32.lib")

/* Socket type compatibility */
typedef SOCKET jsec_socket_t;
  #define JSEC_INVALID_SOCKET INVALID_SOCKET
  #define JSEC_SOCKET_ERROR SOCKET_ERROR

  /* Socket operations */
  #define jsec_close_socket(s) closesocket(s)
  #define jsec_socket_errno WSAGetLastError()

  /* Error code mappings */
  #define JSEC_EWOULDBLOCK WSAEWOULDBLOCK
  #define JSEC_EINPROGRESS WSAEINPROGRESS
  #define JSEC_EAGAIN WSAEWOULDBLOCK
  #define JSEC_EINTR WSAEINTR
  #define JSEC_ECONNRESET WSAECONNRESET
  #define JSEC_EPIPE WSAECONNRESET

  /* fcntl/ioctl compatibility */
  #define F_GETFL 0
  #define F_SETFL 1
  #define O_NONBLOCK 1

  /* Windows doesn't have MSG_NOSIGNAL */
  #ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
  #endif

/* Winsock initialization */
static inline int jsec_winsock_init(void) {
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

static inline void jsec_winsock_cleanup(void) {
    WSACleanup();
}

#else
  /* Unix/POSIX systems */
  #define JSEC_HAS_ARPA_INET 1
  #include <errno.h>
  #include <fcntl.h>
  #include <sys/socket.h>
  #include <unistd.h>

typedef int jsec_socket_t;
  #define JSEC_INVALID_SOCKET (-1)
  #define JSEC_SOCKET_ERROR (-1)

  #define jsec_close_socket(s) close(s)
  #define jsec_socket_errno errno

  #define JSEC_EWOULDBLOCK EWOULDBLOCK
  #define JSEC_EINPROGRESS EINPROGRESS
  #define JSEC_EAGAIN EAGAIN
  #define JSEC_EINTR EINTR
  #define JSEC_ECONNRESET ECONNRESET
  #define JSEC_EPIPE EPIPE

/* No-op on Unix */
static inline int jsec_winsock_init(void) {
    return 0;
}
static inline void jsec_winsock_cleanup(void) {}
#endif

#endif /* JSEC_COMPAT_H */
