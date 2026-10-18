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

/* Enable standard feature test macros before any system includes */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
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
#define LIBRESSL_PREREQ(M, m, p)                                             \
    (LIBRESSL_VERSION_NUMBER >= (((M) << 28) | ((m) << 20) | ((p) << 12)))
#else
#define OPENSSL_PREREQ(M, m, p)                                              \
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
#define HAVE_SSL_CTX_UP_REF                                                  \
    (OPENSSL_PREREQ(1, 1, 0) || LIBRESSL_PREREQ(2, 7, 0))
#endif

#ifndef HAVE_SSL_UP_REF
#define HAVE_SSL_UP_REF (OPENSSL_PREREQ(1, 1, 0) || LIBRESSL_PREREQ(2, 7, 0))
#endif

/*
 * Feature Availability - SSL_get_peer_certificate
 *
 * The portable spelling across OpenSSL 1.1.1/3.x and LibreSSL is
 * SSL_get_peer_certificate; SSL_get1_peer_certificate is the
 * OpenSSL 3.x-only spelling. OpenSSL 3.x keeps the portable name as
 * a deprecated alias that is compiled out when
 * OPENSSL_NO_DEPRECATED_3_0 is set (derived from OPENSSL_NO_DEPRECATED
 * in openssl/macros.h, pulled in by opensslv.h above), so treat the
 * name as missing only there.
 */
#if OPENSSL_PREREQ(3, 0, 0) && defined(OPENSSL_NO_DEPRECATED_3_0)
#define HAVE_SSL_GET_PEER_CERTIFICATE 0
#else
#define HAVE_SSL_GET_PEER_CERTIFICATE 1
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
#define SSL_CTX_up_ref(ctx)                                                  \
    CRYPTO_add(&(ctx)->references, 1, CRYPTO_LOCK_SSL_CTX)
#endif

#if !HAVE_SSL_UP_REF
#include <openssl/crypto.h>
#define SSL_up_ref(ssl) CRYPTO_add(&(ssl)->references, 1, CRYPTO_LOCK_SSL)
#endif

/*
 * Compatibility Shims - SSL_get_peer_certificate
 *
 * For OpenSSL 3.x builds that compile out the deprecated
 * SSL_get_peer_certificate alias: map the portable spelling to the
 * OpenSSL 3.x name. Call sites use SSL_get_peer_certificate only -
 * never SSL_get1_peer_certificate and never per-call-site ifdefs.
 */
#if !HAVE_SSL_GET_PEER_CERTIFICATE
#define SSL_get_peer_certificate(ssl) SSL_get1_peer_certificate(ssl)
#endif

/*
 * =============================================================================
 * Windows Socket Compatibility
 * =============================================================================
 */

#ifdef JANET_WINDOWS
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

/* Cross-platform strerror - returns error message for errno
 * Uses strerror_s on Windows to avoid deprecation warnings.
 * Uses thread-local buffer for thread safety. */
static inline const char *jsec_strerror(int err) {
    static __declspec(thread) char buf[256];
    if (strerror_s(buf, sizeof(buf), err) != 0) {
        buf[0] = '\0';
    }
    return buf;
}

/* Socket-specific error string (thread-local static buffer) */
static inline const char *jsec_socket_strerror(int err) {
    static __declspec(thread) char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf,
                   sizeof(buf), NULL);
    /* Remove trailing newline */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return buf;
}

/* Cross-platform strdup (Windows uses _strdup) */
#define jsec_strdup(s) _strdup(s)

/* Error code mappings */
#define JSEC_EWOULDBLOCK WSAEWOULDBLOCK
#define JSEC_EINPROGRESS WSAEINPROGRESS
#define JSEC_EAGAIN WSAEWOULDBLOCK
#define JSEC_EINTR WSAEINTR
#define JSEC_ECONNRESET WSAECONNRESET
#define JSEC_ECONNABORTED WSAECONNABORTED
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

/* Socket flags for jsec_accept4 (fallback bitmask for Windows) */
#define JSEC_SOCK_CLOEXEC 0x01
#define JSEC_SOCK_NONBLOCK 0x02

static inline jsec_socket_t jsec_accept4(jsec_socket_t sockfd,
                                         struct sockaddr *addr, int *addrlen,
                                         int flags) {
    SOCKET s = accept(sockfd, addr, addrlen);
    if (s == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    if (flags & JSEC_SOCK_NONBLOCK) {
        u_long mode = 1;
        if (ioctlsocket(s, FIONBIO, &mode) != 0) {
            int err = WSAGetLastError();
            closesocket(s);
            WSASetLastError(err);
            return INVALID_SOCKET;
        }
    }
    if (flags & JSEC_SOCK_CLOEXEC) {
        if (!SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0)) {
            int err = GetLastError();
            closesocket(s);
            SetLastError(err);
            return INVALID_SOCKET;
        }
    }
    return s;
}

#else
/* Unix/POSIX systems */
#define JSEC_HAS_ARPA_INET 1
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Socket flags for jsec_accept4:
 * When the platform defines SOCK_CLOEXEC and SOCK_NONBLOCK (Linux, BSDs, Illumos),
 * JSEC_SOCK_* directly aliases the system constants so accept4(2) can consume
 * them without translation overhead. Otherwise fallback bit values are used.
 */
#ifdef SOCK_CLOEXEC
#define JSEC_SOCK_CLOEXEC SOCK_CLOEXEC
#else
#define JSEC_SOCK_CLOEXEC 0x01
#endif

#ifdef SOCK_NONBLOCK
#define JSEC_SOCK_NONBLOCK SOCK_NONBLOCK
#else
#define JSEC_SOCK_NONBLOCK 0x02
#endif

typedef int jsec_socket_t;
#define JSEC_INVALID_SOCKET (-1)
#define JSEC_SOCKET_ERROR (-1)

#define jsec_close_socket(s) close(s)
#define jsec_socket_errno errno

/* Cross-platform strerror - same on Unix */
#define jsec_strerror(err) strerror(err)
#define jsec_socket_strerror(err) strerror(err)

/* Cross-platform strdup - same on Unix (POSIX strdup) */
#define jsec_strdup(s) strdup(s)

#define JSEC_EWOULDBLOCK EWOULDBLOCK
#define JSEC_EINPROGRESS EINPROGRESS
#define JSEC_EAGAIN EAGAIN
#define JSEC_EINTR EINTR
#define JSEC_ECONNRESET ECONNRESET
#define JSEC_ECONNABORTED ECONNABORTED
#define JSEC_EPIPE EPIPE

/* MSG_DONTWAIT and MSG_NOSIGNAL may not be available on all platforms */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* No-op on Unix */
static inline int jsec_winsock_init(void) {
    return 0;
}
static inline void jsec_winsock_cleanup(void) {}

/*
 * Platform accept4 capability detection using Janet's OS macros:
 * Linux, BSDs (FreeBSD 10+, OpenBSD 5.7+, NetBSD 8.0+, DragonFly), and Illumos
 * provide accept4(2) in <sys/socket.h> with SOCK_NONBLOCK and SOCK_CLOEXEC.
 * macOS and other POSIX platforms fall back to accept() + fcntl.
 */
#if (defined(JANET_LINUX) || defined(JANET_BSD) || defined(JANET_ILLUMOS)) && \
    defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
#define JSEC_HAVE_ACCEPT4 1
#else
#define JSEC_HAVE_ACCEPT4 0
#endif

static inline jsec_socket_t jsec_accept4(jsec_socket_t sockfd,
                                         struct sockaddr *addr,
                                         socklen_t *addrlen, int flags) {
    jsec_socket_t fd;
#if JSEC_HAVE_ACCEPT4
    fd = accept4(sockfd, addr, addrlen, flags);
    if (fd >= 0) {
        return fd;
    }
    /* Fall back to accept() + fcntl only if accept4 is unimplemented in running kernel */
    if (errno != ENOSYS) {
        return fd;
    }
#endif
    fd = accept(sockfd, addr, addrlen);
    if (fd < 0) {
        return fd;
    }
    if (flags & JSEC_SOCK_NONBLOCK) {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl == -1 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
            int err = errno;
            close(fd);
            errno = err;
            return -1;
        }
    }
    if (flags & JSEC_SOCK_CLOEXEC) {
        int fl = fcntl(fd, F_GETFD, 0);
        if (fl == -1 || fcntl(fd, F_SETFD, fl | FD_CLOEXEC) == -1) {
            int err = errno;
            close(fd);
            errno = err;
            return -1;
        }
    }
    return fd;
}

#endif

#endif /* JSEC_COMPAT_H */
