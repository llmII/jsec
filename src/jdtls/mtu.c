/*
 * mtu.c - DTLS interface/link MTU resolution and :mtu configuration
 *
 * Resolves interface MTU on platforms lacking IP_MTU / IPV6_MTU (BSDs,
 * macOS, Windows, Illumos) and on memory-BIO server sessions (dtls/listen)
 * so OpenSSL does not clamp outgoing handshake flights to its 256-byte
 * fallback MTU and fragment post-HVR ClientHello messages.
 *
 * Preserves Linux kernel PMTU discovery intact on connected UDP sockets
 * whenever getsockopt(IP_MTU / IPV6_MTU) succeeds and no explicit :mtu
 * override was supplied.
 */

/*
 * Feature-test macros must be defined before <janet.h> (which includes
 * <stdlib.h> / <sys/types.h> and locks BSD/Darwin/NetBSD header visibility
 * under -std=c99) and before "internal.h" (compat.h sets _POSIX_C_SOURCE
 * 200809L, which otherwise hides SIOCGIFMTU / struct ifreq / IFF_UP on
 * BSD/macOS/illumos).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef _NETBSD_SOURCE
#define _NETBSD_SOURCE 1
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
#endif

#include <janet.h>

#if !defined(JANET_WINDOWS) && !defined(JANET_CYGWIN)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#if defined(JANET_BSD) || defined(JANET_APPLE) || defined(JANET_ILLUMOS) ||  \
    defined(__sun)
#include <sys/sockio.h>
#endif
#endif

#include "internal.h"

#include <math.h>
#include <string.h>

#define JDTLS_MIN_EXPLICIT_MTU 256
#define JDTLS_MAX_LINK_MTU 65535
#define JDTLS_MIN_AUTO_MTU 576
#define JDTLS_DEFAULT_IPV4_MTU 1500
#define JDTLS_DEFAULT_IPV6_MTU 1280
#define JDTLS_DEFAULT_MTU_OVERHEAD 28

/*
 * Parse optional :mtu integer in [256, 65535] from an options table/struct.
 * Returns 0 when opts is nil/absent or has :mtu nil. Raises [DTLS:PARAM] on
 * non-integer, non-finite, booleans, or out-of-range values.
 */
long jdtls_parse_mtu_opt(Janet opts) {
    if (!janet_checktype(opts, JANET_TABLE) &&
        !janet_checktype(opts, JANET_STRUCT)) {
        return 0;
    }

    Janet mtu_val = janet_get(opts, janet_ckeywordv("mtu"));
    if (janet_checktype(mtu_val, JANET_NIL)) {
        return 0;
    }

    if (!janet_checktype(mtu_val, JANET_NUMBER)) {
        dtls_panic_param(
            "invalid :mtu %v: expected an integer between %d and %d",
            mtu_val, JDTLS_MIN_EXPLICIT_MTU, JDTLS_MAX_LINK_MTU);
    }

    double d = janet_unwrap_number(mtu_val);
    if (!isfinite(d) || d > floor(d) || d < floor(d) ||
        d < (double)JDTLS_MIN_EXPLICIT_MTU ||
        d > (double)JDTLS_MAX_LINK_MTU) {
        dtls_panic_param(
            "invalid :mtu %v: expected an integer between %d and %d",
            mtu_val, JDTLS_MIN_EXPLICIT_MTU, JDTLS_MAX_LINK_MTU);
    }

    return (long)d;
}

static long default_mtu_for_family(int family) {
    if (family == AF_INET6) {
        return JDTLS_DEFAULT_IPV6_MTU;
    }
    return JDTLS_DEFAULT_IPV4_MTU;
}

/*
 * Check whether the host kernel tracks dynamic PMTU on fd via IP_MTU or
 * IPV6_MTU. Only true on kernels supporting those getsockopt queries (Linux);
 * BSD/macOS/Windows return 0 so caller falls back cleanly to interface MTU.
 */
static int kernel_tracks_pmtu(jsec_socket_t fd, int family) {
    int mtu = 0;
    socklen_t optlen = (socklen_t)sizeof(mtu);

    if (family == AF_INET) {
#ifdef IP_MTU
        return getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &optlen) == 0 &&
               mtu > 0;
#else
        (void)fd;
        (void)optlen;
        (void)mtu;
        return 0;
#endif
    }

    if (family == AF_INET6) {
#ifdef IPV6_MTU
        return getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &mtu, &optlen) == 0 &&
               mtu > 0;
#else
        (void)fd;
        (void)optlen;
        (void)mtu;
        return 0;
#endif
    }

    (void)fd;
    (void)optlen;
    (void)mtu;
    return 0;
}

#ifndef JANET_WINDOWS

static int sockaddr_is_wildcard(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in sin;
        memcpy(&sin, sa, sizeof(sin));
        return sin.sin_addr.s_addr == htonl(INADDR_ANY);
    }
    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 sin6;
        memcpy(&sin6, sa, sizeof(sin6));
        return IN6_IS_ADDR_UNSPECIFIED(&sin6.sin6_addr);
    }
    return 0;
}

static int sockaddr_ip_equal(const struct sockaddr *a,
                             const struct sockaddr *b) {
    if (a->sa_family == AF_INET && b->sa_family == AF_INET) {
        struct sockaddr_in sa;
        struct sockaddr_in sb;
        memcpy(&sa, a, sizeof(sa));
        memcpy(&sb, b, sizeof(sb));
        return sa.sin_addr.s_addr == sb.sin_addr.s_addr;
    }

    if (a->sa_family == AF_INET6 && b->sa_family == AF_INET6) {
        struct sockaddr_in6 sa6;
        struct sockaddr_in6 sb6;
        memcpy(&sa6, a, sizeof(sa6));
        memcpy(&sb6, b, sizeof(sb6));
        if (memcmp(&sa6.sin6_addr, &sb6.sin6_addr,
                   sizeof(struct in6_addr)) != 0) {
            return 0;
        }
        if (IN6_IS_ADDR_LINKLOCAL(&sa6.sin6_addr) &&
            sa6.sin6_scope_id != 0 && sb6.sin6_scope_id != 0) {
            return sa6.sin6_scope_id == sb6.sin6_scope_id;
        }
        return 1;
    }

    /* Handle IPv4-mapped IPv6 socket bound/connected addresses vs AF_INET ifa */
    if (a->sa_family == AF_INET6 && b->sa_family == AF_INET) {
        struct sockaddr_in6 sa6;
        struct sockaddr_in sb;
        memcpy(&sa6, a, sizeof(sa6));
        memcpy(&sb, b, sizeof(sb));
        if (IN6_IS_ADDR_V4MAPPED(&sa6.sin6_addr)) {
            return memcmp(&sa6.sin6_addr.s6_addr[12], &sb.sin_addr.s_addr,
                          sizeof(struct in_addr)) == 0;
        }
    }

    return 0;
}

static int socket_allows_ipv4_on_v6(jsec_socket_t fd) {
    int v6only = 0;
    socklen_t len = (socklen_t)sizeof(v6only);
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &len) == 0) {
        return v6only == 0;
    }
    return 0;
}

static int wildcard_family_matches(int sock_family, int allow_v4_on_v6,
                                   int ifa_family) {
    if (sock_family == AF_INET) {
        return ifa_family == AF_INET;
    }
    if (sock_family == AF_INET6) {
        if (ifa_family == AF_INET6) return 1;
        if (allow_v4_on_v6 && ifa_family == AF_INET) return 1;
    }
    return 0;
}

static long query_interface_mtu(jsec_socket_t fd, const char *ifname) {
#ifdef SIOCGIFMTU
    if (!ifname) return 0;
    size_t len = strlen(ifname);
    if (len == 0 || len >= IFNAMSIZ) return 0;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, len + 1);

    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0) {
        long mtu = (long)ifr.ifr_mtu;
        if (mtu > JDTLS_MAX_LINK_MTU) mtu = JDTLS_MAX_LINK_MTU;
        return mtu;
    }
#else
    (void)fd;
    (void)ifname;
#endif
    return 0;
}

static long resolve_fd_link_mtu_posix(jsec_socket_t fd) {
    struct sockaddr_storage local;
    memset(&local, 0, sizeof(local));
    socklen_t local_len = (socklen_t)sizeof(local);

    if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
        return JDTLS_DEFAULT_IPV4_MTU;
    }

    int family = local.ss_family;
    if (family != AF_INET && family != AF_INET6) {
        return default_mtu_for_family(family);
    }

    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0 || !ifap) {
        return default_mtu_for_family(family);
    }

    const struct sockaddr *local_sa = (const struct sockaddr *)&local;
    int is_wildcard = sockaddr_is_wildcard(local_sa);
    int allow_v4_on_v6 =
        (is_wildcard && family == AF_INET6) ? socket_allows_ipv4_on_v6(fd) : 0;

    long best_mtu = 0;

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        if (!is_wildcard) {
            if (!sockaddr_ip_equal(local_sa, ifa->ifa_addr)) continue;
            long mtu = query_interface_mtu(fd, ifa->ifa_name);
            if (mtu >= JDTLS_MIN_AUTO_MTU) {
                best_mtu = mtu;
                break;
            }
        } else {
            if (!(ifa->ifa_flags & IFF_UP)) continue;
            if (!wildcard_family_matches(family, allow_v4_on_v6,
                                         ifa->ifa_addr->sa_family)) {
                continue;
            }
            long mtu = query_interface_mtu(fd, ifa->ifa_name);
            if (mtu >= JDTLS_MIN_AUTO_MTU) {
                if (best_mtu == 0 || mtu < best_mtu) {
                    best_mtu = mtu;
                }
            }
        }
    }

    freeifaddrs(ifap);

    return best_mtu > 0 ? best_mtu : default_mtu_for_family(family);
}

#endif /* !JANET_WINDOWS */

static long resolve_fd_link_mtu(jsec_socket_t fd, int fallback_family) {
#ifdef JANET_WINDOWS
    struct sockaddr_storage local;
    memset(&local, 0, sizeof(local));
    socklen_t local_len = (socklen_t)sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0) {
        return default_mtu_for_family(local.ss_family);
    }
    return default_mtu_for_family(fallback_family);
#else
    (void)fallback_family;
    return resolve_fd_link_mtu_posix(fd);
#endif
}

static void apply_link_mtu(SSL *ssl, BIO *bio, long link_mtu) {
    if (link_mtu <= 0) return;

#ifdef SSL_OP_NO_QUERY_MTU
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
#endif

    long overhead = JDTLS_DEFAULT_MTU_OVERHEAD;
    if (bio) {
        long bio_oh =
            BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, NULL);
        if (bio_oh > 0 && bio_oh < link_mtu) {
            overhead = bio_oh;
        }
    }

#ifdef DTLS_set_link_mtu
    DTLS_set_link_mtu(ssl, link_mtu);
#else
    SSL_set_mtu(ssl, link_mtu - overhead);
#endif

    if (bio && link_mtu > overhead) {
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_MTU, link_mtu - overhead, NULL);
    }
}

long jdtls_resolve_server_link_mtu(jsec_socket_t fd, int family,
                                   long explicit_mtu) {
    if (explicit_mtu > 0) {
        return explicit_mtu;
    }
    return resolve_fd_link_mtu(fd, family);
}

void jdtls_configure_session_mtu(SSL *ssl, long link_mtu) {
    apply_link_mtu(ssl, NULL, link_mtu);
}

void jdtls_configure_connected_mtu(SSL *ssl, BIO *bio, jsec_socket_t fd,
                                   int family, long explicit_mtu) {
    if (explicit_mtu > 0) {
        apply_link_mtu(ssl, bio, explicit_mtu);
        return;
    }

    /* Preserve native Linux kernel PMTU discovery intact on dgram BIOs. */
    if (bio && kernel_tracks_pmtu(fd, family)) {
        return;
    }

    long link_mtu = resolve_fd_link_mtu(fd, family);
    apply_link_mtu(ssl, bio, link_mtu);
}
