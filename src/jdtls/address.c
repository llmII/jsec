/*
 * address.c - DTLSAddress type implementation
 *
 * Provides a Janet abstract type for socket addresses since Janet's
 * janet_address_type is internal and not exported in janet.h.
 *
 * This type supports:
 * - IPv4 and IPv6 addresses
 * - Comparison (for use as table keys)
 * - Hashing (for efficient lookup)
 * - String representation (for debugging)
 */

#include "internal.h"
#include <string.h>
#include <stdio.h>

/*
 * =============================================================================
 * GC and Lifecycle
 * =============================================================================
 */

static int dtls_address_gc(void *p, size_t s) {
    (void)p; (void)s;
    /* DTLSAddress is POD - no cleanup needed */
    return 0;
}

/*
 * =============================================================================
 * Comparison
 * =============================================================================
 * Compare two addresses for equality and ordering.
 * Used by Janet tables for key lookup.
 */

static int dtls_address_compare(void *a, void *b) {
    DTLSAddress *addr_a = (DTLSAddress *)a;
    DTLSAddress *addr_b = (DTLSAddress *)b;

    /* First compare address lengths */
    if (addr_a->addrlen != addr_b->addrlen) {
        return addr_a->addrlen < addr_b->addrlen ? -1 : 1;
    }

    /* Then compare raw bytes */
    return memcmp(&addr_a->addr, &addr_b->addr, addr_a->addrlen);
}

int dtls_address_equal(const DTLSAddress *a, const DTLSAddress *b) {
    if (a->addrlen != b->addrlen) return 0;
    return memcmp(&a->addr, &b->addr, a->addrlen) == 0;
}

/*
 * =============================================================================
 * Hashing
 * =============================================================================
 * FNV-1a hash of address bytes for hash table lookup.
 */

static int32_t dtls_address_hash(void *p, size_t s) {
    (void)s;
    DTLSAddress *addr = (DTLSAddress *)p;
    return dtls_address_hash_fn(addr);
}

int32_t dtls_address_hash_fn(const DTLSAddress *addr) {
    /* FNV-1a hash */
    uint32_t hash = 2166136261U;
    const uint8_t *bytes = (const uint8_t *)&addr->addr;
    for (socklen_t i = 0; i < addr->addrlen; i++) {
        hash ^= bytes[i];
        hash *= 16777619U;
    }
    return (int32_t)hash;
}

/*
 * =============================================================================
 * String Representation
 * =============================================================================
 */

static void dtls_address_tostring(void *p, JanetBuffer *buf) {
    DTLSAddress *addr = (DTLSAddress *)p;
    dtls_address_tostring_fn(addr, buf);
}

void dtls_address_tostring_fn(const DTLSAddress *addr, JanetBuffer *buf) {
    char host[INET6_ADDRSTRLEN];
    uint16_t port = 0;

    if (addr->addr.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&addr->addr;
        inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
        port = ntohs(sin->sin_port);
    } else if (addr->addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&addr->addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
        port = ntohs(sin6->sin6_port);
        janet_buffer_push_cstring(buf, "[");
        janet_buffer_push_cstring(buf, host);
        janet_buffer_push_cstring(buf, "]:");
        char portbuf[8];
        snprintf(portbuf, sizeof(portbuf), "%u", port);
        janet_buffer_push_cstring(buf, portbuf);
        return;
    } else {
        janet_buffer_push_cstring(buf, "<unknown-address>");
        return;
    }

    janet_buffer_push_cstring(buf, host);
    janet_buffer_push_cstring(buf, ":");
    char portbuf[8];
    snprintf(portbuf, sizeof(portbuf), "%u", port);
    janet_buffer_push_cstring(buf, portbuf);
}

/*
 * =============================================================================
 * Port Accessors
 * =============================================================================
 */

uint16_t dtls_address_port(const DTLSAddress *addr) {
    if (addr->addr.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&addr->addr;
        return ntohs(sin->sin_port);
    } else if (addr->addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&addr->addr;
        return ntohs(sin6->sin6_port);
    }
    return 0;
}

void dtls_address_set_port(DTLSAddress *addr, uint16_t port) {
    if (addr->addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr->addr;
        sin->sin_port = htons(port);
    } else if (addr->addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr->addr;
        sin6->sin6_port = htons(port);
    }
}

/*
 * =============================================================================
 * Abstract Type Definition
 * =============================================================================
 */

const JanetAbstractType dtls_address_type = {
    "jsec/dtls-address",
    dtls_address_gc,
    NULL,                       /* mark - no Janet values to mark */
    NULL,                       /* get */
    NULL,                       /* put */
    NULL,                       /* marshal */
    NULL,                       /* unmarshal */
    dtls_address_tostring,
    dtls_address_compare,
    dtls_address_hash,
    JANET_ATEND_HASH
};

/*
 * =============================================================================
 * Wrap/Unwrap Helpers
 * =============================================================================
 */

Janet dtls_address_wrap(DTLSAddress *addr) {
    /* Allocate a new DTLSAddress abstract and copy the data */
    DTLSAddress *new_addr = janet_abstract(&dtls_address_type,
                                           sizeof(DTLSAddress));
    memcpy(new_addr, addr, sizeof(DTLSAddress));
    return janet_wrap_abstract(new_addr);
}

DTLSAddress *dtls_address_unwrap(Janet v) {
    if (!janet_checkabstract(v, &dtls_address_type)) {
        return NULL;
    }
    return (DTLSAddress *)janet_unwrap_abstract(v);
}

/*
 * Convert Janet value to DTLSAddress.
 * Accepts:
 * - DTLSAddress abstract type
 * - Tuple of [host port]
 * - Struct/table with :host and :port keys
 */
int dtls_address_from_janet(Janet v, DTLSAddress *out) {
    memset(out, 0, sizeof(DTLSAddress));

    /* Already a DTLSAddress */
    if (janet_checkabstract(v, &dtls_address_type)) {
        DTLSAddress *addr = janet_unwrap_abstract(v);
        memcpy(out, addr, sizeof(DTLSAddress));
        return 1;
    }

    const char *host = NULL;
    int port = 0;

    /* Tuple [host port] */
    if (janet_checktype(v, JANET_TUPLE)) {
        const Janet *tuple = janet_unwrap_tuple(v);
        int32_t len = janet_tuple_length(tuple);
        if (len >= 2) {
            if (janet_checktype(tuple[0], JANET_STRING)) {
                host = (const char *)janet_unwrap_string(tuple[0]);
            }
            if (janet_checktype(tuple[1], JANET_NUMBER)) {
                port = (int)janet_unwrap_number(tuple[1]);
            }
        }
    }
    /* Struct/table with :host :port */
    else if (janet_checktype(v, JANET_STRUCT) ||
             janet_checktype(v, JANET_TABLE)) {
        Janet h = janet_get(v, janet_ckeywordv("host"));
        Janet p = janet_get(v, janet_ckeywordv("port"));
        if (janet_checktype(h, JANET_STRING)) {
            host = (const char *)janet_unwrap_string(h);
        }
        if (janet_checktype(p, JANET_NUMBER)) {
            port = (int)janet_unwrap_number(p);
        }
    }

    if (!host) return 0;

    /* Try IPv4 first */
    struct sockaddr_in *sin = (struct sockaddr_in *)&out->addr;
    if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        out->addrlen = sizeof(struct sockaddr_in);
        return 1;
    }

    /* Try IPv6 */
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&out->addr;
    if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        out->addrlen = sizeof(struct sockaddr_in6);
        return 1;
    }

    return 0;
}

/*
 * =============================================================================
 * Janet Functions
 * =============================================================================
 */

/* (dtls/address host port) - Create address from host string and port */
static Janet cfun_dtls_address(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 2);
    const char *host = janet_getcstring(argv, 0);
    int port = janet_getinteger(argv, 1);

    DTLSAddress *addr = janet_abstract(&dtls_address_type, sizeof(DTLSAddress));
    memset(addr, 0, sizeof(DTLSAddress));

    /* Try IPv4 first */
    struct sockaddr_in *sin = (struct sockaddr_in *)&addr->addr;
    if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        addr->addrlen = sizeof(struct sockaddr_in);
        return janet_wrap_abstract(addr);
    }

    /* Try IPv6 */
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr->addr;
    if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        addr->addrlen = sizeof(struct sockaddr_in6);
        return janet_wrap_abstract(addr);
    }

    dtls_panic_param("invalid address: %s", host);
}

/* (dtls/address-host addr) - Get host string from address */
static Janet cfun_dtls_address_host(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSAddress *addr = janet_getabstract(argv, 0, &dtls_address_type);

    char host[INET6_ADDRSTRLEN];

    if (addr->addr.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&addr->addr;
        inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
    } else if (addr->addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&addr->addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
    } else {
        return janet_wrap_nil();
    }

    return janet_cstringv(host);
}

/* (dtls/address-port addr) - Get port from address */
static Janet cfun_dtls_address_port(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    DTLSAddress *addr = janet_getabstract(argv, 0, &dtls_address_type);
    return janet_wrap_integer(dtls_address_port(addr));
}

/* (dtls/address? x) - Check if x is a DTLS address */
static Janet cfun_dtls_address_p(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    return janet_wrap_boolean(janet_checkabstract(argv[0], &dtls_address_type));
}

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

static const JanetReg address_cfuns[] = {
    {
        "address", cfun_dtls_address,
        "(dtls/address host port)\n\n"
        "Create a DTLS address from host string and port number.\n"
        "Supports IPv4 and IPv6 addresses."
    },
    {
        "address-host", cfun_dtls_address_host,
        "(dtls/address-host addr)\n\n"
        "Get the host string from a DTLS address."
    },
    {
        "address-port", cfun_dtls_address_port,
        "(dtls/address-port addr)\n\n"
        "Get the port number from a DTLS address."
    },
    {
        "address?", cfun_dtls_address_p,
        "(dtls/address? x)\n\n"
        "Returns true if x is a DTLS address."
    },
    {NULL, NULL, NULL}
};

void jdtls_register_address(JanetTable *env) {
    janet_register_abstract_type(&dtls_address_type);
    janet_cfuns(env, "jsec/dtls", address_cfuns);
}
