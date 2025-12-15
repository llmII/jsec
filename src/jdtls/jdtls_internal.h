/*
 * jdtls_internal.h - Internal definitions for DTLS implementation
 *
 * Architecture Overview:
 * ======================
 * This DTLS implementation provides an API matching Janet's UDP conventions:
 * - dtls/listen    -> Creates DTLSServer (like net/listen :datagram)
 * - dtls/recv-from -> Receives from any peer, returns [data addr]
 * - dtls/send-to   -> Sends to specific peer address
 * - dtls/connect   -> Creates 1:1 client connection (like net/connect :datagram)
 *
 * Key Structures:
 * - DTLSAddress: Our address type (Janet's is internal, not exported)
 * - DTLSSession: Per-peer TLS state for server connections
 * - DTLSServer: Server managing multiple sessions by peer address
 * - DTLSClient: Simple 1:1 client connection
 *
 * State Machine:
 * ==============
 * DTLS uses a state machine for async I/O similar to TLS but with datagram
 * semantics. The key difference is that UDP is message-based, not stream-based.
 *
 *   IDLE ──────> HANDSHAKING ──────> ESTABLISHED ──────> SHUTDOWN
 *     │              │                    │                  │
 *     │              v                    v                  v
 *     │         WANT_READ             WANT_READ          WANT_READ
 *     │         WANT_WRITE            WANT_WRITE         WANT_WRITE
 *     │              │                    │                  │
 *     └──────────────┴────────────────────┴──────────────────┘
 *                              │
 *                              v
 *                           CLOSED
 *
 * Server Session Lifecycle:
 * =========================
 * 1. Server receives ClientHello from new peer address
 * 2. Cookie exchange (DTLSv1_listen) for DoS protection
 * 3. Session created and added to connection table
 * 4. SSL_accept completes handshake
 * 5. Application uses recv-from/send-to
 * 6. Session times out or peer closes -> cleanup
 *
 * Memory Management:
 * ==================
 * - DTLSServer and DTLSClient are Janet abstract types (GC managed)
 * - DTLSSession is stored in server's connection table
 * - Sessions removed on timeout or explicit close
 * - SSL/SSL_CTX freed in GC callback
 *
 * Threading Notes:
 * ================
 * - Each Janet thread has its own event loop
 * - Connection table uses Janet's table (single-threaded access)
 * - OpenSSL 1.1.1+ is thread-safe for distinct SSL objects
 *
 * Author: jsec project
 * License: ISC
 */

#ifndef JDTLS_INTERNAL_H
#define JDTLS_INTERNAL_H

#include "../jutils.h"
#include "../jutils/internal.h"  /* For standardized error macros */
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/* Get current time in seconds (used for session timeout tracking) */
static inline double get_current_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

/*
 * =============================================================================
 * DTLS States
 * =============================================================================
 */

typedef enum {
    DTLS_STATE_IDLE = 0,       /* Initial state, no handshake started */
    DTLS_STATE_HANDSHAKING,    /* Handshake in progress */
    DTLS_STATE_ESTABLISHED,    /* Handshake complete, ready for data */
    DTLS_STATE_SHUTDOWN,       /* Shutdown in progress */
    DTLS_STATE_CLOSED,         /* Fully closed */
    DTLS_STATE_ERROR           /* Error state */
} DTLSState;

/*
 * =============================================================================
 * DTLS Operations (for async callback)
 * =============================================================================
 */

typedef enum {
    DTLS_OP_NONE = 0,
    DTLS_OP_HANDSHAKE,
    DTLS_OP_READ,
    DTLS_OP_WRITE,
    DTLS_OP_SHUTDOWN,
    DTLS_OP_ACCEPT,         /* Server waiting for new connection */
    DTLS_OP_RECV_FROM,      /* Server recv-from operation */
    DTLS_OP_SEND_TO         /* Server send-to operation */
} DTLSOperation;

/*
 * =============================================================================
 * DTLSAddress - Our address type (Janet's janet_address_type is internal)
 * =============================================================================
 * Wraps sockaddr_storage for IPv4/IPv6 support.
 * Provides comparison and hashing for use as table keys.
 */

typedef struct {
    struct sockaddr_storage addr;
    socklen_t addrlen;
} DTLSAddress;

/* Convert DTLSAddress to/from Janet values */
Janet dtls_address_wrap(DTLSAddress *addr);
DTLSAddress *dtls_address_unwrap(Janet v);
int dtls_address_from_janet(Janet v, DTLSAddress *out);

/* Address utilities */
int dtls_address_equal(const DTLSAddress *a, const DTLSAddress *b);
int32_t dtls_address_hash_fn(const DTLSAddress *addr);
void dtls_address_tostring_fn(const DTLSAddress *addr, JanetBuffer *buf);

/* Get port from address */
uint16_t dtls_address_port(const DTLSAddress *addr);

/* Set port on address */
void dtls_address_set_port(DTLSAddress *addr, uint16_t port);

/*
 * =============================================================================
 * DTLSSession - Per-peer session (used by DTLSServer)
 * =============================================================================
 * Represents a single DTLS session with a specific peer.
 * Stored in server's connection table keyed by peer address.
 */

typedef struct DTLSSession {
    SSL *ssl;                   /* OpenSSL SSL object */
    BIO *rbio;                  /* Read BIO (memory BIO for incoming data) */
    BIO *wbio;                  /* Write BIO (memory BIO for outgoing data) */
    DTLSAddress peer_addr;      /* Peer's address */
    DTLSState state;            /* Session state */
    double last_activity;       /* Time of last activity (for timeout) */
    int cookie_verified;        /* Has client passed cookie exchange? */
    struct DTLSSession *next;   /* For linked list in hash bucket */
    /* Handshake timing (CLOCK_MONOTONIC timestamps) - only recorded if enabled */
    int track_handshake_time;   /* Whether to record handshake timing */
    struct timespec ts_connect; /* Time when session was created */
    struct timespec ts_handshake; /* Time when handshake completed */
} DTLSSession;

/*
 * =============================================================================
 * DTLSClient - Simple 1:1 client connection
 * =============================================================================
 * Created by dtls/connect, wraps a connected UDP socket.
 * Simpler than server - no connection table needed.
 *
 * Embeds JanetStream for compatibility with Janet's stream API.
 * Methods like :read, :write, :close work through method dispatch.
 */

typedef struct {
    JanetStream stream;         /* Embedded stream for method dispatch */
    JanetStream *transport;     /* Underlying UDP socket (connected) */
    SSL *ssl;                   /* OpenSSL SSL object */
    SSL_CTX *ctx;               /* Client SSL context */
    DTLSState state;            /* Connection state */
    DTLSAddress peer_addr;      /* Server address (for reference) */
    int closed;                 /* Client has been closed */
    int owns_ctx;               /* Whether we own ctx (should free on GC) */
    int is_server;              /* Whether acting as server (for upgrade) */
    /* Handshake timing (CLOCK_MONOTONIC timestamps) - only recorded if enabled */
    int track_handshake_time;   /* Whether to record handshake timing */
    struct timespec ts_connect; /* Time when client was created */
    struct timespec ts_handshake; /* Time when handshake completed */
} DTLSClient;

/*
 * =============================================================================
 * DTLSServer - Server managing multiple peer sessions
 * =============================================================================
 * Created by dtls/listen, provides recv-from/send-to operations.
 * Uses a hash table to map peer addresses to sessions.
 *
 * Embeds JanetStream for compatibility with Janet's stream API.
 * Methods like :recv-from, :send-to, :close work through method dispatch.
 */

#define DTLS_SESSION_TABLE_SIZE 256  /* Hash table buckets */
#define DTLS_SESSION_TIMEOUT 300.0   /* 5 minutes default timeout */

typedef struct {
    JanetStream stream;         /* Embedded stream for method dispatch */
    JanetStream *transport;     /* Underlying UDP socket */
    SSL_CTX *ctx;               /* Server SSL context */
    DTLSSession *sessions[DTLS_SESSION_TABLE_SIZE]; /* Hash table */
    int session_count;          /* Number of active sessions */
    double session_timeout;     /* Session timeout in seconds */
    int closed;                 /* Server has been closed */
} DTLSServer;

/* Session lifecycle */
DTLSSession *dtls_session_new(SSL_CTX *ctx, const DTLSAddress *peer);
void dtls_session_free(DTLSSession *session);

/* Server operations */
DTLSSession *dtls_server_get_session(DTLSServer *server,
                                     const DTLSAddress *addr);
DTLSSession *dtls_server_create_session(DTLSServer *server,
                                        const DTLSAddress *addr);
void dtls_server_remove_session(DTLSServer *server, const DTLSAddress *addr);
void dtls_server_cleanup_expired(DTLSServer *server, double now);

/*
 * =============================================================================
 * Async State (for janet_async_start callbacks)
 * =============================================================================
 */

typedef struct {
    DTLSOperation op;           /* Current operation */
    JanetBuffer *buffer;        /* Buffer for read operations */
    JanetByteView write_data;   /* Data for write operations */
    int32_t nbytes;             /* Requested bytes for read */
    double timeout;             /* Operation timeout */
    int flags;                  /* Operation flags */
    DTLSAddress *out_addr;      /* Output address for recv-from */
} DTLSAsyncState;

/*
 * =============================================================================
 * Cookie Generation (DoS protection)
 * =============================================================================
 */

/* Generate cookie for client address */
int dtls_generate_cookie(SSL *ssl, unsigned char *cookie,
                         unsigned int *cookie_len);

/* Verify cookie from client */
int dtls_verify_cookie(SSL *ssl, const unsigned char *cookie,
                       unsigned int cookie_len);

/*
 * =============================================================================
 * State Machine Operations
 * =============================================================================
 * These drive the async I/O using Janet's event loop.
 */

/* Drive SSL operation, return want-read/want-write/done/error */
typedef enum {
    DTLS_RESULT_OK = 0,         /* Operation complete */
    DTLS_RESULT_WANT_READ,      /* Need to wait for readable */
    DTLS_RESULT_WANT_WRITE,     /* Need to wait for writable */
    DTLS_RESULT_EOF,            /* Peer closed */
    DTLS_RESULT_ERROR           /* Error occurred */
} DTLSResult;

/* Convert SSL_get_error to DTLSResult */
DTLSResult dtls_ssl_result(SSL *ssl, int ret);

/* Process handshake step */
DTLSResult dtls_do_handshake(SSL *ssl);

/* Process read step */
DTLSResult dtls_do_read(SSL *ssl, uint8_t *buf, int32_t len,
                        int32_t *out_len);

/* Process write step */
DTLSResult dtls_do_write(SSL *ssl, const uint8_t *buf, int32_t len,
                         int32_t *out_len);

/* Process shutdown step */
DTLSResult dtls_do_shutdown(SSL *ssl);

/* Async operation starters */
void dtls_async_handshake(JanetStream *transport, SSL *ssl,
                          DTLSState *state_ptr, void *owner);
void dtls_async_read(JanetStream *transport, SSL *ssl, int32_t nbytes,
                     double timeout, void *owner);
void dtls_async_write(JanetStream *transport, SSL *ssl,
                      JanetByteView data_view, double timeout, void *owner);
void dtls_async_shutdown(JanetStream *transport, SSL *ssl,
                         DTLSState *state_ptr, void *owner);

/*
 * =============================================================================
 * DTLSContext - Reusable SSL_CTX wrapper (like TLS's TLSContext)
 * =============================================================================
 * Now uses the unified SSLContext type from jshared.h.
 * Note: is_server was removed - that's a connection-level property, not context.
 */

typedef SSLContext DTLSContext;

/* Use the unified ssl_context_type for DTLS contexts */
#define dtls_context_type ssl_context_type

/*
 * =============================================================================
 * Abstract Type Declarations
 * =============================================================================
 */

extern const JanetAbstractType dtls_address_type;
extern const JanetAbstractType dtls_server_type;
extern const JanetAbstractType dtls_client_type;
/* dtls_context_type is now a macro aliasing ssl_context_type from jshared.h */

/* Method tables for stream-like behavior */
extern const JanetMethod dtls_client_methods[];
extern const JanetMethod dtls_server_methods[];
/* dtls_context_methods is now ssl_context_methods from jshared.h */

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

/* Register address type and functions */
void jdtls_register_address(JanetTable *env);

/* Register server type and functions */
void jdtls_register_server(JanetTable *env);

/* Register client type and functions */
void jdtls_register_client(JanetTable *env);

/* Register context type and functions */
void jdtls_register_context(JanetTable *env);

/*
 * =============================================================================
 * API Functions (api subdirectory) - compiled as separate units
 * =============================================================================
 */

/* async.c - Async callbacks and helpers */
void jdtls_async_callback(JanetFiber *fiber, JanetAsyncEvent event);
void dtls_client_async_callback(JanetFiber *fiber, JanetAsyncEvent event);
int dtls_client_start_handshake(DTLSClient *client);
void dtls_client_start_async_read(DTLSClient *client, JanetBuffer *buf,
                                  int32_t nbytes, int mode);
void dtls_client_start_async_write(DTLSClient *client, JanetByteView data,
                                   int mode);
void dtls_client_start_async_close(DTLSClient *client, int mode);

/* close.c */
Janet cfun_dtls_shutdown(int32_t argc, Janet *argv);
Janet cfun_dtls_close(int32_t argc, Janet *argv);

/* connect.c */
Janet cfun_dtls_connect(int32_t argc, Janet *argv);

/* info.c */
Janet cfun_dtls_get_version(int32_t argc, Janet *argv);
Janet cfun_dtls_get_cipher(int32_t argc, Janet *argv);
Janet cfun_dtls_get_cipher_bits(int32_t argc, Janet *argv);
Janet cfun_dtls_get_connection_info(int32_t argc, Janet *argv);
Janet cfun_dtls_session_reused(int32_t argc, Janet *argv);
Janet cfun_dtls_get_session(int32_t argc, Janet *argv);
Janet cfun_dtls_localname(int32_t argc, Janet *argv);
Janet cfun_dtls_peername(int32_t argc, Janet *argv);
Janet cfun_dtls_set_session(int32_t argc, Janet *argv);
Janet cfun_dtls_trust_cert(int32_t argc, Janet *argv);
Janet cfun_dtls_get_handshake_time(int32_t argc, Janet *argv);

/* io.c */
Janet cfun_dtls_read(int32_t argc, Janet *argv);
Janet cfun_dtls_write(int32_t argc, Janet *argv);
Janet cfun_dtls_chunk(int32_t argc, Janet *argv);

/* upgrade.c */
Janet cfun_dtls_upgrade(int32_t argc, Janet *argv);

#endif /* JDTLS_INTERNAL_H */
