/*
 * jtls_internal.h - Internal header for JTLS (Janet TLS) implementation
 *
 * This file defines the internal types, state machines, and function declarations
 * for the TLS implementation that integrates with Janet's event loop.
 *
 * Architecture Overview:
 * =====================
 * The TLS implementation uses a custom BIO (Basic I/O) layer that directly
 * reads/writes to the underlying socket, avoiding intermediate buffer copies.
 * All I/O operations are non-blocking and integrate with Janet's event loop
 * through the async callback system.
 *
 * State Machine:
 * =============
 * TLS operations go through a state machine that handles the non-blocking nature
 * of SSL operations. When SSL_read/SSL_write/SSL_connect/SSL_accept returns
 * WANT_READ or WANT_WRITE, we register with Janet's event loop to be notified
 * when the socket is ready, then retry the operation.
 *
 * Flow:
 * 1. User calls tls/wrap, tls/connect, etc.
 * 2. We create TLSStream and initiate the operation
 * 3. If operation needs I/O, we register with event loop via janet_async_start
 * 4. Event loop calls our callback when socket is ready
 * 5. We retry the SSL operation
 * 6. Repeat 3-5 until operation completes or errors
 * 7. Resume fiber with result
 *
 * Constraints (from overarching guidelines):
 * - ONLY use Janet's public C API from janet.h
 * - NO pthread - use Janet's locking primitives (JanetOSMutex)
 * - NO OpenSSL initialization code (OpenSSL 1.1.1+ auto-initializes)
 * - NO kludging from C to Janet (no janet_resolve/janet_call workarounds)
 * - Production quality with clear state machine documentation
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#ifndef JTLS_INTERNAL_H
#define JTLS_INTERNAL_H

#include "../jutils.h"
#include "../jutils/internal.h"  /* For standardized error macros */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>  /* For X509_CHECK_FLAG_* hostname verification flags */
#include <string.h>
#include <errno.h>
#include <time.h>            /* For clock_gettime, CLOCK_MONOTONIC */

#ifndef JANET_WINDOWS
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>  /* For TCP_NODELAY */
    #include <netdb.h>
    #include <fcntl.h>
#endif

/* MSG_NOSIGNAL prevents SIGPIPE on write to closed socket */
#ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
#endif

/*
 * Buffer size constants for TLS I/O operations
 * DEFAULT_TLS_BUFFER_SIZE (16KB): Optimal for most use cases
 * MIN_TLS_BUFFER_SIZE (512B): Minimum for TLS record headers
 * MAX_TLS_BUFFER_SIZE (64KB): Upper limit to prevent excessive allocation
 */
#define DEFAULT_TLS_BUFFER_SIZE 16384
#define MIN_TLS_BUFFER_SIZE 512
#define MAX_TLS_BUFFER_SIZE 65536

/*============================================================================
 * CONNECTION STATE MACHINE
 *============================================================================
 * Tracks the overall state of the TLS connection lifecycle.
 *
 * State Transitions:
 *   INIT ──► HANDSHAKING ──► READY ──► SHUTDOWN_SENT ──► CLOSED
 *     │           │           │              │
 *     └───────────┴───────────┴──────────────┴──────► ERROR
 *
 * INIT:           Connection created, not yet started
 * HANDSHAKING:    TLS handshake in progress (SSL_connect/SSL_accept)
 * READY:          Handshake complete, ready for application I/O
 * SHUTDOWN_SENT:  Sent close_notify, awaiting peer's response
 * CLOSED:         Connection fully closed
 * ERROR:          Unrecoverable error occurred
 */
typedef enum {
    TLS_CONN_INIT,
    TLS_CONN_HANDSHAKING,
    TLS_CONN_READY,
    TLS_CONN_SHUTDOWN_SENT,
    TLS_CONN_CLOSED,
    TLS_CONN_ERROR
} TLSConnectionState;

/*============================================================================
 * I/O STATE MACHINE
 *============================================================================
 * Tracks what a specific operation is waiting for.
 * Used to determine which event to register with Janet's event loop.
 *
 * When SSL operation returns:
 *   SSL_ERROR_WANT_READ  → TLS_IO_WANT_READ  → listen for read events
 *   SSL_ERROR_WANT_WRITE → TLS_IO_WANT_WRITE → listen for write events
 *   Success              → TLS_IO_COMPLETE   → resume fiber with result
 *   Error                → TLS_IO_ERROR      → cancel fiber with error
 */
typedef enum {
    TLS_IO_INIT,        /* Operation not started */
    TLS_IO_WANT_READ,   /* Waiting for socket to be readable */
    TLS_IO_WANT_WRITE,  /* Waiting for socket to be writable */
    TLS_IO_WANT_BOTH,   /* Waiting for either (rare, for syscall errors) */
    TLS_IO_COMPLETE,    /* Operation completed successfully */
    TLS_IO_ERROR        /* Operation failed */
} TLSIOState;

/*============================================================================
 * OPERATION TYPES
 *============================================================================
 * The type of TLS operation being performed. Each operation has different
 * completion criteria and result handling.
 */
typedef enum {
    TLS_OP_HANDSHAKE,   /* SSL_connect or SSL_accept */
    TLS_OP_READ,        /* SSL_read - read application data (may return early) */
    TLS_OP_CHUNK,       /* SSL_read - read until n bytes or EOF (like ev/chunk) */
    TLS_OP_WRITE,       /* SSL_write - write application data */
    TLS_OP_SHUTDOWN,    /* SSL_shutdown - close TLS, keep socket open */
    TLS_OP_CLOSE        /* SSL_shutdown + close socket */
} TLSOpType;

/*============================================================================
 * FORWARD DECLARATIONS
 *============================================================================*/
typedef struct TLSStream TLSStream;
typedef struct TLSState TLSState;
/* TLSContext is now typedef'd from SSLContext, defined later */
typedef struct SNIData SNIData;
typedef struct OCSPData OCSPData;
typedef struct ALPNConfig ALPNConfig;
typedef struct ServerCTXCache ServerCTXCache;

/*============================================================================
 * TLS OPERATION STATE
 *============================================================================
 * State for an in-flight async operation. Two instances are embedded in
 * TLSStream to support concurrent read and write operations without malloc.
 *
 * This structure tracks:
 * - Which TLS stream the operation is on
 * - What type of operation (read/write/handshake/etc)
 * - Current I/O state (waiting for read/write/complete/error)
 * - Buffers for data transfer
 * - Error messages
 *
 * Lifecycle:
 * 1. Initialized when operation starts (using embedded state in TLSStream)
 * 2. Updated as operation progresses
 * 3. Reset when operation completes
 */
struct TLSState {
    TLSStream *tls;              /* The TLS stream */
    TLSOpType op;                /* Operation type */
    TLSIOState io_state;         /* Current I/O state */
    JanetBuffer *user_buf;       /* Buffer for read operations */
    const uint8_t *write_data;   /* Data for write operations */
    int32_t write_len;           /* Total bytes to write */
    int32_t write_offset;        /* Bytes already written */
    int32_t bytes_requested;     /* Bytes requested for read (-1 for any) */
    char error_msg[256];         /* Error message buffer */
};

/*============================================================================
 * TLS STREAM STRUCTURE
 *============================================================================
 * The main TLS connection object. Contains the SSL state and references to
 * the underlying transport stream.
 *
 * Memory Layout:
 * - stream: Embedded JanetStream for compatibility with Janet's stream API
 * - ssl: OpenSSL SSL object for this connection
 * - ctx: SSL_CTX (may be shared across connections)
 * - bio: Custom BIO for direct socket I/O
 * - transport: The underlying Janet stream (TCP/Unix socket)
 * - conn_state: Current connection state
 * - is_server: True for server-side connections
 * - owns_ctx: True if we should free ctx on cleanup
 * - buffer_size: Size for I/O buffers
 *
 * Embedded Operation States:
 * - read_state: For read/chunk operations (only one active at a time)
 * - write_state: For write operations (can be concurrent with read)
 * This eliminates malloc/free for every I/O operation.
 */
struct TLSStream {
    JanetStream stream;          /* Embedded stream for method dispatch */
    SSL *ssl;                    /* OpenSSL SSL object */
    SSL_CTX *ctx;                /* SSL context */
    BIO *bio;                    /* Custom BIO for socket I/O */
    JanetStream *transport;      /* Underlying TCP/Unix stream */
    TLSConnectionState conn_state;
    int is_server;
    int owns_ctx;
    int32_t buffer_size;
    /* Track pending operations for cooperative mode switching */
    JanetFiber *pending_read;    /* Fiber waiting on read */
    JanetFiber *pending_write;   /* Fiber waiting on write */
    /* Embedded operation states - eliminates malloc per I/O operation */
    TLSState read_state;         /* State for read/chunk operations */
    TLSState write_state;        /* State for write/shutdown/close operations */
    /* BIO read-ahead buffer for reducing syscalls */
    struct {
        unsigned char *data;     /* Buffer storage */
        unsigned char *p;        /* Current read position */
        unsigned char *pe;       /* End of valid data */
        size_t capacity;         /* Total buffer capacity */
    } bio_ahead;
    /* Handshake timing (CLOCK_MONOTONIC timestamps) - only recorded if enabled */
    int track_handshake_time;       /* Whether to record handshake timing */
    struct timespec ts_connect;     /* Time when stream was created */
    struct timespec ts_handshake;   /* Time when handshake completed */
};

/*============================================================================
 * TLS CONTEXT WRAPPER
 *============================================================================
 * TLSContext is now an alias for the unified SSLContext type from jshared.h.
 * This provides backwards compatibility while using the shared implementation.
 */
typedef SSLContext TLSContext;

/* Use the unified ssl_context_type for TLS contexts */
#define tls_context_type ssl_context_type

/*============================================================================
 * SNI (Server Name Indication) DATA
 *============================================================================
 * Maps hostnames to SSL contexts for virtual hosting.
 */
struct SNIData {
    char **hostnames;
    SSL_CTX **contexts;
    int count;
};

/*============================================================================
 * OCSP DATA
 *============================================================================
 * Stores OCSP response for stapling.
 */
struct OCSPData {
    unsigned char *data;
    int len;
};

/*============================================================================
 * ALPN (Application-Layer Protocol Negotiation) CONFIG
 *============================================================================
 * Stores ALPN protocols in wire format for server-side selection.
 */
struct ALPNConfig {
    unsigned char *wire;
    unsigned int len;
};

/*============================================================================
 * SERVER CONTEXT CACHE
 *============================================================================
 * Caches the most recently used server SSL_CTX to enable session resumption
 * across connections with the same certificate/key pair.
 */
struct ServerCTXCache {
    SSL_CTX *ctx;
    char *cert_path;
    char *key_path;
    unsigned char *cert_data;
    int cert_len;
    unsigned char *key_data;
    int key_len;
    unsigned char *alpn_wire;
    unsigned int alpn_len;
};

/*============================================================================
 * GLOBAL STATE (defined in types.c)
 *============================================================================*/
extern int sni_idx;              /* SSL_CTX ex_data index for SNI */
extern int ocsp_idx;             /* SSL_CTX ex_data index for OCSP */
extern int alpn_idx;             /* SSL_CTX ex_data index for ALPN */
extern ServerCTXCache server_ctx_cache;
extern JanetOSMutex *ctx_cache_lock;
extern FILE *keylog_file;
extern const JanetAbstractType tls_stream_type;
/* tls_context_type is now a macro aliasing ssl_context_type from jshared.h */
extern const JanetMethod tls_stream_methods[];

/*============================================================================
 * BIO FUNCTIONS (bio.c)
 *============================================================================
 * Custom BIO implementation for direct socket I/O.
 */

/* Initialize the BIO method (call once at module init, before threads) */
void jtls_init_bio_method(void);

/* Get the BIO method (must be called after jtls_init_bio_method) */
BIO_METHOD *jtls_get_bio_method(void);

/*============================================================================
 * STATE MACHINE FUNCTIONS (state_machine.c)
 *============================================================================
 * Core async I/O state machine that integrates with Janet's event loop.
 */

/* Process a single TLS operation step, return new I/O state */
TLSIOState jtls_process_operation(TLSState *state);

/* Attempt TLS I/O, returns: 1=complete, 0=need async, -1=error */
int jtls_attempt_io(JanetFiber *fiber, TLSState *state, int is_async);

/* Schedule async operation with specified event mode */
void jtls_schedule_async(JanetFiber *fiber, TLSStream *tls,
                         TLSState *state, JanetAsyncMode mode, int is_async);

/* Async callback for all TLS operations */
void jtls_async_callback(JanetFiber *fiber, JanetAsyncEvent event);

/* Keylog callback for debugging (SSLKEYLOGFILE support) */
void jtls_keylog_callback(const SSL *ssl, const char *line);

/*============================================================================
 * CONTEXT FUNCTIONS (context.c)
 *============================================================================
 * SSL_CTX creation and configuration.
 */

/* Create client SSL context */
SSL_CTX *jtls_create_client_ctx(int verify, Janet security_opts);

/* Create server SSL context (with optional caching) */
SSL_CTX *jtls_create_server_ctx(Janet cert, Janet key, Janet security_opts,
                                Janet alpn_opt, int use_cache);

/* ALPN selection callback for server */
int jtls_alpn_select_cb(SSL *ssl, const unsigned char **out,
                        unsigned char *outlen, const unsigned char *in,
                        unsigned int inlen, void *arg);

/* Convert Janet array to ALPN wire format */
unsigned char *jtls_array_to_alpn_wire(Janet array, unsigned int *out_len);

/* SNI callback for server */
int jtls_sni_callback(SSL *ssl, int *ad, void *arg);

/* OCSP status callback */
int jtls_ocsp_status_cb(SSL *ssl, void *arg);

/* Free callbacks for ex_data */
void jtls_alpn_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                       int idx, long argl, void *argp);
void jtls_sni_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                      int idx, long argl, void *argp);
void jtls_ocsp_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                       int idx, long argl, void *argp);

/*============================================================================
 * STREAM FUNCTIONS (stream.c)
 *============================================================================
 * TLS stream setup and method implementations.
 */

/* Setup a TLS stream wrapping a transport */
TLSStream *jtls_setup_stream(JanetStream *transport, SSL_CTX *ctx,
                             int is_server, int owns_ctx, int32_t buffer_size,
                             int tcp_nodelay, int track_handshake_time);

/* GC callbacks */
int jtls_stream_gc(void *p, size_t s);
int jtls_stream_mark(void *p, size_t s);
int jtls_stream_getter(void *p, Janet key, Janet *out);

/* Context GC */
int jtls_context_gc(void *p, size_t s);

/*============================================================================
 * API FUNCTIONS (api.c)
 *============================================================================
 * Public C functions exposed to Janet.
 */

/* Connection/wrapping */
Janet cfun_wrap(int32_t argc, Janet *argv);
Janet cfun_connect(int32_t argc, Janet *argv);
Janet cfun_server(int32_t argc, Janet *argv);
Janet cfun_upgrade(int32_t argc, Janet *argv);
Janet cfun_listen(int32_t argc, Janet *argv);
Janet cfun_accept(int32_t argc, Janet *argv);
Janet cfun_accept_loop(int32_t argc, Janet *argv);

/* I/O operations */
Janet cfun_read(int32_t argc, Janet *argv);
Janet cfun_chunk(int32_t argc, Janet *argv);
Janet cfun_write(int32_t argc, Janet *argv);

/* Lifecycle */
Janet cfun_close(int32_t argc, Janet *argv);
Janet cfun_shutdown(int32_t argc, Janet *argv);

/* Session management */
Janet cfun_session_reused(int32_t argc, Janet *argv);
Janet cfun_get_session(int32_t argc, Janet *argv);
Janet cfun_set_session(int32_t argc, Janet *argv);

/* Protocol features */
Janet cfun_renegotiate(int32_t argc, Janet *argv);
Janet cfun_key_update(int32_t argc, Janet *argv);

/* Context management */
Janet cfun_new_context(int32_t argc, Janet *argv);
Janet cfun_set_ocsp_response(int32_t argc, Janet *argv);
Janet cfun_trust_cert(int32_t argc, Janet *argv);

/* Add trusted certificate to context */
int jtls_add_trusted_cert(SSL_CTX *ctx, Janet cert_pem);

/* Connection info */
Janet cfun_get_version(int32_t argc, Janet *argv);
Janet cfun_get_cipher(int32_t argc, Janet *argv);
Janet cfun_get_cipher_bits(int32_t argc, Janet *argv);
Janet cfun_get_connection_info(int32_t argc, Janet *argv);
Janet cfun_get_handshake_time(int32_t argc, Janet *argv);

/* Socket info (localname/peername) */
Janet cfun_localname(int32_t argc, Janet *argv);
Janet cfun_peername(int32_t argc, Janet *argv);

/*============================================================================
 * MODULE ENTRY (module.c)
 *============================================================================*/
void jtls_module_init(JanetTable *env);

#endif /* JTLS_INTERNAL_H */
