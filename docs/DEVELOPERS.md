
# Table of Contents

1.  [Overview](#orgb9ff619)
2.  [Critical Constraints](#org21a54cf)
    1.  [C Code Requirements](#org9b7150a)
    2.  [API Compatibility](#org10e1835)
    3.  [Platform Strategy](#org38e0cfa)
        1.  [Windows Support](#org2346f67)
        2.  [macOS Support](#orgb34897f)
3.  [Source Organization](#orgee1d4dd)
4.  [TLS State Machine](#orga99c7c9)
    1.  [States](#org94dc6db)
    2.  [State Transitions](#org5288ab1)
    3.  [SSL<sub>ERROR</sub> Handling](#orge3cfbad)
5.  [Event Loop Integration](#org99ceb6c)
    1.  [The Async Pattern](#org059b688)
    2.  [Key Functions](#orgbddb630)
    3.  [Why WANT<sub>WRITE</sub> During Read?](#org21ec16e)
6.  [Memory Management](#org0a7c1d8)
    1.  [OpenSSL Objects](#orgd994a9b)
    2.  [Janet Integration](#orgdd9f04a)
    3.  [Error Path Cleanup](#org44487f4)
7.  [Adding New Functionality](#org4174496)
    1.  [Adding a Stream Method](#orgc13e17a)
    2.  [Adding a Module Function](#org96ebcb7)
8.  [Building and Debugging](#org16e8c23)
    1.  [Build with Debug Symbols](#org516af09)
    2.  [OpenSSL Error Messages](#org9d51228)
    3.  [Useful Tools](#org02cf4d8)
9.  [Common Pitfalls](#org4ee7c9a)
10. [References](#orgfe7ea5d)



<a id="orgb9ff619"></a>

# Overview

This guide covers JSEC internals for contributors. JSEC provides TLS/DTLS
integration for Janet that works seamlessly with Janet's event loop (`ev`).


<a id="org21a54cf"></a>

# Critical Constraints


<a id="org9b7150a"></a>

## C Code Requirements

1.  **ONLY use Janet's public C API** from janet.h
    -   NO pthread includes or direct pthread usage
    -   NO accessing Janet internal structures
    -   Use Janet's locking primitives if locks needed
    -   Use `janet_malloc` / `janet_free` (NOT malloc/free, NOT janet<sub>smalloc</sub>)
    -   **Exception:** Structures tied to OpenSSL ex<sub>data</sub> callbacks use standard
        malloc/free because they are freed in OpenSSL callback context where
        Janet's allocator may not be initialized. This includes: SNIData,
        OCSPData, ALPNConfig, server<sub>ctx</sub><sub>cache</sub> data.

2.  **NO kludging from C to Janet code**
    -   NO `janet_resolve`, `janet_call`, `janet_get_method` from C
    -   If Janet doesn't export it in C API, find proper alternative

3.  **NO OpenSSL initialization code**
    -   OpenSSL 1.1.1+ auto-initializes
    -   **Requirement:** Targets OpenSSL 3.0+ (1.1.1 is EOL)

4.  **Production quality code**
    -   State machine must be clear with comments
    -   Event loop integration must be correct
    -   Proper error handling is mandatory


<a id="org10e1835"></a>

## API Compatibility

1.  TLS streams MUST match Janet's Stream API
    -   **Difference:** Initialization (`tls/connect` vs `net/connect`)
    -   **Identity:** All methods (`:read`, `:write`, `:close`) work identically

2.  DTLS MUST match Janet's UDP API
    -   `dtls/listen`, `dtls/recv-from`, `dtls/send-to`, `dtls/connect`

3.  No features can be lost from prior versions


<a id="org38e0cfa"></a>

## Platform Strategy


<a id="org2346f67"></a>

### Windows Support

-   **Recommended:** MSYS2 with MinGW-w64 (UCRT64 or MINGW64)
-   **CI Strategy:** GitHub Actions `windows-latest` runner
-   **Status:** Best-effort


<a id="orgb34897f"></a>

### macOS Support

-   **Constraint:** Author does not own Apple hardware
-   **Strategy:** Community driven
-   **CI Strategy:** GitHub Actions `macos-latest`
-   **Policy:** macOS-specific issues require community PRs


<a id="orgee1d4dd"></a>

# Source Organization

    src/
    ├── jtls/                    # TLS implementation
    │   ├── types.c              # TLSStream type, GC, methods
    │   ├── api/                 # Public API functions
    │   │   ├── context.c        # tls/new-context
    │   │   ├── connect.c        # tls/connect
    │   │   ├── listen.c         # tls/listen, tls/accept
    │   │   └── upgrade.c        # tls/upgrade (STARTTLS)
    │   └── internal/            # Internal implementation
    │       ├── handshake.c      # Async handshake state machine
    │       └── io.c             # Async read/write
    ├── jdtls/                   # DTLS implementation
    │   ├── client.c             # DTLS client
    │   ├── server.c             # DTLS server with multi-client
    │   ├── session.c            # Session management
    │   └── address.c            # Address abstraction
    ├── jca/                     # Certificate Authority
    │   ├── types.c              # CA type definition
    │   ├── sign.c               # CSR signing
    │   ├── crl.c                # CRL generation
    │   └── ocsp.c               # OCSP responder
    ├── jcrypto/                 # Cryptographic operations
    ├── jutils/                  # Shared utilities
    │   ├── context.c            # Unified SSL_CTX handling
    │   ├── security.c           # Security option parsing
    │   └── panic.c              # Error handling macros
    ├── jbio.c                   # Memory BIO operations
    └── jcert.c                  # Certificate generation


<a id="orga99c7c9"></a>

# TLS State Machine


<a id="org94dc6db"></a>

## States

    typedef enum {
        TLS_STATE_INIT,           /* Initial state after wrap */
        TLS_STATE_HANDSHAKE,      /* Handshake in progress */
        TLS_STATE_READY,          /* Handshake complete, ready for I/O */
        TLS_STATE_SHUTDOWN,       /* Shutdown in progress */
        TLS_STATE_ERROR,          /* Unrecoverable error */
        TLS_STATE_CLOSED          /* Connection closed */
    } tls_state_t;


<a id="org5288ab1"></a>

## State Transitions

                    ┌─────────────────────────────────────────┐
                    │                                         │
                    v                                         │
    ┌──────────┐   wrap    ┌───────────────┐                  │
    │   INIT   │ ────────> │  HANDSHAKE    │ ─── error ───────┤
    └──────────┘           └───────────────┘                  │
                                  │                           │
                           SSL_do_handshake()                 │
                                  │                           │
                           ┌──────┴──────┐                    │
                           │             │                    │
                     WANT_READ     WANT_WRITE                 │
                           │             │                    │
                           │   (wait for event,               │
                           │    retry handshake)              │
                           │             │                    │
                           └──────┬──────┘                    │
                                  │                           │
                              success                         │
                                  │                           │
                                  v                           │
                           ┌───────────────┐                  │
                           │    READY      │ ─── error ───────┤
                           └───────────────┘                  │
                                  │                           │
                             ev/close                         │
                                  │                           │
                                  v                           │
                           ┌───────────────┐                  │
                           │   SHUTDOWN    │ ─── error ───────┤
                           └───────────────┘                  │
                                  │                           │
                           SSL_shutdown()                     │
                           (bidirectional)                    │
                                  │                           │
                                  v                           │
                           ┌───────────────┐      ┌─────────┐ │
                           │    CLOSED     │      │  ERROR  │<┘
                           └───────────────┘      └─────────┘


<a id="orge3cfbad"></a>

## SSL<sub>ERROR</sub> Handling

When OpenSSL returns an error, check `SSL_get_error()`:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">SSL<sub>ERROR</sub></th>
<th scope="col" class="org-left">Action</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left">SSL<sub>ERROR</sub><sub>NONE</sub></td>
<td class="org-left">Operation completed successfully</td>
</tr>

<tr>
<td class="org-left">SSL<sub>ERROR</sub><sub>WANT</sub><sub>READ</sub></td>
<td class="org-left">Register for read event, retry when ready</td>
</tr>

<tr>
<td class="org-left">SSL<sub>ERROR</sub><sub>WANT</sub><sub>WRITE</sub></td>
<td class="org-left">Register for write event, retry when ready</td>
</tr>

<tr>
<td class="org-left">SSL<sub>ERROR</sub><sub>ZERO</sub><sub>RETURN</sub></td>
<td class="org-left">Clean shutdown received (EOF)</td>
</tr>

<tr>
<td class="org-left">SSL<sub>ERROR</sub><sub>SYSCALL</sub></td>
<td class="org-left">Check errno; usually connection reset</td>
</tr>

<tr>
<td class="org-left">SSL<sub>ERROR</sub><sub>SSL</sub></td>
<td class="org-left">Protocol error; check ERR<sub>get</sub><sub>error</sub>()</td>
</tr>
</tbody>
</table>


<a id="org99ceb6c"></a>

# Event Loop Integration

JSEC uses Janet's `janet_async_start()` / `janet_async_end()` API for async I/O.


<a id="org059b688"></a>

## The Async Pattern

    /* 1. Start async operation */
    JanetAsyncHandle handle = janet_async_start(
        stream,              /* The Janet stream */
        JANET_ASYNC_READ,    /* Event type */
        &read_cb,            /* Callback struct */
        state                /* User state */
    );
    
    /* 2. Callback is invoked when event occurs */
    static void read_callback(JanetAsyncHandle handle, JanetAsyncEvent event) {
        switch (event) {
            case JANET_ASYNC_EVENT_READ:
                /* Socket is readable, try SSL_read */
                ret = SSL_read(ssl, buf, n);
                if (ret > 0) {
                    /* Success! Schedule fiber with result */
                    janet_async_end(handle, janet_wrap_buffer(buf));
                } else {
                    int err = SSL_get_error(ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        /* Need more data, stay registered */
                        return;
                    } else if (err == SSL_ERROR_WANT_WRITE) {
                        /* Renegotiation needs write */
                        janet_async_mod(handle, JANET_ASYNC_WRITE);
                        return;
                    }
                    /* Error - schedule fiber with error */
                    janet_async_end(handle, janet_wrap_nil());
                }
                break;
            case JANET_ASYNC_EVENT_CANCEL:
                /* Fiber was cancelled */
                janet_async_end(handle, janet_wrap_nil());
                break;
        }
    }


<a id="orgbddb630"></a>

## Key Functions

-   `janet_async_start()` - Begin async operation, fiber yields
-   `janet_async_end()` - Complete operation, fiber resumes with value
-   `janet_async_mod()` - Change event registration (READ <-> WRITE)


<a id="org21ec16e"></a>

## Why WANT<sub>WRITE</sub> During Read?

TLS can renegotiate at any time. During a read, OpenSSL may need to send
a handshake message, returning `SSL_ERROR_WANT_WRITE`. We must:

1.  Switch to write event registration
2.  When writable, retry the **same** SSL<sub>read</sub>() call
3.  OpenSSL handles the renegotiation transparently


<a id="org0a7c1d8"></a>

# Memory Management


<a id="orgd994a9b"></a>

## OpenSSL Objects

-   `SSL_CTX` - Reference counted, can be shared across connections
-   `SSL` - One per connection, freed on stream close
-   `BIO` - Managed by SSL when attached, freed automatically


<a id="orgdd9f04a"></a>

## Janet Integration

-   Streams are garbage collected via `gc` callback
-   Use `janet_gcroot()` / `janet_gcunroot()` for persistent references
-   Always clean up OpenSSL state in `gc` callback


<a id="org44487f4"></a>

## Error Path Cleanup

Use goto cleanup pattern consistently:

    static Janet cfun_something(int32_t argc, Janet *argv) {
        X509 *cert = NULL;
        EVP_PKEY *key = NULL;
        BIO *bio = NULL;
    
        cert = X509_new();
        if (!cert) goto cleanup;
    
        key = EVP_PKEY_new();
        if (!key) goto cleanup;
    
        /* ... success path ... */
        return result;
    
    cleanup:
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
        if (bio) BIO_free(bio);
        janet_panic("operation failed");
    }


<a id="org4174496"></a>

# Adding New Functionality


<a id="orgc13e17a"></a>

## Adding a Stream Method

1.  Add method function in `jtls/types.c`:
    
        static Janet method_foo(int32_t argc, Janet *argv) {
            janet_fixarity(argc, 1);
            TLSStream *tls = get_tls_stream(argv[0]);
            /* implementation */
            return janet_wrap_nil();
        }

2.  Add to methods table:
    
        static const JanetMethod tls_stream_methods[] = {
            {"foo", method_foo},
            /* ... */
            {NULL, NULL}
        };


<a id="org96ebcb7"></a>

## Adding a Module Function

1.  Add function in appropriate file:
    
        static Janet cfun_something(int32_t argc, Janet *argv) {
            /* implementation */
        }

2.  Add to module registration:
    
        static const JanetReg tls_cfuns[] = {
            {"tls/something", cfun_something, "(tls/something ...)\n\nDocs"},
            {NULL, NULL, NULL}
        };


<a id="org16e8c23"></a>

# Building and Debugging


<a id="org516af09"></a>

## Build with Debug Symbols

    jpm clean
    jpm build -- -O0 -g


<a id="org9d51228"></a>

## OpenSSL Error Messages

    #include <openssl/err.h>
    
    /* Print all queued errors */
    ERR_print_errors_fp(stderr);
    
    /* Get single error */
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "OpenSSL error: %s\n", buf);


<a id="org02cf4d8"></a>

## Useful Tools

-   `strace -f -e trace=network` - Trace network syscalls
-   `openssl s_client -connect host:port` - Test server
-   `openssl s_server -cert cert.pem -key key.pem` - Test client
-   `wireshark` - Packet inspection (can decrypt with SSLKEYLOGFILE)


<a id="org4ee7c9a"></a>

# Common Pitfalls

1.  **Blocking in Event Loop** - Never use blocking OpenSSL calls
2.  **Ignoring WANT<sub>READ</sub>/WANT<sub>WRITE</sub>** - Must handle renegotiation
3.  **Memory Leaks** - Always free SSL/SSL<sub>CTX</sub> in gc callback
4.  **Missing Error Checks** - Always check SSL<sub>get</sub><sub>error</sub>() return
5.  **Thread Safety** - OpenSSL 1.1.1+ is thread-safe, but not Janet streams


<a id="orgfe7ea5d"></a>

# References

-   [Janet C API Documentation](https://janet-lang.org/capi/index.html)
-   [OpenSSL 3.0 Manual](https://www.openssl.org/docs/man3.0/man3/)

