
# Table of Contents

1.  [Overview](#org75a2db0)
2.  [Critical Constraints](#org3af9955)
    1.  [C Code Requirements](#org29b2b37)
    2.  [API Compatibility](#org44f59fb)
    3.  [Platform Strategy](#orgfae6148)
        1.  [Windows Support](#orgdc8250d)
        2.  [macOS Support](#orgd543f89)
3.  [Source Organization](#org127bf14)
4.  [TLS State Machine](#org695fd6a)
    1.  [States](#org7558130)
    2.  [State Transitions](#org61ab989)
    3.  [SSL<sub>ERROR</sub> Handling](#org377e274)
5.  [Event Loop Integration](#orgdf4eb1f)
    1.  [The Async Pattern](#orga8ba064)
    2.  [Key Functions](#orgecd103b)
    3.  [Why WANT<sub>WRITE</sub> During Read?](#org51c68c5)
6.  [Memory Management](#orgef33eb2)
    1.  [OpenSSL Objects](#orgd8337ce)
    2.  [Janet Integration](#orgff9890d)
    3.  [Error Path Cleanup](#org2d8cddc)
7.  [Adding New Functionality](#org9ea87fd)
    1.  [Adding a Stream Method](#orgfe54619)
    2.  [Adding a Module Function](#org3cab636)
8.  [Building and Debugging](#orgae1b9ae)
    1.  [Build with Debug Symbols](#orgffee17a)
    2.  [OpenSSL Error Messages](#org489f024)
    3.  [Useful Tools](#org0f3b0ed)
9.  [Common Pitfalls](#org67e2b0d)
10. [References](#orge2c0b3c)



<a id="org75a2db0"></a>

# Overview

This guide covers JSEC internals for contributors. JSEC provides TLS/DTLS
integration for Janet that works seamlessly with Janet's event loop (`ev`).


<a id="org3af9955"></a>

# Critical Constraints


<a id="org29b2b37"></a>

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


<a id="org44f59fb"></a>

## API Compatibility

1.  TLS streams MUST match Janet's Stream API
    -   **Difference:** Initialization (`tls/connect` vs `net/connect`)
    -   **Identity:** All methods (`:read`, `:write`, `:close`) work identically

2.  DTLS MUST match Janet's UDP API
    -   `dtls/listen`, `dtls/recv-from`, `dtls/send-to`, `dtls/connect`

3.  No features can be lost from prior versions


<a id="orgfae6148"></a>

## Platform Strategy


<a id="orgdc8250d"></a>

### Windows Support

-   **Recommended:** MSYS2 with MinGW-w64 (UCRT64 or MINGW64)
-   **CI Strategy:** GitHub Actions `windows-latest` runner
-   **Status:** Best-effort


<a id="orgd543f89"></a>

### macOS Support

-   **Constraint:** Author does not own Apple hardware
-   **Strategy:** Community driven
-   **CI Strategy:** GitHub Actions `macos-latest`
-   **Policy:** macOS-specific issues require community PRs


<a id="org127bf14"></a>

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
    ├── jcert/
    │   ├── jcert.c                  # Certificate generation


<a id="org695fd6a"></a>

# TLS State Machine


<a id="org7558130"></a>

## States

    typedef enum {
        TLS_STATE_INIT,           /* Initial state after wrap */
        TLS_STATE_HANDSHAKE,      /* Handshake in progress */
        TLS_STATE_READY,          /* Handshake complete, ready for I/O */
        TLS_STATE_SHUTDOWN,       /* Shutdown in progress */
        TLS_STATE_ERROR,          /* Unrecoverable error */
        TLS_STATE_CLOSED          /* Connection closed */
    } tls_state_t;


<a id="org61ab989"></a>

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


<a id="org377e274"></a>

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


<a id="orgdf4eb1f"></a>

# Event Loop Integration

JSEC uses Janet's `janet_async_start()` / `janet_async_end()` API for async I/O.


<a id="orga8ba064"></a>

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


<a id="orgecd103b"></a>

## Key Functions

-   `janet_async_start()` - Begin async operation, fiber yields
-   `janet_async_end()` - Complete operation, fiber resumes with value
-   `janet_async_mod()` - Change event registration (READ <-> WRITE)


<a id="org51c68c5"></a>

## Why WANT<sub>WRITE</sub> During Read?

TLS can renegotiate at any time. During a read, OpenSSL may need to send
a handshake message, returning `SSL_ERROR_WANT_WRITE`. We must:

1.  Switch to write event registration
2.  When writable, retry the **same** SSL<sub>read</sub>() call
3.  OpenSSL handles the renegotiation transparently


<a id="orgef33eb2"></a>

# Memory Management


<a id="orgd8337ce"></a>

## OpenSSL Objects

-   `SSL_CTX` - Reference counted, can be shared across connections
-   `SSL` - One per connection, freed on stream close
-   `BIO` - Managed by SSL when attached, freed automatically


<a id="orgff9890d"></a>

## Janet Integration

-   Streams are garbage collected via `gc` callback
-   Use `janet_gcroot()` / `janet_gcunroot()` for persistent references
-   Always clean up OpenSSL state in `gc` callback


<a id="org2d8cddc"></a>

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


<a id="org9ea87fd"></a>

# Adding New Functionality


<a id="orgfe54619"></a>

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


<a id="org3cab636"></a>

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


<a id="orgae1b9ae"></a>

# Building and Debugging


<a id="orgffee17a"></a>

## Build with Debug Symbols

    jpm clean
    jpm build -- -O0 -g


<a id="org489f024"></a>

## OpenSSL Error Messages

    #include <openssl/err.h>
    
    /* Print all queued errors */
    ERR_print_errors_fp(stderr);
    
    /* Get single error */
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "OpenSSL error: %s\n", buf);


<a id="org0f3b0ed"></a>

## Useful Tools

-   `strace -f -e trace=network` - Trace network syscalls
-   `openssl s_client -connect host:port` - Test server
-   `openssl s_server -cert cert.pem -key key.pem` - Test client
-   `wireshark` - Packet inspection (can decrypt with SSLKEYLOGFILE)


<a id="org67e2b0d"></a>

# Common Pitfalls

1.  **Blocking in Event Loop** - Never use blocking OpenSSL calls
2.  **Ignoring WANT<sub>READ</sub>/WANT<sub>WRITE</sub>** - Must handle renegotiation
3.  **Memory Leaks** - Always free SSL/SSL<sub>CTX</sub> in gc callback
4.  **Missing Error Checks** - Always check SSL<sub>get</sub><sub>error</sub>() return
5.  **Thread Safety** - OpenSSL 1.1.1+ is thread-safe, but not Janet streams


<a id="orge2c0b3c"></a>

# References

-   [Janet C API Documentation](https://janet-lang.org/capi/index.html)
-   [OpenSSL 3.0 Manual](https://www.openssl.org/docs/man3.0/man3/)

