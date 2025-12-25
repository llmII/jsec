
# Table of Contents

1.  [Async Integration](#orgdec8bf0)
    1.  [Best Practices](#org33584bc)
2.  [Certificate Verification](#org97348ba)
3.  [Mutual TLS (mTLS)](#orge3f33ff)
    1.  [Server Side](#org62ec283)
    2.  [Client Side](#orgc948588)
4.  [DTLS (Datagram TLS)](#org4cf1ce7)
5.  [STARTTLS](#org1e7e7b8)
6.  [Session Resumption](#org4f43e93)
7.  [Certificate Generation](#org1acf1fe)
8.  [Custom BIO Transport](#orge22b8e1)
9.  [Cryptographic Operations](#orgfc9cc35)
10. [Security Best Practices](#org9224211)
11. [Performance Tuning](#org692873f)
12. [Using Standard Janet Stream API](#org9fa5ad4)



<a id="orgdec8bf0"></a>

# Async Integration

Jsec is designed to work seamlessly with Janet's event loop (`ev`). All I/O
operations yield to the event loop when they would block. TLS streams work
with standard Janet stream functions (`ev/read`, `ev/write`, `ev/close`).


<a id="org33584bc"></a>

## Best Practices

1.  **Use Fibers**: Handle each connection in a separate fiber using `ev/go`.
2.  **Timeouts**: Use `ev/with-deadline` to enforce timeouts on operations.
    
        (try
          (ev/with-deadline 5.0 (ev/read stream 1024))
          ([err] (print "Read timed out")))
3.  **Cancellation**: Jsec streams handle fiber cancellation gracefully.

**Example**: See [echo<sub>server.janet</sub>](../examples/echo_server.janet) for proper fiber-based connection handling.


<a id="org97348ba"></a>

# Certificate Verification

By default, `tls/connect` verifies the server's certificate against the
system's CA store.

-   **Self-Signed Certs**: To trust a self-signed cert, you can:
    1.  Disable verification (NOT RECOMMENDED for production): `{:verify false}`.
    2.  Load a custom CA file: `{:ca-file "ca.pem"}`.

**Example**: See [simple<sub>https</sub><sub>client.janet</sub>](../examples/simple_https_client.janet) for certificate verification in practice.


<a id="orge3f33ff"></a>

# Mutual TLS (mTLS)

mTLS requires both the server and client to present certificates.


<a id="org62ec283"></a>

## Server Side

    (tls/accept listener {
      :cert "server.crt"
      :key "server.key"
      :verify true  # Request and verify client cert
    })


<a id="orgc948588"></a>

## Client Side

    (tls/connect host port {
      :cert "client.crt"
      :key "client.key"
    })

**Example**: See [mtls<sub>client</sub><sub>server.janet</sub>](../examples/mtls_client_server.janet) for complete mTLS implementation.


<a id="org4cf1ce7"></a>

# DTLS (Datagram TLS)

DTLS brings TLS security to UDP. It handles packet loss and reordering.

-   **Packet Size**: DTLS records must fit within the MTU. Avoid sending huge
    buffers in a single write if possible, though OpenSSL handles fragmentation.
-   **Timeouts**: DTLS handshakes rely on timers. Jsec manages this automatically
    using the event loop.
-   **Multiple Clients**: `dtls/server` handles multiple simultaneous clients
    using cookie-based client verification.

**Example**: See [dtls<sub>echo.janet</sub>](../examples/dtls_echo.janet) for DTLS client and server implementation.


<a id="org1e7e7b8"></a>

# STARTTLS

Upgrade an existing plaintext connection to TLS using `tls/upgrade`. This is
commonly used with protocols like SMTP, IMAP, and FTP.

**Example**: See [starttls<sub>smtp.janet</sub>](../examples/starttls_smtp.janet) for SMTP STARTTLS upgrade.


<a id="org4f43e93"></a>

# Session Resumption

Session resumption speeds up subsequent TLS handshakes by reusing cryptographic
parameters.

-   Use `tls/get-session` to extract session data after a connection.
-   Pass session data via `{:session data}` option in subsequent `connect` calls.
-   Check `tls/session-reused?` to verify resumption occurred.

**Example**: See [session<sub>resumption.janet</sub>](../examples/session_resumption.janet) for session caching and reuse.


<a id="org1acf1fe"></a>

# Certificate Generation

For testing or internal tools, generate self-signed certificates at runtime:

    (import jsec/cert)
    
    (let [certs (cert/generate-self-signed-cert {
                   :common-name "localhost"
                   :days-valid 30
                 })]
      (spit "cert.pem" (certs :cert))
      (spit "key.pem" (certs :key)))

**Example**: See [cert<sub>gen.janet</sub>](../examples/cert_gen.janet) for certificate generation.


<a id="orge22b8e1"></a>

# Custom BIO Transport

For advanced use cases, use OpenSSL BIO (Basic I/O) objects for custom transport layers or in-memory operations.

**Examples**:

-   [bio<sub>memory.janet</sub>](../examples/bio_memory.janet) - Memory BIO operations
-   [custom<sub>bio</sub><sub>transport.janet</sub>](../examples/custom_bio_transport.janet) - Custom transport implementation


<a id="orgfc9cc35"></a>

# Cryptographic Operations

Jsec provides access to OpenSSL cryptographic primitives:

-   Hashing (SHA-256, SHA-384, SHA-512)
-   Digital signatures (Ed25519, RSA)
-   Key generation

**Example**: See [crypto<sub>signing.janet</sub>](../examples/crypto_signing.janet) for signing and verification.


<a id="org9224211"></a>

# Security Best Practices

1.  **Enable Certificate Verification**: Always use `{:verify true}` in production (it's the default for clients).
2.  **Use Modern TLS**: Enforce TLS 1.2+ with `{:security {:min-version "TLS1.2"}}`.
3.  **Strong Ciphers**: Configure cipher suites via `:ciphers` option.
4.  **Session Security**: Protect session data if persisting to disk.
5.  **Rate Limiting**: Implement rate limiting at the application level to prevent DoS attacks.

**Example**: See [policy<sub>enforcement.janet</sub>](../examples/policy_enforcement.janet) for advanced security configuration.

**Note**: All examples include appropriate security warnings and best practices comments.


<a id="org692873f"></a>

# Performance Tuning

-   **Session Resumption**: Use `get-session` and the `:session` option to speed
    up subsequent handshakes.
-   **Buffer Size**: Adjust `:buffer-size` in `connect` options. Larger buffers
    (16KB) are better for throughput; smaller buffers (1-2KB) reduce memory
    usage per connection.
-   **Connection Pooling**: Reuse connections when possible to avoid handshake
    overhead.
-   **Context Reuse**: Create a context with `tls/new-context` and reuse it for
    multiple connections to save memory and improve performance.


<a id="org9fa5ad4"></a>

# Using Standard Janet Stream API

TLS streams are fully compatible with Janet's stream API:

    (import jsec/tls)
    
    (def conn (tls/connect "example.com" "443"))
    
    # Use standard ev functions
    (ev/write conn "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    (def response (ev/read conn 4096))
    (print response)
    
    # Or with timeout
    (ev/with-deadline 5.0
      (ev/write conn request)
      (ev/chunk conn 1024))
    
    # Close properly
    (ev/close conn)

This means TLS streams work with any code that expects Janet streams.

