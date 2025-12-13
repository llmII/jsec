
# Table of Contents

1.  [Overview](#org3e445e4)
    1.  [Janet Stream API Compatibility](#org40b005d)
2.  [Modules](#orgb2fbb40)
3.  [Module: jsec/tls](#orgcae6f5e)
    1.  [(tls/new-context opts)](#orgb554ce1)
    2.  [(tls/connect host port &opt opts)](#org41702a6)
    3.  [(tls/listen host port &opt opts)](#org6e768c4)
    4.  [(tls/accept listener opts)](#org4164221)
    5.  [(tls/accept-loop listener context handler)](#org5be27f1)
    6.  [(tls/upgrade stream hostname &opt opts)](#orgc37f357)
    7.  [(tls/wrap stream &opt hostname-or-opts opts)](#org3df55d0)
    8.  [Stream Methods (Janet Stream API Compatible)](#org9977d00)
        1.  [(ev/read stream n &opt buf timeout)](#org04c3062)
        2.  [(ev/write stream data &opt timeout)](#org8b88302)
        3.  [(ev/chunk stream n &opt buf timeout)](#orga912daa)
        4.  [(ev/close stream)](#org278e1d5)
    9.  [TLS Stream Methods (via jsec/tls-stream)](#orgd407e6c)
        1.  [Connection Information](#orgd6ba318)
        2.  [Session Management](#org09e9961)
        3.  [TLS Operations](#org2e0e146)
        4.  [Certificate Trust](#orge5bb5e3)
4.  [Module: jsec/dtls](#orgdcf42f3)
    1.  [Stream Method Access](#orga552814)
    2.  [Server API (UDP-style, multiple peers)](#org0301067)
        1.  [(dtls/listen host port &opt opts)](#org8256220)
        2.  [(dtls/recv-from server nbytes buf &opt timeout-or-opts)](#org262c640)
        3.  [(dtls/send-to server addr data &opt timeout)](#org783eabd)
        4.  [(dtls/close-server server &opt force)](#orga3bf7c4)
        5.  [(dtls/localname server)](#org9e1ea3d)
    3.  [Client API (1:1 connection)](#org198b997)
        1.  [(dtls/connect host port &opt opts)](#org38b5921)
        2.  [(dtls/read client n &opt buf timeout)](#org05ebe06)
        3.  [(dtls/write client data &opt timeout)](#org19ef075)
        4.  [(dtls/close client &opt force)](#org39d308e)
    4.  [Address Utilities](#orgd338e9b)
    5.  [DTLS Stream Methods (via jsec/dtls-stream)](#orgeda5f12)
        1.  [Connection Information (Client)](#orge5d0a78)
        2.  [Session Management (Client)](#org22a2cf5)
        3.  [DTLS Operations](#org9176207)
        4.  [Certificate Trust](#org2e82ba2)
        5.  [Upgrade (STARTTLS equivalent)](#orgde636cc)
5.  [Module: jsec/cert](#orgc9c08d5)
    1.  [(cert/generate-self-signed-cert opts)](#org82053d8)
    2.  [(cert/generate-self-signed-from-key key-pem opts)](#orgaa8839a)
6.  [Module: jsec/bio](#org5326136)
    1.  [(bio/new-mem)](#orga097f41)
    2.  [(bio/read bio nbytes)](#orgf27d8f4)
    3.  [(bio/write bio data)](#org80a22f3)
    4.  [(bio/to-string bio)](#orga90aa0a)
    5.  [(bio/close bio)](#orga3c7a2e)
7.  [Module: jsec/crypto](#org4fd6d0f)
    1.  [Hashing and Message Authentication](#org913d3b4)
        1.  [(crypto/digest algorithm data)](#orgd0ccb29)
        2.  [(crypto/hmac algorithm key data)](#orga18007a)
    2.  [Key Generation and Management](#orgcc327c8)
        1.  [(crypto/generate-key alg &opt bits)](#org3142f59)
        2.  [(crypto/export-public-key private-key-pem)](#orgf6b7155)
    3.  [Signing and Verification](#orgcb58f45)
        1.  [(crypto/sign key-pem data)](#orgc9b77a9)
        2.  [(crypto/verify key-pem data signature)](#orgdd3f90f)
    4.  [Key Derivation](#org10b1456)
        1.  [(crypto/hkdf algorithm key salt info length)](#org97f6965)
        2.  [(crypto/pbkdf2 algorithm password salt iterations length)](#orgccd5061)
    5.  [Random Data](#org74a8ef0)
        1.  [(crypto/random-bytes n)](#org22b883c)
    6.  [Certificate Signing Requests](#org74465a8)
        1.  [(crypto/generate-csr private-key-pem options)](#orgf774377)
        2.  [(crypto/parse-csr csr-pem)](#org0946e12)
    7.  [Challenge-Response](#org21c4464)
        1.  [(crypto/generate-challenge &opt length)](#orga46b681)
    8.  [CMS/PKCS#7 Operations](#orga3cf026)
        1.  [(crypto/cms-sign data cert key &opt opts)](#org652260d)
        2.  [(crypto/cms-verify cms-data &opt opts)](#org304b500)
        3.  [(crypto/cms-encrypt data certs &opt opts)](#orgae7e5de)
        4.  [(crypto/cms-decrypt cms-data cert key)](#org93b905f)
        5.  [(crypto/cms-certs-only certs)](#org64acdcd)
        6.  [(crypto/cms-get-certs cms-data)](#orgddc1f15)
    9.  [Base64 Encoding](#org5c52695)
        1.  [(crypto/base64-encode data)](#org4847dee)
        2.  [(crypto/base64-decode data)](#orgd44da83)
        3.  [(crypto/base64url-encode data)](#org1962399)
        4.  [(crypto/base64url-decode data)](#orgef7ebbb)
    10. [Symmetric Encryption (AEAD)](#org031b0c5)
        1.  [(crypto/encrypt algo key nonce plaintext &opt aad)](#orgf68e0c0)
        2.  [(crypto/decrypt algo key nonce ciphertext tag &opt aad)](#org3022f70)
        3.  [(crypto/generate-nonce algo)](#orgcc48f37)
        4.  [(crypto/cipher-info algo)](#org43ba49d)
    11. [RSA Encryption](#orgf3499ea)
        1.  [(crypto/rsa-encrypt key-pem plaintext &opt opts)](#orgc76334e)
        2.  [(crypto/rsa-decrypt key-pem ciphertext &opt opts)](#orga945c37)
        3.  [(crypto/rsa-max-plaintext key-pem &opt opts)](#org7a963d8)
    12. [Key/Certificate Format Conversion](#org6b312de)
        1.  [(crypto/convert-key key-data target-format &opt opts)](#org4d2ab85)
        2.  [(crypto/convert-cert cert-data target-format)](#orga7c61a5)
        3.  [(crypto/detect-format data)](#orgc2636be)
        4.  [(crypto/load-key key-pem &opt password)](#org9a19cc5)
        5.  [(crypto/export-key key-pem &opt opts)](#orgba71132)
        6.  [(crypto/key-info key-pem)](#org41ca5f7)
    13. [PKCS#12 Operations](#orge6b008f)
        1.  [(crypto/create-pkcs12 cert-pem key-pem opts)](#orgc24a163)
        2.  [(crypto/parse-pkcs12 pfx-data password)](#orgcae51f5)
    14. [Elliptic Curve Point Operations](#org6f44e7d)
        1.  [(crypto/ec-generate-scalar curve)](#org35dbfdf)
        2.  [(crypto/ec-point-mul curve scalar &opt point)](#orgb1d85c8)
        3.  [(crypto/ec-point-add curve point1 point2)](#org5b787c2)
        4.  [(crypto/ec-point-to-bytes curve point &opt opts)](#org080bb9d)
        5.  [(crypto/ec-point-from-bytes curve bytes)](#orga45e677)
8.  [Security Options](#org23b8c4a)



<a id="org3e445e4"></a>

# Overview

Jsec provides production-quality TLS/DTLS integration for Janet. The APIs are
designed to closely follow Janet's standard conventions:

-   **TLS streams** implement Janet's full stream interface (`ev/read`, `ev/write`,
    `ev/chunk`, `ev/close`) with identical signatures. TLS streams can be used
    anywhere Janet streams are expected - no special-casing required.

-   **DTLS** follows Janet's UDP conventions (`net/recv-from`, `net/send-to`) for
    the server-side API, and stream conventions for 1:1 client connections.

This design allows TLS/DTLS to be a drop-in replacement in existing code.


<a id="org40b005d"></a>

## Janet Stream API Compatibility

TLS streams are designed to be fully compatible with Janet's stream API. This
means:

1.  **Same function signatures**: `ev/read`, `ev/write`, `ev/chunk`, `ev/close`
    work identically on TLS streams as they do on plain TCP streams.

2.  **Drop-in replacement**: Code written for `net/connect` can use `tls/connect`
    with no other changes. Generic stream-processing functions work unchanged.

3.  **Optional parameter convention**: Where Janet stream functions accept one
    optional parameter (e.g., timeout), jsec accepts either:
    -   The original type (number for timeout)
    -   A table/struct containing that parameter and optionally TLS-specific options

4.  **Only initialization differs**: `tls/connect` vs `net/connect` and
    `tls/listen~/~tls/accept` vs `net/listen~/~net/accept` have different
    signatures to accommodate TLS options.

    # These work identically on TLS or plain TCP streams:
    (ev/read stream 1024)              # Read up to 1024 bytes
    (ev/write stream "hello")          # Write data
    (ev/chunk stream 100)              # Read exactly 100 bytes
    (ev/close stream)                  # Close with proper shutdown
    
    # Generic stream function - works with any stream type
    (defn echo-handler [stream]
      (while-let [data (ev/read stream 4096)]
        (ev/write stream data)))
    
    # Works with plain TCP
    (echo-handler (net/connect "localhost" "8080"))
    
    # Works with TLS - no changes needed
    (echo-handler (tls/connect "localhost" "8443" {:verify false}))


<a id="orgb2fbb40"></a>

# Modules

-   `jsec/tls`: TCP/TLS operations (Client & Server). Implements full Janet stream interface.
-   `jsec/dtls`: UDP/DTLS operations (Client & Server). Follows Janet UDP conventions.
-   `jsec/cert`: Certificate generation utilities.
-   `jsec/bio`: Basic I/O abstraction (memory BIOs).
-   `jsec/crypto`: Cryptographic primitives (hashing, signing).

For working examples of all functionality, see the [examples directory](../examples/).


<a id="orgcae6f5e"></a>

# Module: jsec/tls


<a id="orgb554ce1"></a>

## (tls/new-context opts)

Create a reusable TLS context.

-   **opts**: Table/struct.
    -   `:cert`: Path to certificate (PEM) or PEM content (string/buffer).
    -   `:key`: Path to private key (PEM) or PEM content (string/buffer).
    -   `:verify`: Boolean (default `true` for client).
    -   `:ca-file`: Path to CA certificate file or PEM content (string/buffer).
    -   `:ca-path`: Path to CA certificate directory.
    -   `:security`: Security options.
    -   `:alpn`: List of ALPN protocols (e.g. `["h2" "http/1.1"]`).
    -   `:sni`: (Server only) Table of hostname -> options for virtual hosting.
        Example: `{"example.com" {:cert "..." :key "..."}}`.

**Returns**: A TLS context object.

**Example**: See [echo<sub>server.janet</sub>](../examples/echo_server.janet) for context creation and reuse.


<a id="org41702a6"></a>

## (tls/connect host port &opt opts)

Connect to a TLS server.

-   **host**: String (hostname or IP) or `:unix` for Unix sockets.
-   **port**: String (port number) or path for Unix sockets.
-   **opts**: Optional table/struct OR a TLS context object.
    -   If a context is passed, it is used for the connection.
    -   If a table is passed:
        -   `:verify`: Boolean (default `true`). Verify server certificate.
        -   `:hostname`: String. SNI hostname. Defaults to `host` for TCP, "localhost" for Unix.
        -   `:verify-hostname`: String. Hostname to verify against certificate (defaults to `:hostname`).
        -   `:session`: Byte string. Session data for resumption (from `get-session`).
        -   `:cert`: String/buffer. Client certificate (PEM) for mTLS.
        -   `:key`: String/buffer. Client private key (PEM) for mTLS.
        -   `:trusted-cert`: String/buffer. Trust specific cert (for self-signed servers).
        -   `:buffer-size`: Integer. Internal TLS buffer size (default 16384).
        -   `:tcp-nodelay`: Boolean. Enable TCP<sub>NODELAY</sub> (default `true`).
        -   `:handshake-timing`: Boolean. Track handshake duration (default `false`).
        -   `:security`: Table. Security options (see [Security Options](#org23b8c4a)).
        -   `:alpn`: List of ALPN protocols.
        -   `:ca-file`: Path to CA certificate file or PEM content (string/buffer).
        -   `:ca-path`: Path to CA certificate directory.

**Returns**: A TLS stream object.

**Examples**:

-   [simple<sub>https</sub><sub>client.janet</sub>](../examples/simple_https_client.janet) - Basic HTTPS GET request
-   [session<sub>resumption.janet</sub>](../examples/session_resumption.janet) - Using session resumption
-   [mtls<sub>client</sub><sub>server.janet</sub>](../examples/mtls_client_server.janet) - Mutual TLS authentication


<a id="org6e768c4"></a>

## (tls/listen host port &opt opts)

Create a TCP listener. This is a wrapper around `net/listen`.

-   **host**: Bind address.
-   **port**: Bind port.
-   **opts**: Optional table.
    -   `:backlog`: Integer. Listen backlog (default 1024).

**Returns**: A listener object.


<a id="org4164221"></a>

## (tls/accept listener opts)

Accept a connection from a listener and perform the TLS handshake.

-   **listener**: Listener object from `tls/listen`.
-   **opts**: Table/struct OR a TLS context object.
    -   If a context is passed, it is used for the connection.
    -   If a table is passed:
        -   `:cert`: String. Path to server certificate (PEM) or PEM content (string/buffer).
        -   `:key`: String. Path to private key (PEM) or PEM content (string/buffer).
        -   `:verify`: Boolean (default `false`). Require and verify client certificate (mTLS).
        -   `:trusted-cert`: String/buffer. Trust specific client certificate (for mTLS with self-signed).
        -   `:ca`: String. Path to CA file for client certificate verification.
        -   `:buffer-size`: Integer. Internal TLS buffer size (default 16384).
        -   `:tcp-nodelay`: Boolean. Enable TCP<sub>NODELAY</sub> (default `true`).
        -   `:handshake-timing`: Boolean. Track handshake duration (default `false`).
        -   `:security`: Table. Security options.
        -   `:alpn`: List of ALPN protocols.
        -   `:ca-file`: Path to CA certificate file (for mTLS) or PEM content.
        -   `:ca-path`: Path to CA certificate directory (for mTLS).

**Returns**: A TLS stream object.


<a id="org5be27f1"></a>

## (tls/accept-loop listener context handler)

Continuously accept TLS connections on a listener.

-   **listener**: Listener object from `tls/listen`.
-   **context**: TLS context object OR options table (same as `tls/accept`).
    -   Can include `:buffer-size`, `:tcp-nodelay`, `:handshake-timing`.
-   **handler**: Function taking a TLS stream.

**Returns**: The listener stream (when closed).


<a id="orgc37f357"></a>

## (tls/upgrade stream hostname &opt opts)

Upgrade an existing plaintext stream to TLS (STARTTLS).

-   **stream**: Existing connected `JanetStream`.
-   **hostname**: String. SNI hostname.
-   **opts**: Optional table (same as `connect`).

**Returns**: A TLS stream object. **Note**: The original stream is consumed.

**Example**: See [starttls<sub>smtp.janet</sub>](../examples/starttls_smtp.janet) for SMTP STARTTLS upgrade.


<a id="org3df55d0"></a>

## (tls/wrap stream &opt hostname-or-opts opts)

Wrap an existing stream with TLS. Used for both client and server modes.

**Client mode** (provides hostname):

-   **stream**: Existing connected `JanetStream`.
-   **hostname-or-opts**: String. SNI hostname.
-   **opts**: Optional table:
    -   `:verify`: Boolean (default `true`). Verify server certificate.
    -   `:cert`: String/buffer. Client certificate (PEM) for mTLS.
    -   `:key`: String/buffer. Client private key (PEM) for mTLS.
    -   `:trusted-cert`: String/buffer. Trust specific cert (for self-signed).
    -   `:session`: Buffer. Session data for resumption.
    -   `:buffer-size`: Integer. Internal TLS buffer size.
    -   `:tcp-nodelay`: Boolean. Enable TCP<sub>NODELAY</sub> (default `true`).
    -   `:handshake-timing`: Boolean. Track handshake duration (default `false`).
    -   `:security`: Table. Security options.
    -   `:alpn`: List of ALPN protocols.

**Server mode** (provides cert/key):

-   **stream**: Existing connected `JanetStream` from `:accept`.
-   **hostname-or-opts**: Table/struct with:
    -   `:cert`: String/buffer. Server certificate (PEM). Required.
    -   `:key`: String/buffer. Server private key (PEM). Required.
    -   `:verify`: Boolean. If `true`, require client certificate (mTLS).
    -   `:trusted-cert`: String/buffer. Trust specific client cert.
    -   `:ca`: String. Path to CA file for client cert verification.
    -   `:buffer-size`: Integer. Internal TLS buffer size.
    -   `:tcp-nodelay`: Boolean. Enable TCP<sub>NODELAY</sub> (default `true`).
    -   `:handshake-timing`: Boolean. Track handshake duration (default `false`).
    -   `:security`: Table. Security options.
    -   `:alpn`: List of ALPN protocols.

**Returns**: A TLS stream object.

**Examples**:

    # Client mode - connect with client certificate (mTLS)
    (def tls (tls/wrap tcp-stream "example.com" 
               {:cert client-cert :key client-key :verify false}))
    
    # Server mode - require client certificate (mTLS)
    (def tls (tls/wrap accepted-stream 
               {:cert server-cert :key server-key 
                :verify true :trusted-cert client-cert}))


<a id="org9977d00"></a>

## Stream Methods (Janet Stream API Compatible)

TLS streams implement Janet's standard stream interface. They work with:

-   `ev/read` / `:read` - Read data from the stream
-   `ev/write` / `:write` - Write data to the stream
-   `ev/chunk` / `:chunk` - Read exactly n bytes or until EOF
-   `ev/close` / `:close` - Close with proper TLS shutdown


<a id="org04c3062"></a>

### (ev/read stream n &opt buf timeout)

Read up to `n` bytes from the TLS stream.

-   **stream**: TLS stream object
-   **n**: Maximum bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data, or `nil` on EOF.


<a id="org8b88302"></a>

### (ev/write stream data &opt timeout)

Write data to the TLS stream.

-   **stream**: TLS stream object
-   **data**: String or buffer to write
-   **timeout**: Optional timeout in seconds

**Returns**: `nil`


<a id="orga912daa"></a>

### (ev/chunk stream n &opt buf timeout)

Read exactly `n` bytes, or until EOF.

-   **stream**: TLS stream object
-   **n**: Exact number of bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data.


<a id="org278e1d5"></a>

### (ev/close stream)

Close the TLS stream with proper RFC-compliant shutdown.

Performs async bidirectional close<sub>notify</sub> exchange before closing the
underlying transport. Safe to use with Janet's `with` macro.

-   **stream**: TLS stream object

**Note**: For unresponsive peers, use `(:close stream true)` to force immediate
close without TLS shutdown.


<a id="orgd407e6c"></a>

## TLS Stream Methods (via jsec/tls-stream)

These methods are available on TLS stream objects. Access via method syntax
`(:method stream args...)` or import `jsec/tls-stream` for function versions.


<a id="orgd6ba318"></a>

### Connection Information

-   `(:connection-info stream)` or `(tls-stream/connection-info stream)`
    Returns a struct with connection details:
    -   `:version`: TLS version (e.g., "TLSv1.3")
    -   `:cipher`: Cipher suite name
    -   `:cipher-bits`: Cipher strength
    -   `:alpn`: Negotiated ALPN protocol
    -   `:server-name`: SNI hostname

-   `(:version stream)` or `(tls-stream/version stream)`
    Returns TLS version string (e.g., "TLSv1.3")

-   `(:cipher stream)` or `(tls-stream/cipher stream)`
    Returns cipher suite name

-   `(:cipher-bits stream)` or `(tls-stream/cipher-bits stream)`
    Returns cipher bit strength as integer


<a id="org09e9961"></a>

### Session Management

-   `(:session-reused? stream)` or `(tls-stream/session-reused? stream)`
    Returns `true` if session was resumed

-   `(:get-session stream)` or `(tls-stream/get-session stream)`
    Returns session data (byte string) for resumption

-   `(:set-session stream data)` or `(tls-stream/set-session stream data)`
    Sets session data (usually passed in `connect` options instead)


<a id="org2e0e146"></a>

### TLS Operations

-   `(:key-update stream)` or `(tls-stream/key-update stream)`
    Request TLS 1.3 key update (post-handshake key rotation)

-   `(:renegotiate stream)` or `(tls-stream/renegotiate stream)`
    Request TLS 1.2 renegotiation (disabled by default for security)

-   `(:set-ocsp-response stream data)` or `(tls-stream/set-ocsp-response stream data)`
    Set OCSP stapling response

-   `(:shutdown stream &opt force)` or `(tls-stream/shutdown stream &opt force)`
    Perform TLS shutdown. If `force` is true, skip close<sub>notify</sub>.


<a id="orge5bb5e3"></a>

### Certificate Trust

-   `(tls-stream/trust-cert ctx cert-pem)`
    Add a trusted certificate to a context. Used for trusting self-signed certs.

**Example**: See [session<sub>resumption.janet</sub>](../examples/session_resumption.janet) for session management.
**Example**: See [tls<sub>key</sub><sub>update.janet</sub>](../examples/tls_key_update.janet) for key update usage.
**Example**: See [connection<sub>info.janet</sub>](../examples/connection_info.janet) for connection info retrieval.


<a id="orgdcf42f3"></a>

# Module: jsec/dtls

DTLS provides TLS security for UDP datagrams. The API design:

-   **Server-side**: Follows Janet's UDP conventions (`net/recv-from`, `net/send-to`)
    for multiplexed peer handling on a single socket.
-   **Client-side**: 1:1 connections with stream-like `read~/~write` for simplicity.

Both DTLSServer and DTLSClient embed JanetStream and expose methods via the
standard `(:method obj args...)` syntax, matching Janet's stream patterns.


<a id="orga552814"></a>

## Stream Method Access

Both DTLSServer and DTLSClient support method dispatch:

    # Server methods
    (:recv-from server nbytes buf)
    (:send-to server addr data)
    (:close server)
    (:localname server)
    
    # Client methods  
    (:read client nbytes)
    (:write client data)
    (:close client)


<a id="org0301067"></a>

## Server API (UDP-style, multiple peers)


<a id="org8256220"></a>

### (dtls/listen host port &opt opts)

Create a DTLS server bound to an address.

-   **host**: Bind address (string)
-   **port**: Bind port (integer or string)
-   **opts**: Table
    -   `:cert`: Server certificate (PEM string). **Required**.
    -   `:key`: Server private key (PEM string). **Required**.
    -   `:verify`: Boolean (default `false`). Request client certificates (mTLS).
    -   `:ca`: CA certificates for client verification.
    -   `:session-timeout`: Session timeout in seconds (default 300).

**Returns**: A DTLS server object.


<a id="org262c640"></a>

### (dtls/recv-from server nbytes buf &opt timeout-or-opts)

Receive a datagram from any peer. Handles DTLS handshakes transparently.

-   **server**: DTLS server object
-   **nbytes**: Maximum bytes to receive
-   **buf**: Buffer to receive data into
-   **timeout-or-opts**: Number (timeout in seconds) or table `{:timeout n}`

**Returns**: Peer address object, or `nil` on timeout.

Matches Janet's `net/recv-from` convention.


<a id="org783eabd"></a>

### (dtls/send-to server addr data &opt timeout)

Send a datagram to a specific peer.

-   **server**: DTLS server object
-   **addr**: Peer address (from `recv-from`)
-   **data**: Data to send (string or buffer)
-   **timeout**: Optional timeout in seconds

**Returns**: Number of bytes sent.


<a id="orga3bf7c4"></a>

### (dtls/close-server server &opt force)

Close the server and all sessions.

-   **server**: DTLS server object
-   **force**: If true, skip close<sub>notify</sub> alerts (default false)


<a id="org9e1ea3d"></a>

### (dtls/localname server)

Get the local address the server is bound to.

**Returns**: `[host port]` tuple.


<a id="org198b997"></a>

## Client API (1:1 connection)


<a id="org38b5921"></a>

### (dtls/connect host port &opt opts)

Create a DTLS client connection. Performs handshake.

-   **host**: String (hostname or IP address)
-   **port**: Integer or string (port number)
-   **opts**: Optional table
    -   `:verify`: Boolean (default `true`). Verify server certificate.
    -   `:cert`: Client certificate for mTLS (PEM string).
    -   `:key`: Client private key for mTLS (PEM string).
    -   `:ca`: CA certificate (PEM string).
    -   `:sni`: Server name for SNI (defaults to host).
    -   `:verify-hostname`: Hostname to verify against cert.
    -   `:handshake-timing`: Boolean. Track handshake duration.

**Returns**: A DTLS client object.


<a id="org05ebe06"></a>

### (dtls/read client n &opt buf timeout)

Read a datagram from the connection.

-   **client**: DTLS client object
-   **n**: Maximum bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data, or `nil` on EOF.


<a id="org19ef075"></a>

### (dtls/write client data &opt timeout)

Write a datagram to the connection.

-   **client**: DTLS client object
-   **data**: Data to send (string or buffer)
-   **timeout**: Optional timeout in seconds

**Returns**: Number of bytes written.


<a id="org39d308e"></a>

### (dtls/close client &opt force)

Close the client connection.

-   **client**: DTLS client object
-   **force**: If true, skip close<sub>notify</sub> (default false)


<a id="orgd338e9b"></a>

## Address Utilities

-   `(dtls-stream/address host port)`: Create an address object.
-   `(dtls-stream/address-host addr)`: Get host string from address.
-   `(dtls-stream/address-port addr)`: Get port number from address.
-   `(dtls-stream/address? x)`: Check if x is a DTLS address object.


<a id="orgeda5f12"></a>

## DTLS Stream Methods (via jsec/dtls-stream)

These methods are available on DTLS server and client objects. Access via method
syntax `(:method obj args...)` or import `jsec/dtls-stream` for function versions.


<a id="orge5d0a78"></a>

### Connection Information (Client)

-   `(:connection-info client)` or `(dtls-stream/connection-info client)`
    Returns a struct with connection details:
    -   `:version`: DTLS version (e.g., "DTLSv1.2")
    -   `:cipher`: Cipher suite name
    -   `:cipher-bits`: Cipher strength

-   `(:version client)` or `(dtls-stream/version client)`
    Returns DTLS version string

-   `(:cipher client)` or `(dtls-stream/cipher client)`
    Returns cipher suite name

-   `(:cipher-bits client)` or `(dtls-stream/cipher-bits client)`
    Returns cipher bit strength

-   `(:peername client)` or `(dtls-stream/peername client)`
    Returns peer address as `[host port]` tuple


<a id="org22a2cf5"></a>

### Session Management (Client)

-   `(:session-reused? client)` or `(dtls-stream/session-reused? client)`
    Returns `true` if session was resumed

-   `(:get-session client)` or `(dtls-stream/get-session client)`
    Returns session data for resumption

-   `(:set-session client data)` or `(dtls-stream/set-session client data)`
    Sets session data


<a id="org9176207"></a>

### DTLS Operations

-   `(:shutdown client &opt force)` or `(dtls-stream/shutdown client &opt force)`
    Perform DTLS shutdown. If `force` is true, skip close<sub>notify</sub>.

-   `(:chunk client n &opt buf timeout)` or `(dtls-stream/chunk client ...)`
    Read exactly n bytes (for client connections)


<a id="org2e82ba2"></a>

### Certificate Trust

-   `(dtls-stream/trust-cert ctx cert-pem)`
    Add a trusted certificate to a context.


<a id="orgde636cc"></a>

### Upgrade (STARTTLS equivalent)

-   `(dtls-stream/upgrade stream &opt opts)`
    Upgrade an existing UDP socket to DTLS.

**Example**: See [dtls<sub>echo.janet</sub>](../examples/dtls_echo.janet) for complete DTLS usage.
**Example**: See [dtls<sub>session</sub><sub>resumption.janet</sub>](../examples/dtls_session_resumption.janet) for session resumption.
**Example**: See [dtls<sub>connection</sub><sub>info.janet</sub>](../examples/dtls_connection_info.janet) for connection info.


<a id="orgc9c08d5"></a>

# Module: jsec/cert


<a id="org82053d8"></a>

## (cert/generate-self-signed-cert opts)

Generate a self-signed X.509 certificate and private key.

-   **opts**: Table.
    -   `:common-name`: String (default "localhost").
    -   `:days-valid`: Integer (default 365).
    -   `:bits`: Integer, RSA key size (default 2048, only for RSA).
    -   `:key-type`: Keyword, key algorithm (default `:rsa`).
        Supported: `:rsa`, `:ec-p256`, `:ec-p384`, `:ec-p521`, `:ed25519`
    -   `:country`: String (default "US").
    -   `:organization`: String (default "Test").

**Note**: Generated certificates have CA:TRUE basic constraint set.

**Returns**: Struct `{:cert "PEM..." :key "PEM..."}`.


<a id="orgaa8839a"></a>

## (cert/generate-self-signed-from-key key-pem opts)

Generate a self-signed certificate using an existing private key.

-   **key-pem**: Existing private key in PEM format.
-   **opts**: Table.
    -   `:common-name`: String (default "localhost").
    -   `:days-valid`: Integer (default 365).
    -   `:country`: String (default "US").
    -   `:organization`: String (default "Test").

**Note**: Generated certificates have CA:TRUE basic constraint set.

**Returns**: Certificate PEM string.

**Example**: See [cert<sub>gen.janet</sub>](../examples/cert_gen.janet) for certificate generation usage.


<a id="org5326136"></a>

# Module: jsec/bio

BIO (Basic I/O) provides OpenSSL's I/O abstraction layer for in-memory operations.


<a id="orga097f41"></a>

## (bio/new-mem)

Create a memory BIO for in-memory I/O operations.

**Returns**: A BIO object.


<a id="orgf27d8f4"></a>

## (bio/read bio nbytes)

Read from a BIO.

-   **bio**: BIO object
-   **nbytes**: Maximum bytes to read

**Returns**: Buffer with data, or nil if no data available.


<a id="org80a22f3"></a>

## (bio/write bio data)

Write to a BIO.

-   **bio**: BIO object
-   **data**: Data to write (string or buffer)

**Returns**: Number of bytes written.


<a id="orga90aa0a"></a>

## (bio/to-string bio)

Read all pending data from a BIO as a string.

-   **bio**: BIO object

**Returns**: String with all pending data.


<a id="orga3c7a2e"></a>

## (bio/close bio)

Free a BIO object and release its resources.

-   **bio**: BIO object

**Example**: See [bio<sub>memory.janet</sub>](../examples/bio_memory.janet) and [custom<sub>bio</sub><sub>transport.janet</sub>](../examples/custom_bio_transport.janet).


<a id="org4fd6d0f"></a>

# Module: jsec/crypto


<a id="org913d3b4"></a>

## Hashing and Message Authentication


<a id="orgd0ccb29"></a>

### (crypto/digest algorithm data)

Compute a cryptographic hash.

-   **algorithm**: String ("sha256", "sha384", "sha512", "sha1", "md5", etc.)
-   **data**: Data to hash (string or buffer)

**Returns**: Buffer with hash bytes.


<a id="orga18007a"></a>

### (crypto/hmac algorithm key data)

Compute HMAC (Hash-based Message Authentication Code).

-   **algorithm**: Hash algorithm ("sha256", etc.)
-   **key**: Secret key (string or buffer)
-   **data**: Data to authenticate (string or buffer)

**Returns**: Buffer with HMAC bytes.


<a id="orgcc327c8"></a>

## Key Generation and Management


<a id="org3142f59"></a>

### (crypto/generate-key alg &opt bits)

Generate a private key in PEM format.

-   **alg**: Keyword for key algorithm:
    -   `:rsa` - RSA key (optional bits param, default 2048)
    -   `:ed25519` - Ed25519 key (signing)
    -   `:x25519` - X25519 key (key exchange/ECDH)
    -   `:ec-p256` or `:p256` - EC P-256 curve
    -   `:ec-p384` or `:p384` - EC P-384 curve
    -   `:ec-p521` or `:p521` - EC P-521 curve
-   **bits**: Optional key size for RSA (default 2048)

**Returns**: PEM-encoded private key string.


<a id="orgf6b7155"></a>

### (crypto/export-public-key private-key-pem)

Extract public key from a private key.

-   **private-key-pem**: PEM-encoded private key string

**Returns**: PEM-encoded public key string.


<a id="orgcb58f45"></a>

## Signing and Verification


<a id="orgc9b77a9"></a>

### (crypto/sign key-pem data)

Sign data with a private key.

-   **key-pem**: Private key in PEM format
-   **data**: Data to sign (string or buffer)

**Returns**: Signature buffer.


<a id="orgdd3f90f"></a>

### (crypto/verify key-pem data signature)

Verify a signature.

-   **key-pem**: Key in PEM format (public or private)
-   **data**: Original data
-   **signature**: Signature to verify

**Returns**: Boolean (`true` if valid).


<a id="org10b1456"></a>

## Key Derivation


<a id="org97f6965"></a>

### (crypto/hkdf algorithm key salt info length)

HKDF (HMAC-based Key Derivation Function).

-   **algorithm**: Hash algorithm ("sha256", etc.)
-   **key**: Input key material
-   **salt**: Salt value (can be empty string)
-   **info**: Context/application info
-   **length**: Desired output length in bytes

**Returns**: Derived key buffer.


<a id="orgccd5061"></a>

### (crypto/pbkdf2 algorithm password salt iterations length)

PBKDF2 (Password-Based Key Derivation Function 2).

-   **algorithm**: Hash algorithm
-   **password**: Password string
-   **salt**: Salt value
-   **iterations**: Number of iterations (minimum 10000 recommended)
-   **length**: Desired output length in bytes

**Returns**: Derived key buffer.


<a id="org74a8ef0"></a>

## Random Data


<a id="org22b883c"></a>

### (crypto/random-bytes n)

Generate cryptographically secure random bytes.

-   **n**: Number of bytes

**Returns**: Buffer with random bytes.


<a id="org74465a8"></a>

## Certificate Signing Requests


<a id="orgf774377"></a>

### (crypto/generate-csr private-key-pem options)

Generate a Certificate Signing Request (CSR).

-   **private-key-pem**: Private key in PEM format
-   **options**: Table with subject and options:
    -   `:common-name` - CN field (required for most CAs)
    -   `:country` - C field (2-letter code)
    -   `:state` - ST field
    -   `:locality` - L field
    -   `:organization` - O field
    -   `:organizational-unit` - OU field
    -   `:email` - emailAddress field
    -   `:san` - Array of Subject Alt Names (e.g. `["DNS:example.com" "IP:1.2.3.4"]`)
    -   `:digest` - Signing digest (default `:sha256`)

**Returns**: PEM-encoded CSR string.


<a id="org0946e12"></a>

### (crypto/parse-csr csr-pem)

Parse a PEM-encoded CSR.

-   **csr-pem**: CSR in PEM format

**Returns**: Table with CSR information.


<a id="org21c4464"></a>

## Challenge-Response


<a id="orga46b681"></a>

### (crypto/generate-challenge &opt length)

Generate a random challenge for authentication protocols.

-   **length**: Challenge length in bytes (default 32)

**Returns**: Buffer with random challenge.


<a id="orga3cf026"></a>

## CMS/PKCS#7 Operations

For SCEP/ACME foundations and secure message exchange.


<a id="org652260d"></a>

### (crypto/cms-sign data cert key &opt opts)

Sign data using CMS (Cryptographic Message Syntax).

-   **data**: Data to sign
-   **cert**: Signer certificate (PEM)
-   **key**: Signer private key (PEM)
-   **opts**: Optional table
    -   `:detached`: Boolean. If true, create detached signature.

**Returns**: CMS signed data (DER or PEM based on input).


<a id="org304b500"></a>

### (crypto/cms-verify cms-data &opt opts)

Verify a CMS signature.

-   **cms-data**: CMS signed data
-   **opts**: Optional table
    -   `:ca`: CA certificate for verification
    -   `:detached`: Original data if signature is detached

**Returns**: Table `{:valid true/false :content data :certs [...]}`


<a id="orgae7e5de"></a>

### (crypto/cms-encrypt data certs &opt opts)

Encrypt data for recipients using CMS.

-   **data**: Data to encrypt
-   **certs**: Array of recipient certificates (PEM)
-   **opts**: Optional table
    -   `:cipher`: Cipher to use (default "aes-256-cbc")

**Returns**: CMS encrypted data.


<a id="org93b905f"></a>

### (crypto/cms-decrypt cms-data cert key)

Decrypt CMS encrypted data.

-   **cms-data**: Encrypted CMS data
-   **cert**: Recipient certificate (PEM)
-   **key**: Recipient private key (PEM)

**Returns**: Decrypted data buffer.


<a id="org64acdcd"></a>

### (crypto/cms-certs-only certs)

Create a CMS certs-only message (certificate chain).

-   **certs**: Array of certificates (PEM)

**Returns**: CMS data containing certificates.


<a id="orgddc1f15"></a>

### (crypto/cms-get-certs cms-data)

Extract certificates from CMS data.

-   **cms-data**: CMS signed or certs-only data

**Returns**: Array of PEM-encoded certificates.


<a id="org5c52695"></a>

## Base64 Encoding


<a id="org4847dee"></a>

### (crypto/base64-encode data)

Base64 encode data.

**Returns**: Base64 string.


<a id="orgd44da83"></a>

### (crypto/base64-decode data)

Base64 decode data.

**Returns**: Decoded buffer.


<a id="org1962399"></a>

### (crypto/base64url-encode data)

URL-safe Base64 encode (for JWT, etc.).

**Returns**: Base64url string.


<a id="orgef7ebbb"></a>

### (crypto/base64url-decode data)

URL-safe Base64 decode.

**Returns**: Decoded buffer.

**Example**: See [crypto<sub>signing.janet</sub>](../examples/crypto_signing.janet) for signing operations.
**Example**: See [crypto<sub>operations.janet</sub>](../examples/crypto_operations.janet) for comprehensive crypto usage.


<a id="org031b0c5"></a>

## Symmetric Encryption (AEAD)


<a id="orgf68e0c0"></a>

### (crypto/encrypt algo key nonce plaintext &opt aad)

Encrypt data using authenticated encryption (AEAD).

-   **algo**: Cipher algorithm keyword
    -   `:aes-128-gcm` - AES-128 in GCM mode (16-byte key, 12-byte nonce)
    -   `:aes-256-gcm` - AES-256 in GCM mode (32-byte key, 12-byte nonce)
    -   `:chacha20-poly1305` - ChaCha20-Poly1305 (32-byte key, 12-byte nonce)
    -   `:aes-128-cbc` - AES-128 in CBC mode (16-byte key, 16-byte IV)
    -   `:aes-256-cbc` - AES-256 in CBC mode (32-byte key, 16-byte IV)
-   **key**: Encryption key (buffer, correct length for algorithm)
-   **nonce**: Nonce/IV (buffer, correct length for algorithm)
-   **plaintext**: Data to encrypt
-   **aad**: Optional additional authenticated data (AEAD only)

**Returns**: Struct `{:ciphertext <buffer> :tag <buffer>}`

**IMPORTANT**: Never reuse a nonce with the same key!


<a id="org3022f70"></a>

### (crypto/decrypt algo key nonce ciphertext tag &opt aad)

Decrypt data using authenticated encryption.

-   **algo**: Same as encrypt
-   **key**: Encryption key
-   **nonce**: Same nonce used for encryption
-   **ciphertext**: Encrypted data
-   **tag**: Authentication tag (required for AEAD, nil for CBC)
-   **aad**: Must match AAD used during encryption

**Returns**: Decrypted plaintext buffer.

**Errors**: If authentication fails (tag mismatch).


<a id="orgcc48f37"></a>

### (crypto/generate-nonce algo)

Generate a random nonce suitable for the specified cipher.

-   **algo**: Cipher algorithm keyword

**Returns**: Buffer of appropriate length.


<a id="org43ba49d"></a>

### (crypto/cipher-info algo)

Get information about a cipher algorithm.

-   **algo**: Cipher algorithm keyword

**Returns**: Struct with cipher details:

-   `:name` - Algorithm name
-   `:key-length` - Required key length in bytes
-   `:nonce-length` - Required nonce/IV length in bytes
-   `:tag-length` - Authentication tag length (AEAD)
-   `:aead` - Boolean indicating if cipher is AEAD

**Example**: See [symmetric<sub>encryption.janet</sub>](../examples/symmetric_encryption.janet) for AEAD encryption.


<a id="orgf3499ea"></a>

## RSA Encryption


<a id="orgc76334e"></a>

### (crypto/rsa-encrypt key-pem plaintext &opt opts)

Encrypt data with RSA public key.

-   **key-pem**: Public or private key in PEM format
-   **plaintext**: Data to encrypt
-   **opts**: Optional table
    -   `:padding` - Padding mode (default `:oaep-sha256`)
        -   `:oaep-sha256` (recommended)
        -   `:oaep-sha384`
        -   `:oaep-sha512`
        -   `:oaep-sha1` (legacy)
        -   `:pkcs1` (legacy, NOT recommended)

**Returns**: Encrypted ciphertext buffer.

**Note**: RSA can only encrypt limited data based on key size and padding.
Use `rsa-max-plaintext` to check limits. For larger data, use hybrid encryption.


<a id="orga945c37"></a>

### (crypto/rsa-decrypt key-pem ciphertext &opt opts)

Decrypt data with RSA private key.

-   **key-pem**: Private key in PEM format
-   **ciphertext**: Encrypted data
-   **opts**: Must match encryption options

**Returns**: Decrypted plaintext buffer.


<a id="org7a963d8"></a>

### (crypto/rsa-max-plaintext key-pem &opt opts)

Get maximum plaintext size for RSA encryption.

-   **key-pem**: Key in PEM format
-   **opts**: Same as rsa-encrypt

**Returns**: Maximum bytes that can be encrypted.

**Example**: See [rsa<sub>encryption.janet</sub>](../examples/rsa_encryption.janet) for RSA encryption and hybrid encryption.


<a id="org6b312de"></a>

## Key/Certificate Format Conversion


<a id="org4d2ab85"></a>

### (crypto/convert-key key-data target-format &opt opts)

Convert a key between formats.

-   **key-data**: Key in any supported format
-   **target-format**: Keyword
    -   `:pem` - PEM format
    -   `:der` - DER (binary) format
    -   `:pkcs8` - PKCS#8 PEM format
    -   `:pkcs8-der` - PKCS#8 DER format
-   **opts**: Optional table
    -   `:password` - Password for encrypted PKCS#8 output

**Returns**: Key in target format.


<a id="orga7c61a5"></a>

### (crypto/convert-cert cert-data target-format)

Convert a certificate between PEM and DER formats.

-   **cert-data**: Certificate data
-   **target-format**: `:pem` or `:der`

**Returns**: Certificate in target format.


<a id="orgc2636be"></a>

### (crypto/detect-format data)

Detect if data is PEM or DER format.

**Returns**: `:pem` or `:der`


<a id="org9a19cc5"></a>

### (crypto/load-key key-pem &opt password)

Load a private key, optionally decrypting it.

-   **key-pem**: Key in PEM format
-   **password**: Password if key is encrypted

**Returns**: Decrypted key in PEM format.


<a id="orgba71132"></a>

### (crypto/export-key key-pem &opt opts)

Export a private key, optionally encrypting it.

-   **key-pem**: Key in PEM format
-   **opts**: Optional table
    -   `:password` - Password for encryption
    -   `:cipher` - Encryption cipher (`:aes-256-cbc`, `:aes-128-cbc`, `:des-ede3-cbc`)

**Returns**: Key in PEM format.


<a id="org41ca5f7"></a>

### (crypto/key-info key-pem)

Get metadata about a key without needing the password.

**Returns**: Table with:

-   `:type` - `:rsa`, `:ec`, `:ed25519`, `:x25519`, etc.
-   `:bits` - Key size in bits
-   `:curve` - EC curve name (for EC keys)
-   `:encrypted` - True if password-protected

**Example**: See [format<sub>conversion.janet</sub>](../examples/format_conversion.janet) for format conversion.


<a id="orge6b008f"></a>

## PKCS#12 Operations


<a id="orgc24a163"></a>

### (crypto/create-pkcs12 cert-pem key-pem opts)

Create a PKCS#12 (PFX) bundle.

-   **cert-pem**: Certificate in PEM format
-   **key-pem**: Private key in PEM format
-   **opts**: Table
    -   `:password` - Required password for bundle
    -   `:chain` - Optional array of CA certificate PEMs
    -   `:friendly-name` - Optional friendly name attribute

**Returns**: PKCS#12 bundle bytes (DER format).


<a id="orgcae51f5"></a>

### (crypto/parse-pkcs12 pfx-data password)

Parse a PKCS#12 bundle.

-   **pfx-data**: PKCS#12 data (from file or create-pkcs12)
-   **password**: Bundle password

**Returns**: Table with:

-   `:cert` - Certificate PEM
-   `:key` - Private key PEM
-   `:chain` - Array of CA certificate PEMs
-   `:friendly-name` - Friendly name if present

**Example**: See [pkcs12<sub>operations.janet</sub>](../examples/pkcs12_operations.janet) for PKCS#12 usage.


<a id="org6f44e7d"></a>

## Elliptic Curve Point Operations

Low-level EC point arithmetic for custom protocols, threshold cryptography,
zero-knowledge proofs, and Bitcoin/Ethereum cryptography.


<a id="org35dbfdf"></a>

### (crypto/ec-generate-scalar curve)

Generate a random scalar in [1, order-1] for the curve.

-   **curve**: Curve identifier
    -   `:p-256` (secp256r1) - NIST 256-bit
    -   `:p-384` (secp384r1) - NIST 384-bit
    -   `:p-521` (secp521r1) - NIST 521-bit
    -   `:secp256k1` - Bitcoin/Ethereum curve

**Returns**: Big-endian byte buffer.


<a id="orgb1d85c8"></a>

### (crypto/ec-point-mul curve scalar &opt point)

Scalar multiplication on elliptic curve.

-   **curve**: Curve identifier
-   **scalar**: Big-endian byte buffer
-   **point**: Optional `{:x <buffer> :y <buffer>}`. If nil, multiplies generator G.

**Returns**: `{:x <buffer> :y <buffer>}`


<a id="org5b787c2"></a>

### (crypto/ec-point-add curve point1 point2)

Point addition on elliptic curve.

**Returns**: `{:x <buffer> :y <buffer>}`


<a id="org080bb9d"></a>

### (crypto/ec-point-to-bytes curve point &opt opts)

Serialize EC point to SEC1 format.

-   **opts**: Optional table
    -   `:compressed` - If true, use compressed format

**Returns**: Bytes buffer.


<a id="orga45e677"></a>

### (crypto/ec-point-from-bytes curve bytes)

Deserialize EC point from SEC1 format.

**Returns**: `{:x <buffer> :y <buffer>}`

**Example**: See [ec<sub>point</sub><sub>operations.janet</sub>](../examples/ec_point_operations.janet) for EC operations.


<a id="org23b8c4a"></a>

# Security Options

The `:security` option in `connect` and `accept` allows fine-grained control:

-   `:min-version`: Keyword or string. For TLS: :TLS1<sub>2</sub>, :TLS1<sub>3</sub>, or "TLS1.2", "TLS1.3". For DTLS: :DTLS1<sub>0</sub>, :DTLS1<sub>2</sub>, or "DTLS1.0", "DTLS1.2".
-   `:max-version`: Keyword or string. Same format as `:min-version`.
-   `:ciphers`: Keyword or string. OpenSSL cipher list format (e.g., :HIGH, "ECDHE-RSA-AES256-GCM-SHA384").
-   `:curves`: Keyword or string. Supported elliptic curves (e.g., :prime256v1, "prime256v1:secp384r1").
-   `:ca-file`: CA certificate (path or PEM content).
-   `:ca-path`: CA directory path.

**Note**: Keyword symbols are preferred for idiomatic Janet code.

**Example**: See [policy<sub>enforcement.janet</sub>](../examples/policy_enforcement.janet) for advanced security configuration.

