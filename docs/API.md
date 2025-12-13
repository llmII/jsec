
# Table of Contents

1.  [Overview](#orgafeed63)
    1.  [Janet Stream API Compatibility](#org31d04ba)
2.  [Modules](#org20ec85b)
3.  [Module: jsec/tls](#org5e060f3)
    1.  [(tls/new-context opts)](#org0b1e393)
    2.  [(tls/connect host port &opt opts)](#org7b4e413)
    3.  [(tls/listen host port &opt opts)](#org01d89c3)
    4.  [(tls/accept listener opts)](#org164e6d3)
    5.  [(tls/accept-loop listener context handler)](#org7b339c6)
    6.  [(tls/upgrade stream hostname &opt opts)](#org22e7f3e)
    7.  [(tls/wrap stream &opt hostname-or-opts opts)](#org4a75e60)
    8.  [Stream Methods (Janet Stream API Compatible)](#org4237f98)
        1.  [(ev/read stream n &opt buf timeout)](#orga87e4b4)
        2.  [(ev/write stream data &opt timeout)](#org3a33485)
        3.  [(ev/chunk stream n &opt buf timeout)](#org44bf4fc)
        4.  [(ev/close stream)](#org829b94f)
    9.  [TLS Stream Methods (via jsec/tls-stream)](#orgfa2c649)
        1.  [Connection Information](#orgde6609c)
        2.  [Session Management](#org47aeb1a)
        3.  [TLS Operations](#org71a29be)
        4.  [Certificate Trust](#orgd0c8dec)
4.  [Module: jsec/dtls](#org4d3ce87)
    1.  [Stream Method Access](#org80d75e5)
    2.  [Server API (UDP-style, multiple peers)](#org4bcfe41)
        1.  [(dtls/listen host port &opt opts)](#orgaeebef8)
        2.  [(dtls/recv-from server nbytes buf &opt timeout-or-opts)](#org8ef9db2)
        3.  [(dtls/send-to server addr data &opt timeout)](#org7d786aa)
        4.  [(dtls/close-server server &opt force)](#org9ef679c)
        5.  [(dtls/localname server)](#org618baf9)
    3.  [Client API (1:1 connection)](#org1354b32)
        1.  [(dtls/connect host port &opt opts)](#orge76f606)
        2.  [(dtls/read client n &opt buf timeout)](#org86ab01e)
        3.  [(dtls/write client data &opt timeout)](#org9be6b04)
        4.  [(dtls/close client &opt force)](#org3d2c015)
    4.  [Address Utilities](#orge477181)
    5.  [DTLS Stream Methods (via jsec/dtls-stream)](#org5bfd99f)
        1.  [Connection Information (Client)](#org0b5cb45)
        2.  [Session Management (Client)](#org0caedbb)
        3.  [DTLS Operations](#orgdf0db51)
        4.  [Certificate Trust](#orgb53a759)
        5.  [Upgrade (STARTTLS equivalent)](#org49a082c)
5.  [Module: jsec/cert](#orgc0c4d70)
    1.  [(cert/generate-self-signed-cert opts)](#org2d8e1ce)
    2.  [(cert/generate-self-signed-from-key key-pem opts)](#orgdea0a36)
6.  [Module: jsec/bio](#org280d231)
    1.  [(bio/new-mem)](#org5880515)
    2.  [(bio/read bio nbytes)](#org4331b82)
    3.  [(bio/write bio data)](#org96ed749)
    4.  [(bio/to-string bio)](#org286b63e)
    5.  [(bio/close bio)](#org3a68c3d)
7.  [Module: jsec/crypto](#orgf88e634)
    1.  [Hashing and Message Authentication](#orga0bbe22)
        1.  [(crypto/digest algorithm data)](#orgee26cdb)
        2.  [(crypto/hmac algorithm key data)](#orgfddb6e5)
    2.  [Key Generation and Management](#org095554e)
        1.  [(crypto/generate-key alg &opt bits)](#org5f96ac7)
        2.  [(crypto/export-public-key private-key-pem)](#orgfa9c01d)
    3.  [Signing and Verification](#org16f4298)
        1.  [(crypto/sign key-pem data)](#org76ee658)
        2.  [(crypto/verify key-pem data signature)](#org60aecb4)
    4.  [Key Derivation](#org6c3a0af)
        1.  [(crypto/hkdf algorithm key salt info length)](#org3416872)
        2.  [(crypto/pbkdf2 algorithm password salt iterations length)](#org6e43646)
    5.  [Random Data](#org3fd92a7)
        1.  [(crypto/random-bytes n)](#org8554542)
    6.  [Certificate Signing Requests](#org6a0206c)
        1.  [(crypto/generate-csr private-key-pem options)](#org516bfc9)
        2.  [(crypto/parse-csr csr-pem)](#orgef13a29)
    7.  [Challenge-Response](#org3294df6)
        1.  [(crypto/generate-challenge &opt length)](#org462bd7e)
    8.  [CMS/PKCS#7 Operations](#orgb1d097f)
        1.  [(crypto/cms-sign data cert key &opt opts)](#orgdebfc85)
        2.  [(crypto/cms-verify cms-data &opt opts)](#org8afacac)
        3.  [(crypto/cms-encrypt data certs &opt opts)](#orga568a2b)
        4.  [(crypto/cms-decrypt cms-data cert key)](#orgecb894d)
        5.  [(crypto/cms-certs-only certs)](#org7dd7639)
        6.  [(crypto/cms-get-certs cms-data)](#org6eeb8b1)
    9.  [Base64 Encoding](#org3754286)
        1.  [(crypto/base64-encode data)](#org80f8c12)
        2.  [(crypto/base64-decode data)](#org7487aed)
        3.  [(crypto/base64url-encode data)](#orgc02fa52)
        4.  [(crypto/base64url-decode data)](#org65b8fab)
    10. [Symmetric Encryption (AEAD)](#orge5d7429)
        1.  [(crypto/encrypt algo key nonce plaintext &opt aad)](#orgfd9ec17)
        2.  [(crypto/decrypt algo key nonce ciphertext tag &opt aad)](#org79a3d1a)
        3.  [(crypto/generate-nonce algo)](#orgad4b918)
        4.  [(crypto/cipher-info algo)](#org83e1c34)
    11. [RSA Encryption](#org7713286)
        1.  [(crypto/rsa-encrypt key-pem plaintext &opt opts)](#org015c7a1)
        2.  [(crypto/rsa-decrypt key-pem ciphertext &opt opts)](#org20fa2fd)
        3.  [(crypto/rsa-max-plaintext key-pem &opt opts)](#org9ba6423)
    12. [Key/Certificate Format Conversion](#org5613c79)
        1.  [(crypto/convert-key key-data target-format &opt opts)](#orgfb69be3)
        2.  [(crypto/convert-cert cert-data target-format)](#org6c6ca78)
        3.  [(crypto/detect-format data)](#org9be8328)
        4.  [(crypto/load-key key-pem &opt password)](#org2c1c701)
        5.  [(crypto/export-key key-pem &opt opts)](#org35d223b)
        6.  [(crypto/key-info key-pem)](#org7d4bb84)
    13. [PKCS#12 Operations](#org76c4fd7)
        1.  [(crypto/create-pkcs12 cert-pem key-pem opts)](#orgd02c7fc)
        2.  [(crypto/parse-pkcs12 pfx-data password)](#org105db28)
    14. [Elliptic Curve Point Operations](#org71c7870)
        1.  [(crypto/ec-generate-scalar curve)](#org9c04a83)
        2.  [(crypto/ec-point-mul curve scalar &opt point)](#org8880b34)
        3.  [(crypto/ec-point-add curve point1 point2)](#orgc75b806)
        4.  [(crypto/ec-point-to-bytes curve point &opt opts)](#org4e04217)
        5.  [(crypto/ec-point-from-bytes curve bytes)](#org22f9df4)
8.  [Security Options](#orgbe87684)



<a id="orgafeed63"></a>

# Overview

Jsec provides production-quality TLS/DTLS integration for Janet. The APIs are
designed to closely follow Janet's standard conventions:

-   **TLS streams** implement Janet's full stream interface (`ev/read`, `ev/write`,
    `ev/chunk`, `ev/close`) with identical signatures. TLS streams can be used
    anywhere Janet streams are expected - no special-casing required.

-   **DTLS** follows Janet's UDP conventions (`net/recv-from`, `net/send-to`) for
    the server-side API, and stream conventions for 1:1 client connections.

This design allows TLS/DTLS to be a drop-in replacement in existing code.


<a id="org31d04ba"></a>

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


<a id="org20ec85b"></a>

# Modules

-   `jsec/tls`: TCP/TLS operations (Client & Server). Implements full Janet stream interface.
-   `jsec/dtls`: UDP/DTLS operations (Client & Server). Follows Janet UDP conventions.
-   `jsec/cert`: Certificate generation utilities.
-   `jsec/bio`: Basic I/O abstraction (memory BIOs).
-   `jsec/crypto`: Cryptographic primitives (hashing, signing).

For working examples of all functionality, see the [examples directory](../examples/).


<a id="org5e060f3"></a>

# Module: jsec/tls


<a id="org0b1e393"></a>

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


<a id="org7b4e413"></a>

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
        -   `:security`: Table. Security options (see [Security Options](#orgbe87684)).
        -   `:alpn`: List of ALPN protocols.
        -   `:ca-file`: Path to CA certificate file or PEM content (string/buffer).
        -   `:ca-path`: Path to CA certificate directory.

**Returns**: A TLS stream object.

**Examples**:

-   [simple<sub>https</sub><sub>client.janet</sub>](../examples/simple_https_client.janet) - Basic HTTPS GET request
-   [session<sub>resumption.janet</sub>](../examples/session_resumption.janet) - Using session resumption
-   [mtls<sub>client</sub><sub>server.janet</sub>](../examples/mtls_client_server.janet) - Mutual TLS authentication


<a id="org01d89c3"></a>

## (tls/listen host port &opt opts)

Create a TCP listener. This is a wrapper around `net/listen`.

-   **host**: Bind address.
-   **port**: Bind port.
-   **opts**: Optional table.
    -   `:backlog`: Integer. Listen backlog (default 1024).

**Returns**: A listener object.


<a id="org164e6d3"></a>

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


<a id="org7b339c6"></a>

## (tls/accept-loop listener context handler)

Continuously accept TLS connections on a listener.

-   **listener**: Listener object from `tls/listen`.
-   **context**: TLS context object OR options table (same as `tls/accept`).
    -   Can include `:buffer-size`, `:tcp-nodelay`, `:handshake-timing`.
-   **handler**: Function taking a TLS stream.

**Returns**: The listener stream (when closed).


<a id="org22e7f3e"></a>

## (tls/upgrade stream hostname &opt opts)

Upgrade an existing plaintext stream to TLS (STARTTLS).

-   **stream**: Existing connected `JanetStream`.
-   **hostname**: String. SNI hostname.
-   **opts**: Optional table (same as `connect`).

**Returns**: A TLS stream object. **Note**: The original stream is consumed.

**Example**: See [starttls<sub>smtp.janet</sub>](../examples/starttls_smtp.janet) for SMTP STARTTLS upgrade.


<a id="org4a75e60"></a>

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


<a id="org4237f98"></a>

## Stream Methods (Janet Stream API Compatible)

TLS streams implement Janet's standard stream interface. They work with:

-   `ev/read` / `:read` - Read data from the stream
-   `ev/write` / `:write` - Write data to the stream
-   `ev/chunk` / `:chunk` - Read exactly n bytes or until EOF
-   `ev/close` / `:close` - Close with proper TLS shutdown


<a id="orga87e4b4"></a>

### (ev/read stream n &opt buf timeout)

Read up to `n` bytes from the TLS stream.

-   **stream**: TLS stream object
-   **n**: Maximum bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data, or `nil` on EOF.


<a id="org3a33485"></a>

### (ev/write stream data &opt timeout)

Write data to the TLS stream.

-   **stream**: TLS stream object
-   **data**: String or buffer to write
-   **timeout**: Optional timeout in seconds

**Returns**: `nil`


<a id="org44bf4fc"></a>

### (ev/chunk stream n &opt buf timeout)

Read exactly `n` bytes, or until EOF.

-   **stream**: TLS stream object
-   **n**: Exact number of bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data.


<a id="org829b94f"></a>

### (ev/close stream)

Close the TLS stream with proper RFC-compliant shutdown.

Performs async bidirectional close<sub>notify</sub> exchange before closing the
underlying transport. Safe to use with Janet's `with` macro.

-   **stream**: TLS stream object

**Note**: For unresponsive peers, use `(:close stream true)` to force immediate
close without TLS shutdown.


<a id="orgfa2c649"></a>

## TLS Stream Methods (via jsec/tls-stream)

These methods are available on TLS stream objects. Access via method syntax
`(:method stream args...)` or import `jsec/tls-stream` for function versions.


<a id="orgde6609c"></a>

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


<a id="org47aeb1a"></a>

### Session Management

-   `(:session-reused? stream)` or `(tls-stream/session-reused? stream)`
    Returns `true` if session was resumed

-   `(:get-session stream)` or `(tls-stream/get-session stream)`
    Returns session data (byte string) for resumption

-   `(:set-session stream data)` or `(tls-stream/set-session stream data)`
    Sets session data (usually passed in `connect` options instead)


<a id="org71a29be"></a>

### TLS Operations

-   `(:key-update stream)` or `(tls-stream/key-update stream)`
    Request TLS 1.3 key update (post-handshake key rotation)

-   `(:renegotiate stream)` or `(tls-stream/renegotiate stream)`
    Request TLS 1.2 renegotiation (disabled by default for security)

-   `(:set-ocsp-response stream data)` or `(tls-stream/set-ocsp-response stream data)`
    Set OCSP stapling response

-   `(:shutdown stream &opt force)` or `(tls-stream/shutdown stream &opt force)`
    Perform TLS shutdown. If `force` is true, skip close<sub>notify</sub>.


<a id="orgd0c8dec"></a>

### Certificate Trust

-   `(tls-stream/trust-cert ctx cert-pem)`
    Add a trusted certificate to a context. Used for trusting self-signed certs.

**Example**: See [session<sub>resumption.janet</sub>](../examples/session_resumption.janet) for session management.
**Example**: See [tls<sub>key</sub><sub>update.janet</sub>](../examples/tls_key_update.janet) for key update usage.
**Example**: See [connection<sub>info.janet</sub>](../examples/connection_info.janet) for connection info retrieval.


<a id="org4d3ce87"></a>

# Module: jsec/dtls

DTLS provides TLS security for UDP datagrams. The API design:

-   **Server-side**: Follows Janet's UDP conventions (`net/recv-from`, `net/send-to`)
    for multiplexed peer handling on a single socket.
-   **Client-side**: 1:1 connections with stream-like `read~/~write` for simplicity.

Both DTLSServer and DTLSClient embed JanetStream and expose methods via the
standard `(:method obj args...)` syntax, matching Janet's stream patterns.


<a id="org80d75e5"></a>

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


<a id="org4bcfe41"></a>

## Server API (UDP-style, multiple peers)


<a id="orgaeebef8"></a>

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


<a id="org8ef9db2"></a>

### (dtls/recv-from server nbytes buf &opt timeout-or-opts)

Receive a datagram from any peer. Handles DTLS handshakes transparently.

-   **server**: DTLS server object
-   **nbytes**: Maximum bytes to receive
-   **buf**: Buffer to receive data into
-   **timeout-or-opts**: Number (timeout in seconds) or table `{:timeout n}`

**Returns**: Peer address object, or `nil` on timeout.

Matches Janet's `net/recv-from` convention.


<a id="org7d786aa"></a>

### (dtls/send-to server addr data &opt timeout)

Send a datagram to a specific peer.

-   **server**: DTLS server object
-   **addr**: Peer address (from `recv-from`)
-   **data**: Data to send (string or buffer)
-   **timeout**: Optional timeout in seconds

**Returns**: Number of bytes sent.


<a id="org9ef679c"></a>

### (dtls/close-server server &opt force)

Close the server and all sessions.

-   **server**: DTLS server object
-   **force**: If true, skip close<sub>notify</sub> alerts (default false)


<a id="org618baf9"></a>

### (dtls/localname server)

Get the local address the server is bound to.

**Returns**: `[host port]` tuple.


<a id="org1354b32"></a>

## Client API (1:1 connection)


<a id="orge76f606"></a>

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


<a id="org86ab01e"></a>

### (dtls/read client n &opt buf timeout)

Read a datagram from the connection.

-   **client**: DTLS client object
-   **n**: Maximum bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data, or `nil` on EOF.


<a id="org9be6b04"></a>

### (dtls/write client data &opt timeout)

Write a datagram to the connection.

-   **client**: DTLS client object
-   **data**: Data to send (string or buffer)
-   **timeout**: Optional timeout in seconds

**Returns**: Number of bytes written.


<a id="org3d2c015"></a>

### (dtls/close client &opt force)

Close the client connection.

-   **client**: DTLS client object
-   **force**: If true, skip close<sub>notify</sub> (default false)


<a id="orge477181"></a>

## Address Utilities

-   `(dtls-stream/address host port)`: Create an address object.
-   `(dtls-stream/address-host addr)`: Get host string from address.
-   `(dtls-stream/address-port addr)`: Get port number from address.
-   `(dtls-stream/address? x)`: Check if x is a DTLS address object.


<a id="org5bfd99f"></a>

## DTLS Stream Methods (via jsec/dtls-stream)

These methods are available on DTLS server and client objects. Access via method
syntax `(:method obj args...)` or import `jsec/dtls-stream` for function versions.


<a id="org0b5cb45"></a>

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


<a id="org0caedbb"></a>

### Session Management (Client)

-   `(:session-reused? client)` or `(dtls-stream/session-reused? client)`
    Returns `true` if session was resumed

-   `(:get-session client)` or `(dtls-stream/get-session client)`
    Returns session data for resumption

-   `(:set-session client data)` or `(dtls-stream/set-session client data)`
    Sets session data


<a id="orgdf0db51"></a>

### DTLS Operations

-   `(:shutdown client &opt force)` or `(dtls-stream/shutdown client &opt force)`
    Perform DTLS shutdown. If `force` is true, skip close<sub>notify</sub>.

-   `(:chunk client n &opt buf timeout)` or `(dtls-stream/chunk client ...)`
    Read exactly n bytes (for client connections)


<a id="orgb53a759"></a>

### Certificate Trust

-   `(dtls-stream/trust-cert ctx cert-pem)`
    Add a trusted certificate to a context.


<a id="org49a082c"></a>

### Upgrade (STARTTLS equivalent)

-   `(dtls-stream/upgrade stream &opt opts)`
    Upgrade an existing UDP socket to DTLS.

**Example**: See [dtls<sub>echo.janet</sub>](../examples/dtls_echo.janet) for complete DTLS usage.
**Example**: See [dtls<sub>session</sub><sub>resumption.janet</sub>](../examples/dtls_session_resumption.janet) for session resumption.
**Example**: See [dtls<sub>connection</sub><sub>info.janet</sub>](../examples/dtls_connection_info.janet) for connection info.


<a id="orgc0c4d70"></a>

# Module: jsec/cert


<a id="org2d8e1ce"></a>

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


<a id="orgdea0a36"></a>

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


<a id="org280d231"></a>

# Module: jsec/bio

BIO (Basic I/O) provides OpenSSL's I/O abstraction layer for in-memory operations.


<a id="org5880515"></a>

## (bio/new-mem)

Create a memory BIO for in-memory I/O operations.

**Returns**: A BIO object.


<a id="org4331b82"></a>

## (bio/read bio nbytes)

Read from a BIO.

-   **bio**: BIO object
-   **nbytes**: Maximum bytes to read

**Returns**: Buffer with data, or nil if no data available.


<a id="org96ed749"></a>

## (bio/write bio data)

Write to a BIO.

-   **bio**: BIO object
-   **data**: Data to write (string or buffer)

**Returns**: Number of bytes written.


<a id="org286b63e"></a>

## (bio/to-string bio)

Read all pending data from a BIO as a string.

-   **bio**: BIO object

**Returns**: String with all pending data.


<a id="org3a68c3d"></a>

## (bio/close bio)

Free a BIO object and release its resources.

-   **bio**: BIO object

**Example**: See [bio<sub>memory.janet</sub>](../examples/bio_memory.janet) and [custom<sub>bio</sub><sub>transport.janet</sub>](../examples/custom_bio_transport.janet).


<a id="orgf88e634"></a>

# Module: jsec/crypto


<a id="orga0bbe22"></a>

## Hashing and Message Authentication


<a id="orgee26cdb"></a>

### (crypto/digest algorithm data)

Compute a cryptographic hash.

-   **algorithm**: String ("sha256", "sha384", "sha512", "sha1", "md5", etc.)
-   **data**: Data to hash (string or buffer)

**Returns**: Buffer with hash bytes.


<a id="orgfddb6e5"></a>

### (crypto/hmac algorithm key data)

Compute HMAC (Hash-based Message Authentication Code).

-   **algorithm**: Hash algorithm ("sha256", etc.)
-   **key**: Secret key (string or buffer)
-   **data**: Data to authenticate (string or buffer)

**Returns**: Buffer with HMAC bytes.


<a id="org095554e"></a>

## Key Generation and Management


<a id="org5f96ac7"></a>

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


<a id="orgfa9c01d"></a>

### (crypto/export-public-key private-key-pem)

Extract public key from a private key.

-   **private-key-pem**: PEM-encoded private key string

**Returns**: PEM-encoded public key string.


<a id="org16f4298"></a>

## Signing and Verification


<a id="org76ee658"></a>

### (crypto/sign key-pem data)

Sign data with a private key.

-   **key-pem**: Private key in PEM format
-   **data**: Data to sign (string or buffer)

**Returns**: Signature buffer.


<a id="org60aecb4"></a>

### (crypto/verify key-pem data signature)

Verify a signature.

-   **key-pem**: Key in PEM format (public or private)
-   **data**: Original data
-   **signature**: Signature to verify

**Returns**: Boolean (`true` if valid).


<a id="org6c3a0af"></a>

## Key Derivation


<a id="org3416872"></a>

### (crypto/hkdf algorithm key salt info length)

HKDF (HMAC-based Key Derivation Function).

-   **algorithm**: Hash algorithm ("sha256", etc.)
-   **key**: Input key material
-   **salt**: Salt value (can be empty string)
-   **info**: Context/application info
-   **length**: Desired output length in bytes

**Returns**: Derived key buffer.


<a id="org6e43646"></a>

### (crypto/pbkdf2 algorithm password salt iterations length)

PBKDF2 (Password-Based Key Derivation Function 2).

-   **algorithm**: Hash algorithm
-   **password**: Password string
-   **salt**: Salt value
-   **iterations**: Number of iterations (minimum 10000 recommended)
-   **length**: Desired output length in bytes

**Returns**: Derived key buffer.


<a id="org3fd92a7"></a>

## Random Data


<a id="org8554542"></a>

### (crypto/random-bytes n)

Generate cryptographically secure random bytes.

-   **n**: Number of bytes

**Returns**: Buffer with random bytes.


<a id="org6a0206c"></a>

## Certificate Signing Requests


<a id="org516bfc9"></a>

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


<a id="orgef13a29"></a>

### (crypto/parse-csr csr-pem)

Parse a PEM-encoded CSR.

-   **csr-pem**: CSR in PEM format

**Returns**: Table with CSR information.


<a id="org3294df6"></a>

## Challenge-Response


<a id="org462bd7e"></a>

### (crypto/generate-challenge &opt length)

Generate a random challenge for authentication protocols.

-   **length**: Challenge length in bytes (default 32)

**Returns**: Buffer with random challenge.


<a id="orgb1d097f"></a>

## CMS/PKCS#7 Operations

For SCEP/ACME foundations and secure message exchange.


<a id="orgdebfc85"></a>

### (crypto/cms-sign data cert key &opt opts)

Sign data using CMS (Cryptographic Message Syntax).

-   **data**: Data to sign
-   **cert**: Signer certificate (PEM)
-   **key**: Signer private key (PEM)
-   **opts**: Optional table
    -   `:detached`: Boolean. If true, create detached signature.

**Returns**: CMS signed data (DER or PEM based on input).


<a id="org8afacac"></a>

### (crypto/cms-verify cms-data &opt opts)

Verify a CMS signature.

-   **cms-data**: CMS signed data
-   **opts**: Optional table
    -   `:ca`: CA certificate for verification
    -   `:detached`: Original data if signature is detached

**Returns**: Table `{:valid true/false :content data :certs [...]}`


<a id="orga568a2b"></a>

### (crypto/cms-encrypt data certs &opt opts)

Encrypt data for recipients using CMS.

-   **data**: Data to encrypt
-   **certs**: Array of recipient certificates (PEM)
-   **opts**: Optional table
    -   `:cipher`: Cipher to use (default "aes-256-cbc")

**Returns**: CMS encrypted data.


<a id="orgecb894d"></a>

### (crypto/cms-decrypt cms-data cert key)

Decrypt CMS encrypted data.

-   **cms-data**: Encrypted CMS data
-   **cert**: Recipient certificate (PEM)
-   **key**: Recipient private key (PEM)

**Returns**: Decrypted data buffer.


<a id="org7dd7639"></a>

### (crypto/cms-certs-only certs)

Create a CMS certs-only message (certificate chain).

-   **certs**: Array of certificates (PEM)

**Returns**: CMS data containing certificates.


<a id="org6eeb8b1"></a>

### (crypto/cms-get-certs cms-data)

Extract certificates from CMS data.

-   **cms-data**: CMS signed or certs-only data

**Returns**: Array of PEM-encoded certificates.


<a id="org3754286"></a>

## Base64 Encoding


<a id="org80f8c12"></a>

### (crypto/base64-encode data)

Base64 encode data.

**Returns**: Base64 string.


<a id="org7487aed"></a>

### (crypto/base64-decode data)

Base64 decode data.

**Returns**: Decoded buffer.


<a id="orgc02fa52"></a>

### (crypto/base64url-encode data)

URL-safe Base64 encode (for JWT, etc.).

**Returns**: Base64url string.


<a id="org65b8fab"></a>

### (crypto/base64url-decode data)

URL-safe Base64 decode.

**Returns**: Decoded buffer.

**Example**: See [crypto<sub>signing.janet</sub>](../examples/crypto_signing.janet) for signing operations.
**Example**: See [crypto<sub>operations.janet</sub>](../examples/crypto_operations.janet) for comprehensive crypto usage.


<a id="orge5d7429"></a>

## Symmetric Encryption (AEAD)


<a id="orgfd9ec17"></a>

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


<a id="org79a3d1a"></a>

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


<a id="orgad4b918"></a>

### (crypto/generate-nonce algo)

Generate a random nonce suitable for the specified cipher.

-   **algo**: Cipher algorithm keyword

**Returns**: Buffer of appropriate length.


<a id="org83e1c34"></a>

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


<a id="org7713286"></a>

## RSA Encryption


<a id="org015c7a1"></a>

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


<a id="org20fa2fd"></a>

### (crypto/rsa-decrypt key-pem ciphertext &opt opts)

Decrypt data with RSA private key.

-   **key-pem**: Private key in PEM format
-   **ciphertext**: Encrypted data
-   **opts**: Must match encryption options

**Returns**: Decrypted plaintext buffer.


<a id="org9ba6423"></a>

### (crypto/rsa-max-plaintext key-pem &opt opts)

Get maximum plaintext size for RSA encryption.

-   **key-pem**: Key in PEM format
-   **opts**: Same as rsa-encrypt

**Returns**: Maximum bytes that can be encrypted.

**Example**: See [rsa<sub>encryption.janet</sub>](../examples/rsa_encryption.janet) for RSA encryption and hybrid encryption.


<a id="org5613c79"></a>

## Key/Certificate Format Conversion


<a id="orgfb69be3"></a>

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


<a id="org6c6ca78"></a>

### (crypto/convert-cert cert-data target-format)

Convert a certificate between PEM and DER formats.

-   **cert-data**: Certificate data
-   **target-format**: `:pem` or `:der`

**Returns**: Certificate in target format.


<a id="org9be8328"></a>

### (crypto/detect-format data)

Detect if data is PEM or DER format.

**Returns**: `:pem` or `:der`


<a id="org2c1c701"></a>

### (crypto/load-key key-pem &opt password)

Load a private key, optionally decrypting it.

-   **key-pem**: Key in PEM format
-   **password**: Password if key is encrypted

**Returns**: Decrypted key in PEM format.


<a id="org35d223b"></a>

### (crypto/export-key key-pem &opt opts)

Export a private key, optionally encrypting it.

-   **key-pem**: Key in PEM format
-   **opts**: Optional table
    -   `:password` - Password for encryption
    -   `:cipher` - Encryption cipher (`:aes-256-cbc`, `:aes-128-cbc`, `:des-ede3-cbc`)

**Returns**: Key in PEM format.


<a id="org7d4bb84"></a>

### (crypto/key-info key-pem)

Get metadata about a key without needing the password.

**Returns**: Table with:

-   `:type` - `:rsa`, `:ec`, `:ed25519`, `:x25519`, etc.
-   `:bits` - Key size in bits
-   `:curve` - EC curve name (for EC keys)
-   `:encrypted` - True if password-protected

**Example**: See [format<sub>conversion.janet</sub>](../examples/format_conversion.janet) for format conversion.


<a id="org76c4fd7"></a>

## PKCS#12 Operations


<a id="orgd02c7fc"></a>

### (crypto/create-pkcs12 cert-pem key-pem opts)

Create a PKCS#12 (PFX) bundle.

-   **cert-pem**: Certificate in PEM format
-   **key-pem**: Private key in PEM format
-   **opts**: Table
    -   `:password` - Required password for bundle
    -   `:chain` - Optional array of CA certificate PEMs
    -   `:friendly-name` - Optional friendly name attribute

**Returns**: PKCS#12 bundle bytes (DER format).


<a id="org105db28"></a>

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


<a id="org71c7870"></a>

## Elliptic Curve Point Operations

Low-level EC point arithmetic for custom protocols, threshold cryptography,
zero-knowledge proofs, and Bitcoin/Ethereum cryptography.


<a id="org9c04a83"></a>

### (crypto/ec-generate-scalar curve)

Generate a random scalar in [1, order-1] for the curve.

-   **curve**: Curve identifier
    -   `:p-256` (secp256r1) - NIST 256-bit
    -   `:p-384` (secp384r1) - NIST 384-bit
    -   `:p-521` (secp521r1) - NIST 521-bit
    -   `:secp256k1` - Bitcoin/Ethereum curve

**Returns**: Big-endian byte buffer.


<a id="org8880b34"></a>

### (crypto/ec-point-mul curve scalar &opt point)

Scalar multiplication on elliptic curve.

-   **curve**: Curve identifier
-   **scalar**: Big-endian byte buffer
-   **point**: Optional `{:x <buffer> :y <buffer>}`. If nil, multiplies generator G.

**Returns**: `{:x <buffer> :y <buffer>}`


<a id="orgc75b806"></a>

### (crypto/ec-point-add curve point1 point2)

Point addition on elliptic curve.

**Returns**: `{:x <buffer> :y <buffer>}`


<a id="org4e04217"></a>

### (crypto/ec-point-to-bytes curve point &opt opts)

Serialize EC point to SEC1 format.

-   **opts**: Optional table
    -   `:compressed` - If true, use compressed format

**Returns**: Bytes buffer.


<a id="org22f9df4"></a>

### (crypto/ec-point-from-bytes curve bytes)

Deserialize EC point from SEC1 format.

**Returns**: `{:x <buffer> :y <buffer>}`

**Example**: See [ec<sub>point</sub><sub>operations.janet</sub>](../examples/ec_point_operations.janet) for EC operations.


<a id="orgbe87684"></a>

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

