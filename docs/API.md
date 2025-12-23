
# Table of Contents

1.  [Overview](#orgb3a7e90)
    1.  [Janet Stream API Compatibility](#orgb4d58e5)
2.  [Modules](#org5ae4e30)
3.  [Module: jsec/tls](#org8e34627)
    1.  [(tls/new-context opts)](#orgfdcf26c)
    2.  [(tls/connect host port &opt opts)](#orgbdda967)
    3.  [(tls/listen host port &opt opts)](#org64949ec)
    4.  [(tls/accept listener opts)](#orgd58285c)
    5.  [(tls/accept-loop listener context handler)](#org3508182)
    6.  [(tls/upgrade stream hostname &opt opts)](#orgb82f989)
    7.  [(tls/wrap stream &opt hostname-or-opts opts)](#orgae8bdad)
    8.  [Stream Methods (Janet Stream API Compatible)](#org7ef335e)
        1.  [(ev/read stream n &opt buf timeout)](#orgcef81d0)
        2.  [(ev/write stream data &opt timeout)](#orgd2fb879)
        3.  [(ev/chunk stream n &opt buf timeout)](#org30646cc)
        4.  [(ev/close stream)](#orgacbddcc)
    9.  [TLS Stream Methods (via jsec/tls-stream)](#orgf22ed01)
        1.  [Connection Information](#orgf3eae4d)
        2.  [Session Management](#org59ab4c4)
        3.  [TLS Operations](#org5372269)
        4.  [Certificate Trust](#org3231b11)
4.  [Module: jsec/dtls](#org0109664)
    1.  [Stream Method Access](#org385cf49)
    2.  [Server API (UDP-style, multiple peers)](#orgedda4c0)
        1.  [(dtls/listen host port &opt opts)](#orgbc9b0a8)
        2.  [(dtls/recv-from server nbytes buf &opt timeout-or-opts)](#orgf570b98)
        3.  [(dtls/send-to server addr data &opt timeout)](#org4517e42)
        4.  [(dtls/close-server server &opt force)](#orgb70786a)
        5.  [(dtls/localname server)](#orgc19e430)
    3.  [Client API (1:1 connection)](#org8524cc6)
        1.  [(dtls/connect host port &opt opts)](#org06eb015)
        2.  [(dtls/read client n &opt buf timeout)](#org8815e78)
        3.  [(dtls/write client data &opt timeout)](#org7bb45fc)
        4.  [(dtls/close client &opt force)](#org9d5a0c7)
    4.  [Address Utilities](#orgb4cf7f9)
    5.  [DTLS Stream Methods (via jsec/dtls-stream)](#org8524bd8)
        1.  [Connection Information (Client)](#org4c9a643)
        2.  [Session Management (Client)](#org1251f4f)
        3.  [DTLS Operations](#org3425790)
        4.  [Certificate Trust](#org9e23e47)
        5.  [Upgrade (STARTTLS equivalent)](#orgb093b51)
5.  [Module: jsec/cert](#orgbccad9f)
    1.  [(cert/generate-self-signed-cert opts)](#org54142ee)
    2.  [(cert/generate-self-signed-from-key key-pem opts)](#org8291772)
6.  [Module: jsec/bio](#org3fca20d)
    1.  [(bio/new-mem)](#org20dd13b)
    2.  [(bio/read bio nbytes)](#org9d9204a)
    3.  [(bio/write bio data)](#org31b5d97)
    4.  [(bio/to-string bio)](#orgd99efee)
    5.  [(bio/close bio)](#orgf79cf64)
7.  [Module: jsec/crypto](#org6493545)
    1.  [Hashing and Message Authentication](#org2335245)
        1.  [(crypto/digest algorithm data)](#org622ed0f)
        2.  [(crypto/hmac algorithm key data)](#orgbc9f89c)
    2.  [Key Generation and Management](#org472a2a7)
        1.  [(crypto/generate-key alg &opt bits)](#org0afc9de)
        2.  [(crypto/export-public-key private-key-pem)](#org65bd58f)
    3.  [Signing and Verification](#org55b8e20)
        1.  [(crypto/sign key-pem data)](#orgb7b322f)
        2.  [(crypto/verify key-pem data signature)](#orga3e93c2)
    4.  [Key Derivation](#org674e9a9)
        1.  [(crypto/hkdf algorithm key salt info length)](#org70bc79e)
        2.  [(crypto/pbkdf2 algorithm password salt iterations length)](#org4069766)
    5.  [Random Data](#org2026a82)
        1.  [(crypto/random-bytes n)](#org05a7dd8)
    6.  [Certificate Signing Requests](#orga763c54)
        1.  [(crypto/generate-csr private-key-pem options)](#org9882d6c)
        2.  [(crypto/parse-csr csr-pem)](#orge1df151)
    7.  [Challenge-Response](#orgd6eb42e)
        1.  [(crypto/generate-challenge &opt length)](#orge89fb53)
    8.  [CMS/PKCS#7 Operations](#org85c4e99)
        1.  [(crypto/cms-sign data cert key &opt opts)](#orgd469f87)
        2.  [(crypto/cms-verify cms-data &opt opts)](#org57953bc)
        3.  [(crypto/cms-encrypt data certs &opt opts)](#org8aaed13)
        4.  [(crypto/cms-decrypt cms-data cert key)](#org0e72db5)
        5.  [(crypto/cms-certs-only certs)](#org1a659df)
        6.  [(crypto/cms-get-certs cms-data)](#org4c58c0c)
    9.  [Base64 Encoding](#orge858ce8)
        1.  [(crypto/base64-encode data)](#org3619714)
        2.  [(crypto/base64-decode data)](#org3e3f93a)
        3.  [(crypto/base64url-encode data)](#org1154b5d)
        4.  [(crypto/base64url-decode data)](#org90c0281)
    10. [Symmetric Encryption (AEAD)](#org32dcfb9)
        1.  [(crypto/encrypt algo key nonce plaintext &opt aad)](#org82dfaa5)
        2.  [(crypto/decrypt algo key nonce ciphertext tag &opt aad)](#orgec098ee)
        3.  [(crypto/generate-nonce algo)](#org19d1b54)
        4.  [(crypto/cipher-info algo)](#org3bd9c7f)
    11. [RSA Encryption](#orgff3f424)
        1.  [(crypto/rsa-encrypt key-pem plaintext &opt opts)](#orga378163)
        2.  [(crypto/rsa-decrypt key-pem ciphertext &opt opts)](#org2bcc7d1)
        3.  [(crypto/rsa-max-plaintext key-pem &opt opts)](#org85c94da)
    12. [Key/Certificate Format Conversion](#org98a3cb6)
        1.  [(crypto/convert-key key-data target-format &opt opts)](#orgd9bb3cc)
        2.  [(crypto/convert-cert cert-data target-format)](#orgd4d1975)
        3.  [(crypto/detect-format data)](#org335a897)
        4.  [(crypto/load-key key-pem &opt password)](#orgd856fa3)
        5.  [(crypto/export-key key-pem &opt opts)](#orgd064128)
        6.  [(crypto/key-info key-pem)](#org8ad089c)
    13. [PKCS#12 Operations](#org9d1da5a)
        1.  [(crypto/create-pkcs12 cert-pem key-pem opts)](#orge31679b)
        2.  [(crypto/parse-pkcs12 pfx-data password)](#org51cc404)
    14. [Elliptic Curve Point Operations](#org4548905)
        1.  [(crypto/ec-generate-scalar curve)](#org05b6c82)
        2.  [(crypto/ec-point-mul curve scalar &opt point)](#org71b8125)
        3.  [(crypto/ec-point-add curve point1 point2)](#org175048f)
        4.  [(crypto/ec-point-to-bytes curve point &opt opts)](#org4131094)
        5.  [(crypto/ec-point-from-bytes curve bytes)](#org7ffc3b6)
8.  [Security Options](#orgdc0c750)



<a id="orgb3a7e90"></a>

# Overview

Jsec provides production-quality TLS/DTLS integration for Janet. The APIs are
designed to closely follow Janet's standard conventions:

-   **TLS streams** implement Janet's full stream interface (`ev/read`, `ev/write`,
    `ev/chunk`, `ev/close`) with identical signatures. TLS streams can be used
    anywhere Janet streams are expected - no special-casing required.

-   **DTLS** follows Janet's UDP conventions (`net/recv-from`, `net/send-to`) for
    the server-side API, and stream conventions for 1:1 client connections.

This design allows TLS/DTLS to be a drop-in replacement in existing code.


<a id="orgb4d58e5"></a>

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


<a id="org5ae4e30"></a>

# Modules

-   `jsec/tls`: TCP/TLS operations (Client & Server). Implements full Janet stream interface.
-   `jsec/dtls`: UDP/DTLS operations (Client & Server). Follows Janet UDP conventions.
-   `jsec/cert`: Certificate generation utilities.
-   `jsec/bio`: Basic I/O abstraction (memory BIOs).
-   `jsec/crypto`: Cryptographic primitives (hashing, signing).

For working examples of all functionality, see the [examples directory](../examples/).


<a id="org8e34627"></a>

# Module: jsec/tls


<a id="orgfdcf26c"></a>

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


<a id="orgbdda967"></a>

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
        -   `:security`: Table. Security options (see [Security Options](#orgdc0c750)).
        -   `:alpn`: List of ALPN protocols.
        -   `:ca-file`: Path to CA certificate file or PEM content (string/buffer).
        -   `:ca-path`: Path to CA certificate directory.

**Returns**: A TLS stream object.

**Examples**:

-   [simple<sub>https</sub><sub>client.janet</sub>](../examples/simple_https_client.janet) - Basic HTTPS GET request
-   [session<sub>resumption.janet</sub>](../examples/session_resumption.janet) - Using session resumption
-   [mtls<sub>client</sub><sub>server.janet</sub>](../examples/mtls_client_server.janet) - Mutual TLS authentication


<a id="org64949ec"></a>

## (tls/listen host port &opt opts)

Create a TCP listener. This is a wrapper around `net/listen`.

-   **host**: Bind address.
-   **port**: Bind port.
-   **opts**: Optional table.
    -   `:backlog`: Integer. Listen backlog (default 1024).

**Returns**: A listener object.


<a id="orgd58285c"></a>

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


<a id="org3508182"></a>

## (tls/accept-loop listener context handler)

Continuously accept TLS connections on a listener.

-   **listener**: Listener object from `tls/listen`.
-   **context**: TLS context object OR options table (same as `tls/accept`).
    -   Can include `:buffer-size`, `:tcp-nodelay`, `:handshake-timing`.
-   **handler**: Function taking a TLS stream.

**Returns**: The listener stream (when closed).


<a id="orgb82f989"></a>

## (tls/upgrade stream hostname &opt opts)

Upgrade an existing plaintext stream to TLS (STARTTLS).

-   **stream**: Existing connected `JanetStream`.
-   **hostname**: String. SNI hostname.
-   **opts**: Optional table (same as `connect`).

**Returns**: A TLS stream object. **Note**: The original stream is consumed.

**Example**: See [starttls<sub>smtp.janet</sub>](../examples/starttls_smtp.janet) for SMTP STARTTLS upgrade.


<a id="orgae8bdad"></a>

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


<a id="org7ef335e"></a>

## Stream Methods (Janet Stream API Compatible)

TLS streams implement Janet's standard stream interface. They work with:

-   `ev/read` / `:read` - Read data from the stream
-   `ev/write` / `:write` - Write data to the stream
-   `ev/chunk` / `:chunk` - Read exactly n bytes or until EOF
-   `ev/close` / `:close` - Close with proper TLS shutdown


<a id="orgcef81d0"></a>

### (ev/read stream n &opt buf timeout)

Read up to `n` bytes from the TLS stream.

-   **stream**: TLS stream object
-   **n**: Maximum bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data, or `nil` on EOF.


<a id="orgd2fb879"></a>

### (ev/write stream data &opt timeout)

Write data to the TLS stream.

-   **stream**: TLS stream object
-   **data**: String or buffer to write
-   **timeout**: Optional timeout in seconds

**Returns**: `nil`


<a id="org30646cc"></a>

### (ev/chunk stream n &opt buf timeout)

Read exactly `n` bytes, or until EOF.

-   **stream**: TLS stream object
-   **n**: Exact number of bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data.


<a id="orgacbddcc"></a>

### (ev/close stream)

Close the TLS stream with proper RFC-compliant shutdown.

Performs async bidirectional close<sub>notify</sub> exchange before closing the
underlying transport. Safe to use with Janet's `with` macro.

-   **stream**: TLS stream object

**Note**: For unresponsive peers, use `(:close stream true)` to force immediate
close without TLS shutdown.


<a id="orgf22ed01"></a>

## TLS Stream Methods (via jsec/tls-stream)

These methods are available on TLS stream objects. Access via method syntax
`(:method stream args...)` or import `jsec/tls-stream` for function versions.


<a id="orgf3eae4d"></a>

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


<a id="org59ab4c4"></a>

### Session Management

-   `(:session-reused? stream)` or `(tls-stream/session-reused? stream)`
    Returns `true` if session was resumed

-   `(:get-session stream)` or `(tls-stream/get-session stream)`
    Returns session data (byte string) for resumption

-   `(:set-session stream data)` or `(tls-stream/set-session stream data)`
    Sets session data (usually passed in `connect` options instead)


<a id="org5372269"></a>

### TLS Operations

-   `(:key-update stream)` or `(tls-stream/key-update stream)`
    Request TLS 1.3 key update (post-handshake key rotation)

-   `(:renegotiate stream)` or `(tls-stream/renegotiate stream)`
    Request TLS 1.2 renegotiation (disabled by default for security)

-   `(:set-ocsp-response stream data)` or `(tls-stream/set-ocsp-response stream data)`
    Set OCSP stapling response

-   `(:shutdown stream &opt force)` or `(tls-stream/shutdown stream &opt force)`
    Perform TLS shutdown. If `force` is true, skip close<sub>notify</sub>.


<a id="org3231b11"></a>

### Certificate Trust

-   `(tls-stream/trust-cert ctx cert-pem)`
    Add a trusted certificate to a context. Used for trusting self-signed certs.

**Example**: See [session<sub>resumption.janet</sub>](../examples/session_resumption.janet) for session management.
**Example**: See [tls<sub>key</sub><sub>update.janet</sub>](../examples/tls_key_update.janet) for key update usage.
**Example**: See [connection<sub>info.janet</sub>](../examples/connection_info.janet) for connection info retrieval.


<a id="org0109664"></a>

# Module: jsec/dtls

DTLS provides TLS security for UDP datagrams. The API design:

-   **Server-side**: Follows Janet's UDP conventions (`net/recv-from`, `net/send-to`)
    for multiplexed peer handling on a single socket.
-   **Client-side**: 1:1 connections with stream-like `read~/~write` for simplicity.

Both DTLSServer and DTLSClient embed JanetStream and expose methods via the
standard `(:method obj args...)` syntax, matching Janet's stream patterns.


<a id="org385cf49"></a>

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


<a id="orgedda4c0"></a>

## Server API (UDP-style, multiple peers)


<a id="orgbc9b0a8"></a>

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


<a id="orgf570b98"></a>

### (dtls/recv-from server nbytes buf &opt timeout-or-opts)

Receive a datagram from any peer. Handles DTLS handshakes transparently.

-   **server**: DTLS server object
-   **nbytes**: Maximum bytes to receive
-   **buf**: Buffer to receive data into
-   **timeout-or-opts**: Number (timeout in seconds) or table `{:timeout n}`

**Returns**: Peer address object, or `nil` on timeout.

Matches Janet's `net/recv-from` convention.


<a id="org4517e42"></a>

### (dtls/send-to server addr data &opt timeout)

Send a datagram to a specific peer.

-   **server**: DTLS server object
-   **addr**: Peer address (from `recv-from`)
-   **data**: Data to send (string or buffer)
-   **timeout**: Optional timeout in seconds

**Returns**: Number of bytes sent.


<a id="orgb70786a"></a>

### (dtls/close-server server &opt force)

Close the server and all sessions.

-   **server**: DTLS server object
-   **force**: If true, skip close<sub>notify</sub> alerts (default false)


<a id="orgc19e430"></a>

### (dtls/localname server)

Get the local address the server is bound to.

**Returns**: `[host port]` tuple.


<a id="org8524cc6"></a>

## Client API (1:1 connection)


<a id="org06eb015"></a>

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


<a id="org8815e78"></a>

### (dtls/read client n &opt buf timeout)

Read a datagram from the connection.

-   **client**: DTLS client object
-   **n**: Maximum bytes to read
-   **buf**: Optional buffer to read into
-   **timeout**: Optional timeout in seconds

**Returns**: Buffer with data, or `nil` on EOF.


<a id="org7bb45fc"></a>

### (dtls/write client data &opt timeout)

Write a datagram to the connection.

-   **client**: DTLS client object
-   **data**: Data to send (string or buffer)
-   **timeout**: Optional timeout in seconds

**Returns**: Number of bytes written.


<a id="org9d5a0c7"></a>

### (dtls/close client &opt force)

Close the client connection.

-   **client**: DTLS client object
-   **force**: If true, skip close<sub>notify</sub> (default false)


<a id="orgb4cf7f9"></a>

## Address Utilities

-   `(dtls-stream/address host port)`: Create an address object.
-   `(dtls-stream/address-host addr)`: Get host string from address.
-   `(dtls-stream/address-port addr)`: Get port number from address.
-   `(dtls-stream/address? x)`: Check if x is a DTLS address object.


<a id="org8524bd8"></a>

## DTLS Stream Methods (via jsec/dtls-stream)

These methods are available on DTLS server and client objects. Access via method
syntax `(:method obj args...)` or import `jsec/dtls-stream` for function versions.


<a id="org4c9a643"></a>

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


<a id="org1251f4f"></a>

### Session Management (Client)

-   `(:session-reused? client)` or `(dtls-stream/session-reused? client)`
    Returns `true` if session was resumed

-   `(:get-session client)` or `(dtls-stream/get-session client)`
    Returns session data for resumption

-   `(:set-session client data)` or `(dtls-stream/set-session client data)`
    Sets session data


<a id="org3425790"></a>

### DTLS Operations

-   `(:shutdown client &opt force)` or `(dtls-stream/shutdown client &opt force)`
    Perform DTLS shutdown. If `force` is true, skip close<sub>notify</sub>.

-   `(:chunk client n &opt buf timeout)` or `(dtls-stream/chunk client ...)`
    Read exactly n bytes (for client connections)


<a id="org9e23e47"></a>

### Certificate Trust

-   `(dtls-stream/trust-cert ctx cert-pem)`
    Add a trusted certificate to a context.


<a id="orgb093b51"></a>

### Upgrade (STARTTLS equivalent)

-   `(dtls-stream/upgrade stream &opt opts)`
    Upgrade an existing UDP socket to DTLS.

**Example**: See [dtls<sub>echo.janet</sub>](../examples/dtls_echo.janet) for complete DTLS usage.
**Example**: See [dtls<sub>session</sub><sub>resumption.janet</sub>](../examples/dtls_session_resumption.janet) for session resumption.
**Example**: See [dtls<sub>connection</sub><sub>info.janet</sub>](../examples/dtls_connection_info.janet) for connection info.


<a id="orgbccad9f"></a>

# Module: jsec/cert


<a id="org54142ee"></a>

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


<a id="org8291772"></a>

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


<a id="org3fca20d"></a>

# Module: jsec/bio

BIO (Basic I/O) provides OpenSSL's I/O abstraction layer for in-memory operations.


<a id="org20dd13b"></a>

## (bio/new-mem)

Create a memory BIO for in-memory I/O operations.

**Returns**: A BIO object.


<a id="org9d9204a"></a>

## (bio/read bio nbytes)

Read from a BIO.

-   **bio**: BIO object
-   **nbytes**: Maximum bytes to read

**Returns**: Buffer with data, or nil if no data available.


<a id="org31b5d97"></a>

## (bio/write bio data)

Write to a BIO.

-   **bio**: BIO object
-   **data**: Data to write (string or buffer)

**Returns**: Number of bytes written.


<a id="orgd99efee"></a>

## (bio/to-string bio)

Read all pending data from a BIO as a string.

-   **bio**: BIO object

**Returns**: String with all pending data.


<a id="orgf79cf64"></a>

## (bio/close bio)

Free a BIO object and release its resources.

-   **bio**: BIO object

**Example**: See [bio<sub>memory.janet</sub>](../examples/bio_memory.janet) and [custom<sub>bio</sub><sub>transport.janet</sub>](../examples/custom_bio_transport.janet).


<a id="org6493545"></a>

# Module: jsec/crypto


<a id="org2335245"></a>

## Hashing and Message Authentication


<a id="org622ed0f"></a>

### (crypto/digest algorithm data)

Compute a cryptographic hash.

-   **algorithm**: String ("sha256", "sha384", "sha512", "sha1", "md5", etc.)
-   **data**: Data to hash (string or buffer)

**Returns**: Buffer with hash bytes.


<a id="orgbc9f89c"></a>

### (crypto/hmac algorithm key data)

Compute HMAC (Hash-based Message Authentication Code).

-   **algorithm**: Hash algorithm ("sha256", etc.)
-   **key**: Secret key (string or buffer)
-   **data**: Data to authenticate (string or buffer)

**Returns**: Buffer with HMAC bytes.


<a id="org472a2a7"></a>

## Key Generation and Management


<a id="org0afc9de"></a>

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


<a id="org65bd58f"></a>

### (crypto/export-public-key private-key-pem)

Extract public key from a private key.

-   **private-key-pem**: PEM-encoded private key string

**Returns**: PEM-encoded public key string.


<a id="org55b8e20"></a>

## Signing and Verification


<a id="orgb7b322f"></a>

### (crypto/sign key-pem data)

Sign data with a private key.

-   **key-pem**: Private key in PEM format
-   **data**: Data to sign (string or buffer)

**Returns**: Signature buffer.


<a id="orga3e93c2"></a>

### (crypto/verify key-pem data signature)

Verify a signature.

-   **key-pem**: Key in PEM format (public or private)
-   **data**: Original data
-   **signature**: Signature to verify

**Returns**: Boolean (`true` if valid).


<a id="org674e9a9"></a>

## Key Derivation


<a id="org70bc79e"></a>

### (crypto/hkdf algorithm key salt info length)

HKDF (HMAC-based Key Derivation Function).

-   **algorithm**: Hash algorithm ("sha256", etc.)
-   **key**: Input key material
-   **salt**: Salt value (can be empty string)
-   **info**: Context/application info
-   **length**: Desired output length in bytes

**Returns**: Derived key buffer.


<a id="org4069766"></a>

### (crypto/pbkdf2 algorithm password salt iterations length)

PBKDF2 (Password-Based Key Derivation Function 2).

-   **algorithm**: Hash algorithm
-   **password**: Password string
-   **salt**: Salt value
-   **iterations**: Number of iterations (minimum 10000 recommended)
-   **length**: Desired output length in bytes

**Returns**: Derived key buffer.


<a id="org2026a82"></a>

## Random Data


<a id="org05a7dd8"></a>

### (crypto/random-bytes n)

Generate cryptographically secure random bytes.

-   **n**: Number of bytes

**Returns**: Buffer with random bytes.


<a id="orga763c54"></a>

## Certificate Signing Requests


<a id="org9882d6c"></a>

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


<a id="orge1df151"></a>

### (crypto/parse-csr csr-pem)

Parse a PEM-encoded CSR.

-   **csr-pem**: CSR in PEM format

**Returns**: Table with CSR information.


<a id="orgd6eb42e"></a>

## Challenge-Response


<a id="orge89fb53"></a>

### (crypto/generate-challenge &opt length)

Generate a random challenge for authentication protocols.

-   **length**: Challenge length in bytes (default 32)

**Returns**: Buffer with random challenge.


<a id="org85c4e99"></a>

## CMS/PKCS#7 Operations

For SCEP/ACME foundations and secure message exchange.


<a id="orgd469f87"></a>

### (crypto/cms-sign data cert key &opt opts)

Sign data using CMS (Cryptographic Message Syntax).

-   **data**: Data to sign
-   **cert**: Signer certificate (PEM)
-   **key**: Signer private key (PEM)
-   **opts**: Optional table
    -   `:detached`: Boolean. If true, create detached signature.

**Returns**: CMS signed data (DER or PEM based on input).


<a id="org57953bc"></a>

### (crypto/cms-verify cms-data &opt opts)

Verify a CMS signature.

-   **cms-data**: CMS signed data
-   **opts**: Optional table
    -   `:ca`: CA certificate for verification
    -   `:detached`: Original data if signature is detached

**Returns**: Table `{:valid true/false :content data :certs [...]}`


<a id="org8aaed13"></a>

### (crypto/cms-encrypt data certs &opt opts)

Encrypt data for recipients using CMS.

-   **data**: Data to encrypt
-   **certs**: Array of recipient certificates (PEM)
-   **opts**: Optional table
    -   `:cipher`: Cipher to use (default "aes-256-cbc")

**Returns**: CMS encrypted data.


<a id="org0e72db5"></a>

### (crypto/cms-decrypt cms-data cert key)

Decrypt CMS encrypted data.

-   **cms-data**: Encrypted CMS data
-   **cert**: Recipient certificate (PEM)
-   **key**: Recipient private key (PEM)

**Returns**: Decrypted data buffer.


<a id="org1a659df"></a>

### (crypto/cms-certs-only certs)

Create a CMS certs-only message (certificate chain).

-   **certs**: Array of certificates (PEM)

**Returns**: CMS data containing certificates.


<a id="org4c58c0c"></a>

### (crypto/cms-get-certs cms-data)

Extract certificates from CMS data.

-   **cms-data**: CMS signed or certs-only data

**Returns**: Array of PEM-encoded certificates.


<a id="orge858ce8"></a>

## Base64 Encoding


<a id="org3619714"></a>

### (crypto/base64-encode data)

Base64 encode data.

**Returns**: Base64 string.


<a id="org3e3f93a"></a>

### (crypto/base64-decode data)

Base64 decode data.

**Returns**: Decoded buffer.


<a id="org1154b5d"></a>

### (crypto/base64url-encode data)

URL-safe Base64 encode (for JWT, etc.).

**Returns**: Base64url string.


<a id="org90c0281"></a>

### (crypto/base64url-decode data)

URL-safe Base64 decode.

**Returns**: Decoded buffer.

**Example**: See [crypto<sub>signing.janet</sub>](../examples/crypto_signing.janet) for signing operations.
**Example**: See [crypto<sub>operations.janet</sub>](../examples/crypto_operations.janet) for comprehensive crypto usage.


<a id="org32dcfb9"></a>

## Symmetric Encryption (AEAD)


<a id="org82dfaa5"></a>

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


<a id="orgec098ee"></a>

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


<a id="org19d1b54"></a>

### (crypto/generate-nonce algo)

Generate a random nonce suitable for the specified cipher.

-   **algo**: Cipher algorithm keyword

**Returns**: Buffer of appropriate length.


<a id="org3bd9c7f"></a>

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


<a id="orgff3f424"></a>

## RSA Encryption


<a id="orga378163"></a>

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


<a id="org2bcc7d1"></a>

### (crypto/rsa-decrypt key-pem ciphertext &opt opts)

Decrypt data with RSA private key.

-   **key-pem**: Private key in PEM format
-   **ciphertext**: Encrypted data
-   **opts**: Must match encryption options

**Returns**: Decrypted plaintext buffer.


<a id="org85c94da"></a>

### (crypto/rsa-max-plaintext key-pem &opt opts)

Get maximum plaintext size for RSA encryption.

-   **key-pem**: Key in PEM format
-   **opts**: Same as rsa-encrypt

**Returns**: Maximum bytes that can be encrypted.

**Example**: See [rsa<sub>encryption.janet</sub>](../examples/rsa_encryption.janet) for RSA encryption and hybrid encryption.


<a id="org98a3cb6"></a>

## Key/Certificate Format Conversion


<a id="orgd9bb3cc"></a>

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


<a id="orgd4d1975"></a>

### (crypto/convert-cert cert-data target-format)

Convert a certificate between PEM and DER formats.

-   **cert-data**: Certificate data
-   **target-format**: `:pem` or `:der`

**Returns**: Certificate in target format.


<a id="org335a897"></a>

### (crypto/detect-format data)

Detect if data is PEM or DER format.

**Returns**: `:pem` or `:der`


<a id="orgd856fa3"></a>

### (crypto/load-key key-pem &opt password)

Load a private key, optionally decrypting it.

-   **key-pem**: Key in PEM format
-   **password**: Password if key is encrypted

**Returns**: Decrypted key in PEM format.


<a id="orgd064128"></a>

### (crypto/export-key key-pem &opt opts)

Export a private key, optionally encrypting it.

-   **key-pem**: Key in PEM format
-   **opts**: Optional table
    -   `:password` - Password for encryption
    -   `:cipher` - Encryption cipher (`:aes-256-cbc`, `:aes-128-cbc`, `:des-ede3-cbc`)

**Returns**: Key in PEM format.


<a id="org8ad089c"></a>

### (crypto/key-info key-pem)

Get metadata about a key without needing the password.

**Returns**: Table with:

-   `:type` - `:rsa`, `:ec`, `:ed25519`, `:x25519`, etc.
-   `:bits` - Key size in bits
-   `:curve` - EC curve name (for EC keys)
-   `:encrypted` - True if password-protected

**Example**: See [format<sub>conversion.janet</sub>](../examples/format_conversion.janet) for format conversion.


<a id="org9d1da5a"></a>

## PKCS#12 Operations


<a id="orge31679b"></a>

### (crypto/create-pkcs12 cert-pem key-pem opts)

Create a PKCS#12 (PFX) bundle.

-   **cert-pem**: Certificate in PEM format
-   **key-pem**: Private key in PEM format
-   **opts**: Table
    -   `:password` - Required password for bundle
    -   `:chain` - Optional array of CA certificate PEMs
    -   `:friendly-name` - Optional friendly name attribute

**Returns**: PKCS#12 bundle bytes (DER format).


<a id="org51cc404"></a>

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


<a id="org4548905"></a>

## Elliptic Curve Point Operations

Low-level EC point arithmetic for custom protocols, threshold cryptography,
zero-knowledge proofs, and Bitcoin/Ethereum cryptography.


<a id="org05b6c82"></a>

### (crypto/ec-generate-scalar curve)

Generate a random scalar in [1, order-1] for the curve.

-   **curve**: Curve identifier
    -   `:p-256` (secp256r1) - NIST 256-bit
    -   `:p-384` (secp384r1) - NIST 384-bit
    -   `:p-521` (secp521r1) - NIST 521-bit
    -   `:secp256k1` - Bitcoin/Ethereum curve

**Returns**: Big-endian byte buffer.


<a id="org71b8125"></a>

### (crypto/ec-point-mul curve scalar &opt point)

Scalar multiplication on elliptic curve.

-   **curve**: Curve identifier
-   **scalar**: Big-endian byte buffer
-   **point**: Optional `{:x <buffer> :y <buffer>}`. If nil, multiplies generator G.

**Returns**: `{:x <buffer> :y <buffer>}`


<a id="org175048f"></a>

### (crypto/ec-point-add curve point1 point2)

Point addition on elliptic curve.

**Returns**: `{:x <buffer> :y <buffer>}`


<a id="org4131094"></a>

### (crypto/ec-point-to-bytes curve point &opt opts)

Serialize EC point to SEC1 format.

-   **opts**: Optional table
    -   `:compressed` - If true, use compressed format

**Returns**: Bytes buffer.


<a id="org7ffc3b6"></a>

### (crypto/ec-point-from-bytes curve bytes)

Deserialize EC point from SEC1 format.

**Returns**: `{:x <buffer> :y <buffer>}`

**Example**: See [ec<sub>point</sub><sub>operations.janet</sub>](../examples/ec_point_operations.janet) for EC operations.


<a id="orgdc0c750"></a>

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

