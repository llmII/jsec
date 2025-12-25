
# Table of Contents

1.  [Overview](#org75153d2)
    1.  [Error Format](#orgbe1e086)
    2.  [Example Errors](#org975f500)
2.  [TLS Module Errors](#org1e71be0)
    1.  [CONFIG - Configuration Errors](#org8af7316)
        1.  [`[TLS:CONFIG] buffer-size must be a number`](#org71ca1af)
        2.  [`[TLS:CONFIG] invalid cipher suite: <suite>`](#orgf22e2d7)
        3.  [`[TLS:CONFIG] sni option must be a table or struct`](#orgb730755)
        4.  [`[TLS:CONFIG] Invalid ALPN protocols`](#org3ca15f0)
        5.  [`[TLS:CONFIG] handler function must take at least 1 argument`](#orgcea4f38)
    2.  [PARAM - Parameter Errors](#orgbfa6b9e)
        1.  [`[TLS:PARAM] timeout must be non-negative, got <value>`](#org423edb9)
        2.  [`[TLS:PARAM] expected keyword or nil, got <value>`](#org6ff3dec)
        3.  [`[TLS:PARAM] length must be non-negative`](#orgfe5774c)
    3.  [IO - I/O Errors](#org8752aac)
        1.  [`[TLS:IO] stream is closed`](#orga0ff36e)
        2.  [`[TLS:IO] connection is shutting down`](#org9ba969e)
    4.  [SSL - OpenSSL Errors](#orgb1ea613)
        1.  [`[TLS:SSL] failed to create SSL context: <ssl-error>`](#orgf7232db)
        2.  [`[TLS:SSL] failed to create SSL object: <ssl-error>`](#org7ff16ff)
        3.  [`[TLS:SSL] handshake failed: <ssl-error>`](#org59db37a)
        4.  [`[TLS:SSL] certificate verification failed: <ssl-error>`](#org0864140)
        5.  [`[TLS:SSL] failed to load private key: <ssl-error>`](#org9696e45)
        6.  [`[TLS:SSL] failed to load certificate: <ssl-error>`](#orgac84357)
        7.  [`[TLS:SSL] private key does not match certificate: <ssl-error>`](#orga32c268)
    5.  [SOCKET - Socket Errors](#orgd7b0c83)
        1.  [`[TLS:SOCKET] could not connect to <host>:<port>: <errno>`](#org0b85d6d)
        2.  [`[TLS:SOCKET] bind failed: <errno>`](#orgcbedbb8)
        3.  [`[TLS:SOCKET] listen failed: <errno>`](#org4ee9b5c)
        4.  [`[TLS:SOCKET] getaddrinfo failed: <errno>`](#org8defa2e)
    6.  [VERIFY - Verification Errors](#orge91f224)
        1.  [`[TLS:VERIFY] hostname verification failed for <hostname>`](#org81d2010)
3.  [DTLS Module Errors](#orgae0e6a6)
    1.  [CONFIG - Configuration Errors](#org64b4fb1)
        1.  [`[DTLS:CONFIG] dtls/listen requires :cert and :key options`](#org30e41c8)
        2.  [`[DTLS:CONFIG] cannot use TLS context for DTLS connection`](#org4e4802d)
    2.  [PARAM - Parameter Errors](#orgad50cf8)
        1.  [`[DTLS:PARAM] invalid address: <address>`](#org8cf83c0)
    3.  [IO - I/O Errors](#org23b8d03)
        1.  [`[DTLS:IO] client not connected`](#orgf71bab8)
        2.  [`[DTLS:IO] client is closed`](#org01fcddf)
        3.  [`[DTLS:IO] server is closed`](#orgec05284)
        4.  [`[DTLS:IO] no session for peer address`](#org89f1e33)
        5.  [`[DTLS:IO] session not established`](#org54ef70a)
    4.  [SSL - OpenSSL Errors](#org3843795)
        1.  [`[DTLS:SSL] handshake failed: <ssl-error>`](#orgab84c0d)
        2.  [`[DTLS:SSL] write failed: <ssl-error>`](#org6d8f6f0)
    5.  [SOCKET - Socket Errors](#orgd805df9)
        1.  [`[DTLS:SOCKET] bind failed: <errno>`](#org7f1e670)
        2.  [`[DTLS:SOCKET] connect failed: <errno>`](#orgc5d0d62)
        3.  [`[DTLS:SOCKET] sendto failed: <errno>`](#orgfb5174d)
        4.  [`[DTLS:SOCKET] failed to get peer address: <errno>`](#org108296f)
4.  [CRYPTO Module Errors](#orgac4678b)
    1.  [CONFIG - Configuration Errors](#org2b5e73e)
        1.  [`[CRYPTO:CONFIG] unknown digest algorithm: <alg>`](#orgddeda3f)
        2.  [`[CRYPTO:CONFIG] unsupported key algorithm: <alg>`](#org578817e)
    2.  [PARAM - Parameter Errors](#org7a798a0)
        1.  [`[CRYPTO:PARAM] byte count must be 1-65536, got <n>`](#orgd112aeb)
        2.  [`[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`](#org7b7a736)
        3.  [`[CRYPTO:PARAM] output length must be 1-<max>`](#orgf73e84d)
        4.  [`[CRYPTO:PARAM] output length must be 1-1024`](#org463de2f)
        5.  [`[CRYPTO:PARAM] iterations must be positive`](#org5bbb391)
        6.  [`[CRYPTO:PARAM] options must be a table or struct`](#orgc9a20f7)
    3.  [SSL - OpenSSL Errors](#orgb9da854)
        1.  [`[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`](#orge94c85a)
        2.  [`[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`](#org8da2c38)
        3.  [`[CRYPTO:SSL] HMAC computation failed: <ssl-error>`](#orgbf812b2)
        4.  [`[CRYPTO:SSL] signing failed: <ssl-error>`](#org0b7168d)
        5.  [`[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`](#orgfb0fcca)
    4.  [RESOURCE - Resource Errors](#orgf6fa6cd)
        1.  [`[CRYPTO:RESOURCE] out of memory`](#orga5c56a3)
        2.  [`[CRYPTO:RESOURCE] failed to create context`](#orgba83dcc)
    5.  [PARSE - Parse Errors](#orgea464ea)
        1.  [`[CRYPTO:PARSE] base64 decode failed`](#orge8e06ea)
        2.  [`[CRYPTO:PARSE] failed to parse CSR`](#org381f2a3)
5.  [CA Module Errors](#org6d3421e)
    1.  [CONFIG - Configuration Errors](#org49c2ef7)
        1.  [`[CA:CONFIG] common-name is required`](#org98c3809)
        2.  [`[CA:CONFIG] ca-cert is required`](#org052f89c)
        3.  [`[CA:CONFIG] ca-key is required`](#org2e7079c)
    2.  [PARAM - Parameter Errors](#org4ac0642)
        1.  [`[CA:PARAM] validity-days must be positive`](#org1da7ed4)
        2.  [`[CA:PARAM] serial must be positive`](#org5df3cab)
    3.  [SSL - OpenSSL Errors](#orgdc17bbc)
        1.  [`[CA:SSL] failed to sign certificate: <ssl-error>`](#orgd746211)
        2.  [`[CA:SSL] failed to create certificate: <ssl-error>`](#orga1c80fd)
    4.  [VERIFY - Verification Errors](#org73d7d1b)
        1.  [`[CA:VERIFY] certificate has expired`](#org389f293)
        2.  [`[CA:VERIFY] certificate not yet valid`](#orga5dd18f)
6.  [CERT Module Errors](#orgd21307e)
    1.  [PARAM - Parameter Errors](#orgacf807d)
        1.  [`[CERT:PARAM] certificates must be string or array of strings`](#org6a9cc24)
    2.  [PARSE - Parse Errors](#orgb5c6923)
        1.  [`[CERT:PARSE] failed to parse certificate: <ssl-error>`](#org1cd6d7f)
        2.  [`[CERT:PARSE] failed to parse private key: <ssl-error>`](#orga00a46e)
7.  [Error Handling Best Practices](#orga957c9a)
    1.  [Using protect/try](#org853bbdf)
    2.  [Checking Return Values](#orgac4fb44)
    3.  [Timeouts](#org657b35a)
8.  [Testing Error Conditions](#orga581082)
9.  [See Also](#orgcbea718)



<a id="org75153d2"></a>

# Overview

This document catalogs all errors that JSEC can produce, organized by module and category.


<a id="orgbe1e086"></a>

## Error Format

All errors follow a standardized format:

    [MODULE:CATEGORY] message: detail

Where:

-   **MODULE**: TLS, DTLS, CRYPTO, CA, CERT, UTILS
-   **CATEGORY**: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY, PARSE


<a id="org975f500"></a>

## Example Errors

    [TLS:CONFIG] invalid cipher suite: RC4-MD5
    [DTLS:SOCKET] bind failed: address already in use
    [CRYPTO:PARAM] output length must be 1-1024, got 2000
    [CA:SSL] failed to sign certificate: key mismatch


<a id="org1e71be0"></a>

# TLS Module Errors


<a id="org8af7316"></a>

## CONFIG - Configuration Errors


<a id="org71ca1af"></a>

### `[TLS:CONFIG] buffer-size must be a number`

**When**: Non-numeric `:buffer-size` option
**Fix**: Pass a positive integer

    # Wrong
    (tls/connect "host" "443" {:buffer-size "big"})
    
    # Correct
    (tls/connect "host" "443" {:buffer-size 16384})


<a id="orgf22e2d7"></a>

### `[TLS:CONFIG] invalid cipher suite: <suite>`

**When**: Unrecognized or disabled cipher suite specified
**Fix**: Use valid OpenSSL cipher string


<a id="orgb730755"></a>

### `[TLS:CONFIG] sni option must be a table or struct`

**When**: Invalid `:sni` option format for server context
**Fix**: Pass table mapping hostnames to cert/key configs

    {:sni {"api.example.com" {:cert api-cert :key api-key}
           "www.example.com" {:cert www-cert :key www-key}}}


<a id="org3ca15f0"></a>

### `[TLS:CONFIG] Invalid ALPN protocols`

**When**: Invalid `:alpn` option format
**Fix**: Pass array of protocol strings

    {:alpn ["h2" "http/1.1"]}


<a id="orgcea4f38"></a>

### `[TLS:CONFIG] handler function must take at least 1 argument`

**When**: Server handler function has wrong arity
**Fix**: Handler must accept at least the stream argument

    # Wrong
    (tls/server "0.0.0.0" "8443" (fn [] (print "no args")) opts)
    
    # Correct
    (tls/server "0.0.0.0" "8443" (fn [stream] (:close stream)) opts)


<a id="orgbfa6b9e"></a>

## PARAM - Parameter Errors


<a id="org423edb9"></a>

### `[TLS:PARAM] timeout must be non-negative, got <value>`

**When**: Passing negative timeout value to I/O operations
**Fix**: Use zero or positive timeout (seconds)

    # Wrong
    (:read stream -1)
    
    # Correct
    (:read stream 1024 5.0)  # 5 second timeout


<a id="org6ff3dec"></a>

### `[TLS:PARAM] expected keyword or nil, got <value>`

**When**: Passing wrong type to `:close` method
**Fix**: Pass `:r`, `:w`, `:rw`, or `nil`

    # Wrong
    (:close stream "both")
    
    # Correct
    (:close stream :rw)  # Close both directions
    (:close stream)      # Same as :rw


<a id="orgfe5774c"></a>

### `[TLS:PARAM] length must be non-negative`

**When**: Negative length to read operations
**Fix**: Pass zero or positive length


<a id="org8752aac"></a>

## IO - I/O Errors


<a id="orga0ff36e"></a>

### `[TLS:IO] stream is closed`

**When**: I/O on a closed TLS stream
**Fix**: Don't use stream after closing

    (def stream (tls/connect "host" "443"))
    (:close stream)
    (:read stream 1024)  # Error! Stream is closed


<a id="org9ba969e"></a>

### `[TLS:IO] connection is shutting down`

**When**: Write attempt during TLS shutdown
**Fix**: Complete shutdown before further operations


<a id="orgb1ea613"></a>

## SSL - OpenSSL Errors


<a id="orgf7232db"></a>

### `[TLS:SSL] failed to create SSL context: <ssl-error>`

**When**: SSL<sub>CTX</sub><sub>new</sub>() failed
**Fix**: Check OpenSSL installation, memory


<a id="org7ff16ff"></a>

### `[TLS:SSL] failed to create SSL object: <ssl-error>`

**When**: SSL<sub>new</sub>() failed
**Fix**: Check context validity, memory


<a id="org59db37a"></a>

### `[TLS:SSL] handshake failed: <ssl-error>`

**When**: TLS handshake failed
**Fix**: Check certificates, protocol compatibility


<a id="org0864140"></a>

### `[TLS:SSL] certificate verification failed: <ssl-error>`

**When**: Peer certificate verification failed
**Fix**: Check certificate chain, CA trust


<a id="org9696e45"></a>

### `[TLS:SSL] failed to load private key: <ssl-error>`

**When**: Private key PEM parsing failed
**Fix**: Verify key format, check for corruption


<a id="orgac84357"></a>

### `[TLS:SSL] failed to load certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="orga32c268"></a>

### `[TLS:SSL] private key does not match certificate: <ssl-error>`

**When**: Certificate/key mismatch in server config
**Fix**: Ensure cert and key are a matching pair


<a id="orgd7b0c83"></a>

## SOCKET - Socket Errors


<a id="org0b85d6d"></a>

### `[TLS:SOCKET] could not connect to <host>:<port>: <errno>`

**When**: TCP connection failed
**Fix**: Check host/port, firewall, server status


<a id="orgcbedbb8"></a>

### `[TLS:SOCKET] bind failed: <errno>`

**When**: Server bind failed
**Fix**: Check port availability, permissions


<a id="org4ee9b5c"></a>

### `[TLS:SOCKET] listen failed: <errno>`

**When**: Socket listen() failed
**Fix**: Check socket state


<a id="org8defa2e"></a>

### `[TLS:SOCKET] getaddrinfo failed: <errno>`

**When**: DNS resolution failed
**Fix**: Check hostname, DNS configuration


<a id="orge91f224"></a>

## VERIFY - Verification Errors


<a id="org81d2010"></a>

### `[TLS:VERIFY] hostname verification failed for <hostname>`

**When**: Certificate doesn't match expected hostname
**Fix**: Check certificate SAN/CN, or disable verification if intended


<a id="orgae0e6a6"></a>

# DTLS Module Errors


<a id="org64b4fb1"></a>

## CONFIG - Configuration Errors


<a id="org30e41c8"></a>

### `[DTLS:CONFIG] dtls/listen requires :cert and :key options`

**When**: DTLS server missing required certificate/key
**Fix**: Provide certificate and private key

    (dtls/listen "0.0.0.0" "5684" {:cert cert-pem :key key-pem})


<a id="org4e4802d"></a>

### `[DTLS:CONFIG] cannot use TLS context for DTLS connection`

**When**: Passing a TLS context to DTLS functions
**Fix**: Create a DTLS-specific context or use options


<a id="orgad50cf8"></a>

## PARAM - Parameter Errors


<a id="org8cf83c0"></a>

### `[DTLS:PARAM] invalid address: <address>`

**When**: Cannot parse host address
**Fix**: Use valid IPv4/IPv6 address or hostname


<a id="org23b8d03"></a>

## IO - I/O Errors


<a id="orgf71bab8"></a>

### `[DTLS:IO] client not connected`

**When**: I/O on unconnected DTLS client
**Fix**: Complete handshake first


<a id="org01fcddf"></a>

### `[DTLS:IO] client is closed`

**When**: Operations on closed DTLS client
**Fix**: Don't use client after closing


<a id="orgec05284"></a>

### `[DTLS:IO] server is closed`

**When**: Operations on closed DTLS server
**Fix**: Don't use server after closing


<a id="org89f1e33"></a>

### `[DTLS:IO] no session for peer address`

**When**: DTLS send to unknown peer
**Fix**: Peer must complete handshake first


<a id="org54ef70a"></a>

### `[DTLS:IO] session not established`

**When**: DTLS send before handshake complete
**Fix**: Wait for handshake completion


<a id="org3843795"></a>

## SSL - OpenSSL Errors


<a id="orgab84c0d"></a>

### `[DTLS:SSL] handshake failed: <ssl-error>`

**When**: DTLS handshake failed
**Fix**: Check certificates, network connectivity


<a id="org6d8f6f0"></a>

### `[DTLS:SSL] write failed: <ssl-error>`

**When**: DTLS write operation failed
**Fix**: Check connection state


<a id="orgd805df9"></a>

## SOCKET - Socket Errors


<a id="org7f1e670"></a>

### `[DTLS:SOCKET] bind failed: <errno>`

**When**: DTLS bind failed
**Fix**: Check address/port availability


<a id="orgc5d0d62"></a>

### `[DTLS:SOCKET] connect failed: <errno>`

**When**: DTLS connect failed
**Fix**: Check server reachability


<a id="orgfb5174d"></a>

### `[DTLS:SOCKET] sendto failed: <errno>`

**When**: DTLS sendto() failed
**Fix**: Check connection state, buffer size


<a id="org108296f"></a>

### `[DTLS:SOCKET] failed to get peer address: <errno>`

**When**: getpeername() failed on DTLS upgrade
**Fix**: Socket must be connected before upgrade


<a id="orgac4678b"></a>

# CRYPTO Module Errors


<a id="org2b5e73e"></a>

## CONFIG - Configuration Errors


<a id="orgddeda3f"></a>

### `[CRYPTO:CONFIG] unknown digest algorithm: <alg>`

**When**: Invalid hash algorithm name
**Fix**: Use supported algorithm (sha256, sha384, sha512, etc.)

    (crypto/digest :sha256 data)  # Correct
    (crypto/digest :md5 data)     # May fail depending on OpenSSL config


<a id="org578817e"></a>

### `[CRYPTO:CONFIG] unsupported key algorithm: <alg>`

**When**: Invalid algorithm for key generation
**Fix**: Use supported algorithm

    # Supported: :rsa, :ed25519, :x25519, :ec-p256, :ec-p384, :ec-p521
    (crypto/generate-keypair :ec-p256)  # Correct
    (crypto/generate-keypair :dsa)       # Error: unsupported


<a id="org7a798a0"></a>

## PARAM - Parameter Errors


<a id="orgd112aeb"></a>

### `[CRYPTO:PARAM] byte count must be 1-65536, got <n>`

**When**: Requesting too many or too few random bytes
**Fix**: Request between 1 and 65536 bytes

    (crypto/random-bytes 32)  # Correct: 32 bytes


<a id="org7b7a736"></a>

### `[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`

**When**: Invalid challenge length for `crypto/random-challenge`
**Fix**: Request between 8 and 64 bytes


<a id="orgf73e84d"></a>

### `[CRYPTO:PARAM] output length must be 1-<max>`

**When**: HKDF output length exceeds maximum (255 \* hash-size)
**Fix**: Request smaller output


<a id="org463de2f"></a>

### `[CRYPTO:PARAM] output length must be 1-1024`

**When**: PBKDF2 output length out of range
**Fix**: Request between 1 and 1024 bytes


<a id="org5bbb391"></a>

### `[CRYPTO:PARAM] iterations must be positive`

**When**: Non-positive iteration count for PBKDF2
**Fix**: Use at least 1 iteration (recommend 100000+ for security)


<a id="orgc9a20f7"></a>

### `[CRYPTO:PARAM] options must be a table or struct`

**When**: Passing non-table/struct to functions expecting options
**Fix**: Pass a table `{}` or struct `@{}`


<a id="orgb9da854"></a>

## SSL - OpenSSL Errors


<a id="orge94c85a"></a>

### `[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`

**When**: Key derivation operation failed
**Fix**: Check input parameters


<a id="org8da2c38"></a>

### `[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`

**When**: PBKDF2 operation failed
**Fix**: Check input parameters


<a id="orgbf812b2"></a>

### `[CRYPTO:SSL] HMAC computation failed: <ssl-error>`

**When**: HMAC operation failed
**Fix**: Check algorithm and key


<a id="org0b7168d"></a>

### `[CRYPTO:SSL] signing failed: <ssl-error>`

**When**: Signature operation failed
**Fix**: Check key type supports signing


<a id="orgfb0fcca"></a>

### `[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`

**When**: Entropy source failure
**Fix**: Check system entropy (/dev/urandom)


<a id="orgf6fa6cd"></a>

## RESOURCE - Resource Errors


<a id="orga5c56a3"></a>

### `[CRYPTO:RESOURCE] out of memory`

**When**: Memory allocation failed
**Fix**: Check system memory, reduce allocations


<a id="orgba83dcc"></a>

### `[CRYPTO:RESOURCE] failed to create context`

**When**: EVP context allocation failed
**Fix**: Check memory, OpenSSL state


<a id="orgea464ea"></a>

## PARSE - Parse Errors


<a id="orge8e06ea"></a>

### `[CRYPTO:PARSE] base64 decode failed`

**When**: Invalid base64 input
**Fix**: Verify input is valid base64


<a id="org381f2a3"></a>

### `[CRYPTO:PARSE] failed to parse CSR`

**When**: CSR parsing failed
**Fix**: Check CSR data validity


<a id="org6d3421e"></a>

# CA Module Errors


<a id="org49c2ef7"></a>

## CONFIG - Configuration Errors


<a id="org98c3809"></a>

### `[CA:CONFIG] common-name is required`

**When**: Certificate issuance without CN
**Fix**: Provide :cn option


<a id="org052f89c"></a>

### `[CA:CONFIG] ca-cert is required`

**When**: CA operations without CA certificate
**Fix**: Provide CA certificate PEM


<a id="org2e7079c"></a>

### `[CA:CONFIG] ca-key is required`

**When**: CA operations without CA private key
**Fix**: Provide CA private key PEM


<a id="org4ac0642"></a>

## PARAM - Parameter Errors


<a id="org1da7ed4"></a>

### `[CA:PARAM] validity-days must be positive`

**When**: Invalid certificate validity period
**Fix**: Use positive number of days


<a id="org5df3cab"></a>

### `[CA:PARAM] serial must be positive`

**When**: Invalid certificate serial number
**Fix**: Use positive serial number


<a id="orgdc17bbc"></a>

## SSL - OpenSSL Errors


<a id="orgd746211"></a>

### `[CA:SSL] failed to sign certificate: <ssl-error>`

**When**: Certificate signing failed
**Fix**: Check CA key compatibility


<a id="orga1c80fd"></a>

### `[CA:SSL] failed to create certificate: <ssl-error>`

**When**: X509 creation failed
**Fix**: Check memory, parameters


<a id="org73d7d1b"></a>

## VERIFY - Verification Errors


<a id="org389f293"></a>

### `[CA:VERIFY] certificate has expired`

**When**: Certificate past its validity period
**Fix**: Renew certificate


<a id="orga5dd18f"></a>

### `[CA:VERIFY] certificate not yet valid`

**When**: Certificate not yet in validity period
**Fix**: Check system time, certificate dates


<a id="orgd21307e"></a>

# CERT Module Errors


<a id="orgacf807d"></a>

## PARAM - Parameter Errors


<a id="org6a9cc24"></a>

### `[CERT:PARAM] certificates must be string or array of strings`

**When**: Invalid certificate format in operations
**Fix**: Pass PEM string or array of PEM strings


<a id="orgb5c6923"></a>

## PARSE - Parse Errors


<a id="org1cd6d7f"></a>

### `[CERT:PARSE] failed to parse certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="orga00a46e"></a>

### `[CERT:PARSE] failed to parse private key: <ssl-error>`

**When**: Private key parsing failed
**Fix**: Verify key format


<a id="orga957c9a"></a>

# Error Handling Best Practices


<a id="org853bbdf"></a>

## Using protect/try

    (def result
      (protect
        (tls/connect "untrusted.example.com" "443" {:verify true})))
    
    (if (nil? result)
      (print "Connection failed - check certificate")
      (do-something-with result))


<a id="orgac4fb44"></a>

## Checking Return Values

Many functions return `nil` on failure:

    (when-let [stream (tls/connect host port opts)]
      (defer (:close stream)
        (process-stream stream)))


<a id="org657b35a"></a>

## Timeouts

Always use timeouts for network operations:

    (def data (:read stream 1024 30.0))  # 30 second timeout
    (when (nil? data)
      (print "Read timed out or connection closed"))


<a id="orga581082"></a>

# Testing Error Conditions

To test that your code handles errors correctly, use janet-assay's
`:expected-fail` feature for negative testing:

    (import assay)
    
    (assay/def-suite "error-handling"
      (assay/def-test "rejects invalid iterations"
        :expected-fail "[CRYPTO:PARAM]"
        (crypto/pbkdf2 :sha256 "password" "salt" 0 32)))


<a id="orgcbea718"></a>

# See Also

-   [API Reference](API.md) - Complete function documentation
-   [User Guide](GUIDE.md) - Getting started and examples
-   [Developer Guide](DEVELOPERS.md) - Contributing and internals

