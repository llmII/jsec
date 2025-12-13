
# Table of Contents

1.  [Overview](#orgbb7bfe9)
    1.  [Error Format](#org5798c1a)
    2.  [Example Errors](#orgd49c5c3)
2.  [TLS Module Errors](#org125e755)
    1.  [CONFIG - Configuration Errors](#orga612b62)
        1.  [`[TLS:CONFIG] buffer-size must be a number`](#org0f21bf1)
        2.  [`[TLS:CONFIG] invalid cipher suite: <suite>`](#org560c9b6)
        3.  [`[TLS:CONFIG] sni option must be a table or struct`](#orgf8c9af2)
        4.  [`[TLS:CONFIG] Invalid ALPN protocols`](#org1a276de)
        5.  [`[TLS:CONFIG] handler function must take at least 1 argument`](#orge1e1e99)
    2.  [PARAM - Parameter Errors](#org39e5cd6)
        1.  [`[TLS:PARAM] timeout must be non-negative, got <value>`](#org2e002a9)
        2.  [`[TLS:PARAM] expected keyword or nil, got <value>`](#orga9130f3)
        3.  [`[TLS:PARAM] length must be non-negative`](#org0b2ed51)
    3.  [IO - I/O Errors](#orgf5a6cad)
        1.  [`[TLS:IO] stream is closed`](#org2b33b14)
        2.  [`[TLS:IO] connection is shutting down`](#org93846a4)
    4.  [SSL - OpenSSL Errors](#orgfb567c7)
        1.  [`[TLS:SSL] failed to create SSL context: <ssl-error>`](#org359260b)
        2.  [`[TLS:SSL] failed to create SSL object: <ssl-error>`](#orga7e36c1)
        3.  [`[TLS:SSL] handshake failed: <ssl-error>`](#orga158b6a)
        4.  [`[TLS:SSL] certificate verification failed: <ssl-error>`](#org01c3b8a)
        5.  [`[TLS:SSL] failed to load private key: <ssl-error>`](#orgb17fad8)
        6.  [`[TLS:SSL] failed to load certificate: <ssl-error>`](#orgffa485f)
        7.  [`[TLS:SSL] private key does not match certificate: <ssl-error>`](#org56aa226)
    5.  [SOCKET - Socket Errors](#orgc2c35e7)
        1.  [`[TLS:SOCKET] could not connect to <host>:<port>: <errno>`](#org9ed70f7)
        2.  [`[TLS:SOCKET] bind failed: <errno>`](#org876cbc1)
        3.  [`[TLS:SOCKET] listen failed: <errno>`](#org9964890)
        4.  [`[TLS:SOCKET] getaddrinfo failed: <errno>`](#org1ac1669)
    6.  [VERIFY - Verification Errors](#org630fe7e)
        1.  [`[TLS:VERIFY] hostname verification failed for <hostname>`](#orgba0a200)
3.  [DTLS Module Errors](#org522009d)
    1.  [CONFIG - Configuration Errors](#orgf473a83)
        1.  [`[DTLS:CONFIG] dtls/listen requires :cert and :key options`](#org0cb6396)
        2.  [`[DTLS:CONFIG] cannot use TLS context for DTLS connection`](#org153adc9)
    2.  [PARAM - Parameter Errors](#org681547c)
        1.  [`[DTLS:PARAM] invalid address: <address>`](#org9407a80)
    3.  [IO - I/O Errors](#org573e8a0)
        1.  [`[DTLS:IO] client not connected`](#orga453159)
        2.  [`[DTLS:IO] client is closed`](#orgdff95b8)
        3.  [`[DTLS:IO] server is closed`](#org52d7272)
        4.  [`[DTLS:IO] no session for peer address`](#org6da64e3)
        5.  [`[DTLS:IO] session not established`](#org3212cbd)
    4.  [SSL - OpenSSL Errors](#org4352c88)
        1.  [`[DTLS:SSL] handshake failed: <ssl-error>`](#org9e91f0b)
        2.  [`[DTLS:SSL] write failed: <ssl-error>`](#org2cc5179)
    5.  [SOCKET - Socket Errors](#org66d7790)
        1.  [`[DTLS:SOCKET] bind failed: <errno>`](#orga70aaf4)
        2.  [`[DTLS:SOCKET] connect failed: <errno>`](#org0f49f88)
        3.  [`[DTLS:SOCKET] sendto failed: <errno>`](#org4d52475)
        4.  [`[DTLS:SOCKET] failed to get peer address: <errno>`](#org488fe66)
4.  [CRYPTO Module Errors](#orge4226f0)
    1.  [CONFIG - Configuration Errors](#orgc394622)
        1.  [`[CRYPTO:CONFIG] unknown digest algorithm: <alg>`](#org5b27f6e)
        2.  [`[CRYPTO:CONFIG] unsupported key algorithm: <alg>`](#orgada98da)
    2.  [PARAM - Parameter Errors](#org17fdd93)
        1.  [`[CRYPTO:PARAM] byte count must be 1-65536, got <n>`](#orgf0024c7)
        2.  [`[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`](#orgc0eb7aa)
        3.  [`[CRYPTO:PARAM] output length must be 1-<max>`](#org205ce17)
        4.  [`[CRYPTO:PARAM] output length must be 1-1024`](#org8ebce24)
        5.  [`[CRYPTO:PARAM] iterations must be positive`](#orgfc552c4)
        6.  [`[CRYPTO:PARAM] options must be a table or struct`](#orgc7a0e2a)
    3.  [SSL - OpenSSL Errors](#org571f4d0)
        1.  [`[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`](#org3de5e01)
        2.  [`[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`](#org04ba68b)
        3.  [`[CRYPTO:SSL] HMAC computation failed: <ssl-error>`](#org2ea4ec6)
        4.  [`[CRYPTO:SSL] signing failed: <ssl-error>`](#org479836f)
        5.  [`[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`](#org0bbd44d)
    4.  [RESOURCE - Resource Errors](#org5f537f2)
        1.  [`[CRYPTO:RESOURCE] out of memory`](#org82a9375)
        2.  [`[CRYPTO:RESOURCE] failed to create context`](#org609418b)
    5.  [PARSE - Parse Errors](#org89cefe5)
        1.  [`[CRYPTO:PARSE] base64 decode failed`](#org26788d5)
        2.  [`[CRYPTO:PARSE] failed to parse CSR`](#orgb299e62)
5.  [CA Module Errors](#org2d975c1)
    1.  [CONFIG - Configuration Errors](#org513fbd2)
        1.  [`[CA:CONFIG] common-name is required`](#orgd60d8cc)
        2.  [`[CA:CONFIG] ca-cert is required`](#org8f5e6fc)
        3.  [`[CA:CONFIG] ca-key is required`](#org1eebdb6)
    2.  [PARAM - Parameter Errors](#org3834d4c)
        1.  [`[CA:PARAM] validity-days must be positive`](#org3f56770)
        2.  [`[CA:PARAM] serial must be positive`](#orgd669208)
    3.  [SSL - OpenSSL Errors](#org3ea7abd)
        1.  [`[CA:SSL] failed to sign certificate: <ssl-error>`](#org8eaa54e)
        2.  [`[CA:SSL] failed to create certificate: <ssl-error>`](#orge23eaf3)
    4.  [VERIFY - Verification Errors](#orgbba28ce)
        1.  [`[CA:VERIFY] certificate has expired`](#org723c7f7)
        2.  [`[CA:VERIFY] certificate not yet valid`](#orgd1396c9)
6.  [CERT Module Errors](#org8d9e4d0)
    1.  [PARAM - Parameter Errors](#org03d5fc6)
        1.  [`[CERT:PARAM] certificates must be string or array of strings`](#org27b6710)
    2.  [PARSE - Parse Errors](#org0adc33e)
        1.  [`[CERT:PARSE] failed to parse certificate: <ssl-error>`](#org94ed61e)
        2.  [`[CERT:PARSE] failed to parse private key: <ssl-error>`](#orgab95b19)
7.  [Error Handling Best Practices](#org5bd0a1d)
    1.  [Using protect/try](#orgb48e443)
    2.  [Checking Return Values](#org9da380c)
    3.  [Timeouts](#org63854a4)
8.  [Testing Error Conditions](#org3704efd)
9.  [See Also](#orgc414f1d)



<a id="orgbb7bfe9"></a>

# Overview

This document catalogs all errors that JSEC can produce, organized by module and category.


<a id="org5798c1a"></a>

## Error Format

All errors follow a standardized format:

    [MODULE:CATEGORY] message: detail

Where:

-   **MODULE**: TLS, DTLS, CRYPTO, CA, CERT, UTILS
-   **CATEGORY**: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY, PARSE


<a id="orgd49c5c3"></a>

## Example Errors

    [TLS:CONFIG] invalid cipher suite: RC4-MD5
    [DTLS:SOCKET] bind failed: address already in use
    [CRYPTO:PARAM] output length must be 1-1024, got 2000
    [CA:SSL] failed to sign certificate: key mismatch


<a id="org125e755"></a>

# TLS Module Errors


<a id="orga612b62"></a>

## CONFIG - Configuration Errors


<a id="org0f21bf1"></a>

### `[TLS:CONFIG] buffer-size must be a number`

**When**: Non-numeric `:buffer-size` option
**Fix**: Pass a positive integer

    # Wrong
    (tls/connect "host" "443" {:buffer-size "big"})
    
    # Correct
    (tls/connect "host" "443" {:buffer-size 16384})


<a id="org560c9b6"></a>

### `[TLS:CONFIG] invalid cipher suite: <suite>`

**When**: Unrecognized or disabled cipher suite specified
**Fix**: Use valid OpenSSL cipher string


<a id="orgf8c9af2"></a>

### `[TLS:CONFIG] sni option must be a table or struct`

**When**: Invalid `:sni` option format for server context
**Fix**: Pass table mapping hostnames to cert/key configs

    {:sni {"api.example.com" {:cert api-cert :key api-key}
           "www.example.com" {:cert www-cert :key www-key}}}


<a id="org1a276de"></a>

### `[TLS:CONFIG] Invalid ALPN protocols`

**When**: Invalid `:alpn` option format
**Fix**: Pass array of protocol strings

    {:alpn ["h2" "http/1.1"]}


<a id="orge1e1e99"></a>

### `[TLS:CONFIG] handler function must take at least 1 argument`

**When**: Server handler function has wrong arity
**Fix**: Handler must accept at least the stream argument

    # Wrong
    (tls/server "0.0.0.0" "8443" (fn [] (print "no args")) opts)
    
    # Correct
    (tls/server "0.0.0.0" "8443" (fn [stream] (:close stream)) opts)


<a id="org39e5cd6"></a>

## PARAM - Parameter Errors


<a id="org2e002a9"></a>

### `[TLS:PARAM] timeout must be non-negative, got <value>`

**When**: Passing negative timeout value to I/O operations
**Fix**: Use zero or positive timeout (seconds)

    # Wrong
    (:read stream -1)
    
    # Correct
    (:read stream 1024 5.0)  # 5 second timeout


<a id="orga9130f3"></a>

### `[TLS:PARAM] expected keyword or nil, got <value>`

**When**: Passing wrong type to `:close` method
**Fix**: Pass `:r`, `:w`, `:rw`, or `nil`

    # Wrong
    (:close stream "both")
    
    # Correct
    (:close stream :rw)  # Close both directions
    (:close stream)      # Same as :rw


<a id="org0b2ed51"></a>

### `[TLS:PARAM] length must be non-negative`

**When**: Negative length to read operations
**Fix**: Pass zero or positive length


<a id="orgf5a6cad"></a>

## IO - I/O Errors


<a id="org2b33b14"></a>

### `[TLS:IO] stream is closed`

**When**: I/O on a closed TLS stream
**Fix**: Don't use stream after closing

    (def stream (tls/connect "host" "443"))
    (:close stream)
    (:read stream 1024)  # Error! Stream is closed


<a id="org93846a4"></a>

### `[TLS:IO] connection is shutting down`

**When**: Write attempt during TLS shutdown
**Fix**: Complete shutdown before further operations


<a id="orgfb567c7"></a>

## SSL - OpenSSL Errors


<a id="org359260b"></a>

### `[TLS:SSL] failed to create SSL context: <ssl-error>`

**When**: SSL<sub>CTX</sub><sub>new</sub>() failed
**Fix**: Check OpenSSL installation, memory


<a id="orga7e36c1"></a>

### `[TLS:SSL] failed to create SSL object: <ssl-error>`

**When**: SSL<sub>new</sub>() failed
**Fix**: Check context validity, memory


<a id="orga158b6a"></a>

### `[TLS:SSL] handshake failed: <ssl-error>`

**When**: TLS handshake failed
**Fix**: Check certificates, protocol compatibility


<a id="org01c3b8a"></a>

### `[TLS:SSL] certificate verification failed: <ssl-error>`

**When**: Peer certificate verification failed
**Fix**: Check certificate chain, CA trust


<a id="orgb17fad8"></a>

### `[TLS:SSL] failed to load private key: <ssl-error>`

**When**: Private key PEM parsing failed
**Fix**: Verify key format, check for corruption


<a id="orgffa485f"></a>

### `[TLS:SSL] failed to load certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org56aa226"></a>

### `[TLS:SSL] private key does not match certificate: <ssl-error>`

**When**: Certificate/key mismatch in server config
**Fix**: Ensure cert and key are a matching pair


<a id="orgc2c35e7"></a>

## SOCKET - Socket Errors


<a id="org9ed70f7"></a>

### `[TLS:SOCKET] could not connect to <host>:<port>: <errno>`

**When**: TCP connection failed
**Fix**: Check host/port, firewall, server status


<a id="org876cbc1"></a>

### `[TLS:SOCKET] bind failed: <errno>`

**When**: Server bind failed
**Fix**: Check port availability, permissions


<a id="org9964890"></a>

### `[TLS:SOCKET] listen failed: <errno>`

**When**: Socket listen() failed
**Fix**: Check socket state


<a id="org1ac1669"></a>

### `[TLS:SOCKET] getaddrinfo failed: <errno>`

**When**: DNS resolution failed
**Fix**: Check hostname, DNS configuration


<a id="org630fe7e"></a>

## VERIFY - Verification Errors


<a id="orgba0a200"></a>

### `[TLS:VERIFY] hostname verification failed for <hostname>`

**When**: Certificate doesn't match expected hostname
**Fix**: Check certificate SAN/CN, or disable verification if intended


<a id="org522009d"></a>

# DTLS Module Errors


<a id="orgf473a83"></a>

## CONFIG - Configuration Errors


<a id="org0cb6396"></a>

### `[DTLS:CONFIG] dtls/listen requires :cert and :key options`

**When**: DTLS server missing required certificate/key
**Fix**: Provide certificate and private key

    (dtls/listen "0.0.0.0" "5684" {:cert cert-pem :key key-pem})


<a id="org153adc9"></a>

### `[DTLS:CONFIG] cannot use TLS context for DTLS connection`

**When**: Passing a TLS context to DTLS functions
**Fix**: Create a DTLS-specific context or use options


<a id="org681547c"></a>

## PARAM - Parameter Errors


<a id="org9407a80"></a>

### `[DTLS:PARAM] invalid address: <address>`

**When**: Cannot parse host address
**Fix**: Use valid IPv4/IPv6 address or hostname


<a id="org573e8a0"></a>

## IO - I/O Errors


<a id="orga453159"></a>

### `[DTLS:IO] client not connected`

**When**: I/O on unconnected DTLS client
**Fix**: Complete handshake first


<a id="orgdff95b8"></a>

### `[DTLS:IO] client is closed`

**When**: Operations on closed DTLS client
**Fix**: Don't use client after closing


<a id="org52d7272"></a>

### `[DTLS:IO] server is closed`

**When**: Operations on closed DTLS server
**Fix**: Don't use server after closing


<a id="org6da64e3"></a>

### `[DTLS:IO] no session for peer address`

**When**: DTLS send to unknown peer
**Fix**: Peer must complete handshake first


<a id="org3212cbd"></a>

### `[DTLS:IO] session not established`

**When**: DTLS send before handshake complete
**Fix**: Wait for handshake completion


<a id="org4352c88"></a>

## SSL - OpenSSL Errors


<a id="org9e91f0b"></a>

### `[DTLS:SSL] handshake failed: <ssl-error>`

**When**: DTLS handshake failed
**Fix**: Check certificates, network connectivity


<a id="org2cc5179"></a>

### `[DTLS:SSL] write failed: <ssl-error>`

**When**: DTLS write operation failed
**Fix**: Check connection state


<a id="org66d7790"></a>

## SOCKET - Socket Errors


<a id="orga70aaf4"></a>

### `[DTLS:SOCKET] bind failed: <errno>`

**When**: DTLS bind failed
**Fix**: Check address/port availability


<a id="org0f49f88"></a>

### `[DTLS:SOCKET] connect failed: <errno>`

**When**: DTLS connect failed
**Fix**: Check server reachability


<a id="org4d52475"></a>

### `[DTLS:SOCKET] sendto failed: <errno>`

**When**: DTLS sendto() failed
**Fix**: Check connection state, buffer size


<a id="org488fe66"></a>

### `[DTLS:SOCKET] failed to get peer address: <errno>`

**When**: getpeername() failed on DTLS upgrade
**Fix**: Socket must be connected before upgrade


<a id="orge4226f0"></a>

# CRYPTO Module Errors


<a id="orgc394622"></a>

## CONFIG - Configuration Errors


<a id="org5b27f6e"></a>

### `[CRYPTO:CONFIG] unknown digest algorithm: <alg>`

**When**: Invalid hash algorithm name
**Fix**: Use supported algorithm (sha256, sha384, sha512, etc.)

    (crypto/digest :sha256 data)  # Correct
    (crypto/digest :md5 data)     # May fail depending on OpenSSL config


<a id="orgada98da"></a>

### `[CRYPTO:CONFIG] unsupported key algorithm: <alg>`

**When**: Invalid algorithm for key generation
**Fix**: Use supported algorithm

    # Supported: :rsa, :ed25519, :x25519, :ec-p256, :ec-p384, :ec-p521
    (crypto/generate-keypair :ec-p256)  # Correct
    (crypto/generate-keypair :dsa)       # Error: unsupported


<a id="org17fdd93"></a>

## PARAM - Parameter Errors


<a id="orgf0024c7"></a>

### `[CRYPTO:PARAM] byte count must be 1-65536, got <n>`

**When**: Requesting too many or too few random bytes
**Fix**: Request between 1 and 65536 bytes

    (crypto/random-bytes 32)  # Correct: 32 bytes


<a id="orgc0eb7aa"></a>

### `[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`

**When**: Invalid challenge length for `crypto/random-challenge`
**Fix**: Request between 8 and 64 bytes


<a id="org205ce17"></a>

### `[CRYPTO:PARAM] output length must be 1-<max>`

**When**: HKDF output length exceeds maximum (255 \* hash-size)
**Fix**: Request smaller output


<a id="org8ebce24"></a>

### `[CRYPTO:PARAM] output length must be 1-1024`

**When**: PBKDF2 output length out of range
**Fix**: Request between 1 and 1024 bytes


<a id="orgfc552c4"></a>

### `[CRYPTO:PARAM] iterations must be positive`

**When**: Non-positive iteration count for PBKDF2
**Fix**: Use at least 1 iteration (recommend 100000+ for security)


<a id="orgc7a0e2a"></a>

### `[CRYPTO:PARAM] options must be a table or struct`

**When**: Passing non-table/struct to functions expecting options
**Fix**: Pass a table `{}` or struct `@{}`


<a id="org571f4d0"></a>

## SSL - OpenSSL Errors


<a id="org3de5e01"></a>

### `[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`

**When**: Key derivation operation failed
**Fix**: Check input parameters


<a id="org04ba68b"></a>

### `[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`

**When**: PBKDF2 operation failed
**Fix**: Check input parameters


<a id="org2ea4ec6"></a>

### `[CRYPTO:SSL] HMAC computation failed: <ssl-error>`

**When**: HMAC operation failed
**Fix**: Check algorithm and key


<a id="org479836f"></a>

### `[CRYPTO:SSL] signing failed: <ssl-error>`

**When**: Signature operation failed
**Fix**: Check key type supports signing


<a id="org0bbd44d"></a>

### `[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`

**When**: Entropy source failure
**Fix**: Check system entropy (/dev/urandom)


<a id="org5f537f2"></a>

## RESOURCE - Resource Errors


<a id="org82a9375"></a>

### `[CRYPTO:RESOURCE] out of memory`

**When**: Memory allocation failed
**Fix**: Check system memory, reduce allocations


<a id="org609418b"></a>

### `[CRYPTO:RESOURCE] failed to create context`

**When**: EVP context allocation failed
**Fix**: Check memory, OpenSSL state


<a id="org89cefe5"></a>

## PARSE - Parse Errors


<a id="org26788d5"></a>

### `[CRYPTO:PARSE] base64 decode failed`

**When**: Invalid base64 input
**Fix**: Verify input is valid base64


<a id="orgb299e62"></a>

### `[CRYPTO:PARSE] failed to parse CSR`

**When**: CSR parsing failed
**Fix**: Check CSR data validity


<a id="org2d975c1"></a>

# CA Module Errors


<a id="org513fbd2"></a>

## CONFIG - Configuration Errors


<a id="orgd60d8cc"></a>

### `[CA:CONFIG] common-name is required`

**When**: Certificate issuance without CN
**Fix**: Provide :cn option


<a id="org8f5e6fc"></a>

### `[CA:CONFIG] ca-cert is required`

**When**: CA operations without CA certificate
**Fix**: Provide CA certificate PEM


<a id="org1eebdb6"></a>

### `[CA:CONFIG] ca-key is required`

**When**: CA operations without CA private key
**Fix**: Provide CA private key PEM


<a id="org3834d4c"></a>

## PARAM - Parameter Errors


<a id="org3f56770"></a>

### `[CA:PARAM] validity-days must be positive`

**When**: Invalid certificate validity period
**Fix**: Use positive number of days


<a id="orgd669208"></a>

### `[CA:PARAM] serial must be positive`

**When**: Invalid certificate serial number
**Fix**: Use positive serial number


<a id="org3ea7abd"></a>

## SSL - OpenSSL Errors


<a id="org8eaa54e"></a>

### `[CA:SSL] failed to sign certificate: <ssl-error>`

**When**: Certificate signing failed
**Fix**: Check CA key compatibility


<a id="orge23eaf3"></a>

### `[CA:SSL] failed to create certificate: <ssl-error>`

**When**: X509 creation failed
**Fix**: Check memory, parameters


<a id="orgbba28ce"></a>

## VERIFY - Verification Errors


<a id="org723c7f7"></a>

### `[CA:VERIFY] certificate has expired`

**When**: Certificate past its validity period
**Fix**: Renew certificate


<a id="orgd1396c9"></a>

### `[CA:VERIFY] certificate not yet valid`

**When**: Certificate not yet in validity period
**Fix**: Check system time, certificate dates


<a id="org8d9e4d0"></a>

# CERT Module Errors


<a id="org03d5fc6"></a>

## PARAM - Parameter Errors


<a id="org27b6710"></a>

### `[CERT:PARAM] certificates must be string or array of strings`

**When**: Invalid certificate format in operations
**Fix**: Pass PEM string or array of PEM strings


<a id="org0adc33e"></a>

## PARSE - Parse Errors


<a id="org94ed61e"></a>

### `[CERT:PARSE] failed to parse certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="orgab95b19"></a>

### `[CERT:PARSE] failed to parse private key: <ssl-error>`

**When**: Private key parsing failed
**Fix**: Verify key format


<a id="org5bd0a1d"></a>

# Error Handling Best Practices


<a id="orgb48e443"></a>

## Using protect/try

    (def result
      (protect
        (tls/connect "untrusted.example.com" "443" {:verify true})))
    
    (if (nil? result)
      (print "Connection failed - check certificate")
      (do-something-with result))


<a id="org9da380c"></a>

## Checking Return Values

Many functions return `nil` on failure:

    (when-let [stream (tls/connect host port opts)]
      (defer (:close stream)
        (process-stream stream)))


<a id="org63854a4"></a>

## Timeouts

Always use timeouts for network operations:

    (def data (:read stream 1024 30.0))  # 30 second timeout
    (when (nil? data)
      (print "Read timed out or connection closed"))


<a id="org3704efd"></a>

# Testing Error Conditions

To test that your code handles errors correctly, use janet-assay's
`:expected-fail` feature for negative testing:

    (import assay)
    
    (assay/def-suite "error-handling"
      (assay/def-test "rejects invalid iterations"
        :expected-fail "[CRYPTO:PARAM]"
        (crypto/pbkdf2 :sha256 "password" "salt" 0 32)))


<a id="orgc414f1d"></a>

# See Also

-   [API Reference](API.md) - Complete function documentation
-   [User Guide](GUIDE.md) - Getting started and examples
-   [Developer Guide](DEVELOPERS.md) - Contributing and internals

