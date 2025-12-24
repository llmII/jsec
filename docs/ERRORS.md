
# Table of Contents

1.  [Overview](#orgf72cd3f)
    1.  [Error Format](#org3c419b2)
    2.  [Example Errors](#org793af63)
2.  [TLS Module Errors](#orga9dc13e)
    1.  [CONFIG - Configuration Errors](#org033d2a9)
        1.  [`[TLS:CONFIG] buffer-size must be a number`](#org3528420)
        2.  [`[TLS:CONFIG] invalid cipher suite: <suite>`](#orgc5680c2)
        3.  [`[TLS:CONFIG] sni option must be a table or struct`](#orge32c3c2)
        4.  [`[TLS:CONFIG] Invalid ALPN protocols`](#org71899ce)
        5.  [`[TLS:CONFIG] handler function must take at least 1 argument`](#orgf943e00)
    2.  [PARAM - Parameter Errors](#org0e12674)
        1.  [`[TLS:PARAM] timeout must be non-negative, got <value>`](#orgb81e3a7)
        2.  [`[TLS:PARAM] expected keyword or nil, got <value>`](#org7ef93a3)
        3.  [`[TLS:PARAM] length must be non-negative`](#org465187d)
    3.  [IO - I/O Errors](#org0ad2ba9)
        1.  [`[TLS:IO] stream is closed`](#org809a60c)
        2.  [`[TLS:IO] connection is shutting down`](#orgf2f32b8)
    4.  [SSL - OpenSSL Errors](#org8784c49)
        1.  [`[TLS:SSL] failed to create SSL context: <ssl-error>`](#org9eb457e)
        2.  [`[TLS:SSL] failed to create SSL object: <ssl-error>`](#orgecd9a6c)
        3.  [`[TLS:SSL] handshake failed: <ssl-error>`](#orgaaec826)
        4.  [`[TLS:SSL] certificate verification failed: <ssl-error>`](#org674ff1b)
        5.  [`[TLS:SSL] failed to load private key: <ssl-error>`](#org9a0c9c6)
        6.  [`[TLS:SSL] failed to load certificate: <ssl-error>`](#org620a60c)
        7.  [`[TLS:SSL] private key does not match certificate: <ssl-error>`](#org8e86bad)
    5.  [SOCKET - Socket Errors](#org4965dff)
        1.  [`[TLS:SOCKET] could not connect to <host>:<port>: <errno>`](#orgdd1c82e)
        2.  [`[TLS:SOCKET] bind failed: <errno>`](#org02e676d)
        3.  [`[TLS:SOCKET] listen failed: <errno>`](#org9372630)
        4.  [`[TLS:SOCKET] getaddrinfo failed: <errno>`](#orgd315eff)
    6.  [VERIFY - Verification Errors](#org75176d7)
        1.  [`[TLS:VERIFY] hostname verification failed for <hostname>`](#org4a85405)
3.  [DTLS Module Errors](#org7a53b5a)
    1.  [CONFIG - Configuration Errors](#orgad4d29a)
        1.  [`[DTLS:CONFIG] dtls/listen requires :cert and :key options`](#org61300ff)
        2.  [`[DTLS:CONFIG] cannot use TLS context for DTLS connection`](#org2bf3467)
    2.  [PARAM - Parameter Errors](#orgf0d6cdd)
        1.  [`[DTLS:PARAM] invalid address: <address>`](#orgd1b314c)
    3.  [IO - I/O Errors](#org481166b)
        1.  [`[DTLS:IO] client not connected`](#orgc044b24)
        2.  [`[DTLS:IO] client is closed`](#orgfb6235d)
        3.  [`[DTLS:IO] server is closed`](#orgbfa68cc)
        4.  [`[DTLS:IO] no session for peer address`](#org2133516)
        5.  [`[DTLS:IO] session not established`](#org4700790)
    4.  [SSL - OpenSSL Errors](#orgc888e2c)
        1.  [`[DTLS:SSL] handshake failed: <ssl-error>`](#orgdd38cfe)
        2.  [`[DTLS:SSL] write failed: <ssl-error>`](#org62d1cc2)
    5.  [SOCKET - Socket Errors](#orgf221da1)
        1.  [`[DTLS:SOCKET] bind failed: <errno>`](#orgc2b093a)
        2.  [`[DTLS:SOCKET] connect failed: <errno>`](#orgc2df5f3)
        3.  [`[DTLS:SOCKET] sendto failed: <errno>`](#orgba6f2bc)
        4.  [`[DTLS:SOCKET] failed to get peer address: <errno>`](#org1a0b1e2)
4.  [CRYPTO Module Errors](#org23449e5)
    1.  [CONFIG - Configuration Errors](#orgd64447a)
        1.  [`[CRYPTO:CONFIG] unknown digest algorithm: <alg>`](#org59214e9)
        2.  [`[CRYPTO:CONFIG] unsupported key algorithm: <alg>`](#org3142fb6)
    2.  [PARAM - Parameter Errors](#org5a5b170)
        1.  [`[CRYPTO:PARAM] byte count must be 1-65536, got <n>`](#org7bc83f2)
        2.  [`[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`](#org7bbd4fa)
        3.  [`[CRYPTO:PARAM] output length must be 1-<max>`](#orge1141db)
        4.  [`[CRYPTO:PARAM] output length must be 1-1024`](#orgc0374ce)
        5.  [`[CRYPTO:PARAM] iterations must be positive`](#org42ff729)
        6.  [`[CRYPTO:PARAM] options must be a table or struct`](#org2d8e39e)
    3.  [SSL - OpenSSL Errors](#org8e67dba)
        1.  [`[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`](#orgfa49805)
        2.  [`[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`](#orgc034c6a)
        3.  [`[CRYPTO:SSL] HMAC computation failed: <ssl-error>`](#orgbe1ad91)
        4.  [`[CRYPTO:SSL] signing failed: <ssl-error>`](#org8d26adb)
        5.  [`[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`](#orgcd928eb)
    4.  [RESOURCE - Resource Errors](#orgd08775a)
        1.  [`[CRYPTO:RESOURCE] out of memory`](#orgeb01ac9)
        2.  [`[CRYPTO:RESOURCE] failed to create context`](#orgd412382)
    5.  [PARSE - Parse Errors](#orgda3e0f0)
        1.  [`[CRYPTO:PARSE] base64 decode failed`](#orgfa7c6b9)
        2.  [`[CRYPTO:PARSE] failed to parse CSR`](#org65ae357)
5.  [CA Module Errors](#org644b0c9)
    1.  [CONFIG - Configuration Errors](#orgdc9b51f)
        1.  [`[CA:CONFIG] common-name is required`](#org430898a)
        2.  [`[CA:CONFIG] ca-cert is required`](#orgf4f75ce)
        3.  [`[CA:CONFIG] ca-key is required`](#orgbcf1af5)
    2.  [PARAM - Parameter Errors](#org61d8d30)
        1.  [`[CA:PARAM] validity-days must be positive`](#orgc2196e6)
        2.  [`[CA:PARAM] serial must be positive`](#org46c3005)
    3.  [SSL - OpenSSL Errors](#org8f41692)
        1.  [`[CA:SSL] failed to sign certificate: <ssl-error>`](#org9a1220b)
        2.  [`[CA:SSL] failed to create certificate: <ssl-error>`](#orgb8c6ce1)
    4.  [VERIFY - Verification Errors](#org41f829b)
        1.  [`[CA:VERIFY] certificate has expired`](#org9af14d1)
        2.  [`[CA:VERIFY] certificate not yet valid`](#org1859ffd)
6.  [CERT Module Errors](#org1434546)
    1.  [PARAM - Parameter Errors](#orgae8351e)
        1.  [`[CERT:PARAM] certificates must be string or array of strings`](#org8f46178)
    2.  [PARSE - Parse Errors](#org39fe582)
        1.  [`[CERT:PARSE] failed to parse certificate: <ssl-error>`](#org037ae9b)
        2.  [`[CERT:PARSE] failed to parse private key: <ssl-error>`](#org3ada31c)
7.  [Error Handling Best Practices](#org24da325)
    1.  [Using protect/try](#orga7f6349)
    2.  [Checking Return Values](#org677690f)
    3.  [Timeouts](#orgc517b60)
8.  [Testing Error Conditions](#org2af9cb4)
9.  [See Also](#org8e64120)



<a id="orgf72cd3f"></a>

# Overview

This document catalogs all errors that JSEC can produce, organized by module and category.


<a id="org3c419b2"></a>

## Error Format

All errors follow a standardized format:

    [MODULE:CATEGORY] message: detail

Where:

-   **MODULE**: TLS, DTLS, CRYPTO, CA, CERT, UTILS
-   **CATEGORY**: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY, PARSE


<a id="org793af63"></a>

## Example Errors

    [TLS:CONFIG] invalid cipher suite: RC4-MD5
    [DTLS:SOCKET] bind failed: address already in use
    [CRYPTO:PARAM] output length must be 1-1024, got 2000
    [CA:SSL] failed to sign certificate: key mismatch


<a id="orga9dc13e"></a>

# TLS Module Errors


<a id="org033d2a9"></a>

## CONFIG - Configuration Errors


<a id="org3528420"></a>

### `[TLS:CONFIG] buffer-size must be a number`

**When**: Non-numeric `:buffer-size` option
**Fix**: Pass a positive integer

    # Wrong
    (tls/connect "host" "443" {:buffer-size "big"})
    
    # Correct
    (tls/connect "host" "443" {:buffer-size 16384})


<a id="orgc5680c2"></a>

### `[TLS:CONFIG] invalid cipher suite: <suite>`

**When**: Unrecognized or disabled cipher suite specified
**Fix**: Use valid OpenSSL cipher string


<a id="orge32c3c2"></a>

### `[TLS:CONFIG] sni option must be a table or struct`

**When**: Invalid `:sni` option format for server context
**Fix**: Pass table mapping hostnames to cert/key configs

    {:sni {"api.example.com" {:cert api-cert :key api-key}
           "www.example.com" {:cert www-cert :key www-key}}}


<a id="org71899ce"></a>

### `[TLS:CONFIG] Invalid ALPN protocols`

**When**: Invalid `:alpn` option format
**Fix**: Pass array of protocol strings

    {:alpn ["h2" "http/1.1"]}


<a id="orgf943e00"></a>

### `[TLS:CONFIG] handler function must take at least 1 argument`

**When**: Server handler function has wrong arity
**Fix**: Handler must accept at least the stream argument

    # Wrong
    (tls/server "0.0.0.0" "8443" (fn [] (print "no args")) opts)
    
    # Correct
    (tls/server "0.0.0.0" "8443" (fn [stream] (:close stream)) opts)


<a id="org0e12674"></a>

## PARAM - Parameter Errors


<a id="orgb81e3a7"></a>

### `[TLS:PARAM] timeout must be non-negative, got <value>`

**When**: Passing negative timeout value to I/O operations
**Fix**: Use zero or positive timeout (seconds)

    # Wrong
    (:read stream -1)
    
    # Correct
    (:read stream 1024 5.0)  # 5 second timeout


<a id="org7ef93a3"></a>

### `[TLS:PARAM] expected keyword or nil, got <value>`

**When**: Passing wrong type to `:close` method
**Fix**: Pass `:r`, `:w`, `:rw`, or `nil`

    # Wrong
    (:close stream "both")
    
    # Correct
    (:close stream :rw)  # Close both directions
    (:close stream)      # Same as :rw


<a id="org465187d"></a>

### `[TLS:PARAM] length must be non-negative`

**When**: Negative length to read operations
**Fix**: Pass zero or positive length


<a id="org0ad2ba9"></a>

## IO - I/O Errors


<a id="org809a60c"></a>

### `[TLS:IO] stream is closed`

**When**: I/O on a closed TLS stream
**Fix**: Don't use stream after closing

    (def stream (tls/connect "host" "443"))
    (:close stream)
    (:read stream 1024)  # Error! Stream is closed


<a id="orgf2f32b8"></a>

### `[TLS:IO] connection is shutting down`

**When**: Write attempt during TLS shutdown
**Fix**: Complete shutdown before further operations


<a id="org8784c49"></a>

## SSL - OpenSSL Errors


<a id="org9eb457e"></a>

### `[TLS:SSL] failed to create SSL context: <ssl-error>`

**When**: SSL<sub>CTX</sub><sub>new</sub>() failed
**Fix**: Check OpenSSL installation, memory


<a id="orgecd9a6c"></a>

### `[TLS:SSL] failed to create SSL object: <ssl-error>`

**When**: SSL<sub>new</sub>() failed
**Fix**: Check context validity, memory


<a id="orgaaec826"></a>

### `[TLS:SSL] handshake failed: <ssl-error>`

**When**: TLS handshake failed
**Fix**: Check certificates, protocol compatibility


<a id="org674ff1b"></a>

### `[TLS:SSL] certificate verification failed: <ssl-error>`

**When**: Peer certificate verification failed
**Fix**: Check certificate chain, CA trust


<a id="org9a0c9c6"></a>

### `[TLS:SSL] failed to load private key: <ssl-error>`

**When**: Private key PEM parsing failed
**Fix**: Verify key format, check for corruption


<a id="org620a60c"></a>

### `[TLS:SSL] failed to load certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org8e86bad"></a>

### `[TLS:SSL] private key does not match certificate: <ssl-error>`

**When**: Certificate/key mismatch in server config
**Fix**: Ensure cert and key are a matching pair


<a id="org4965dff"></a>

## SOCKET - Socket Errors


<a id="orgdd1c82e"></a>

### `[TLS:SOCKET] could not connect to <host>:<port>: <errno>`

**When**: TCP connection failed
**Fix**: Check host/port, firewall, server status


<a id="org02e676d"></a>

### `[TLS:SOCKET] bind failed: <errno>`

**When**: Server bind failed
**Fix**: Check port availability, permissions


<a id="org9372630"></a>

### `[TLS:SOCKET] listen failed: <errno>`

**When**: Socket listen() failed
**Fix**: Check socket state


<a id="orgd315eff"></a>

### `[TLS:SOCKET] getaddrinfo failed: <errno>`

**When**: DNS resolution failed
**Fix**: Check hostname, DNS configuration


<a id="org75176d7"></a>

## VERIFY - Verification Errors


<a id="org4a85405"></a>

### `[TLS:VERIFY] hostname verification failed for <hostname>`

**When**: Certificate doesn't match expected hostname
**Fix**: Check certificate SAN/CN, or disable verification if intended


<a id="org7a53b5a"></a>

# DTLS Module Errors


<a id="orgad4d29a"></a>

## CONFIG - Configuration Errors


<a id="org61300ff"></a>

### `[DTLS:CONFIG] dtls/listen requires :cert and :key options`

**When**: DTLS server missing required certificate/key
**Fix**: Provide certificate and private key

    (dtls/listen "0.0.0.0" "5684" {:cert cert-pem :key key-pem})


<a id="org2bf3467"></a>

### `[DTLS:CONFIG] cannot use TLS context for DTLS connection`

**When**: Passing a TLS context to DTLS functions
**Fix**: Create a DTLS-specific context or use options


<a id="orgf0d6cdd"></a>

## PARAM - Parameter Errors


<a id="orgd1b314c"></a>

### `[DTLS:PARAM] invalid address: <address>`

**When**: Cannot parse host address
**Fix**: Use valid IPv4/IPv6 address or hostname


<a id="org481166b"></a>

## IO - I/O Errors


<a id="orgc044b24"></a>

### `[DTLS:IO] client not connected`

**When**: I/O on unconnected DTLS client
**Fix**: Complete handshake first


<a id="orgfb6235d"></a>

### `[DTLS:IO] client is closed`

**When**: Operations on closed DTLS client
**Fix**: Don't use client after closing


<a id="orgbfa68cc"></a>

### `[DTLS:IO] server is closed`

**When**: Operations on closed DTLS server
**Fix**: Don't use server after closing


<a id="org2133516"></a>

### `[DTLS:IO] no session for peer address`

**When**: DTLS send to unknown peer
**Fix**: Peer must complete handshake first


<a id="org4700790"></a>

### `[DTLS:IO] session not established`

**When**: DTLS send before handshake complete
**Fix**: Wait for handshake completion


<a id="orgc888e2c"></a>

## SSL - OpenSSL Errors


<a id="orgdd38cfe"></a>

### `[DTLS:SSL] handshake failed: <ssl-error>`

**When**: DTLS handshake failed
**Fix**: Check certificates, network connectivity


<a id="org62d1cc2"></a>

### `[DTLS:SSL] write failed: <ssl-error>`

**When**: DTLS write operation failed
**Fix**: Check connection state


<a id="orgf221da1"></a>

## SOCKET - Socket Errors


<a id="orgc2b093a"></a>

### `[DTLS:SOCKET] bind failed: <errno>`

**When**: DTLS bind failed
**Fix**: Check address/port availability


<a id="orgc2df5f3"></a>

### `[DTLS:SOCKET] connect failed: <errno>`

**When**: DTLS connect failed
**Fix**: Check server reachability


<a id="orgba6f2bc"></a>

### `[DTLS:SOCKET] sendto failed: <errno>`

**When**: DTLS sendto() failed
**Fix**: Check connection state, buffer size


<a id="org1a0b1e2"></a>

### `[DTLS:SOCKET] failed to get peer address: <errno>`

**When**: getpeername() failed on DTLS upgrade
**Fix**: Socket must be connected before upgrade


<a id="org23449e5"></a>

# CRYPTO Module Errors


<a id="orgd64447a"></a>

## CONFIG - Configuration Errors


<a id="org59214e9"></a>

### `[CRYPTO:CONFIG] unknown digest algorithm: <alg>`

**When**: Invalid hash algorithm name
**Fix**: Use supported algorithm (sha256, sha384, sha512, etc.)

    (crypto/digest :sha256 data)  # Correct
    (crypto/digest :md5 data)     # May fail depending on OpenSSL config


<a id="org3142fb6"></a>

### `[CRYPTO:CONFIG] unsupported key algorithm: <alg>`

**When**: Invalid algorithm for key generation
**Fix**: Use supported algorithm

    # Supported: :rsa, :ed25519, :x25519, :ec-p256, :ec-p384, :ec-p521
    (crypto/generate-keypair :ec-p256)  # Correct
    (crypto/generate-keypair :dsa)       # Error: unsupported


<a id="org5a5b170"></a>

## PARAM - Parameter Errors


<a id="org7bc83f2"></a>

### `[CRYPTO:PARAM] byte count must be 1-65536, got <n>`

**When**: Requesting too many or too few random bytes
**Fix**: Request between 1 and 65536 bytes

    (crypto/random-bytes 32)  # Correct: 32 bytes


<a id="org7bbd4fa"></a>

### `[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`

**When**: Invalid challenge length for `crypto/random-challenge`
**Fix**: Request between 8 and 64 bytes


<a id="orge1141db"></a>

### `[CRYPTO:PARAM] output length must be 1-<max>`

**When**: HKDF output length exceeds maximum (255 \* hash-size)
**Fix**: Request smaller output


<a id="orgc0374ce"></a>

### `[CRYPTO:PARAM] output length must be 1-1024`

**When**: PBKDF2 output length out of range
**Fix**: Request between 1 and 1024 bytes


<a id="org42ff729"></a>

### `[CRYPTO:PARAM] iterations must be positive`

**When**: Non-positive iteration count for PBKDF2
**Fix**: Use at least 1 iteration (recommend 100000+ for security)


<a id="org2d8e39e"></a>

### `[CRYPTO:PARAM] options must be a table or struct`

**When**: Passing non-table/struct to functions expecting options
**Fix**: Pass a table `{}` or struct `@{}`


<a id="org8e67dba"></a>

## SSL - OpenSSL Errors


<a id="orgfa49805"></a>

### `[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`

**When**: Key derivation operation failed
**Fix**: Check input parameters


<a id="orgc034c6a"></a>

### `[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`

**When**: PBKDF2 operation failed
**Fix**: Check input parameters


<a id="orgbe1ad91"></a>

### `[CRYPTO:SSL] HMAC computation failed: <ssl-error>`

**When**: HMAC operation failed
**Fix**: Check algorithm and key


<a id="org8d26adb"></a>

### `[CRYPTO:SSL] signing failed: <ssl-error>`

**When**: Signature operation failed
**Fix**: Check key type supports signing


<a id="orgcd928eb"></a>

### `[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`

**When**: Entropy source failure
**Fix**: Check system entropy (/dev/urandom)


<a id="orgd08775a"></a>

## RESOURCE - Resource Errors


<a id="orgeb01ac9"></a>

### `[CRYPTO:RESOURCE] out of memory`

**When**: Memory allocation failed
**Fix**: Check system memory, reduce allocations


<a id="orgd412382"></a>

### `[CRYPTO:RESOURCE] failed to create context`

**When**: EVP context allocation failed
**Fix**: Check memory, OpenSSL state


<a id="orgda3e0f0"></a>

## PARSE - Parse Errors


<a id="orgfa7c6b9"></a>

### `[CRYPTO:PARSE] base64 decode failed`

**When**: Invalid base64 input
**Fix**: Verify input is valid base64


<a id="org65ae357"></a>

### `[CRYPTO:PARSE] failed to parse CSR`

**When**: CSR parsing failed
**Fix**: Check CSR data validity


<a id="org644b0c9"></a>

# CA Module Errors


<a id="orgdc9b51f"></a>

## CONFIG - Configuration Errors


<a id="org430898a"></a>

### `[CA:CONFIG] common-name is required`

**When**: Certificate issuance without CN
**Fix**: Provide :cn option


<a id="orgf4f75ce"></a>

### `[CA:CONFIG] ca-cert is required`

**When**: CA operations without CA certificate
**Fix**: Provide CA certificate PEM


<a id="orgbcf1af5"></a>

### `[CA:CONFIG] ca-key is required`

**When**: CA operations without CA private key
**Fix**: Provide CA private key PEM


<a id="org61d8d30"></a>

## PARAM - Parameter Errors


<a id="orgc2196e6"></a>

### `[CA:PARAM] validity-days must be positive`

**When**: Invalid certificate validity period
**Fix**: Use positive number of days


<a id="org46c3005"></a>

### `[CA:PARAM] serial must be positive`

**When**: Invalid certificate serial number
**Fix**: Use positive serial number


<a id="org8f41692"></a>

## SSL - OpenSSL Errors


<a id="org9a1220b"></a>

### `[CA:SSL] failed to sign certificate: <ssl-error>`

**When**: Certificate signing failed
**Fix**: Check CA key compatibility


<a id="orgb8c6ce1"></a>

### `[CA:SSL] failed to create certificate: <ssl-error>`

**When**: X509 creation failed
**Fix**: Check memory, parameters


<a id="org41f829b"></a>

## VERIFY - Verification Errors


<a id="org9af14d1"></a>

### `[CA:VERIFY] certificate has expired`

**When**: Certificate past its validity period
**Fix**: Renew certificate


<a id="org1859ffd"></a>

### `[CA:VERIFY] certificate not yet valid`

**When**: Certificate not yet in validity period
**Fix**: Check system time, certificate dates


<a id="org1434546"></a>

# CERT Module Errors


<a id="orgae8351e"></a>

## PARAM - Parameter Errors


<a id="org8f46178"></a>

### `[CERT:PARAM] certificates must be string or array of strings`

**When**: Invalid certificate format in operations
**Fix**: Pass PEM string or array of PEM strings


<a id="org39fe582"></a>

## PARSE - Parse Errors


<a id="org037ae9b"></a>

### `[CERT:PARSE] failed to parse certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org3ada31c"></a>

### `[CERT:PARSE] failed to parse private key: <ssl-error>`

**When**: Private key parsing failed
**Fix**: Verify key format


<a id="org24da325"></a>

# Error Handling Best Practices


<a id="orga7f6349"></a>

## Using protect/try

    (def result
      (protect
        (tls/connect "untrusted.example.com" "443" {:verify true})))
    
    (if (nil? result)
      (print "Connection failed - check certificate")
      (do-something-with result))


<a id="org677690f"></a>

## Checking Return Values

Many functions return `nil` on failure:

    (when-let [stream (tls/connect host port opts)]
      (defer (:close stream)
        (process-stream stream)))


<a id="orgc517b60"></a>

## Timeouts

Always use timeouts for network operations:

    (def data (:read stream 1024 30.0))  # 30 second timeout
    (when (nil? data)
      (print "Read timed out or connection closed"))


<a id="org2af9cb4"></a>

# Testing Error Conditions

To test that your code handles errors correctly, use janet-assay's
`:expected-fail` feature for negative testing:

    (import assay)
    
    (assay/def-suite "error-handling"
      (assay/def-test "rejects invalid iterations"
        :expected-fail "[CRYPTO:PARAM]"
        (crypto/pbkdf2 :sha256 "password" "salt" 0 32)))


<a id="org8e64120"></a>

# See Also

-   [API Reference](API.md) - Complete function documentation
-   [User Guide](GUIDE.md) - Getting started and examples
-   [Developer Guide](DEVELOPERS.md) - Contributing and internals

