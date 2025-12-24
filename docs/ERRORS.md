
# Table of Contents

1.  [Overview](#org6a3cc21)
    1.  [Error Format](#org382af87)
    2.  [Example Errors](#org64148fb)
2.  [TLS Module Errors](#org5c9dd8c)
    1.  [CONFIG - Configuration Errors](#orgdee5986)
        1.  [`[TLS:CONFIG] buffer-size must be a number`](#org6a744cf)
        2.  [`[TLS:CONFIG] invalid cipher suite: <suite>`](#org1f16e68)
        3.  [`[TLS:CONFIG] sni option must be a table or struct`](#org9dc720a)
        4.  [`[TLS:CONFIG] Invalid ALPN protocols`](#org3e1bdaa)
        5.  [`[TLS:CONFIG] handler function must take at least 1 argument`](#org2a70611)
    2.  [PARAM - Parameter Errors](#org5d877a9)
        1.  [`[TLS:PARAM] timeout must be non-negative, got <value>`](#orga233ca0)
        2.  [`[TLS:PARAM] expected keyword or nil, got <value>`](#org50c3d70)
        3.  [`[TLS:PARAM] length must be non-negative`](#org2090f15)
    3.  [IO - I/O Errors](#org2e2f5e4)
        1.  [`[TLS:IO] stream is closed`](#org5d17f54)
        2.  [`[TLS:IO] connection is shutting down`](#orgc96b5ef)
    4.  [SSL - OpenSSL Errors](#orgdfbf004)
        1.  [`[TLS:SSL] failed to create SSL context: <ssl-error>`](#org84f5176)
        2.  [`[TLS:SSL] failed to create SSL object: <ssl-error>`](#org2f98d3c)
        3.  [`[TLS:SSL] handshake failed: <ssl-error>`](#orgfacb9ce)
        4.  [`[TLS:SSL] certificate verification failed: <ssl-error>`](#orgcea65e6)
        5.  [`[TLS:SSL] failed to load private key: <ssl-error>`](#org1cf172f)
        6.  [`[TLS:SSL] failed to load certificate: <ssl-error>`](#org0a36b28)
        7.  [`[TLS:SSL] private key does not match certificate: <ssl-error>`](#org48dcef0)
    5.  [SOCKET - Socket Errors](#org7be19e9)
        1.  [`[TLS:SOCKET] could not connect to <host>:<port>: <errno>`](#org694bd2d)
        2.  [`[TLS:SOCKET] bind failed: <errno>`](#orgd4099f5)
        3.  [`[TLS:SOCKET] listen failed: <errno>`](#org4261816)
        4.  [`[TLS:SOCKET] getaddrinfo failed: <errno>`](#org3b1915c)
    6.  [VERIFY - Verification Errors](#org60c864e)
        1.  [`[TLS:VERIFY] hostname verification failed for <hostname>`](#org2f62241)
3.  [DTLS Module Errors](#org1e28014)
    1.  [CONFIG - Configuration Errors](#orgd50bb12)
        1.  [`[DTLS:CONFIG] dtls/listen requires :cert and :key options`](#org8b71765)
        2.  [`[DTLS:CONFIG] cannot use TLS context for DTLS connection`](#org3cdf4ee)
    2.  [PARAM - Parameter Errors](#org3fc4c87)
        1.  [`[DTLS:PARAM] invalid address: <address>`](#org367ab61)
    3.  [IO - I/O Errors](#org0fa1fc0)
        1.  [`[DTLS:IO] client not connected`](#org2e52241)
        2.  [`[DTLS:IO] client is closed`](#org7484d01)
        3.  [`[DTLS:IO] server is closed`](#orgb2c036d)
        4.  [`[DTLS:IO] no session for peer address`](#org3e9fe7f)
        5.  [`[DTLS:IO] session not established`](#org0efd029)
    4.  [SSL - OpenSSL Errors](#org34099f9)
        1.  [`[DTLS:SSL] handshake failed: <ssl-error>`](#org4440d5c)
        2.  [`[DTLS:SSL] write failed: <ssl-error>`](#orgcad81a4)
    5.  [SOCKET - Socket Errors](#org62c14ed)
        1.  [`[DTLS:SOCKET] bind failed: <errno>`](#org20e0ffe)
        2.  [`[DTLS:SOCKET] connect failed: <errno>`](#org0d6d2d7)
        3.  [`[DTLS:SOCKET] sendto failed: <errno>`](#orga7d891d)
        4.  [`[DTLS:SOCKET] failed to get peer address: <errno>`](#orgcc998b6)
4.  [CRYPTO Module Errors](#orgcea5fa7)
    1.  [CONFIG - Configuration Errors](#org13ebf96)
        1.  [`[CRYPTO:CONFIG] unknown digest algorithm: <alg>`](#org32505f7)
        2.  [`[CRYPTO:CONFIG] unsupported key algorithm: <alg>`](#orga5bb690)
    2.  [PARAM - Parameter Errors](#orgb42e8b0)
        1.  [`[CRYPTO:PARAM] byte count must be 1-65536, got <n>`](#org509782d)
        2.  [`[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`](#orgdf063d2)
        3.  [`[CRYPTO:PARAM] output length must be 1-<max>`](#org9ab58b1)
        4.  [`[CRYPTO:PARAM] output length must be 1-1024`](#org3e13883)
        5.  [`[CRYPTO:PARAM] iterations must be positive`](#org7ce0239)
        6.  [`[CRYPTO:PARAM] options must be a table or struct`](#org327e5ba)
    3.  [SSL - OpenSSL Errors](#org926134c)
        1.  [`[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`](#orga0c7fca)
        2.  [`[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`](#org7421da1)
        3.  [`[CRYPTO:SSL] HMAC computation failed: <ssl-error>`](#orgd36da04)
        4.  [`[CRYPTO:SSL] signing failed: <ssl-error>`](#orgb9bafa2)
        5.  [`[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`](#org51e8f2d)
    4.  [RESOURCE - Resource Errors](#orgdbcc35d)
        1.  [`[CRYPTO:RESOURCE] out of memory`](#orgb8e88df)
        2.  [`[CRYPTO:RESOURCE] failed to create context`](#org61c56d8)
    5.  [PARSE - Parse Errors](#orgeabb329)
        1.  [`[CRYPTO:PARSE] base64 decode failed`](#orgbf8cb4c)
        2.  [`[CRYPTO:PARSE] failed to parse CSR`](#org1a37e97)
5.  [CA Module Errors](#orgaa1ee62)
    1.  [CONFIG - Configuration Errors](#orgfa44e8c)
        1.  [`[CA:CONFIG] common-name is required`](#org9b3652c)
        2.  [`[CA:CONFIG] ca-cert is required`](#orgc5e6e50)
        3.  [`[CA:CONFIG] ca-key is required`](#org5eb9ac9)
    2.  [PARAM - Parameter Errors](#org9e54da2)
        1.  [`[CA:PARAM] validity-days must be positive`](#orgfbeba43)
        2.  [`[CA:PARAM] serial must be positive`](#org99a3afb)
    3.  [SSL - OpenSSL Errors](#org3f2df47)
        1.  [`[CA:SSL] failed to sign certificate: <ssl-error>`](#orgb04f8f3)
        2.  [`[CA:SSL] failed to create certificate: <ssl-error>`](#org0a80156)
    4.  [VERIFY - Verification Errors](#orgd780b01)
        1.  [`[CA:VERIFY] certificate has expired`](#org714adb4)
        2.  [`[CA:VERIFY] certificate not yet valid`](#orgacad595)
6.  [CERT Module Errors](#org4812ad2)
    1.  [PARAM - Parameter Errors](#org8ffe56f)
        1.  [`[CERT:PARAM] certificates must be string or array of strings`](#org8608e3b)
    2.  [PARSE - Parse Errors](#orga4d7e01)
        1.  [`[CERT:PARSE] failed to parse certificate: <ssl-error>`](#org3181467)
        2.  [`[CERT:PARSE] failed to parse private key: <ssl-error>`](#org24769d3)
7.  [Error Handling Best Practices](#org0e907d4)
    1.  [Using protect/try](#orge39894d)
    2.  [Checking Return Values](#org74ea52a)
    3.  [Timeouts](#org7c58932)
8.  [Testing Error Conditions](#orgeeec4cb)
9.  [See Also](#org607dd1e)



<a id="org6a3cc21"></a>

# Overview

This document catalogs all errors that JSEC can produce, organized by module and category.


<a id="org382af87"></a>

## Error Format

All errors follow a standardized format:

    [MODULE:CATEGORY] message: detail

Where:

-   **MODULE**: TLS, DTLS, CRYPTO, CA, CERT, UTILS
-   **CATEGORY**: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY, PARSE


<a id="org64148fb"></a>

## Example Errors

    [TLS:CONFIG] invalid cipher suite: RC4-MD5
    [DTLS:SOCKET] bind failed: address already in use
    [CRYPTO:PARAM] output length must be 1-1024, got 2000
    [CA:SSL] failed to sign certificate: key mismatch


<a id="org5c9dd8c"></a>

# TLS Module Errors


<a id="orgdee5986"></a>

## CONFIG - Configuration Errors


<a id="org6a744cf"></a>

### `[TLS:CONFIG] buffer-size must be a number`

**When**: Non-numeric `:buffer-size` option
**Fix**: Pass a positive integer

    # Wrong
    (tls/connect "host" "443" {:buffer-size "big"})
    
    # Correct
    (tls/connect "host" "443" {:buffer-size 16384})


<a id="org1f16e68"></a>

### `[TLS:CONFIG] invalid cipher suite: <suite>`

**When**: Unrecognized or disabled cipher suite specified
**Fix**: Use valid OpenSSL cipher string


<a id="org9dc720a"></a>

### `[TLS:CONFIG] sni option must be a table or struct`

**When**: Invalid `:sni` option format for server context
**Fix**: Pass table mapping hostnames to cert/key configs

    {:sni {"api.example.com" {:cert api-cert :key api-key}
           "www.example.com" {:cert www-cert :key www-key}}}


<a id="org3e1bdaa"></a>

### `[TLS:CONFIG] Invalid ALPN protocols`

**When**: Invalid `:alpn` option format
**Fix**: Pass array of protocol strings

    {:alpn ["h2" "http/1.1"]}


<a id="org2a70611"></a>

### `[TLS:CONFIG] handler function must take at least 1 argument`

**When**: Server handler function has wrong arity
**Fix**: Handler must accept at least the stream argument

    # Wrong
    (tls/server "0.0.0.0" "8443" (fn [] (print "no args")) opts)
    
    # Correct
    (tls/server "0.0.0.0" "8443" (fn [stream] (:close stream)) opts)


<a id="org5d877a9"></a>

## PARAM - Parameter Errors


<a id="orga233ca0"></a>

### `[TLS:PARAM] timeout must be non-negative, got <value>`

**When**: Passing negative timeout value to I/O operations
**Fix**: Use zero or positive timeout (seconds)

    # Wrong
    (:read stream -1)
    
    # Correct
    (:read stream 1024 5.0)  # 5 second timeout


<a id="org50c3d70"></a>

### `[TLS:PARAM] expected keyword or nil, got <value>`

**When**: Passing wrong type to `:close` method
**Fix**: Pass `:r`, `:w`, `:rw`, or `nil`

    # Wrong
    (:close stream "both")
    
    # Correct
    (:close stream :rw)  # Close both directions
    (:close stream)      # Same as :rw


<a id="org2090f15"></a>

### `[TLS:PARAM] length must be non-negative`

**When**: Negative length to read operations
**Fix**: Pass zero or positive length


<a id="org2e2f5e4"></a>

## IO - I/O Errors


<a id="org5d17f54"></a>

### `[TLS:IO] stream is closed`

**When**: I/O on a closed TLS stream
**Fix**: Don't use stream after closing

    (def stream (tls/connect "host" "443"))
    (:close stream)
    (:read stream 1024)  # Error! Stream is closed


<a id="orgc96b5ef"></a>

### `[TLS:IO] connection is shutting down`

**When**: Write attempt during TLS shutdown
**Fix**: Complete shutdown before further operations


<a id="orgdfbf004"></a>

## SSL - OpenSSL Errors


<a id="org84f5176"></a>

### `[TLS:SSL] failed to create SSL context: <ssl-error>`

**When**: SSL<sub>CTX</sub><sub>new</sub>() failed
**Fix**: Check OpenSSL installation, memory


<a id="org2f98d3c"></a>

### `[TLS:SSL] failed to create SSL object: <ssl-error>`

**When**: SSL<sub>new</sub>() failed
**Fix**: Check context validity, memory


<a id="orgfacb9ce"></a>

### `[TLS:SSL] handshake failed: <ssl-error>`

**When**: TLS handshake failed
**Fix**: Check certificates, protocol compatibility


<a id="orgcea65e6"></a>

### `[TLS:SSL] certificate verification failed: <ssl-error>`

**When**: Peer certificate verification failed
**Fix**: Check certificate chain, CA trust


<a id="org1cf172f"></a>

### `[TLS:SSL] failed to load private key: <ssl-error>`

**When**: Private key PEM parsing failed
**Fix**: Verify key format, check for corruption


<a id="org0a36b28"></a>

### `[TLS:SSL] failed to load certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org48dcef0"></a>

### `[TLS:SSL] private key does not match certificate: <ssl-error>`

**When**: Certificate/key mismatch in server config
**Fix**: Ensure cert and key are a matching pair


<a id="org7be19e9"></a>

## SOCKET - Socket Errors


<a id="org694bd2d"></a>

### `[TLS:SOCKET] could not connect to <host>:<port>: <errno>`

**When**: TCP connection failed
**Fix**: Check host/port, firewall, server status


<a id="orgd4099f5"></a>

### `[TLS:SOCKET] bind failed: <errno>`

**When**: Server bind failed
**Fix**: Check port availability, permissions


<a id="org4261816"></a>

### `[TLS:SOCKET] listen failed: <errno>`

**When**: Socket listen() failed
**Fix**: Check socket state


<a id="org3b1915c"></a>

### `[TLS:SOCKET] getaddrinfo failed: <errno>`

**When**: DNS resolution failed
**Fix**: Check hostname, DNS configuration


<a id="org60c864e"></a>

## VERIFY - Verification Errors


<a id="org2f62241"></a>

### `[TLS:VERIFY] hostname verification failed for <hostname>`

**When**: Certificate doesn't match expected hostname
**Fix**: Check certificate SAN/CN, or disable verification if intended


<a id="org1e28014"></a>

# DTLS Module Errors


<a id="orgd50bb12"></a>

## CONFIG - Configuration Errors


<a id="org8b71765"></a>

### `[DTLS:CONFIG] dtls/listen requires :cert and :key options`

**When**: DTLS server missing required certificate/key
**Fix**: Provide certificate and private key

    (dtls/listen "0.0.0.0" "5684" {:cert cert-pem :key key-pem})


<a id="org3cdf4ee"></a>

### `[DTLS:CONFIG] cannot use TLS context for DTLS connection`

**When**: Passing a TLS context to DTLS functions
**Fix**: Create a DTLS-specific context or use options


<a id="org3fc4c87"></a>

## PARAM - Parameter Errors


<a id="org367ab61"></a>

### `[DTLS:PARAM] invalid address: <address>`

**When**: Cannot parse host address
**Fix**: Use valid IPv4/IPv6 address or hostname


<a id="org0fa1fc0"></a>

## IO - I/O Errors


<a id="org2e52241"></a>

### `[DTLS:IO] client not connected`

**When**: I/O on unconnected DTLS client
**Fix**: Complete handshake first


<a id="org7484d01"></a>

### `[DTLS:IO] client is closed`

**When**: Operations on closed DTLS client
**Fix**: Don't use client after closing


<a id="orgb2c036d"></a>

### `[DTLS:IO] server is closed`

**When**: Operations on closed DTLS server
**Fix**: Don't use server after closing


<a id="org3e9fe7f"></a>

### `[DTLS:IO] no session for peer address`

**When**: DTLS send to unknown peer
**Fix**: Peer must complete handshake first


<a id="org0efd029"></a>

### `[DTLS:IO] session not established`

**When**: DTLS send before handshake complete
**Fix**: Wait for handshake completion


<a id="org34099f9"></a>

## SSL - OpenSSL Errors


<a id="org4440d5c"></a>

### `[DTLS:SSL] handshake failed: <ssl-error>`

**When**: DTLS handshake failed
**Fix**: Check certificates, network connectivity


<a id="orgcad81a4"></a>

### `[DTLS:SSL] write failed: <ssl-error>`

**When**: DTLS write operation failed
**Fix**: Check connection state


<a id="org62c14ed"></a>

## SOCKET - Socket Errors


<a id="org20e0ffe"></a>

### `[DTLS:SOCKET] bind failed: <errno>`

**When**: DTLS bind failed
**Fix**: Check address/port availability


<a id="org0d6d2d7"></a>

### `[DTLS:SOCKET] connect failed: <errno>`

**When**: DTLS connect failed
**Fix**: Check server reachability


<a id="orga7d891d"></a>

### `[DTLS:SOCKET] sendto failed: <errno>`

**When**: DTLS sendto() failed
**Fix**: Check connection state, buffer size


<a id="orgcc998b6"></a>

### `[DTLS:SOCKET] failed to get peer address: <errno>`

**When**: getpeername() failed on DTLS upgrade
**Fix**: Socket must be connected before upgrade


<a id="orgcea5fa7"></a>

# CRYPTO Module Errors


<a id="org13ebf96"></a>

## CONFIG - Configuration Errors


<a id="org32505f7"></a>

### `[CRYPTO:CONFIG] unknown digest algorithm: <alg>`

**When**: Invalid hash algorithm name
**Fix**: Use supported algorithm (sha256, sha384, sha512, etc.)

    (crypto/digest :sha256 data)  # Correct
    (crypto/digest :md5 data)     # May fail depending on OpenSSL config


<a id="orga5bb690"></a>

### `[CRYPTO:CONFIG] unsupported key algorithm: <alg>`

**When**: Invalid algorithm for key generation
**Fix**: Use supported algorithm

    # Supported: :rsa, :ed25519, :x25519, :ec-p256, :ec-p384, :ec-p521
    (crypto/generate-keypair :ec-p256)  # Correct
    (crypto/generate-keypair :dsa)       # Error: unsupported


<a id="orgb42e8b0"></a>

## PARAM - Parameter Errors


<a id="org509782d"></a>

### `[CRYPTO:PARAM] byte count must be 1-65536, got <n>`

**When**: Requesting too many or too few random bytes
**Fix**: Request between 1 and 65536 bytes

    (crypto/random-bytes 32)  # Correct: 32 bytes


<a id="orgdf063d2"></a>

### `[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`

**When**: Invalid challenge length for `crypto/random-challenge`
**Fix**: Request between 8 and 64 bytes


<a id="org9ab58b1"></a>

### `[CRYPTO:PARAM] output length must be 1-<max>`

**When**: HKDF output length exceeds maximum (255 \* hash-size)
**Fix**: Request smaller output


<a id="org3e13883"></a>

### `[CRYPTO:PARAM] output length must be 1-1024`

**When**: PBKDF2 output length out of range
**Fix**: Request between 1 and 1024 bytes


<a id="org7ce0239"></a>

### `[CRYPTO:PARAM] iterations must be positive`

**When**: Non-positive iteration count for PBKDF2
**Fix**: Use at least 1 iteration (recommend 100000+ for security)


<a id="org327e5ba"></a>

### `[CRYPTO:PARAM] options must be a table or struct`

**When**: Passing non-table/struct to functions expecting options
**Fix**: Pass a table `{}` or struct `@{}`


<a id="org926134c"></a>

## SSL - OpenSSL Errors


<a id="orga0c7fca"></a>

### `[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`

**When**: Key derivation operation failed
**Fix**: Check input parameters


<a id="org7421da1"></a>

### `[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`

**When**: PBKDF2 operation failed
**Fix**: Check input parameters


<a id="orgd36da04"></a>

### `[CRYPTO:SSL] HMAC computation failed: <ssl-error>`

**When**: HMAC operation failed
**Fix**: Check algorithm and key


<a id="orgb9bafa2"></a>

### `[CRYPTO:SSL] signing failed: <ssl-error>`

**When**: Signature operation failed
**Fix**: Check key type supports signing


<a id="org51e8f2d"></a>

### `[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`

**When**: Entropy source failure
**Fix**: Check system entropy (/dev/urandom)


<a id="orgdbcc35d"></a>

## RESOURCE - Resource Errors


<a id="orgb8e88df"></a>

### `[CRYPTO:RESOURCE] out of memory`

**When**: Memory allocation failed
**Fix**: Check system memory, reduce allocations


<a id="org61c56d8"></a>

### `[CRYPTO:RESOURCE] failed to create context`

**When**: EVP context allocation failed
**Fix**: Check memory, OpenSSL state


<a id="orgeabb329"></a>

## PARSE - Parse Errors


<a id="orgbf8cb4c"></a>

### `[CRYPTO:PARSE] base64 decode failed`

**When**: Invalid base64 input
**Fix**: Verify input is valid base64


<a id="org1a37e97"></a>

### `[CRYPTO:PARSE] failed to parse CSR`

**When**: CSR parsing failed
**Fix**: Check CSR data validity


<a id="orgaa1ee62"></a>

# CA Module Errors


<a id="orgfa44e8c"></a>

## CONFIG - Configuration Errors


<a id="org9b3652c"></a>

### `[CA:CONFIG] common-name is required`

**When**: Certificate issuance without CN
**Fix**: Provide :cn option


<a id="orgc5e6e50"></a>

### `[CA:CONFIG] ca-cert is required`

**When**: CA operations without CA certificate
**Fix**: Provide CA certificate PEM


<a id="org5eb9ac9"></a>

### `[CA:CONFIG] ca-key is required`

**When**: CA operations without CA private key
**Fix**: Provide CA private key PEM


<a id="org9e54da2"></a>

## PARAM - Parameter Errors


<a id="orgfbeba43"></a>

### `[CA:PARAM] validity-days must be positive`

**When**: Invalid certificate validity period
**Fix**: Use positive number of days


<a id="org99a3afb"></a>

### `[CA:PARAM] serial must be positive`

**When**: Invalid certificate serial number
**Fix**: Use positive serial number


<a id="org3f2df47"></a>

## SSL - OpenSSL Errors


<a id="orgb04f8f3"></a>

### `[CA:SSL] failed to sign certificate: <ssl-error>`

**When**: Certificate signing failed
**Fix**: Check CA key compatibility


<a id="org0a80156"></a>

### `[CA:SSL] failed to create certificate: <ssl-error>`

**When**: X509 creation failed
**Fix**: Check memory, parameters


<a id="orgd780b01"></a>

## VERIFY - Verification Errors


<a id="org714adb4"></a>

### `[CA:VERIFY] certificate has expired`

**When**: Certificate past its validity period
**Fix**: Renew certificate


<a id="orgacad595"></a>

### `[CA:VERIFY] certificate not yet valid`

**When**: Certificate not yet in validity period
**Fix**: Check system time, certificate dates


<a id="org4812ad2"></a>

# CERT Module Errors


<a id="org8ffe56f"></a>

## PARAM - Parameter Errors


<a id="org8608e3b"></a>

### `[CERT:PARAM] certificates must be string or array of strings`

**When**: Invalid certificate format in operations
**Fix**: Pass PEM string or array of PEM strings


<a id="orga4d7e01"></a>

## PARSE - Parse Errors


<a id="org3181467"></a>

### `[CERT:PARSE] failed to parse certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org24769d3"></a>

### `[CERT:PARSE] failed to parse private key: <ssl-error>`

**When**: Private key parsing failed
**Fix**: Verify key format


<a id="org0e907d4"></a>

# Error Handling Best Practices


<a id="orge39894d"></a>

## Using protect/try

    (def result
      (protect
        (tls/connect "untrusted.example.com" "443" {:verify true})))
    
    (if (nil? result)
      (print "Connection failed - check certificate")
      (do-something-with result))


<a id="org74ea52a"></a>

## Checking Return Values

Many functions return `nil` on failure:

    (when-let [stream (tls/connect host port opts)]
      (defer (:close stream)
        (process-stream stream)))


<a id="org7c58932"></a>

## Timeouts

Always use timeouts for network operations:

    (def data (:read stream 1024 30.0))  # 30 second timeout
    (when (nil? data)
      (print "Read timed out or connection closed"))


<a id="orgeeec4cb"></a>

# Testing Error Conditions

To test that your code handles errors correctly, use janet-assay's
`:expected-fail` feature for negative testing:

    (import assay)
    
    (assay/def-suite "error-handling"
      (assay/def-test "rejects invalid iterations"
        :expected-fail "[CRYPTO:PARAM]"
        (crypto/pbkdf2 :sha256 "password" "salt" 0 32)))


<a id="org607dd1e"></a>

# See Also

-   [API Reference](API.md) - Complete function documentation
-   [User Guide](GUIDE.md) - Getting started and examples
-   [Developer Guide](DEVELOPERS.md) - Contributing and internals

