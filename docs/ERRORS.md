
# Table of Contents

1.  [Overview](#orgea57a6f)
    1.  [Error Format](#orgc6ac5df)
    2.  [Example Errors](#org1eced0e)
2.  [TLS Module Errors](#orge918769)
    1.  [CONFIG - Configuration Errors](#org3843b9a)
        1.  [`[TLS:CONFIG] buffer-size must be a number`](#orgff5ba2e)
        2.  [`[TLS:CONFIG] invalid cipher suite: <suite>`](#orgbcc6c48)
        3.  [`[TLS:CONFIG] sni option must be a table or struct`](#org6d92786)
        4.  [`[TLS:CONFIG] Invalid ALPN protocols`](#orgbee4a80)
        5.  [`[TLS:CONFIG] handler function must take at least 1 argument`](#orga73def1)
    2.  [PARAM - Parameter Errors](#orgc2b8bb9)
        1.  [`[TLS:PARAM] timeout must be non-negative, got <value>`](#orgdf1e12d)
        2.  [`[TLS:PARAM] expected keyword or nil, got <value>`](#orgc8ffbf1)
        3.  [`[TLS:PARAM] length must be non-negative`](#org3afbd27)
    3.  [IO - I/O Errors](#org1097af3)
        1.  [`[TLS:IO] stream is closed`](#org600cdee)
        2.  [`[TLS:IO] connection is shutting down`](#orgb592b6e)
    4.  [SSL - OpenSSL Errors](#org65bc572)
        1.  [`[TLS:SSL] failed to create SSL context: <ssl-error>`](#orgae18fb4)
        2.  [`[TLS:SSL] failed to create SSL object: <ssl-error>`](#orga6abfc0)
        3.  [`[TLS:SSL] handshake failed: <ssl-error>`](#org92265d3)
        4.  [`[TLS:SSL] certificate verification failed: <ssl-error>`](#org4722972)
        5.  [`[TLS:SSL] failed to load private key: <ssl-error>`](#org487eaed)
        6.  [`[TLS:SSL] failed to load certificate: <ssl-error>`](#org1f60b57)
        7.  [`[TLS:SSL] private key does not match certificate: <ssl-error>`](#org528e62c)
    5.  [SOCKET - Socket Errors](#org38b9440)
        1.  [`[TLS:SOCKET] could not connect to <host>:<port>: <errno>`](#org5c5309e)
        2.  [`[TLS:SOCKET] bind failed: <errno>`](#org0527555)
        3.  [`[TLS:SOCKET] listen failed: <errno>`](#org8f1769d)
        4.  [`[TLS:SOCKET] getaddrinfo failed: <errno>`](#org2be145b)
    6.  [VERIFY - Verification Errors](#orgae1b4f6)
        1.  [`[TLS:VERIFY] hostname verification failed for <hostname>`](#org7f85950)
3.  [DTLS Module Errors](#org888facb)
    1.  [CONFIG - Configuration Errors](#orgbd23b92)
        1.  [`[DTLS:CONFIG] dtls/listen requires :cert and :key options`](#org3d3aefc)
        2.  [`[DTLS:CONFIG] cannot use TLS context for DTLS connection`](#orgd488c99)
    2.  [PARAM - Parameter Errors](#org6c6c7a2)
        1.  [`[DTLS:PARAM] invalid address: <address>`](#orgd65eece)
    3.  [IO - I/O Errors](#org6d0b92b)
        1.  [`[DTLS:IO] client not connected`](#org91b9bc7)
        2.  [`[DTLS:IO] client is closed`](#org5ea00d1)
        3.  [`[DTLS:IO] server is closed`](#org7706650)
        4.  [`[DTLS:IO] no session for peer address`](#org372cef5)
        5.  [`[DTLS:IO] session not established`](#org9a5ef1d)
    4.  [SSL - OpenSSL Errors](#org35a394e)
        1.  [`[DTLS:SSL] handshake failed: <ssl-error>`](#orgb686071)
        2.  [`[DTLS:SSL] write failed: <ssl-error>`](#orga8aca52)
    5.  [SOCKET - Socket Errors](#org28124ab)
        1.  [`[DTLS:SOCKET] bind failed: <errno>`](#org56739c1)
        2.  [`[DTLS:SOCKET] connect failed: <errno>`](#org96e2d47)
        3.  [`[DTLS:SOCKET] sendto failed: <errno>`](#orgbb54270)
        4.  [`[DTLS:SOCKET] failed to get peer address: <errno>`](#orgc63e05a)
4.  [CRYPTO Module Errors](#orgf749735)
    1.  [CONFIG - Configuration Errors](#org445e83c)
        1.  [`[CRYPTO:CONFIG] unknown digest algorithm: <alg>`](#org5c4b74d)
        2.  [`[CRYPTO:CONFIG] unsupported key algorithm: <alg>`](#orga241d2d)
    2.  [PARAM - Parameter Errors](#org01001b5)
        1.  [`[CRYPTO:PARAM] byte count must be 1-65536, got <n>`](#orgbd33fd8)
        2.  [`[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`](#org45aa418)
        3.  [`[CRYPTO:PARAM] output length must be 1-<max>`](#orgfb0008a)
        4.  [`[CRYPTO:PARAM] output length must be 1-1024`](#org51d61fc)
        5.  [`[CRYPTO:PARAM] iterations must be positive`](#org3078262)
        6.  [`[CRYPTO:PARAM] options must be a table or struct`](#org06899ea)
    3.  [SSL - OpenSSL Errors](#orga5fa7af)
        1.  [`[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`](#org409b6d4)
        2.  [`[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`](#orgfa86f68)
        3.  [`[CRYPTO:SSL] HMAC computation failed: <ssl-error>`](#orgfb4ddfa)
        4.  [`[CRYPTO:SSL] signing failed: <ssl-error>`](#org5011e83)
        5.  [`[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`](#org58040fe)
    4.  [RESOURCE - Resource Errors](#org51d1192)
        1.  [`[CRYPTO:RESOURCE] out of memory`](#org928af4b)
        2.  [`[CRYPTO:RESOURCE] failed to create context`](#orgfd2ad86)
    5.  [PARSE - Parse Errors](#org0020583)
        1.  [`[CRYPTO:PARSE] base64 decode failed`](#org09471cd)
        2.  [`[CRYPTO:PARSE] failed to parse CSR`](#org12cb220)
5.  [CA Module Errors](#org86a55e6)
    1.  [CONFIG - Configuration Errors](#orgd83eb8a)
        1.  [`[CA:CONFIG] common-name is required`](#org79cb92f)
        2.  [`[CA:CONFIG] ca-cert is required`](#orgd4df508)
        3.  [`[CA:CONFIG] ca-key is required`](#org6ea9d59)
    2.  [PARAM - Parameter Errors](#orge682843)
        1.  [`[CA:PARAM] validity-days must be positive`](#org4ecf610)
        2.  [`[CA:PARAM] serial must be positive`](#org2ec7142)
    3.  [SSL - OpenSSL Errors](#org82db603)
        1.  [`[CA:SSL] failed to sign certificate: <ssl-error>`](#org9a63c56)
        2.  [`[CA:SSL] failed to create certificate: <ssl-error>`](#org928e6b2)
    4.  [VERIFY - Verification Errors](#org20e9d11)
        1.  [`[CA:VERIFY] certificate has expired`](#org177f2fd)
        2.  [`[CA:VERIFY] certificate not yet valid`](#org4426333)
6.  [CERT Module Errors](#org13198a5)
    1.  [PARAM - Parameter Errors](#org1187caf)
        1.  [`[CERT:PARAM] certificates must be string or array of strings`](#orgce6669b)
    2.  [PARSE - Parse Errors](#orgfbc5712)
        1.  [`[CERT:PARSE] failed to parse certificate: <ssl-error>`](#org3ed8266)
        2.  [`[CERT:PARSE] failed to parse private key: <ssl-error>`](#org28b506d)
7.  [Error Handling Best Practices](#org44e195b)
    1.  [Using protect/try](#org61f69e1)
    2.  [Checking Return Values](#org61e32d7)
    3.  [Timeouts](#orge59391c)
8.  [Testing Error Conditions](#orga3ecc8b)
9.  [See Also](#org218b292)



<a id="orgea57a6f"></a>

# Overview

This document catalogs all errors that JSEC can produce, organized by module and category.


<a id="orgc6ac5df"></a>

## Error Format

All errors follow a standardized format:

    [MODULE:CATEGORY] message: detail

Where:

-   **MODULE**: TLS, DTLS, CRYPTO, CA, CERT, UTILS
-   **CATEGORY**: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY, PARSE


<a id="org1eced0e"></a>

## Example Errors

    [TLS:CONFIG] invalid cipher suite: RC4-MD5
    [DTLS:SOCKET] bind failed: address already in use
    [CRYPTO:PARAM] output length must be 1-1024, got 2000
    [CA:SSL] failed to sign certificate: key mismatch


<a id="orge918769"></a>

# TLS Module Errors


<a id="org3843b9a"></a>

## CONFIG - Configuration Errors


<a id="orgff5ba2e"></a>

### `[TLS:CONFIG] buffer-size must be a number`

**When**: Non-numeric `:buffer-size` option
**Fix**: Pass a positive integer

    # Wrong
    (tls/connect "host" "443" {:buffer-size "big"})
    
    # Correct
    (tls/connect "host" "443" {:buffer-size 16384})


<a id="orgbcc6c48"></a>

### `[TLS:CONFIG] invalid cipher suite: <suite>`

**When**: Unrecognized or disabled cipher suite specified
**Fix**: Use valid OpenSSL cipher string


<a id="org6d92786"></a>

### `[TLS:CONFIG] sni option must be a table or struct`

**When**: Invalid `:sni` option format for server context
**Fix**: Pass table mapping hostnames to cert/key configs

    {:sni {"api.example.com" {:cert api-cert :key api-key}
           "www.example.com" {:cert www-cert :key www-key}}}


<a id="orgbee4a80"></a>

### `[TLS:CONFIG] Invalid ALPN protocols`

**When**: Invalid `:alpn` option format
**Fix**: Pass array of protocol strings

    {:alpn ["h2" "http/1.1"]}


<a id="orga73def1"></a>

### `[TLS:CONFIG] handler function must take at least 1 argument`

**When**: Server handler function has wrong arity
**Fix**: Handler must accept at least the stream argument

    # Wrong
    (tls/server "0.0.0.0" "8443" (fn [] (print "no args")) opts)
    
    # Correct
    (tls/server "0.0.0.0" "8443" (fn [stream] (:close stream)) opts)


<a id="orgc2b8bb9"></a>

## PARAM - Parameter Errors


<a id="orgdf1e12d"></a>

### `[TLS:PARAM] timeout must be non-negative, got <value>`

**When**: Passing negative timeout value to I/O operations
**Fix**: Use zero or positive timeout (seconds)

    # Wrong
    (:read stream -1)
    
    # Correct
    (:read stream 1024 5.0)  # 5 second timeout


<a id="orgc8ffbf1"></a>

### `[TLS:PARAM] expected keyword or nil, got <value>`

**When**: Passing wrong type to `:close` method
**Fix**: Pass `:r`, `:w`, `:rw`, or `nil`

    # Wrong
    (:close stream "both")
    
    # Correct
    (:close stream :rw)  # Close both directions
    (:close stream)      # Same as :rw


<a id="org3afbd27"></a>

### `[TLS:PARAM] length must be non-negative`

**When**: Negative length to read operations
**Fix**: Pass zero or positive length


<a id="org1097af3"></a>

## IO - I/O Errors


<a id="org600cdee"></a>

### `[TLS:IO] stream is closed`

**When**: I/O on a closed TLS stream
**Fix**: Don't use stream after closing

    (def stream (tls/connect "host" "443"))
    (:close stream)
    (:read stream 1024)  # Error! Stream is closed


<a id="orgb592b6e"></a>

### `[TLS:IO] connection is shutting down`

**When**: Write attempt during TLS shutdown
**Fix**: Complete shutdown before further operations


<a id="org65bc572"></a>

## SSL - OpenSSL Errors


<a id="orgae18fb4"></a>

### `[TLS:SSL] failed to create SSL context: <ssl-error>`

**When**: SSL<sub>CTX</sub><sub>new</sub>() failed
**Fix**: Check OpenSSL installation, memory


<a id="orga6abfc0"></a>

### `[TLS:SSL] failed to create SSL object: <ssl-error>`

**When**: SSL<sub>new</sub>() failed
**Fix**: Check context validity, memory


<a id="org92265d3"></a>

### `[TLS:SSL] handshake failed: <ssl-error>`

**When**: TLS handshake failed
**Fix**: Check certificates, protocol compatibility


<a id="org4722972"></a>

### `[TLS:SSL] certificate verification failed: <ssl-error>`

**When**: Peer certificate verification failed
**Fix**: Check certificate chain, CA trust


<a id="org487eaed"></a>

### `[TLS:SSL] failed to load private key: <ssl-error>`

**When**: Private key PEM parsing failed
**Fix**: Verify key format, check for corruption


<a id="org1f60b57"></a>

### `[TLS:SSL] failed to load certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org528e62c"></a>

### `[TLS:SSL] private key does not match certificate: <ssl-error>`

**When**: Certificate/key mismatch in server config
**Fix**: Ensure cert and key are a matching pair


<a id="org38b9440"></a>

## SOCKET - Socket Errors


<a id="org5c5309e"></a>

### `[TLS:SOCKET] could not connect to <host>:<port>: <errno>`

**When**: TCP connection failed
**Fix**: Check host/port, firewall, server status


<a id="org0527555"></a>

### `[TLS:SOCKET] bind failed: <errno>`

**When**: Server bind failed
**Fix**: Check port availability, permissions


<a id="org8f1769d"></a>

### `[TLS:SOCKET] listen failed: <errno>`

**When**: Socket listen() failed
**Fix**: Check socket state


<a id="org2be145b"></a>

### `[TLS:SOCKET] getaddrinfo failed: <errno>`

**When**: DNS resolution failed
**Fix**: Check hostname, DNS configuration


<a id="orgae1b4f6"></a>

## VERIFY - Verification Errors


<a id="org7f85950"></a>

### `[TLS:VERIFY] hostname verification failed for <hostname>`

**When**: Certificate doesn't match expected hostname
**Fix**: Check certificate SAN/CN, or disable verification if intended


<a id="org888facb"></a>

# DTLS Module Errors


<a id="orgbd23b92"></a>

## CONFIG - Configuration Errors


<a id="org3d3aefc"></a>

### `[DTLS:CONFIG] dtls/listen requires :cert and :key options`

**When**: DTLS server missing required certificate/key
**Fix**: Provide certificate and private key

    (dtls/listen "0.0.0.0" "5684" {:cert cert-pem :key key-pem})


<a id="orgd488c99"></a>

### `[DTLS:CONFIG] cannot use TLS context for DTLS connection`

**When**: Passing a TLS context to DTLS functions
**Fix**: Create a DTLS-specific context or use options


<a id="org6c6c7a2"></a>

## PARAM - Parameter Errors


<a id="orgd65eece"></a>

### `[DTLS:PARAM] invalid address: <address>`

**When**: Cannot parse host address
**Fix**: Use valid IPv4/IPv6 address or hostname


<a id="org6d0b92b"></a>

## IO - I/O Errors


<a id="org91b9bc7"></a>

### `[DTLS:IO] client not connected`

**When**: I/O on unconnected DTLS client
**Fix**: Complete handshake first


<a id="org5ea00d1"></a>

### `[DTLS:IO] client is closed`

**When**: Operations on closed DTLS client
**Fix**: Don't use client after closing


<a id="org7706650"></a>

### `[DTLS:IO] server is closed`

**When**: Operations on closed DTLS server
**Fix**: Don't use server after closing


<a id="org372cef5"></a>

### `[DTLS:IO] no session for peer address`

**When**: DTLS send to unknown peer
**Fix**: Peer must complete handshake first


<a id="org9a5ef1d"></a>

### `[DTLS:IO] session not established`

**When**: DTLS send before handshake complete
**Fix**: Wait for handshake completion


<a id="org35a394e"></a>

## SSL - OpenSSL Errors


<a id="orgb686071"></a>

### `[DTLS:SSL] handshake failed: <ssl-error>`

**When**: DTLS handshake failed
**Fix**: Check certificates, network connectivity


<a id="orga8aca52"></a>

### `[DTLS:SSL] write failed: <ssl-error>`

**When**: DTLS write operation failed
**Fix**: Check connection state


<a id="org28124ab"></a>

## SOCKET - Socket Errors


<a id="org56739c1"></a>

### `[DTLS:SOCKET] bind failed: <errno>`

**When**: DTLS bind failed
**Fix**: Check address/port availability


<a id="org96e2d47"></a>

### `[DTLS:SOCKET] connect failed: <errno>`

**When**: DTLS connect failed
**Fix**: Check server reachability


<a id="orgbb54270"></a>

### `[DTLS:SOCKET] sendto failed: <errno>`

**When**: DTLS sendto() failed
**Fix**: Check connection state, buffer size


<a id="orgc63e05a"></a>

### `[DTLS:SOCKET] failed to get peer address: <errno>`

**When**: getpeername() failed on DTLS upgrade
**Fix**: Socket must be connected before upgrade


<a id="orgf749735"></a>

# CRYPTO Module Errors


<a id="org445e83c"></a>

## CONFIG - Configuration Errors


<a id="org5c4b74d"></a>

### `[CRYPTO:CONFIG] unknown digest algorithm: <alg>`

**When**: Invalid hash algorithm name
**Fix**: Use supported algorithm (sha256, sha384, sha512, etc.)

    (crypto/digest :sha256 data)  # Correct
    (crypto/digest :md5 data)     # May fail depending on OpenSSL config


<a id="orga241d2d"></a>

### `[CRYPTO:CONFIG] unsupported key algorithm: <alg>`

**When**: Invalid algorithm for key generation
**Fix**: Use supported algorithm

    # Supported: :rsa, :ed25519, :x25519, :ec-p256, :ec-p384, :ec-p521
    (crypto/generate-keypair :ec-p256)  # Correct
    (crypto/generate-keypair :dsa)       # Error: unsupported


<a id="org01001b5"></a>

## PARAM - Parameter Errors


<a id="orgbd33fd8"></a>

### `[CRYPTO:PARAM] byte count must be 1-65536, got <n>`

**When**: Requesting too many or too few random bytes
**Fix**: Request between 1 and 65536 bytes

    (crypto/random-bytes 32)  # Correct: 32 bytes


<a id="org45aa418"></a>

### `[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`

**When**: Invalid challenge length for `crypto/random-challenge`
**Fix**: Request between 8 and 64 bytes


<a id="orgfb0008a"></a>

### `[CRYPTO:PARAM] output length must be 1-<max>`

**When**: HKDF output length exceeds maximum (255 \* hash-size)
**Fix**: Request smaller output


<a id="org51d61fc"></a>

### `[CRYPTO:PARAM] output length must be 1-1024`

**When**: PBKDF2 output length out of range
**Fix**: Request between 1 and 1024 bytes


<a id="org3078262"></a>

### `[CRYPTO:PARAM] iterations must be positive`

**When**: Non-positive iteration count for PBKDF2
**Fix**: Use at least 1 iteration (recommend 100000+ for security)


<a id="org06899ea"></a>

### `[CRYPTO:PARAM] options must be a table or struct`

**When**: Passing non-table/struct to functions expecting options
**Fix**: Pass a table `{}` or struct `@{}`


<a id="orga5fa7af"></a>

## SSL - OpenSSL Errors


<a id="org409b6d4"></a>

### `[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`

**When**: Key derivation operation failed
**Fix**: Check input parameters


<a id="orgfa86f68"></a>

### `[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`

**When**: PBKDF2 operation failed
**Fix**: Check input parameters


<a id="orgfb4ddfa"></a>

### `[CRYPTO:SSL] HMAC computation failed: <ssl-error>`

**When**: HMAC operation failed
**Fix**: Check algorithm and key


<a id="org5011e83"></a>

### `[CRYPTO:SSL] signing failed: <ssl-error>`

**When**: Signature operation failed
**Fix**: Check key type supports signing


<a id="org58040fe"></a>

### `[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`

**When**: Entropy source failure
**Fix**: Check system entropy (/dev/urandom)


<a id="org51d1192"></a>

## RESOURCE - Resource Errors


<a id="org928af4b"></a>

### `[CRYPTO:RESOURCE] out of memory`

**When**: Memory allocation failed
**Fix**: Check system memory, reduce allocations


<a id="orgfd2ad86"></a>

### `[CRYPTO:RESOURCE] failed to create context`

**When**: EVP context allocation failed
**Fix**: Check memory, OpenSSL state


<a id="org0020583"></a>

## PARSE - Parse Errors


<a id="org09471cd"></a>

### `[CRYPTO:PARSE] base64 decode failed`

**When**: Invalid base64 input
**Fix**: Verify input is valid base64


<a id="org12cb220"></a>

### `[CRYPTO:PARSE] failed to parse CSR`

**When**: CSR parsing failed
**Fix**: Check CSR data validity


<a id="org86a55e6"></a>

# CA Module Errors


<a id="orgd83eb8a"></a>

## CONFIG - Configuration Errors


<a id="org79cb92f"></a>

### `[CA:CONFIG] common-name is required`

**When**: Certificate issuance without CN
**Fix**: Provide :cn option


<a id="orgd4df508"></a>

### `[CA:CONFIG] ca-cert is required`

**When**: CA operations without CA certificate
**Fix**: Provide CA certificate PEM


<a id="org6ea9d59"></a>

### `[CA:CONFIG] ca-key is required`

**When**: CA operations without CA private key
**Fix**: Provide CA private key PEM


<a id="orge682843"></a>

## PARAM - Parameter Errors


<a id="org4ecf610"></a>

### `[CA:PARAM] validity-days must be positive`

**When**: Invalid certificate validity period
**Fix**: Use positive number of days


<a id="org2ec7142"></a>

### `[CA:PARAM] serial must be positive`

**When**: Invalid certificate serial number
**Fix**: Use positive serial number


<a id="org82db603"></a>

## SSL - OpenSSL Errors


<a id="org9a63c56"></a>

### `[CA:SSL] failed to sign certificate: <ssl-error>`

**When**: Certificate signing failed
**Fix**: Check CA key compatibility


<a id="org928e6b2"></a>

### `[CA:SSL] failed to create certificate: <ssl-error>`

**When**: X509 creation failed
**Fix**: Check memory, parameters


<a id="org20e9d11"></a>

## VERIFY - Verification Errors


<a id="org177f2fd"></a>

### `[CA:VERIFY] certificate has expired`

**When**: Certificate past its validity period
**Fix**: Renew certificate


<a id="org4426333"></a>

### `[CA:VERIFY] certificate not yet valid`

**When**: Certificate not yet in validity period
**Fix**: Check system time, certificate dates


<a id="org13198a5"></a>

# CERT Module Errors


<a id="org1187caf"></a>

## PARAM - Parameter Errors


<a id="orgce6669b"></a>

### `[CERT:PARAM] certificates must be string or array of strings`

**When**: Invalid certificate format in operations
**Fix**: Pass PEM string or array of PEM strings


<a id="orgfbc5712"></a>

## PARSE - Parse Errors


<a id="org3ed8266"></a>

### `[CERT:PARSE] failed to parse certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org28b506d"></a>

### `[CERT:PARSE] failed to parse private key: <ssl-error>`

**When**: Private key parsing failed
**Fix**: Verify key format


<a id="org44e195b"></a>

# Error Handling Best Practices


<a id="org61f69e1"></a>

## Using protect/try

    (def result
      (protect
        (tls/connect "untrusted.example.com" "443" {:verify true})))
    
    (if (nil? result)
      (print "Connection failed - check certificate")
      (do-something-with result))


<a id="org61e32d7"></a>

## Checking Return Values

Many functions return `nil` on failure:

    (when-let [stream (tls/connect host port opts)]
      (defer (:close stream)
        (process-stream stream)))


<a id="orge59391c"></a>

## Timeouts

Always use timeouts for network operations:

    (def data (:read stream 1024 30.0))  # 30 second timeout
    (when (nil? data)
      (print "Read timed out or connection closed"))


<a id="orga3ecc8b"></a>

# Testing Error Conditions

To test that your code handles errors correctly, use janet-assay's
`:expected-fail` feature for negative testing:

    (import assay)
    
    (assay/def-suite "error-handling"
      (assay/def-test "rejects invalid iterations"
        :expected-fail "[CRYPTO:PARAM]"
        (crypto/pbkdf2 :sha256 "password" "salt" 0 32)))


<a id="org218b292"></a>

# See Also

-   [API Reference](API.md) - Complete function documentation
-   [User Guide](GUIDE.md) - Getting started and examples
-   [Developer Guide](DEVELOPERS.md) - Contributing and internals

