
# Table of Contents

1.  [Overview](#org74d84fb)
    1.  [Error Format](#org567f51d)
    2.  [Example Errors](#orga62db96)
2.  [TLS Module Errors](#orgf66d328)
    1.  [CONFIG - Configuration Errors](#org9b8c666)
        1.  [`[TLS:CONFIG] buffer-size must be a number`](#org4586193)
        2.  [`[TLS:CONFIG] invalid cipher suite: <suite>`](#org08bca6c)
        3.  [`[TLS:CONFIG] sni option must be a table or struct`](#orgc8df47f)
        4.  [`[TLS:CONFIG] Invalid ALPN protocols`](#org8314e2e)
        5.  [`[TLS:CONFIG] handler function must take at least 1 argument`](#org400f040)
    2.  [PARAM - Parameter Errors](#orgd6038f1)
        1.  [`[TLS:PARAM] timeout must be non-negative, got <value>`](#org32db5c5)
        2.  [`[TLS:PARAM] expected keyword or nil, got <value>`](#orga97e169)
        3.  [`[TLS:PARAM] length must be non-negative`](#org59f4c8b)
    3.  [IO - I/O Errors](#org74c2dd0)
        1.  [`[TLS:IO] stream is closed`](#org08e5441)
        2.  [`[TLS:IO] connection is shutting down`](#org16aa46f)
    4.  [SSL - OpenSSL Errors](#orge0d45ad)
        1.  [`[TLS:SSL] failed to create SSL context: <ssl-error>`](#org5ea1d7f)
        2.  [`[TLS:SSL] failed to create SSL object: <ssl-error>`](#orge138b1d)
        3.  [`[TLS:SSL] handshake failed: <ssl-error>`](#org7b3e952)
        4.  [`[TLS:SSL] certificate verification failed: <ssl-error>`](#org3f4b895)
        5.  [`[TLS:SSL] failed to load private key: <ssl-error>`](#org74d9c3c)
        6.  [`[TLS:SSL] failed to load certificate: <ssl-error>`](#org0002528)
        7.  [`[TLS:SSL] private key does not match certificate: <ssl-error>`](#org61d3340)
    5.  [SOCKET - Socket Errors](#org9964255)
        1.  [`[TLS:SOCKET] could not connect to <host>:<port>: <errno>`](#orge3833f6)
        2.  [`[TLS:SOCKET] bind failed: <errno>`](#org48febf9)
        3.  [`[TLS:SOCKET] listen failed: <errno>`](#org682d629)
        4.  [`[TLS:SOCKET] getaddrinfo failed: <errno>`](#org641102d)
    6.  [VERIFY - Verification Errors](#orge6d7075)
        1.  [`[TLS:VERIFY] hostname verification failed for <hostname>`](#org75da326)
3.  [DTLS Module Errors](#orgae830f8)
    1.  [CONFIG - Configuration Errors](#org6e70bb0)
        1.  [`[DTLS:CONFIG] dtls/listen requires :cert and :key options`](#orgf56d273)
        2.  [`[DTLS:CONFIG] cannot use TLS context for DTLS connection`](#org3f4cf6c)
    2.  [PARAM - Parameter Errors](#orgf4b803e)
        1.  [`[DTLS:PARAM] invalid address: <address>`](#org3a34389)
    3.  [IO - I/O Errors](#orgeb3b455)
        1.  [`[DTLS:IO] client not connected`](#org32bb2d9)
        2.  [`[DTLS:IO] client is closed`](#org5a1ff9b)
        3.  [`[DTLS:IO] server is closed`](#org83aed88)
        4.  [`[DTLS:IO] no session for peer address`](#orgc1bbfa5)
        5.  [`[DTLS:IO] session not established`](#orgba38ed8)
    4.  [SSL - OpenSSL Errors](#orgc0594b9)
        1.  [`[DTLS:SSL] handshake failed: <ssl-error>`](#org41c3ae8)
        2.  [`[DTLS:SSL] write failed: <ssl-error>`](#org7a3e2ff)
    5.  [SOCKET - Socket Errors](#orga0168af)
        1.  [`[DTLS:SOCKET] bind failed: <errno>`](#orgde7389d)
        2.  [`[DTLS:SOCKET] connect failed: <errno>`](#orgec38996)
        3.  [`[DTLS:SOCKET] sendto failed: <errno>`](#orgdccf353)
        4.  [`[DTLS:SOCKET] failed to get peer address: <errno>`](#orgaec5cf9)
4.  [CRYPTO Module Errors](#org819faa2)
    1.  [CONFIG - Configuration Errors](#orgbe650e7)
        1.  [`[CRYPTO:CONFIG] unknown digest algorithm: <alg>`](#org822f237)
        2.  [`[CRYPTO:CONFIG] unsupported key algorithm: <alg>`](#orgeacce71)
    2.  [PARAM - Parameter Errors](#orgf27b9e2)
        1.  [`[CRYPTO:PARAM] byte count must be 1-65536, got <n>`](#orgfd9b984)
        2.  [`[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`](#org6a6c8f8)
        3.  [`[CRYPTO:PARAM] output length must be 1-<max>`](#org03d354c)
        4.  [`[CRYPTO:PARAM] output length must be 1-1024`](#orgcd9fd59)
        5.  [`[CRYPTO:PARAM] iterations must be positive`](#orgd09d156)
        6.  [`[CRYPTO:PARAM] options must be a table or struct`](#org362842d)
    3.  [SSL - OpenSSL Errors](#org49c5c8c)
        1.  [`[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`](#org0642d08)
        2.  [`[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`](#org6f78fca)
        3.  [`[CRYPTO:SSL] HMAC computation failed: <ssl-error>`](#orgd57a5a3)
        4.  [`[CRYPTO:SSL] signing failed: <ssl-error>`](#org21c0fc6)
        5.  [`[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`](#org02ea233)
    4.  [RESOURCE - Resource Errors](#org37f0c16)
        1.  [`[CRYPTO:RESOURCE] out of memory`](#orgcda96be)
        2.  [`[CRYPTO:RESOURCE] failed to create context`](#orgc880979)
    5.  [PARSE - Parse Errors](#org752ef6e)
        1.  [`[CRYPTO:PARSE] base64 decode failed`](#orgc25df41)
        2.  [`[CRYPTO:PARSE] failed to parse CSR`](#orgbf982a9)
5.  [CA Module Errors](#orga020a2f)
    1.  [CONFIG - Configuration Errors](#orgde2bc61)
        1.  [`[CA:CONFIG] common-name is required`](#org269f31f)
        2.  [`[CA:CONFIG] ca-cert is required`](#org944dc57)
        3.  [`[CA:CONFIG] ca-key is required`](#org2a5a653)
    2.  [PARAM - Parameter Errors](#org2bbc201)
        1.  [`[CA:PARAM] validity-days must be positive`](#org3493895)
        2.  [`[CA:PARAM] serial must be positive`](#org5a2556c)
    3.  [SSL - OpenSSL Errors](#org5535508)
        1.  [`[CA:SSL] failed to sign certificate: <ssl-error>`](#org4cb03d8)
        2.  [`[CA:SSL] failed to create certificate: <ssl-error>`](#orgcdb3ba2)
    4.  [VERIFY - Verification Errors](#org562859d)
        1.  [`[CA:VERIFY] certificate has expired`](#org6c87c63)
        2.  [`[CA:VERIFY] certificate not yet valid`](#org323ec2f)
6.  [CERT Module Errors](#orge041bf5)
    1.  [PARAM - Parameter Errors](#orgdf96ba4)
        1.  [`[CERT:PARAM] certificates must be string or array of strings`](#org2091430)
    2.  [PARSE - Parse Errors](#orgf3e7bf2)
        1.  [`[CERT:PARSE] failed to parse certificate: <ssl-error>`](#org9ac7754)
        2.  [`[CERT:PARSE] failed to parse private key: <ssl-error>`](#org495428e)
7.  [Error Handling Best Practices](#org19d87a2)
    1.  [Using protect/try](#orge77ee5c)
    2.  [Checking Return Values](#org18c5d94)
    3.  [Timeouts](#org97ec0c8)
8.  [Testing Error Conditions](#orgb7fac8f)
9.  [See Also](#org32b0fb4)



<a id="org74d84fb"></a>

# Overview

This document catalogs all errors that JSEC can produce, organized by module and category.


<a id="org567f51d"></a>

## Error Format

All errors follow a standardized format:

    [MODULE:CATEGORY] message: detail

Where:

-   **MODULE**: TLS, DTLS, CRYPTO, CA, CERT, UTILS
-   **CATEGORY**: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY, PARSE


<a id="orga62db96"></a>

## Example Errors

    [TLS:CONFIG] invalid cipher suite: RC4-MD5
    [DTLS:SOCKET] bind failed: address already in use
    [CRYPTO:PARAM] output length must be 1-1024, got 2000
    [CA:SSL] failed to sign certificate: key mismatch


<a id="orgf66d328"></a>

# TLS Module Errors


<a id="org9b8c666"></a>

## CONFIG - Configuration Errors


<a id="org4586193"></a>

### `[TLS:CONFIG] buffer-size must be a number`

**When**: Non-numeric `:buffer-size` option
**Fix**: Pass a positive integer

    # Wrong
    (tls/connect "host" "443" {:buffer-size "big"})
    
    # Correct
    (tls/connect "host" "443" {:buffer-size 16384})


<a id="org08bca6c"></a>

### `[TLS:CONFIG] invalid cipher suite: <suite>`

**When**: Unrecognized or disabled cipher suite specified
**Fix**: Use valid OpenSSL cipher string


<a id="orgc8df47f"></a>

### `[TLS:CONFIG] sni option must be a table or struct`

**When**: Invalid `:sni` option format for server context
**Fix**: Pass table mapping hostnames to cert/key configs

    {:sni {"api.example.com" {:cert api-cert :key api-key}
           "www.example.com" {:cert www-cert :key www-key}}}


<a id="org8314e2e"></a>

### `[TLS:CONFIG] Invalid ALPN protocols`

**When**: Invalid `:alpn` option format
**Fix**: Pass array of protocol strings

    {:alpn ["h2" "http/1.1"]}


<a id="org400f040"></a>

### `[TLS:CONFIG] handler function must take at least 1 argument`

**When**: Server handler function has wrong arity
**Fix**: Handler must accept at least the stream argument

    # Wrong
    (tls/server "0.0.0.0" "8443" (fn [] (print "no args")) opts)
    
    # Correct
    (tls/server "0.0.0.0" "8443" (fn [stream] (:close stream)) opts)


<a id="orgd6038f1"></a>

## PARAM - Parameter Errors


<a id="org32db5c5"></a>

### `[TLS:PARAM] timeout must be non-negative, got <value>`

**When**: Passing negative timeout value to I/O operations
**Fix**: Use zero or positive timeout (seconds)

    # Wrong
    (:read stream -1)
    
    # Correct
    (:read stream 1024 5.0)  # 5 second timeout


<a id="orga97e169"></a>

### `[TLS:PARAM] expected keyword or nil, got <value>`

**When**: Passing wrong type to `:close` method
**Fix**: Pass `:r`, `:w`, `:rw`, or `nil`

    # Wrong
    (:close stream "both")
    
    # Correct
    (:close stream :rw)  # Close both directions
    (:close stream)      # Same as :rw


<a id="org59f4c8b"></a>

### `[TLS:PARAM] length must be non-negative`

**When**: Negative length to read operations
**Fix**: Pass zero or positive length


<a id="org74c2dd0"></a>

## IO - I/O Errors


<a id="org08e5441"></a>

### `[TLS:IO] stream is closed`

**When**: I/O on a closed TLS stream
**Fix**: Don't use stream after closing

    (def stream (tls/connect "host" "443"))
    (:close stream)
    (:read stream 1024)  # Error! Stream is closed


<a id="org16aa46f"></a>

### `[TLS:IO] connection is shutting down`

**When**: Write attempt during TLS shutdown
**Fix**: Complete shutdown before further operations


<a id="orge0d45ad"></a>

## SSL - OpenSSL Errors


<a id="org5ea1d7f"></a>

### `[TLS:SSL] failed to create SSL context: <ssl-error>`

**When**: SSL<sub>CTX</sub><sub>new</sub>() failed
**Fix**: Check OpenSSL installation, memory


<a id="orge138b1d"></a>

### `[TLS:SSL] failed to create SSL object: <ssl-error>`

**When**: SSL<sub>new</sub>() failed
**Fix**: Check context validity, memory


<a id="org7b3e952"></a>

### `[TLS:SSL] handshake failed: <ssl-error>`

**When**: TLS handshake failed
**Fix**: Check certificates, protocol compatibility


<a id="org3f4b895"></a>

### `[TLS:SSL] certificate verification failed: <ssl-error>`

**When**: Peer certificate verification failed
**Fix**: Check certificate chain, CA trust


<a id="org74d9c3c"></a>

### `[TLS:SSL] failed to load private key: <ssl-error>`

**When**: Private key PEM parsing failed
**Fix**: Verify key format, check for corruption


<a id="org0002528"></a>

### `[TLS:SSL] failed to load certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org61d3340"></a>

### `[TLS:SSL] private key does not match certificate: <ssl-error>`

**When**: Certificate/key mismatch in server config
**Fix**: Ensure cert and key are a matching pair


<a id="org9964255"></a>

## SOCKET - Socket Errors


<a id="orge3833f6"></a>

### `[TLS:SOCKET] could not connect to <host>:<port>: <errno>`

**When**: TCP connection failed
**Fix**: Check host/port, firewall, server status


<a id="org48febf9"></a>

### `[TLS:SOCKET] bind failed: <errno>`

**When**: Server bind failed
**Fix**: Check port availability, permissions


<a id="org682d629"></a>

### `[TLS:SOCKET] listen failed: <errno>`

**When**: Socket listen() failed
**Fix**: Check socket state


<a id="org641102d"></a>

### `[TLS:SOCKET] getaddrinfo failed: <errno>`

**When**: DNS resolution failed
**Fix**: Check hostname, DNS configuration


<a id="orge6d7075"></a>

## VERIFY - Verification Errors


<a id="org75da326"></a>

### `[TLS:VERIFY] hostname verification failed for <hostname>`

**When**: Certificate doesn't match expected hostname
**Fix**: Check certificate SAN/CN, or disable verification if intended


<a id="orgae830f8"></a>

# DTLS Module Errors


<a id="org6e70bb0"></a>

## CONFIG - Configuration Errors


<a id="orgf56d273"></a>

### `[DTLS:CONFIG] dtls/listen requires :cert and :key options`

**When**: DTLS server missing required certificate/key
**Fix**: Provide certificate and private key

    (dtls/listen "0.0.0.0" "5684" {:cert cert-pem :key key-pem})


<a id="org3f4cf6c"></a>

### `[DTLS:CONFIG] cannot use TLS context for DTLS connection`

**When**: Passing a TLS context to DTLS functions
**Fix**: Create a DTLS-specific context or use options


<a id="orgf4b803e"></a>

## PARAM - Parameter Errors


<a id="org3a34389"></a>

### `[DTLS:PARAM] invalid address: <address>`

**When**: Cannot parse host address
**Fix**: Use valid IPv4/IPv6 address or hostname


<a id="orgeb3b455"></a>

## IO - I/O Errors


<a id="org32bb2d9"></a>

### `[DTLS:IO] client not connected`

**When**: I/O on unconnected DTLS client
**Fix**: Complete handshake first


<a id="org5a1ff9b"></a>

### `[DTLS:IO] client is closed`

**When**: Operations on closed DTLS client
**Fix**: Don't use client after closing


<a id="org83aed88"></a>

### `[DTLS:IO] server is closed`

**When**: Operations on closed DTLS server
**Fix**: Don't use server after closing


<a id="orgc1bbfa5"></a>

### `[DTLS:IO] no session for peer address`

**When**: DTLS send to unknown peer
**Fix**: Peer must complete handshake first


<a id="orgba38ed8"></a>

### `[DTLS:IO] session not established`

**When**: DTLS send before handshake complete
**Fix**: Wait for handshake completion


<a id="orgc0594b9"></a>

## SSL - OpenSSL Errors


<a id="org41c3ae8"></a>

### `[DTLS:SSL] handshake failed: <ssl-error>`

**When**: DTLS handshake failed
**Fix**: Check certificates, network connectivity


<a id="org7a3e2ff"></a>

### `[DTLS:SSL] write failed: <ssl-error>`

**When**: DTLS write operation failed
**Fix**: Check connection state


<a id="orga0168af"></a>

## SOCKET - Socket Errors


<a id="orgde7389d"></a>

### `[DTLS:SOCKET] bind failed: <errno>`

**When**: DTLS bind failed
**Fix**: Check address/port availability


<a id="orgec38996"></a>

### `[DTLS:SOCKET] connect failed: <errno>`

**When**: DTLS connect failed
**Fix**: Check server reachability


<a id="orgdccf353"></a>

### `[DTLS:SOCKET] sendto failed: <errno>`

**When**: DTLS sendto() failed
**Fix**: Check connection state, buffer size


<a id="orgaec5cf9"></a>

### `[DTLS:SOCKET] failed to get peer address: <errno>`

**When**: getpeername() failed on DTLS upgrade
**Fix**: Socket must be connected before upgrade


<a id="org819faa2"></a>

# CRYPTO Module Errors


<a id="orgbe650e7"></a>

## CONFIG - Configuration Errors


<a id="org822f237"></a>

### `[CRYPTO:CONFIG] unknown digest algorithm: <alg>`

**When**: Invalid hash algorithm name
**Fix**: Use supported algorithm (sha256, sha384, sha512, etc.)

    (crypto/digest :sha256 data)  # Correct
    (crypto/digest :md5 data)     # May fail depending on OpenSSL config


<a id="orgeacce71"></a>

### `[CRYPTO:CONFIG] unsupported key algorithm: <alg>`

**When**: Invalid algorithm for key generation
**Fix**: Use supported algorithm

    # Supported: :rsa, :ed25519, :x25519, :ec-p256, :ec-p384, :ec-p521
    (crypto/generate-keypair :ec-p256)  # Correct
    (crypto/generate-keypair :dsa)       # Error: unsupported


<a id="orgf27b9e2"></a>

## PARAM - Parameter Errors


<a id="orgfd9b984"></a>

### `[CRYPTO:PARAM] byte count must be 1-65536, got <n>`

**When**: Requesting too many or too few random bytes
**Fix**: Request between 1 and 65536 bytes

    (crypto/random-bytes 32)  # Correct: 32 bytes


<a id="org6a6c8f8"></a>

### `[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`

**When**: Invalid challenge length for `crypto/random-challenge`
**Fix**: Request between 8 and 64 bytes


<a id="org03d354c"></a>

### `[CRYPTO:PARAM] output length must be 1-<max>`

**When**: HKDF output length exceeds maximum (255 \* hash-size)
**Fix**: Request smaller output


<a id="orgcd9fd59"></a>

### `[CRYPTO:PARAM] output length must be 1-1024`

**When**: PBKDF2 output length out of range
**Fix**: Request between 1 and 1024 bytes


<a id="orgd09d156"></a>

### `[CRYPTO:PARAM] iterations must be positive`

**When**: Non-positive iteration count for PBKDF2
**Fix**: Use at least 1 iteration (recommend 100000+ for security)


<a id="org362842d"></a>

### `[CRYPTO:PARAM] options must be a table or struct`

**When**: Passing non-table/struct to functions expecting options
**Fix**: Pass a table `{}` or struct `@{}`


<a id="org49c5c8c"></a>

## SSL - OpenSSL Errors


<a id="org0642d08"></a>

### `[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`

**When**: Key derivation operation failed
**Fix**: Check input parameters


<a id="org6f78fca"></a>

### `[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`

**When**: PBKDF2 operation failed
**Fix**: Check input parameters


<a id="orgd57a5a3"></a>

### `[CRYPTO:SSL] HMAC computation failed: <ssl-error>`

**When**: HMAC operation failed
**Fix**: Check algorithm and key


<a id="org21c0fc6"></a>

### `[CRYPTO:SSL] signing failed: <ssl-error>`

**When**: Signature operation failed
**Fix**: Check key type supports signing


<a id="org02ea233"></a>

### `[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`

**When**: Entropy source failure
**Fix**: Check system entropy (/dev/urandom)


<a id="org37f0c16"></a>

## RESOURCE - Resource Errors


<a id="orgcda96be"></a>

### `[CRYPTO:RESOURCE] out of memory`

**When**: Memory allocation failed
**Fix**: Check system memory, reduce allocations


<a id="orgc880979"></a>

### `[CRYPTO:RESOURCE] failed to create context`

**When**: EVP context allocation failed
**Fix**: Check memory, OpenSSL state


<a id="org752ef6e"></a>

## PARSE - Parse Errors


<a id="orgc25df41"></a>

### `[CRYPTO:PARSE] base64 decode failed`

**When**: Invalid base64 input
**Fix**: Verify input is valid base64


<a id="orgbf982a9"></a>

### `[CRYPTO:PARSE] failed to parse CSR`

**When**: CSR parsing failed
**Fix**: Check CSR data validity


<a id="orga020a2f"></a>

# CA Module Errors


<a id="orgde2bc61"></a>

## CONFIG - Configuration Errors


<a id="org269f31f"></a>

### `[CA:CONFIG] common-name is required`

**When**: Certificate issuance without CN
**Fix**: Provide :cn option


<a id="org944dc57"></a>

### `[CA:CONFIG] ca-cert is required`

**When**: CA operations without CA certificate
**Fix**: Provide CA certificate PEM


<a id="org2a5a653"></a>

### `[CA:CONFIG] ca-key is required`

**When**: CA operations without CA private key
**Fix**: Provide CA private key PEM


<a id="org2bbc201"></a>

## PARAM - Parameter Errors


<a id="org3493895"></a>

### `[CA:PARAM] validity-days must be positive`

**When**: Invalid certificate validity period
**Fix**: Use positive number of days


<a id="org5a2556c"></a>

### `[CA:PARAM] serial must be positive`

**When**: Invalid certificate serial number
**Fix**: Use positive serial number


<a id="org5535508"></a>

## SSL - OpenSSL Errors


<a id="org4cb03d8"></a>

### `[CA:SSL] failed to sign certificate: <ssl-error>`

**When**: Certificate signing failed
**Fix**: Check CA key compatibility


<a id="orgcdb3ba2"></a>

### `[CA:SSL] failed to create certificate: <ssl-error>`

**When**: X509 creation failed
**Fix**: Check memory, parameters


<a id="org562859d"></a>

## VERIFY - Verification Errors


<a id="org6c87c63"></a>

### `[CA:VERIFY] certificate has expired`

**When**: Certificate past its validity period
**Fix**: Renew certificate


<a id="org323ec2f"></a>

### `[CA:VERIFY] certificate not yet valid`

**When**: Certificate not yet in validity period
**Fix**: Check system time, certificate dates


<a id="orge041bf5"></a>

# CERT Module Errors


<a id="orgdf96ba4"></a>

## PARAM - Parameter Errors


<a id="org2091430"></a>

### `[CERT:PARAM] certificates must be string or array of strings`

**When**: Invalid certificate format in operations
**Fix**: Pass PEM string or array of PEM strings


<a id="orgf3e7bf2"></a>

## PARSE - Parse Errors


<a id="org9ac7754"></a>

### `[CERT:PARSE] failed to parse certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org495428e"></a>

### `[CERT:PARSE] failed to parse private key: <ssl-error>`

**When**: Private key parsing failed
**Fix**: Verify key format


<a id="org19d87a2"></a>

# Error Handling Best Practices


<a id="orge77ee5c"></a>

## Using protect/try

    (def result
      (protect
        (tls/connect "untrusted.example.com" "443" {:verify true})))
    
    (if (nil? result)
      (print "Connection failed - check certificate")
      (do-something-with result))


<a id="org18c5d94"></a>

## Checking Return Values

Many functions return `nil` on failure:

    (when-let [stream (tls/connect host port opts)]
      (defer (:close stream)
        (process-stream stream)))


<a id="org97ec0c8"></a>

## Timeouts

Always use timeouts for network operations:

    (def data (:read stream 1024 30.0))  # 30 second timeout
    (when (nil? data)
      (print "Read timed out or connection closed"))


<a id="orgb7fac8f"></a>

# Testing Error Conditions

To test that your code handles errors correctly, use janet-assay's
`:expected-fail` feature for negative testing:

    (import assay)
    
    (assay/def-suite "error-handling"
      (assay/def-test "rejects invalid iterations"
        :expected-fail "[CRYPTO:PARAM]"
        (crypto/pbkdf2 :sha256 "password" "salt" 0 32)))


<a id="org32b0fb4"></a>

# See Also

-   [API Reference](API.md) - Complete function documentation
-   [User Guide](GUIDE.md) - Getting started and examples
-   [Developer Guide](DEVELOPERS.md) - Contributing and internals

