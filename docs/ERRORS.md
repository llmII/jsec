
# Table of Contents

1.  [Overview](#orgc67e5ba)
    1.  [Error Format](#orgdc2705a)
    2.  [Example Errors](#org1cad904)
2.  [TLS Module Errors](#orgd785382)
    1.  [CONFIG - Configuration Errors](#orgc5935c3)
        1.  [`[TLS:CONFIG] buffer-size must be a number`](#org86fc0e8)
        2.  [`[TLS:CONFIG] invalid cipher suite: <suite>`](#org05fd063)
        3.  [`[TLS:CONFIG] sni option must be a table or struct`](#org63a83e1)
        4.  [`[TLS:CONFIG] Invalid ALPN protocols`](#org396fb96)
        5.  [`[TLS:CONFIG] handler function must take at least 1 argument`](#org8498984)
    2.  [PARAM - Parameter Errors](#org4a07200)
        1.  [`[TLS:PARAM] timeout must be non-negative, got <value>`](#orge110a65)
        2.  [`[TLS:PARAM] expected keyword or nil, got <value>`](#orgd5d0b81)
        3.  [`[TLS:PARAM] length must be non-negative`](#org9f616e3)
    3.  [IO - I/O Errors](#orgc145c75)
        1.  [`[TLS:IO] stream is closed`](#orgd568a7e)
        2.  [`[TLS:IO] connection is shutting down`](#orga16d1d9)
    4.  [SSL - OpenSSL Errors](#org2daee4c)
        1.  [`[TLS:SSL] failed to create SSL context: <ssl-error>`](#org7ff9f53)
        2.  [`[TLS:SSL] failed to create SSL object: <ssl-error>`](#org6dff350)
        3.  [`[TLS:SSL] handshake failed: <ssl-error>`](#org3909ec7)
        4.  [`[TLS:SSL] certificate verification failed: <ssl-error>`](#org1d13e59)
        5.  [`[TLS:SSL] failed to load private key: <ssl-error>`](#org1f2032f)
        6.  [`[TLS:SSL] failed to load certificate: <ssl-error>`](#org43a7c4c)
        7.  [`[TLS:SSL] private key does not match certificate: <ssl-error>`](#org85ef78f)
    5.  [SOCKET - Socket Errors](#org4f060a2)
        1.  [`[TLS:SOCKET] could not connect to <host>:<port>: <errno>`](#orgaaac421)
        2.  [`[TLS:SOCKET] bind failed: <errno>`](#orgf4d67df)
        3.  [`[TLS:SOCKET] listen failed: <errno>`](#orga21cb29)
        4.  [`[TLS:SOCKET] getaddrinfo failed: <errno>`](#org3237080)
    6.  [VERIFY - Verification Errors](#orgda7d292)
        1.  [`[TLS:VERIFY] hostname verification failed for <hostname>`](#orgbe6bfe9)
3.  [DTLS Module Errors](#org34de05d)
    1.  [CONFIG - Configuration Errors](#org9ad3f3b)
        1.  [`[DTLS:CONFIG] dtls/listen requires :cert and :key options`](#org08796b5)
        2.  [`[DTLS:CONFIG] cannot use TLS context for DTLS connection`](#org02c9799)
    2.  [PARAM - Parameter Errors](#org35c40cb)
        1.  [`[DTLS:PARAM] invalid address: <address>`](#org3e179d9)
    3.  [IO - I/O Errors](#orgede56f6)
        1.  [`[DTLS:IO] client not connected`](#orgd9f32bc)
        2.  [`[DTLS:IO] client is closed`](#org7374f7b)
        3.  [`[DTLS:IO] server is closed`](#org9b29107)
        4.  [`[DTLS:IO] no session for peer address`](#orgb276416)
        5.  [`[DTLS:IO] session not established`](#org1ff440e)
    4.  [SSL - OpenSSL Errors](#org186bd06)
        1.  [`[DTLS:SSL] handshake failed: <ssl-error>`](#org943e847)
        2.  [`[DTLS:SSL] write failed: <ssl-error>`](#orgee92fba)
    5.  [SOCKET - Socket Errors](#org0b11a51)
        1.  [`[DTLS:SOCKET] bind failed: <errno>`](#orgd7fe6ea)
        2.  [`[DTLS:SOCKET] connect failed: <errno>`](#org07914f8)
        3.  [`[DTLS:SOCKET] sendto failed: <errno>`](#org1e08953)
        4.  [`[DTLS:SOCKET] failed to get peer address: <errno>`](#org6d56a8f)
4.  [CRYPTO Module Errors](#org92fd31e)
    1.  [CONFIG - Configuration Errors](#orgc807da0)
        1.  [`[CRYPTO:CONFIG] unknown digest algorithm: <alg>`](#org19c9320)
        2.  [`[CRYPTO:CONFIG] unsupported key algorithm: <alg>`](#org252cd58)
    2.  [PARAM - Parameter Errors](#org832ae49)
        1.  [`[CRYPTO:PARAM] byte count must be 1-65536, got <n>`](#orgc9b47f7)
        2.  [`[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`](#org4500e15)
        3.  [`[CRYPTO:PARAM] output length must be 1-<max>`](#orgf99659c)
        4.  [`[CRYPTO:PARAM] output length must be 1-1024`](#org787cee9)
        5.  [`[CRYPTO:PARAM] iterations must be positive`](#orgd07ff81)
        6.  [`[CRYPTO:PARAM] options must be a table or struct`](#orgc356078)
    3.  [SSL - OpenSSL Errors](#orgce2f4d6)
        1.  [`[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`](#org1282903)
        2.  [`[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`](#org64d2f49)
        3.  [`[CRYPTO:SSL] HMAC computation failed: <ssl-error>`](#org8c43890)
        4.  [`[CRYPTO:SSL] signing failed: <ssl-error>`](#org89cf8b7)
        5.  [`[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`](#org831d7bb)
    4.  [RESOURCE - Resource Errors](#org15591e6)
        1.  [`[CRYPTO:RESOURCE] out of memory`](#org99bc927)
        2.  [`[CRYPTO:RESOURCE] failed to create context`](#org6520ead)
    5.  [PARSE - Parse Errors](#org4e658a0)
        1.  [`[CRYPTO:PARSE] base64 decode failed`](#orgad13074)
        2.  [`[CRYPTO:PARSE] failed to parse CSR`](#orgee3c54f)
5.  [CA Module Errors](#orgc5e8c92)
    1.  [CONFIG - Configuration Errors](#org65c1ca9)
        1.  [`[CA:CONFIG] common-name is required`](#orge4a5491)
        2.  [`[CA:CONFIG] ca-cert is required`](#org6df1fe0)
        3.  [`[CA:CONFIG] ca-key is required`](#orgce536c7)
    2.  [PARAM - Parameter Errors](#orgbdd8bcf)
        1.  [`[CA:PARAM] validity-days must be positive`](#orgc237df1)
        2.  [`[CA:PARAM] serial must be positive`](#org6b42442)
    3.  [SSL - OpenSSL Errors](#orgba6a8bf)
        1.  [`[CA:SSL] failed to sign certificate: <ssl-error>`](#orgb8f44fe)
        2.  [`[CA:SSL] failed to create certificate: <ssl-error>`](#orgd18fcd4)
    4.  [VERIFY - Verification Errors](#org55288fb)
        1.  [`[CA:VERIFY] certificate has expired`](#orga4d4686)
        2.  [`[CA:VERIFY] certificate not yet valid`](#orgc593095)
6.  [CERT Module Errors](#orgcc58dfa)
    1.  [PARAM - Parameter Errors](#org0267cdb)
        1.  [`[CERT:PARAM] certificates must be string or array of strings`](#org099d4f6)
    2.  [PARSE - Parse Errors](#orgaace89a)
        1.  [`[CERT:PARSE] failed to parse certificate: <ssl-error>`](#orgab44f9e)
        2.  [`[CERT:PARSE] failed to parse private key: <ssl-error>`](#orgd7783b6)
7.  [Error Handling Best Practices](#org1b8bf37)
    1.  [Using protect/try](#org813307e)
    2.  [Checking Return Values](#orge56f807)
    3.  [Timeouts](#org0ea3d45)
8.  [Testing Error Conditions](#org26bf8b2)
9.  [See Also](#org329905e)



<a id="orgc67e5ba"></a>

# Overview

This document catalogs all errors that JSEC can produce, organized by module and category.


<a id="orgdc2705a"></a>

## Error Format

All errors follow a standardized format:

    [MODULE:CATEGORY] message: detail

Where:

-   **MODULE**: TLS, DTLS, CRYPTO, CA, CERT, UTILS
-   **CATEGORY**: CONFIG, IO, SSL, SOCKET, PARAM, RESOURCE, VERIFY, PARSE


<a id="org1cad904"></a>

## Example Errors

    [TLS:CONFIG] invalid cipher suite: RC4-MD5
    [DTLS:SOCKET] bind failed: address already in use
    [CRYPTO:PARAM] output length must be 1-1024, got 2000
    [CA:SSL] failed to sign certificate: key mismatch


<a id="orgd785382"></a>

# TLS Module Errors


<a id="orgc5935c3"></a>

## CONFIG - Configuration Errors


<a id="org86fc0e8"></a>

### `[TLS:CONFIG] buffer-size must be a number`

**When**: Non-numeric `:buffer-size` option
**Fix**: Pass a positive integer

    # Wrong
    (tls/connect "host" "443" {:buffer-size "big"})
    
    # Correct
    (tls/connect "host" "443" {:buffer-size 16384})


<a id="org05fd063"></a>

### `[TLS:CONFIG] invalid cipher suite: <suite>`

**When**: Unrecognized or disabled cipher suite specified
**Fix**: Use valid OpenSSL cipher string


<a id="org63a83e1"></a>

### `[TLS:CONFIG] sni option must be a table or struct`

**When**: Invalid `:sni` option format for server context
**Fix**: Pass table mapping hostnames to cert/key configs

    {:sni {"api.example.com" {:cert api-cert :key api-key}
           "www.example.com" {:cert www-cert :key www-key}}}


<a id="org396fb96"></a>

### `[TLS:CONFIG] Invalid ALPN protocols`

**When**: Invalid `:alpn` option format
**Fix**: Pass array of protocol strings

    {:alpn ["h2" "http/1.1"]}


<a id="org8498984"></a>

### `[TLS:CONFIG] handler function must take at least 1 argument`

**When**: Server handler function has wrong arity
**Fix**: Handler must accept at least the stream argument

    # Wrong
    (tls/server "0.0.0.0" "8443" (fn [] (print "no args")) opts)
    
    # Correct
    (tls/server "0.0.0.0" "8443" (fn [stream] (:close stream)) opts)


<a id="org4a07200"></a>

## PARAM - Parameter Errors


<a id="orge110a65"></a>

### `[TLS:PARAM] timeout must be non-negative, got <value>`

**When**: Passing negative timeout value to I/O operations
**Fix**: Use zero or positive timeout (seconds)

    # Wrong
    (:read stream -1)
    
    # Correct
    (:read stream 1024 5.0)  # 5 second timeout


<a id="orgd5d0b81"></a>

### `[TLS:PARAM] expected keyword or nil, got <value>`

**When**: Passing wrong type to `:close` method
**Fix**: Pass `:r`, `:w`, `:rw`, or `nil`

    # Wrong
    (:close stream "both")
    
    # Correct
    (:close stream :rw)  # Close both directions
    (:close stream)      # Same as :rw


<a id="org9f616e3"></a>

### `[TLS:PARAM] length must be non-negative`

**When**: Negative length to read operations
**Fix**: Pass zero or positive length


<a id="orgc145c75"></a>

## IO - I/O Errors


<a id="orgd568a7e"></a>

### `[TLS:IO] stream is closed`

**When**: I/O on a closed TLS stream
**Fix**: Don't use stream after closing

    (def stream (tls/connect "host" "443"))
    (:close stream)
    (:read stream 1024)  # Error! Stream is closed


<a id="orga16d1d9"></a>

### `[TLS:IO] connection is shutting down`

**When**: Write attempt during TLS shutdown
**Fix**: Complete shutdown before further operations


<a id="org2daee4c"></a>

## SSL - OpenSSL Errors


<a id="org7ff9f53"></a>

### `[TLS:SSL] failed to create SSL context: <ssl-error>`

**When**: SSL<sub>CTX</sub><sub>new</sub>() failed
**Fix**: Check OpenSSL installation, memory


<a id="org6dff350"></a>

### `[TLS:SSL] failed to create SSL object: <ssl-error>`

**When**: SSL<sub>new</sub>() failed
**Fix**: Check context validity, memory


<a id="org3909ec7"></a>

### `[TLS:SSL] handshake failed: <ssl-error>`

**When**: TLS handshake failed
**Fix**: Check certificates, protocol compatibility


<a id="org1d13e59"></a>

### `[TLS:SSL] certificate verification failed: <ssl-error>`

**When**: Peer certificate verification failed
**Fix**: Check certificate chain, CA trust


<a id="org1f2032f"></a>

### `[TLS:SSL] failed to load private key: <ssl-error>`

**When**: Private key PEM parsing failed
**Fix**: Verify key format, check for corruption


<a id="org43a7c4c"></a>

### `[TLS:SSL] failed to load certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="org85ef78f"></a>

### `[TLS:SSL] private key does not match certificate: <ssl-error>`

**When**: Certificate/key mismatch in server config
**Fix**: Ensure cert and key are a matching pair


<a id="org4f060a2"></a>

## SOCKET - Socket Errors


<a id="orgaaac421"></a>

### `[TLS:SOCKET] could not connect to <host>:<port>: <errno>`

**When**: TCP connection failed
**Fix**: Check host/port, firewall, server status


<a id="orgf4d67df"></a>

### `[TLS:SOCKET] bind failed: <errno>`

**When**: Server bind failed
**Fix**: Check port availability, permissions


<a id="orga21cb29"></a>

### `[TLS:SOCKET] listen failed: <errno>`

**When**: Socket listen() failed
**Fix**: Check socket state


<a id="org3237080"></a>

### `[TLS:SOCKET] getaddrinfo failed: <errno>`

**When**: DNS resolution failed
**Fix**: Check hostname, DNS configuration


<a id="orgda7d292"></a>

## VERIFY - Verification Errors


<a id="orgbe6bfe9"></a>

### `[TLS:VERIFY] hostname verification failed for <hostname>`

**When**: Certificate doesn't match expected hostname
**Fix**: Check certificate SAN/CN, or disable verification if intended


<a id="org34de05d"></a>

# DTLS Module Errors


<a id="org9ad3f3b"></a>

## CONFIG - Configuration Errors


<a id="org08796b5"></a>

### `[DTLS:CONFIG] dtls/listen requires :cert and :key options`

**When**: DTLS server missing required certificate/key
**Fix**: Provide certificate and private key

    (dtls/listen "0.0.0.0" "5684" {:cert cert-pem :key key-pem})


<a id="org02c9799"></a>

### `[DTLS:CONFIG] cannot use TLS context for DTLS connection`

**When**: Passing a TLS context to DTLS functions
**Fix**: Create a DTLS-specific context or use options


<a id="org35c40cb"></a>

## PARAM - Parameter Errors


<a id="org3e179d9"></a>

### `[DTLS:PARAM] invalid address: <address>`

**When**: Cannot parse host address
**Fix**: Use valid IPv4/IPv6 address or hostname


<a id="orgede56f6"></a>

## IO - I/O Errors


<a id="orgd9f32bc"></a>

### `[DTLS:IO] client not connected`

**When**: I/O on unconnected DTLS client
**Fix**: Complete handshake first


<a id="org7374f7b"></a>

### `[DTLS:IO] client is closed`

**When**: Operations on closed DTLS client
**Fix**: Don't use client after closing


<a id="org9b29107"></a>

### `[DTLS:IO] server is closed`

**When**: Operations on closed DTLS server
**Fix**: Don't use server after closing


<a id="orgb276416"></a>

### `[DTLS:IO] no session for peer address`

**When**: DTLS send to unknown peer
**Fix**: Peer must complete handshake first


<a id="org1ff440e"></a>

### `[DTLS:IO] session not established`

**When**: DTLS send before handshake complete
**Fix**: Wait for handshake completion


<a id="org186bd06"></a>

## SSL - OpenSSL Errors


<a id="org943e847"></a>

### `[DTLS:SSL] handshake failed: <ssl-error>`

**When**: DTLS handshake failed
**Fix**: Check certificates, network connectivity


<a id="orgee92fba"></a>

### `[DTLS:SSL] write failed: <ssl-error>`

**When**: DTLS write operation failed
**Fix**: Check connection state


<a id="org0b11a51"></a>

## SOCKET - Socket Errors


<a id="orgd7fe6ea"></a>

### `[DTLS:SOCKET] bind failed: <errno>`

**When**: DTLS bind failed
**Fix**: Check address/port availability


<a id="org07914f8"></a>

### `[DTLS:SOCKET] connect failed: <errno>`

**When**: DTLS connect failed
**Fix**: Check server reachability


<a id="org1e08953"></a>

### `[DTLS:SOCKET] sendto failed: <errno>`

**When**: DTLS sendto() failed
**Fix**: Check connection state, buffer size


<a id="org6d56a8f"></a>

### `[DTLS:SOCKET] failed to get peer address: <errno>`

**When**: getpeername() failed on DTLS upgrade
**Fix**: Socket must be connected before upgrade


<a id="org92fd31e"></a>

# CRYPTO Module Errors


<a id="orgc807da0"></a>

## CONFIG - Configuration Errors


<a id="org19c9320"></a>

### `[CRYPTO:CONFIG] unknown digest algorithm: <alg>`

**When**: Invalid hash algorithm name
**Fix**: Use supported algorithm (sha256, sha384, sha512, etc.)

    (crypto/digest :sha256 data)  # Correct
    (crypto/digest :md5 data)     # May fail depending on OpenSSL config


<a id="org252cd58"></a>

### `[CRYPTO:CONFIG] unsupported key algorithm: <alg>`

**When**: Invalid algorithm for key generation
**Fix**: Use supported algorithm

    # Supported: :rsa, :ed25519, :x25519, :ec-p256, :ec-p384, :ec-p521
    (crypto/generate-keypair :ec-p256)  # Correct
    (crypto/generate-keypair :dsa)       # Error: unsupported


<a id="org832ae49"></a>

## PARAM - Parameter Errors


<a id="orgc9b47f7"></a>

### `[CRYPTO:PARAM] byte count must be 1-65536, got <n>`

**When**: Requesting too many or too few random bytes
**Fix**: Request between 1 and 65536 bytes

    (crypto/random-bytes 32)  # Correct: 32 bytes


<a id="org4500e15"></a>

### `[CRYPTO:PARAM] challenge length must be 8-64 bytes, got <n>`

**When**: Invalid challenge length for `crypto/random-challenge`
**Fix**: Request between 8 and 64 bytes


<a id="orgf99659c"></a>

### `[CRYPTO:PARAM] output length must be 1-<max>`

**When**: HKDF output length exceeds maximum (255 \* hash-size)
**Fix**: Request smaller output


<a id="org787cee9"></a>

### `[CRYPTO:PARAM] output length must be 1-1024`

**When**: PBKDF2 output length out of range
**Fix**: Request between 1 and 1024 bytes


<a id="orgd07ff81"></a>

### `[CRYPTO:PARAM] iterations must be positive`

**When**: Non-positive iteration count for PBKDF2
**Fix**: Use at least 1 iteration (recommend 100000+ for security)


<a id="orgc356078"></a>

### `[CRYPTO:PARAM] options must be a table or struct`

**When**: Passing non-table/struct to functions expecting options
**Fix**: Pass a table `{}` or struct `@{}`


<a id="orgce2f4d6"></a>

## SSL - OpenSSL Errors


<a id="org1282903"></a>

### `[CRYPTO:SSL] HKDF derivation failed: <ssl-error>`

**When**: Key derivation operation failed
**Fix**: Check input parameters


<a id="org64d2f49"></a>

### `[CRYPTO:SSL] PBKDF2 derivation failed: <ssl-error>`

**When**: PBKDF2 operation failed
**Fix**: Check input parameters


<a id="org8c43890"></a>

### `[CRYPTO:SSL] HMAC computation failed: <ssl-error>`

**When**: HMAC operation failed
**Fix**: Check algorithm and key


<a id="org89cf8b7"></a>

### `[CRYPTO:SSL] signing failed: <ssl-error>`

**When**: Signature operation failed
**Fix**: Check key type supports signing


<a id="org831d7bb"></a>

### `[CRYPTO:SSL] failed to generate random bytes: <ssl-error>`

**When**: Entropy source failure
**Fix**: Check system entropy (/dev/urandom)


<a id="org15591e6"></a>

## RESOURCE - Resource Errors


<a id="org99bc927"></a>

### `[CRYPTO:RESOURCE] out of memory`

**When**: Memory allocation failed
**Fix**: Check system memory, reduce allocations


<a id="org6520ead"></a>

### `[CRYPTO:RESOURCE] failed to create context`

**When**: EVP context allocation failed
**Fix**: Check memory, OpenSSL state


<a id="org4e658a0"></a>

## PARSE - Parse Errors


<a id="orgad13074"></a>

### `[CRYPTO:PARSE] base64 decode failed`

**When**: Invalid base64 input
**Fix**: Verify input is valid base64


<a id="orgee3c54f"></a>

### `[CRYPTO:PARSE] failed to parse CSR`

**When**: CSR parsing failed
**Fix**: Check CSR data validity


<a id="orgc5e8c92"></a>

# CA Module Errors


<a id="org65c1ca9"></a>

## CONFIG - Configuration Errors


<a id="orge4a5491"></a>

### `[CA:CONFIG] common-name is required`

**When**: Certificate issuance without CN
**Fix**: Provide :cn option


<a id="org6df1fe0"></a>

### `[CA:CONFIG] ca-cert is required`

**When**: CA operations without CA certificate
**Fix**: Provide CA certificate PEM


<a id="orgce536c7"></a>

### `[CA:CONFIG] ca-key is required`

**When**: CA operations without CA private key
**Fix**: Provide CA private key PEM


<a id="orgbdd8bcf"></a>

## PARAM - Parameter Errors


<a id="orgc237df1"></a>

### `[CA:PARAM] validity-days must be positive`

**When**: Invalid certificate validity period
**Fix**: Use positive number of days


<a id="org6b42442"></a>

### `[CA:PARAM] serial must be positive`

**When**: Invalid certificate serial number
**Fix**: Use positive serial number


<a id="orgba6a8bf"></a>

## SSL - OpenSSL Errors


<a id="orgb8f44fe"></a>

### `[CA:SSL] failed to sign certificate: <ssl-error>`

**When**: Certificate signing failed
**Fix**: Check CA key compatibility


<a id="orgd18fcd4"></a>

### `[CA:SSL] failed to create certificate: <ssl-error>`

**When**: X509 creation failed
**Fix**: Check memory, parameters


<a id="org55288fb"></a>

## VERIFY - Verification Errors


<a id="orga4d4686"></a>

### `[CA:VERIFY] certificate has expired`

**When**: Certificate past its validity period
**Fix**: Renew certificate


<a id="orgc593095"></a>

### `[CA:VERIFY] certificate not yet valid`

**When**: Certificate not yet in validity period
**Fix**: Check system time, certificate dates


<a id="orgcc58dfa"></a>

# CERT Module Errors


<a id="org0267cdb"></a>

## PARAM - Parameter Errors


<a id="org099d4f6"></a>

### `[CERT:PARAM] certificates must be string or array of strings`

**When**: Invalid certificate format in operations
**Fix**: Pass PEM string or array of PEM strings


<a id="orgaace89a"></a>

## PARSE - Parse Errors


<a id="orgab44f9e"></a>

### `[CERT:PARSE] failed to parse certificate: <ssl-error>`

**When**: Certificate PEM parsing failed
**Fix**: Verify certificate format


<a id="orgd7783b6"></a>

### `[CERT:PARSE] failed to parse private key: <ssl-error>`

**When**: Private key parsing failed
**Fix**: Verify key format


<a id="org1b8bf37"></a>

# Error Handling Best Practices


<a id="org813307e"></a>

## Using protect/try

    (def result
      (protect
        (tls/connect "untrusted.example.com" "443" {:verify true})))
    
    (if (nil? result)
      (print "Connection failed - check certificate")
      (do-something-with result))


<a id="orge56f807"></a>

## Checking Return Values

Many functions return `nil` on failure:

    (when-let [stream (tls/connect host port opts)]
      (defer (:close stream)
        (process-stream stream)))


<a id="org0ea3d45"></a>

## Timeouts

Always use timeouts for network operations:

    (def data (:read stream 1024 30.0))  # 30 second timeout
    (when (nil? data)
      (print "Read timed out or connection closed"))


<a id="org26bf8b2"></a>

# Testing Error Conditions

To test that your code handles errors correctly, use janet-assay's
`:expected-fail` feature for negative testing:

    (import assay)
    
    (assay/def-suite "error-handling"
      (assay/def-test "rejects invalid iterations"
        :expected-fail "[CRYPTO:PARAM]"
        (crypto/pbkdf2 :sha256 "password" "salt" 0 32)))


<a id="org329905e"></a>

# See Also

-   [API Reference](API.md) - Complete function documentation
-   [User Guide](GUIDE.md) - Getting started and examples
-   [Developer Guide](DEVELOPERS.md) - Contributing and internals

