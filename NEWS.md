
# Table of Contents

-   [News](#orga094e85)
    -   [2025-12-23 - macOS Support via Homebrew OpenSSL](#org898fe99)
    -   [2025-12-15 - FreeBSD Support & Performance Improvements](#org84f5b3b)
    -   [2025-12-13 - OpenSSL 3.0 Compatibility Fixes](#orgcfe8bca)
    -   [2025-12-13 - Dependency Update](#orgb0e8b77)
    -   [2025-12-12 - Initial Release](#org487de19)



<a id="orga094e85"></a>

# News


<a id="org898fe99"></a>

## 2025-12-23 - macOS Support via Homebrew OpenSSL

macOS is now fully supported with all tests passing:


### Requirements

-   Homebrew OpenSSL 3.x: `brew install openssl@3`
-   Janet and jpm


<a id="org84f5b3b"></a>

## 2025-12-15 - FreeBSD Support & Performance Improvements

All tests continue to pass under Linux and FreeBSD is now fully supported with
all tests passing:


### FreeBSD Fixes

-   Fixed build failures: header order, implicit fallthrough warnings, MSG<sub>DONTWAIT</sub>
-   Fixed time function calls: use `clock_gettime` with `CLOCK_MONOTONIC` instead
    of `gettimeofday` which isn't available with `__POSIX_C_SOURCE`
-   Fixed DTLS and Unix socket handling for FreeBSD's kqueue-based event loop
-   Better shutdown handling with scheduled close operations for TLS streams


### Performance Improvements

-   Embedded `TLSState` directly in `TLSStream` to eliminate malloc per I/O operation
-   Reduced `memset` calls in hot paths by only zeroing fields that need reset
-   Added `-O2` optimization flag to production builds
-   Some keywords cached to prevent runtime lookups in hot paths


<a id="orgcfe8bca"></a>

## 2025-12-13 - OpenSSL 3.0 Compatibility Fixes

Several fixes were made to ensure jsec works correctly with OpenSSL 3.0:

-   Fixed `PEM_read_bio_PrivateKey` usage to provide explicit empty password
    callback, preventing OpenSSL 3.0 from prompting on TTY for pass phrases
-   Extended pass phrase handling to cover cases where a password is expected
    but none is provided
-   Fixed `crypto/key-info` to detect encrypted keys early and return without
    attempting to parse the private key (which would trigger TTY prompts)
-   Fixed `X509_PURPOSE_CODE_SIGN` which doesn't exist in OpenSSL 3.0, now
    using alternative approach for code signing purpose verification
-   Fixed function name capitalization issue affecting OpenSSL 3.0

These changes ensure jsec works with both OpenSSL 3.0.x and 3.5.x.


<a id="orgb0e8b77"></a>

## 2025-12-13 - Dependency Update

-   Changed spork dependency to use upstream instead of fork, as upstream
    merged the necessary changes for spork-https compatibility


<a id="org487de19"></a>

## 2025-12-12 - Initial Release

First release of jsec, a comprehensive TLS/SSL library for Janet providing:

-   Full TLS client and server support with modern cipher suites
-   X.509 certificate handling (creation, parsing, verification)
-   Private key management (RSA, EC, Ed25519, Ed448)
-   CSR (Certificate Signing Request) support
-   PKCS#12 bundle handling
-   CA (Certificate Authority) operations
-   Digest functions (SHA-256, SHA-384, SHA-512, etc.)
-   HMAC support
-   Random number generation
-   Base64 encoding/decoding
-   Comprehensive error handling

See [README](README.md) for full documentation and usage examples.

