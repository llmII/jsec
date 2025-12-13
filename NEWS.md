
# Table of Contents

-   [News](#org12a51db)
    -   [2025-12-13 - OpenSSL 3.0 Compatibility Fixes](#org38f395f)
    -   [2025-12-13 - Dependency Update](#orge1c0859)
    -   [2025-12-12 - Initial Release](#org6e1b1a0)



<a id="org12a51db"></a>

# News


<a id="org38f395f"></a>

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


<a id="orge1c0859"></a>

## 2025-12-13 - Dependency Update

-   Changed spork dependency to use upstream instead of fork, as upstream
    merged the necessary changes for spork-https compatibility


<a id="org6e1b1a0"></a>

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

