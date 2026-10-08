

# News


## 2026-10-08 - Baseline Janet Raised to 1.41.1

-   NOTE: the minimum supported Janet baseline is now **1.41.1** (was 1.40.1),
    pinned in `scripts/bootstrap-toolchain.sh` at the v1.41.1 githash. Janet
    1.41.1 contains the upstream fix for the unix-socket connect hang on
    edge-triggered kqueue (FreeBSD); without it things hang.
-   The "Verified under" platform matrix in the 2026-10-03 entry below
    predates this change: it was run against Janet 1.40.1 and has NOT been
    re-run against 1.41.1. Treat it as a historical record and re-run the
    matrix before citing it for the 1.41.1 baseline.


## 2026-10-03 - Read Buffer Accounting & Streaming Digest Context


### Read Buffer Accounting

-   Fixed buffer offset accounting in `cfun_read` and `TLS_OP_READ` to measure
    bytes appended relative to `buf_start` instead of total buffer length
-   Matches Janet `ev/read` semantics, preventing premature EOF and early returns
    when reading into pre-filled or accumulating buffers
-   Fixes chunked encoding state corruption and premature stream termination in HTTP clients


### Streaming Digest Context

-   Added streaming cryptographic digest context API: `crypto/digest-begin`,
    `crypto/digest-update`, `crypto/digest-finish`, `crypto/digest-close`
-   Uses boxed `EVP_MD_CTX*` abstract type (`jsec/digest-ctx`) for incremental
    hashing without buffering entire payloads in memory


### Platform Verification Note

-   Verified under Linux Host x86\_64 (Janet 1.40.1, OpenSSL 3.6.5)
-   Verified under Ubuntu 24.04 LTS x86\_64 (Janet 1.40.1, GCC 13.3.0, OpenSSL 3.0.13)
-   Verified under Chimera Linux x86\_64 (musl libc, LLVM/Clang 22.1.8, OpenSSL 3.6.4, with -j fiber:16,thread:6,subprocess:6 assay parallelism)
-   Verified under DragonFly BSD 6.4.2 x86\_64 (Janet 1.40.1, LibreSSL 3.6.1)
-   Verified under FreeBSD 15.0-RELEASE x86\_64 (Janet 1.40.1, OpenSSL 3.5.4)
-   Verified under OpenBSD 7.8 x86\_64 (Janet 1.40.1, LibreSSL 4.2.0)
-   Verified under NetBSD 10.1 x86\_64 (Janet 1.40.1, OpenSSL 3.0.12)
-   Verified under macOS Sequoia 15.7 x86\_64 (Darwin 24.6.0, Janet 1.40.1, OpenSSL 3.x)
-   Verified under macOS Tahoe 26.2 x86\_64 (Darwin 25.2.0, Janet 1.40.1, OpenSSL 3.x)
-   Verified under OpenIndiana Hipster x86\_64 (SunOS 5.11 / Illumos, Janet 1.40.1, OpenSSL 3.5.9)
-   Verified under Windows 11 x86\_64 (Janet 1.40.1, MSVC 2022, vcpkg OpenSSL 3.x, IOCP)
-   Note: Janet 1.40.1 headers emit -Wcast-align warnings under macOS Apple Clang for
    the time being; left unpatched to retain clean compatibility with supported Janet 1.40.1
-   Cross-platform verification complete across all 11 target environments


## 2025-12-27 - DTLS Cross-Platform Fixes

DTLS now works correctly on all platforms:


### Platform-Specific BIO Strategy

-   Unix (Linux, FreeBSD, NetBSD, macOS, DragonflyBSD, OpenBSD): Uses dgram BIO which handles socket I/O directly
-   Windows: Uses memory BIOs with manual recv/send coordination for IOCP compatibility


### Bug Fixes

-   Fixed DTLS hangs on BSD platforms (FreeBSD, NetBSD, macOS)
-   Fixed `dtls/upgrade` handshake failure on NetBSD (missing peer address on dgram BIO)
-   Code now correctly matches trunk behavior: SSL operations handle socket I/O through dgram BIO


## 2025-12-26 - Windows IOCP Support Complete

Windows is now fully supported with all tests passing:


### Windows Platform Status

-   All tests pass (Unix socket tests automatically skipped)
-   Build via MSVC (Visual Studio 2022) with vcpkg OpenSSL
-   IOCP event loop integration complete


### Key Fixes

-   Fixed connection error detection on Windows
    -   Windows `WSAConnect` returns success immediately, errors on first I/O
    -   Updated tests to write after connect for cross-platform consistency
-   DTLS client refactored to use memory BIOs on Windows


### clang-format Configuration

-   `IndentPPDirectives: None` - preprocessor directives at column 0
-   Code inside `#ifdef` blocks maintains normal indentation


## 2025-12-24 - OpenBSD LibreSSL Support & Code Quality Improvements

OpenBSD is now fully supported with all tests passing:


### OpenBSD (LibreSSL 3.9+)

-   Fixed TLS hang in `accept-loop` test caused by premature WANT\_READ returns
-   Added do-while loop in `jtls_attempt_io` to retry operations when BIO buffer has unread data
-   Prevents yielding to event loop when local buffered data can satisfy reads
-   All tests now pass on OpenBSD 7.6


### Code Quality Improvements

-   Migrated from astyle to clang-format for C code formatting
-   Consistent style with 4-space indentation, 78/80 column limits
-   Improved buffer allocation code clarity with better variable naming
-   Added `check-format-c` task to verify formatting compliance
-   Updated CONTRIBUTING documentation


### Buffer Management

-   Clarified `janet_buffer_ensure` usage in TLS read operations
-   Renamed confusing `capacity` variables to `read_size` for clarity
-   Added comments explaining buffer allocation logic
-   No functional changes - existing code was correct


## 2025-12-24 - NetBSD & DragonflyBSD Support

NetBSD and DragonflyBSD are now fully supported with all tests passing:


### NetBSD (OpenSSL 3.x)

-   Tested on NetBSD 10.1
-   All tests pass
-   No platform-specific changes needed


### DragonflyBSD (LibreSSL 3.9+)

-   Tested on DragonflyBSD 6.4
-   All tests pass
-   Fixed `BIO_flush~/~BIO_reset` unused value warnings


### LibreSSL Compatibility

-   LibreSSL support now working across all BSD platforms upon which it is native
-   Conditional compilation for OpenSSL 3.0 vs LibreSSL APIs
-   All BSDs tested and passing: FreeBSD, NetBSD, DragonflyBSD


## 2025-12-23 - macOS Support via Homebrew OpenSSL

macOS is now fully supported with all tests passing:


### Requirements

-   Homebrew OpenSSL 3.x: `brew install openssl@3`
-   Janet and jpm


## 2025-12-15 - FreeBSD Support & Performance Improvements

All tests continue to pass under Linux and FreeBSD is now fully supported with
all tests passing:


### FreeBSD Fixes

-   Fixed build failures: header order, implicit fallthrough warnings, MSG\_DONTWAIT
-   Fixed time function calls: use `clock_gettime` with `CLOCK_MONOTONIC` instead
    of `gettimeofday` which isn't available with `__POSIX_C_SOURCE`
-   Fixed DTLS and Unix socket handling for FreeBSD's kqueue-based event loop
-   Better shutdown handling with scheduled close operations for TLS streams


### Performance Improvements

-   Embedded `TLSState` directly in `TLSStream` to eliminate malloc per I/O operation
-   Reduced `memset` calls in hot paths by only zeroing fields that need reset
-   Added `-O2` optimization flag to production builds
-   Some keywords cached to prevent runtime lookups in hot paths


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


## 2025-12-13 - Dependency Update

-   Changed spork dependency to use upstream instead of fork, as upstream
    merged the necessary changes for spork-https compatibility


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

