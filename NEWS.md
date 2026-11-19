

# News


## 2026-11-19 - 0.2.0-interim1

Checkpoint release from the `0.2.0` development series ahead of the remaining
full `0.2.0` release blockers. Below is the chronological summary of merges and
focus areas on `0.2.0` since the 1.41.1 baseline bump:


### 2026-11-19: Windows Support, Struct Packing, Leak Plateau Heuristics & \*San Hardening

-   Merged `fix-windows-0.2.0` (`750789c16c`): completed Windows MSVC (/W4,
    0 warnings) + Winsock2/IOCP support for TLS and DTLS (`CancelIoEx`
    in-flight teardown, `ConnectEx~/~AcceptEx` lifecycle, graceful
    `TLS_OP_CLOSE` drain, `WSAPoll` / `MSG_PEEK` reset surfacing), replaced
    the shell toolchain bootstrapper with `scripts/bootstrap-toolchain.janet`,
    and fixed cross-platform warnings.
-   Packed async state enums and boolean flags into compact `uint8_t` bitmasks
    (`JTLS_STATE_*`, `JDTLS_CAS_*`, `JTLS_ACCEPT_IO_IN_FLIGHT`) and reordered
    trailing buffers in TLS/DTLS state structs (`217c40a8d8`).
-   Merged `ticket-8437d94e5c` (`3f133c41a7`, fix `b6dee06541`): replaced
    single-window leak ceilings and macOS RSS workarounds with shared
    two-window `:vsize` plateau heuristics (`suites/helpers/leaks.janet`),
    stabilized DTLS read allocation regression under parallel workers, resolved
    all 11 `clang-tidy` diagnostics, and fixed security bugs caught by full
    Linux ASan+LSan+UBSan (0 findings, 0 LSan suppressions): heap-use-after-free
    in `jtls_attempt_io` and `cert/parse` (`extract_san`), error-path OpenSSL
    object leaks in `cert/parse` and `ca/sign-csr` / `ca/issue`, and
    GC-tracked `DTLSFlightTimer` abstract lifecycle.


### 2026-11-18: Cross-Platform BSD / macOS Waves & Async SO\_ERROR Parity

-   Merged BSD Wave 1 (`b96e1451ca`) and Wave 2 (`1bc2feb830`): enabled BSD
    toolchain bootstrap, aligned DTLS MTU setup, bounded test deadlines, and
    unified `SO_ERROR` surfacing on `JANET_ASYNC_EVENT_HUP` across epoll,
    kqueue, poll, and Windows (plus test-only `SO_LINGER` helper `rst_linger.c`
    for deterministic RST parity tests).
-   Standardized Janet platform macros across `connect.c`, `mtu.c`, and
    ~rst\_linger.c= (`cce88741cf`) and resolved Apple Clang header warnings
    (`966e6b6e41`).


### 2026-11-17: Licensing

-   Added repository ISC `LICENSE` file (`402f8aa4b6`).


### 2026-10-18: Performance Cohorts, Buffer Sizing & OCSP Serial Ceiling

-   Merged `jtls` write buffering, record coalescing, and `accept4`
    (`JSEC_SOCK_NONBLOCK` / `JSEC_SOCK_CLOEXEC`) optimizations (`d0cc05cb9f`,
    `0a676d135c`), direct-write cryptographic output buffers (`a0ed716975`),
    and the conjoined DTLS performance improvements (`d6e7bd7c18`).
-   Converted `ca/parse-ocsp-request` CertID serials from `ASN1_INTEGER`
    (`902544c9a0`) and surfaced recorded failure details across `jdtls` error
    paths (`af5796a1ca`).


### 2026-10-17: TLS Performance Cohort & Echo Benchmark Harness

-   Merged four-ticket `jtls` performance cohort (`810ffdb701`) and updated
    `perf9` echo benchmarks to pre-allocate and reuse caller ~JanetBuffer~s
    (`a2b04afe66`).


### 2026-10-16: DTLS Reliability, CA/Crypto/Cert Hardening & Stream Parity

-   Hardened DTLS server/client lifecycle across 34 ticket merges: stateless
    cookie gate ahead of session allocation (`f3e4c8c88d`), handshake flight
    retransmission timers (`8bf5daad82`), `:max-sessions` eviction
    (`1df69be2c5`), combined flight-timer reclaim guard (`d21a2ff4cf`),
    unidirectional `dtls/close` (`9957d73dbe`), port/session validation,
    datagram-sized read/recv-from caps, and error-queue draining.
-   Unified TLS/DTLS stream parity: clean `close_notify` EOF semantics
    (`4849944de8`), `:flush` method (`9bdb6dc142`), `localname~/~peername`
    exports (`430d6ef874`), `tls-stream/set-ocsp-response` stapling
    (`45ffcb0ad4`), centralized timeout parsing, and draining buffered records
    without redundant `EAGAIN` reads (`cc1c943f99`).
-   Hardened `jca`, `jcert`, and `jcrypto`: structured `crypto/cms-verify`
    verdicts (`cc8bda2de5`), checked OpenSSL returns and error-path cleanup,
    dropped legacy RSA PKCS#1 padding / 3DES key-export policies, and
    enforced option-dictionary contracts.


### 2026-10-12: DTLS Localname Dispatch & Context Security Contracts

-   Merged 19 ticket branches (`2eef29afaf`, `082164eee4`), fixing
    `dtls/localname` registration shadowing and unifying security-option
    acceptance across context builders.


### 2026-10-11: Hermetic Sanitizer Toolchain Profiles

-   Merged hermetic `*SAN` toolchain profiles (`--sanitizer none|asan|lsan|ubsan|san`
    and `self-test-*` targets, `ecef0d3bb2`) and sanitizer harness tuning for
    high-allocation and subprocess suites (`f971260a9a`).


### 2026-10-10: Fiber GC / Async Slot Lifecycle & DTLS Read Accounting

-   Merged conjoined fiber GC teardown fixes (`98a780b6cd`), stale
    `pending_read~/~pending_write` slot cleanup on cancellation (`5d33005915`),
    and 6 ticket branches including relative DTLS read `n` accounting
    (`a395e5a5c1`).


### 2026-10-09: poll(2) Event Backend & Initial 0.2.0 Ticket Batches

-   Added `poll(2)` Janet `ev`-backend support, `self-test-poll`, and the
    Janet `1.41.1` version floor guard (`03ff7fb439`), followed by 16 early
    stream/crypto/cert ticket fixes (`2457add6bb`, `6fb4ac8bdf`).


## 2026-10-15 - cms-verify Structured Verdict Table and verify-certs Option

-   PUBLIC API CHANGE (release notes): `crypto/cms-verify` now returns a
    structured result table `{:valid :content :signers :certs :error
      :error-code}`, replacing the earlier documented content-or-nil
    contract and the interim bare validity table. Verification failures
    (untrusted signer, missing trust anchor, bad signature) now report
    `:valid false` with `:error` and `:error-code` diagnostics instead of
    raising or returning an unexplained verdict; malformed inputs and
    wrong argument types still raise.
-   `crypto/cms-verify` accepts an options dictionary as its second
    argument: `:ca` / `:trusted-cert` (PEM string, buffer, array, or
    tuple) and `:verify-certs` (boolean, default true). `:verify-certs
      false` checks the cryptographic signature only - the self-signed
    inspection posture (SCEP initial enrollment) where the caller
    verifies the signer certificate out-of-band.
-   The positional form keeps working: `(crypto/cms-verify cms-der
      &opt trusted-certs detached-data)`; a detached signature is verified
    against the supplied detached content and reported in the same
    verdict table.


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

