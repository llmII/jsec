
# Table of Contents

1.  [Overview](#org036ccbf)
    1.  [API Compatibility Guarantee](#org8565e01)
2.  [⚠️ Security and Auditing Disclaimer](#orge564d60)
3.  [✅ Robust Testing & Stability Assurance](#orgde6ae6b)
    1.  [Example Performance Output](#orgf587270)
    2.  [Testing Status & Maturity](#orgde8c1ab)
4.  [⭐ Features and Compatibility](#orgd2ec54b)
    1.  [Core Features](#org22e07df)
    2.  [Supported Backends](#org22c4154)
    3.  [Operating System Support](#org68605a8)
    4.  [Current Limitations](#org14a2327)
5.  [Installation](#org382bcce)
6.  [Documentation & Examples](#orgd7d40ba)
7.  [Quick Start](#org7823b69)
    1.  [Secure Client (TCP/TLS)](#org831dd79)
    2.  [Secure Server (TCP/TLS)](#orgf5e11a5)
    3.  [Self-Signed Certificate Generation](#orga82d847)
    4.  [STARTTLS Upgrade](#orgc49ee94)
    5.  [DTLS (Datagram TLS)](#org8714f82)
    6.  [BIO (Basic I/O Abstraction)](#org98a4a92)
    7.  [Crypto Primitives](#org87c2bf5)
8.  [Development & Testing](#orgf927aa8)
    1.  [Building](#orga216693)
    2.  [Running Tests](#org54f1b40)
    3.  [Memory Leak Checking](#orgc6eaf91)
    4.  [Debug Build](#orge0383cd)
    5.  [Code Formatting](#orga6bc3cf)
    6.  [Documentation Generation](#org5275f92)
    7.  [Release Process](#orgcb6514e)
    8.  [Test Coverage Details](#orga8cf2db)
9.  [Security Configuration](#orge83960a)
10. [Contributing](#orge3c97a9)
    1.  [Areas Seeking Help](#org976cd9e)
        1.  [Platform Support](#org73640f7)
        2.  [Testing & Quality](#org026aa11)
        3.  [Performance](#org7e6784d)
        4.  [DTLS](#org2bc629d)
        5.  [Documentation & Examples](#orga132af2)
        6.  [Infrastructure](#orgf078a83)
    2.  [How to Contribute](#org0aa916d)
11. [License](#org7dc86b9)
12. [Credits and Acknowledgments](#org05c3605)
    1.  [Janet Language](#org0d2488a)
    2.  [cqueues](#orgc45ff72)
    3.  [janet-jdn](#org1af230f)



<a id="org036ccbf"></a>

# Overview

**jsec** (JSEC) is a TLS/SSL library for Janet that aims to be production-quality, built on OpenSSL. It features proper async integration with Janet's event loop (\`ev/\`), a security-first design, and comprehensive support for both client and server modes.


<a id="org8565e01"></a>

## API Compatibility Guarantee

The primary design goal of \`jsec\` is strict compatibility with Janet's standard Stream API.

-   ****Initialization:**** The only intended difference is in connection initialization (e.g., \`tls/connect\` vs \`net/connect\`).
-   ****Behavior:**** Once established, a TLS stream should behave **identically** to a standard TCP stream for all methods (\`:read\`, \`:write\`, \`:close\`, \`:chunk\`, etc.).
-   ****Extensions:**** Where the standard API uses optional arguments (\`&opt\`), \`jsec\` may offer extensions. These arguments function as an "either/or" mechanism: they strictly support the standard Janet Stream API conventions but may **also** accept library-specific values (e.g., TLS-specific configuration tables) where appropriate.

****Any deviation in behavior from the standard Janet Stream API (unexpected blocking, method signature mismatches, return value differences) when used in a standard context is considered a bug.**** The author has validated this to the best of their ability, but if you encounter any such inconsistency, please report it immediately.


<a id="orge564d60"></a>

# ⚠️ Security and Auditing Disclaimer

This library implements critical cryptographic protocols. Users must understand the risks associated with this type of software:

-   ****NO formal security audit has been performed on this codebase.**** While the library aims to follow strict engineering and testing standards, we recommend users perform their own risk assessment before deploying in high-value or sensitive production environments. Use at your own risk.
-   ****Cryptographic Primitives:**** The security of the library relies heavily on the underlying C libraries (OpenSSL). While these libraries are industry standards, the binding layer and integration logic have not yet undergone external security review.
-   ****Vulnerability Reporting:**** We highly encourage community review. If you discover a vulnerability, please report it immediately via a fossil ticket or GitHub issue as a public issue. We will address valid reports as promptly as possible. Once the library has been audited in the future this section will be updated with information on how to submit privately so that a fix can be made before the issue is made publicly known, but during this phase of development there is no reason such should not be public by default, and we will strive to keep things as public by default even in the future unless there is a true worry that disclosure might lead to abuse.


<a id="orgde6ae6b"></a>

# ✅ Robust Testing & Stability Assurance

While a security audit is pending, the library maintains high standards for functional correctness and stability:

-   ****Comprehensive Test Suite:**** The library currently passes over ****2,000 automated functional tests**** covering handshake procedures, certificate validation, data transfer, error handling, and various edge cases. The high test count is derived from a matrix of test configurations (TLS versions, cipher suites, underlying raw protocol, etc.) run against every functional test case.
-   ****Performance Benchmarking (Experimental):**** A preliminary performance testing framework (perf9) exists for benchmarking throughput, latency, and scalability. **Note: Performance testing is unstable - output formats, metrics, and implementation details are subject to change. Both Janet and C-side optimizations are ongoing.**
    -   Protocol comparison (TCP vs TLS vs Unix sockets)
    -   TLS version performance comparison
    -   Scaling tests across client counts
    -   Concurrency mode testing (fibers, threads, subprocesses)
    -   Handshake timing analysis
-   ****Continuous Integration:**** Tests are run automatically on every commit via GitHub Actions across Linux environments to ensure ongoing stability. (planned)


<a id="orgf587270"></a>

## Example Performance Output

Note that perf can be somewhat skewed by testing framework intricacies but it
gives a bit of an idea.

<div class="details" id="org19f657b">
<div class="summary" id="orgf5a9355">
<p>
Sample perf9 run: 50 clients, 4 servers, 4 client-hosts, threaded mode, 30s duration
</p>

</div>

<pre class="example" id="org4d44002">
================================================================================
  Results by Protocol
================================================================================

  tcp:
    Throughput:    338.07 MB/s (mean), 338.07 MB/s (median), 338.07 MB/s (p95)
    Client range:  1.68 MB/s (slowest) → 1.87 MB/s (fastest)
    Total bytes:   9.90 GB
    Iterations:    81136
    Connected:     200/200
    Participants:  4 server(s), 4 client-host(s)
    Tests:         1

  tls:
    Throughput:    196.54 MB/s (mean), 196.54 MB/s (median), 200.93 MB/s (p95)
    Client range:  980.33 KB/s (slowest) → 1.01 MB/s (fastest)
    Handshake:     346.24 ms (mean), 363.73 ms (p95)
    Total bytes:   11.52 GB
    Iterations:    94339
    Connected:     400/400
    Participants:  4 server(s), 4 client-host(s)
    Tests:         2

================================================================================
  Results by TLS Version
================================================================================

  TLS 1.3:
    Throughput:    196.54 MB/s (mean), 196.54 MB/s (median), 200.93 MB/s (p95)
    Client range:  980.33 KB/s (slowest) → 1.01 MB/s (fastest)
    Handshake:     347.64 ms (mean), 366.18 ms (p95)
    Total bytes:   11.52 GB
    Iterations:    94339
    Connected:     400/400
    Participants:  4 server(s), 4 client-host(s)
    Tests:         2

================================================================================
  Overall Statistics
================================================================================

  All tests:
    Throughput:    243.72 MB/s (mean), 200.93 MB/s (median), 338.07 MB/s (p95)
    Client range:  980.33 KB/s (slowest) → 1.87 MB/s (fastest)
    Handshake:     348.33 ms (mean), 366.47 ms (p95)
    Total bytes:   21.42 GB
    Iterations:    175475
    Connected:     600/600
    Participants:  4 server(s), 4 client-host(s)
    Tests:         3
</pre>

<p>
Run command:
</p>

<div class="org-src-container">
<pre class="src src-bash"># TCP test
janet test/runner.janet \
  -f 'performance/perf9/echo[protocol=:tcp,client-count=50,duration=30]&lt;parallel=:thread,server=4,client-host=4&gt;' \
  --json /tmp/perf-tcp.json

# TLS 1.3 test
janet test/runner.janet \
  -f 'performance/perf9/echo[protocol=:tls,client-count=50,duration=30,tls-version=1.3]&lt;parallel=:thread,server=4,client-host=4&gt;' \
  --json /tmp/perf-tls.json

# Analyze results
./bin/perf9-analyze -n /tmp/perf-combined.json
</pre>
</div>

</div>


<a id="orgde8c1ab"></a>

## Testing Status & Maturity

Although the test count is high, effectively approaching fuzzing-level coverage, the library is still in active development. While the current test suite has successfully prevented known bugs, coverage is not yet exhaustive. Users should assume that testing requires further refinement, even though the current state is robust. The test infrastructure includes mechanisms to track expected failures and skips, ensuring that the matrix of scenarios is handled correctly.


<a id="orgd2ec54b"></a>

# ⭐ Features and Compatibility

The library is designed for flexibility and portability across various systems and underlying TLS implementations.


<a id="org22e07df"></a>

## Core Features

-   ****Async-First:**** Fully integrated with Janet's \`ev\` module for non-blocking I/O.
-   ****Secure Defaults:**** Certificate verification enabled by default. Modern TLS 1.2+ only.
-   ****TLS 1.2 & 1.3:**** Full support (dependent on underlying C library version).
-   ****Client & Server Modes:**** Robust support for both ends of the connection.
-   ****Certificate Handling:**** Full support for validation and mTLS (Mutual TLS).
-   ****OCSP Stapling:**** Support included.
-   ****SNI:**** Server Name Indication support.
-   ****Session Resumption:**** Built-in OpenSSL session cache support for performance.
-   ****Runtime Cert Generation:**** Generate self-signed certificates on the fly.


<a id="org22c4154"></a>

## Supported Backends

The library is designed to abstract communication using multiple industry-standard C libraries:

-   ****OpenSSL (Priority):**** Initial development is focused entirely on OpenSSL bindings. This provides robust, battle-tested security infrastructure.
-   ****mbedTLS (Planned):**** Support for mbedTLS is intended for future releases to offer a lighter-weight alternative, particularly suited for embedded systems.


<a id="org68605a8"></a>

## Operating System Support

-   ****Linux:**** Fully supported from day one via standard CI pipelines. (CI planned)
-   ****BSD & Windows (Planned):**** These platforms are intended targets. The underlying architecture should make portability straightforward.
    -   If you are willing to help debug and test on these platforms, we encourage you to submit patches! The author welcomes contributions and will assist wherever possible in ironing out platform-specific bugs.


<a id="org14a2327"></a>

## Current Limitations

-   [ ] ****DTLS Support is minimal/experimental.**** It is not recommended for production use yet (mostly performance issues).
-   [ ] Only X.509 certificates are supported; no FIDO/U2F integration.


<a id="org382bcce"></a>

# Installation

    jpm install https://github.com/llmII/jsec.git


<a id="orgd7d40ba"></a>

# Documentation & Examples

-   ****[API Reference](docs/API.md)****: Detailed documentation of all modules and functions.
-   ****[Guides](docs/GUIDE.md)****: Best practices, Async I/O, mTLS, and more.
-   ****[Examples](examples/)****: Complete, runnable code examples.


<a id="org7823b69"></a>

# Quick Start


<a id="org831dd79"></a>

## Secure Client (TCP/TLS)

    (import jsec/tls)
    
    # Connect to a server (certificate verification enabled by default)
    (def stream (tls/connect "example.com" "443"))
    
    (defer (:close stream)
      # Send HTTP request
      (:write stream "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    
      # Read response
      (def buf @"")
      (while (def chunk (:read stream 4096))
        (buffer/push buf chunk))
    
      (print (string buf)))


<a id="orgf5e11a5"></a>

## Secure Server (TCP/TLS)

    (import jsec/tls)
    
    # Create a listener
    (def listener (tls/listen "127.0.0.1" "8443"))
    
    (print "Listening on 127.0.0.1:8443...")
    
    (forever
      (def client (tls/accept listener {
        :cert "server-cert.pem"
        :key "server-key.pem"
      }))
    
      (ev/go (fn []
        (defer (:close client)
          (:write client "Hello, Secure World!\n")))))


<a id="orga82d847"></a>

## Self-Signed Certificate Generation

Useful for testing or internal tools.

    (import jsec/cert)
    
    (def certs (cert/generate-self-signed-cert {
      :common-name "localhost"
      :days-valid 30
    }))
    
    (spit "cert.pem" (certs :cert))
    (spit "key.pem" (certs :key))


<a id="orgc49ee94"></a>

## STARTTLS Upgrade

Upgrade an existing plaintext connection to TLS.

    (import jsec/tls)
    
    # 1. Connect in plaintext
    (def stream (net/connect "smtp.example.com" "25"))
    
    # ... perform plaintext handshake (EHLO, STARTTLS) ...
    (:write stream "STARTTLS\r\n")
    (:read stream 1024) # Consume server response
    
    # 2. Upgrade to TLS
    (print "Upgrading...")
    (def tls-stream (tls/upgrade stream "smtp.example.com" {
      :verify true
    }))
    
    # 3. Continue securely
    (:write tls-stream "AUTH PLAIN ...")


<a id="org8714f82"></a>

## DTLS (Datagram TLS)

**Note: DTLS support is currently experimental.**

    (import jsec/dtls)
    
    # Client
    (def udp-socket (net/connect "127.0.0.1" "4433" :datagram))
    (def dtls-client (dtls/client udp-socket {:verify true}))
    
    (dtls/write dtls-client "Hello DTLS")
    (print (dtls/read dtls-client 1024))
    (dtls/close dtls-client)
    
    # Server
    (def listener (net/listen "0.0.0.0" "4433" :datagram))
    (def dtls-server (dtls/server listener {
      :cert "cert.pem"
      :key "key.pem"
    }))


<a id="org98a4a92"></a>

## BIO (Basic I/O Abstraction)

Use OpenSSL BIOs for custom I/O handling, such as memory buffers.

    (import jsec/bio)
    
    (def mem-bio (bio/new-mem))
    (bio/write mem-bio "Secret Data")
    (def data (bio/read mem-bio 100))


<a id="org87c2bf5"></a>

## Crypto Primitives

Access to OpenSSL crypto functions for hashing, signing, and verification.

    (import jsec/crypto)
    
    # Hashing
    (def hash (crypto/digest :sha256 "data"))
    
    # Signing (Ed25519)
    (def key (crypto/generate-key :ed25519))
    (def sig (crypto/sign key "data"))
    (def valid (crypto/verify key "data" sig))


<a id="orgf927aa8"></a>

# Development & Testing


<a id="orga216693"></a>

## Building

Standard build:

    jpm build

Clean build:

    jpm clean
    jpm build


<a id="org54f1b40"></a>

## Running Tests

Run tests using the assay test runner directly (jpm test is deprecated):

    # Run unit, regression, and coverage tests (excludes long-running performance)
    janet test/runner.janet -f '{unit,regression,coverage}'
    
    # Run with summary output
    janet test/runner.janet -f '{unit,regression,coverage}' --verbosity 1
    
    # Run specific category
    janet test/runner.janet -f 'unit'
    
    # Run specific suite pattern
    janet test/runner.janet -f 'unit/TLS*'
    
    # List available suites
    janet test/runner.janet --list suites

See [docs/TESTING.org](docs/TESTING.md) for complete testing documentation.


<a id="orgc6eaf91"></a>

## Memory Leak Checking

Run tests under valgrind:

    janet test/runner.janet --wrapper 'valgrind --leak-check=full'


<a id="orge0383cd"></a>

## Debug Build

Enable debug logging in C code:

    # Edit src/jshared.h and uncomment: #define JSEC_DEBUG 1
    jpm build


<a id="orga6bc3cf"></a>

## Code Formatting

Format Janet code:

    jpm run format-janet

Format C code:

    jpm run format-c


<a id="org5275f92"></a>

## Documentation Generation

Generate markdown from org files:

    jpm run docs


<a id="orgcb6514e"></a>

## Release Process

Prepare a release:

    jpm run release

This runs: clean, format checks, build, tests, leak checks, and documentation
generation.


<a id="orga8cf2db"></a>

## Test Coverage Details

The test suite is extensive, with over 2,000 generated test cases covering:

-   TLS Suite: Client/server, STARTTLS, SNI, session resumption, OCSP, concurrency (Main Matrix)
-   DTLS Suite: UDP/DTLS client/server operations
-   Cert Suite: Certificate generation and validation
-   BIO Suite: Memory BIO operations
-   Crypto Suite: Hashing, signing, verification


<a id="orge83960a"></a>

# Security Configuration

You can pass a \`:security\` table to \`connect\` or \`accept\` to enforce policies:

    :security {
      :min-version "TLS1.2"
      :max-version "TLS1.3"
      :ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
      :curves "X25519:P-256"
      :session-cache-size 1000
    }


<a id="orge3c97a9"></a>

# Contributing

We welcome contributions! JSEC is an ambitious project and there are many areas where community help would be valuable.


<a id="org976cd9e"></a>

## Areas Seeking Help


<a id="org73640f7"></a>

### Platform Support

-   **Windows:** Testing, debugging, and CI improvements for Windows builds (MSYS2/MinGW-w64)
-   **macOS:** The author lacks Apple hardware; community testing and fixes are essential
-   **BSD:** Porting and testing on FreeBSD, OpenBSD, NetBSD


<a id="org026aa11"></a>

### Testing & Quality

-   **Test Suite Expansion:** Additional edge cases, protocol scenarios, error conditions
-   **Sanitizer Integration:** Improving ASan/UBSan/LSan coverage and CI integration
-   **Fuzzing:** Setting up continuous fuzzing infrastructure
-   **Code Review:** Security-focused review of the C binding layer

1.  Quick Wins for New Contributors

    Looking for an easy way to get started? These focused improvements help build familiarity with the codebase:
    
    -   **Convert server/client tests to assay coordinated tests:** Many TLS/DTLS tests manually spawn server and client fibers with `ev/sleep` delays to coordinate timing. These patterns are ideal candidates for conversion to assay's `coordinated` test type, which provides built-in participant synchronization via barriers and channels. While `coordinated` was designed for performance testing, it works well for any multi-participant scenario requiring coordination. See `suites/performance/` for examples.
    -   **Expand matrix test coverage:** assay's `matrix` feature generates test combinations automatically. Originally designed for fuzz testing parameter spaces, matrices are useful anywhere you need to test across multiple configurations (TLS versions, cipher suites, buffer sizes, etc.). Look for tests with manual loops over configurations that could be converted to declarative matrices.


<a id="org7e6784d"></a>

### Performance

-   **C-side Optimizations:** Buffer handling, memory allocation patterns
-   **Janet-side Optimizations:** API layer efficiency improvements
-   **Benchmarking:** Expanding the perf9 test matrix and analysis tools
-   **Profiling:** Identifying bottlenecks under various workloads


<a id="org2bc629d"></a>

### DTLS

-   **Protocol Correctness:** DTLS has known issues and needs attention
-   **Multi-client Server:** Improving the DTLS server implementation
-   **Testing:** Expanding DTLS test coverage


<a id="orga132af2"></a>

### Documentation & Examples

-   **Tutorials:** Real-world usage guides (mTLS setup, OCSP, etc.)
-   **Examples:** More complete example applications
-   **API Documentation:** Improving clarity and completeness


<a id="orgf078a83"></a>

### Infrastructure

-   **CI/CD:** GitHub Actions improvements, cross-platform testing
-   **Packaging:** Distribution packages, container images
-   **Testing Framework:** Improvements to the [assay](https://github.com/llmII/janet-assay) test framework


<a id="org0aa916d"></a>

## How to Contribute

1.  Check existing issues on GitHub or Fossil
2.  For large changes, open an issue first to discuss approach
3.  Follow the coding style (see `jpm run format-janet` and `jpm run format-c`)
4.  Ensure tests pass: `janet test/runner.janet -f '{unit,regression,coverage}'`
5.  Submit a PR on GitHub or patch via Fossil


<a id="org7dc86b9"></a>

# License

ISC License. See LICENSE file.


<a id="org05c3605"></a>

# Credits and Acknowledgments

This project was made possible by studying and learning from:


<a id="org0d2488a"></a>

## Janet Language

-   Authors: Calvin Rose and contributors
-   License: MIT
-   Website: <https://janet-lang.org/>
-   Some test patterns in this library were adapted from Janet's test suite (MIT licensed).


<a id="orgc45ff72"></a>

## cqueues

-   Author: William Ahern
-   License: MIT
-   Repository: <https://github.com/wahern/cqueues>
-   The event loop integration patterns, particularly for TLS BIO handling, were informed by studying cqueues' excellent implementation.


<a id="org1af230f"></a>

## janet-jdn

-   Author: Andrew Chambers
-   License: MIT
-   Repository: <https://github.com/andrewchambers/janet-jdn>
-   The JDN encode/decode pattern in our performance testing framework is based on his work.

If you are an author or contributor to any project that influenced this work and would like explicit acknowledgment, please file a GitHub issue or fossil ticket.

