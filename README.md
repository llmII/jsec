

# Overview

**jsec** (JSEC) is a TLS/SSL library for Janet that aims to be production-quality, built on OpenSSL. It features proper async integration with Janet's event loop (\`ev/\`), a security-first design, and comprehensive support for both client and server modes.


## API Compatibility Guarantee

The primary design goal of \`jsec\` is strict compatibility with Janet's standard Stream API.

-   ****Initialization:**** The only intended difference is in connection initialization (e.g., \`tls/connect\` vs \`net/connect\`).
-   ****Behavior:**** Once established, a TLS stream should behave **identically** to a standard TCP stream for all methods (\`:read\`, \`:write\`, \`:close\`, \`:chunk\`, etc.).
-   ****Extensions:**** Where the standard API uses optional arguments (\`&opt\`), \`jsec\` may offer extensions. These arguments function as an "either/or" mechanism: they strictly support the standard Janet Stream API conventions but may **also** accept library-specific values (e.g., TLS-specific configuration tables) where appropriate.

****Any deviation in behavior from the standard Janet Stream API (unexpected blocking, method signature mismatches, return value differences) when used in a standard context is considered a bug.**** The author has validated this to the best of their ability, but if you encounter any such inconsistency, please report it immediately.


# ⚠️ Security and Auditing Disclaimer

This library implements critical cryptographic protocols. Users must understand the risks associated with this type of software:

-   ****NO formal security audit has been performed on this codebase.**** While the library aims to follow strict engineering and testing standards, we recommend users perform their own risk assessment before deploying in high-value or sensitive production environments. Use at your own risk.
-   ****Cryptographic Primitives:**** The security of the library relies heavily on the underlying C libraries (OpenSSL). While these libraries are industry standards, the binding layer and integration logic have not yet undergone external security review.
-   ****Vulnerability Reporting:**** We highly encourage community review. If you discover a vulnerability, please report it immediately via a fossil ticket or GitHub issue as a public issue. We will address valid reports as promptly as possible. Once the library has been audited in the future this section will be updated with information on how to submit privately so that a fix can be made before the issue is made publicly known, but during this phase of development there is no reason such should not be public by default, and we will strive to keep things as public by default even in the future unless there is a true worry that disclosure might lead to abuse.


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


## Example Performance Output

Note that perf can be somewhat skewed by testing framework intricacies but it
gives a bit of an idea.

<div class="details" id="org987d585">
<div class="summary" id="orgc5e7371">
<p>
Sample perf9 run: 50 clients, 4 servers, 4 client-hosts, threaded mode, 30s duration
</p>

</div>

<pre class="example" id="org1da8024">
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


## Testing Status & Maturity

Although the test count is high, effectively approaching fuzzing-level coverage, the library is still in active development. While the current test suite has successfully prevented known bugs, coverage is not yet exhaustive. Users should assume that testing requires further refinement, even though the current state is robust. The test infrastructure includes mechanisms to track expected failures and skips, ensuring that the matrix of scenarios is handled correctly.


# ⭐ Features and Compatibility

The library is designed for flexibility and portability across various systems and underlying TLS implementations.


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


## Supported Backends

The library supports multiple industry-standard TLS/SSL C libraries:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Backend</th>
<th scope="col" class="org-left">Status</th>
<th scope="col" class="org-left">Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left">OpenSSL</td>
<td class="org-left">Working</td>
<td class="org-left">Primary backend. OpenSSL 3.0+ required.</td>
</tr>

<tr>
<td class="org-left">LibreSSL</td>
<td class="org-left">Working</td>
<td class="org-left">For BSD platforms. Requires LibreSSL 3.9+.</td>
</tr>

<tr>
<td class="org-left">SChannel</td>
<td class="org-left">Future</td>
<td class="org-left">Native Windows TLS (no OpenSSL dependency).</td>
</tr>

<tr>
<td class="org-left">Network.framework</td>
<td class="org-left">Future</td>
<td class="org-left">Native MacOS way of doing TLS.</td>
</tr>

<tr>
<td class="org-left">mbedTLS</td>
<td class="org-left">Future</td>
<td class="org-left">Lighter-weight alternative for embedded use.</td>
</tr>
</tbody>
</table>


## Operating System Support

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Platform</th>
<th scope="col" class="org-left">Status</th>
<th scope="col" class="org-left">Backend</th>
<th scope="col" class="org-left">Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left">Linux</td>
<td class="org-left">Working</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">Primary development platform</td>
</tr>

<tr>
<td class="org-left">FreeBSD</td>
<td class="org-left">Working</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">Tested on FreeBSD 15</td>
</tr>

<tr>
<td class="org-left">macOS</td>
<td class="org-left">Working</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">Via Homebrew: <code>brew install openssl@3</code></td>
</tr>

<tr>
<td class="org-left">NetBSD</td>
<td class="org-left">Working</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">Tested on NetBSD 10.1</td>
</tr>

<tr>
<td class="org-left">DragonflyBSD</td>
<td class="org-left">Working</td>
<td class="org-left">LibreSSL 3.6+</td>
<td class="org-left">Tested on DragonflyBSD 6.4</td>
</tr>

<tr>
<td class="org-left">OpenBSD</td>
<td class="org-left">Working</td>
<td class="org-left">LibreSSL 3.6+</td>
<td class="org-left">All tests pass on OpenBSD 7.6</td>
</tr>

<tr>
<td class="org-left">Windows</td>
<td class="org-left">Working</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">MSVC + vcpkg, see <a href="docs/WINDOWS.html">Windows Guide</a></td>
</tr>
</tbody>
</table>


## Current Limitations

-   [ ] ****DTLS Support is minimal/experimental.**** It is not recommended for production use yet (mostly performance issues).
-   [ ] Only X.509 certificates are supported; no FIDO/U2F integration.


# Installation

    jpm install https://github.com/llmII/jsec.git


# Documentation & Examples

-   ****[API Reference](docs/API.md)****: Detailed documentation of all modules and functions.
-   ****[Guides](docs/GUIDE.md)****: Best practices, Async I/O, mTLS, and more.
-   ****[Examples](examples/)****: Complete, runnable code examples.


# Quick Start


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


## Self-Signed Certificate Generation

Useful for testing or internal tools.

    (import jsec/cert)
    
    (def certs (cert/generate-self-signed-cert {
      :common-name "localhost"
      :days-valid 30
    }))
    
    (spit "cert.pem" (certs :cert))
    (spit "key.pem" (certs :key))


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


## BIO (Basic I/O Abstraction)

Use OpenSSL BIOs for custom I/O handling, such as memory buffers.

    (import jsec/bio)
    
    (def mem-bio (bio/new-mem))
    (bio/write mem-bio "Secret Data")
    (def data (bio/read mem-bio 100))


## Crypto Primitives

Access to OpenSSL crypto functions for hashing, signing, and verification.

    (import jsec/crypto)
    
    # Hashing
    (def hash (crypto/digest :sha256 "data"))
    
    # Signing (Ed25519)
    (def key (crypto/generate-key :ed25519))
    (def sig (crypto/sign key "data"))
    (def valid (crypto/verify key "data" sig))


# Development & Testing


## Building

Standard build:

    jpm build

Clean build:

    jpm clean
    jpm build


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


## Memory Leak Checking

Note: This is not currently operable (valgrind is too slow)

Run tests under valgrind:

    janet test/runner.janet --wrapper 'valgrind --leak-check=full'


## Debug Build

Enable debug logging in C code:

    # Edit src/jshared.h and uncomment: #define JSEC_DEBUG 1
    jpm build


## Code Formatting

Format Janet code:

    jpm run format-janet

Format C code:

    jpm run format-c


## Documentation Generation

Generate markdown from org files:

    jpm run docs


## Release Process

Prepare a release:

    jpm run release

This runs: clean, format checks, build, tests, leak checks, and documentation
generation.


## Test Coverage Details

The test suite is extensive, with over 2,000 generated test cases covering:

-   TLS Suite: Client/server, STARTTLS, SNI, session resumption, OCSP, concurrency (Main Matrix)
-   DTLS Suite: UDP/DTLS client/server operations
-   Cert Suite: Certificate generation and validation
-   BIO Suite: Memory BIO operations
-   Crypto Suite: Hashing, signing, verification


# Security Configuration

You can pass a \`:security\` table to \`connect\` or \`accept\` to enforce policies:

    :security {
      :min-version "TLS1.2"
      :max-version "TLS1.3"
      :ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
      :curves "X25519:P-256"
      :session-cache-size 1000
    }


# Contributing

We welcome contributions! JSEC is an ambitious project and there are many areas where community help would be valuable.


## Areas Seeking Help


### Platform Support

-   **Cross-platform testing:** Help test on additional BSD variants or Linux distributions
-   **SChannel backend:** Native Windows TLS implementation (future direction)


### Testing & Quality

-   **Test Suite Expansion:** Additional edge cases, protocol scenarios, error conditions
-   **Sanitizer Integration:** Improving ASan/UBSan/LSan coverage and CI integration
-   **Fuzzing:** Setting up continuous fuzzing infrastructure
-   **Code Review:** Security-focused review of the C binding layer

1.  Quick Wins for New Contributors

    Looking for an easy way to get started? These focused improvements help build familiarity with the codebase:
    
    -   **Convert server/client tests to assay coordinated tests:** Many TLS/DTLS tests manually spawn server and client fibers with `ev/sleep` delays to coordinate timing. These patterns are ideal candidates for conversion to assay's `coordinated` test type, which provides built-in participant synchronization via barriers and channels. While `coordinated` was designed for performance testing, it works well for any multi-participant scenario requiring coordination. See `suites/performance/` for examples.
    -   **Expand matrix test coverage:** assay's `matrix` feature generates test combinations automatically. Originally designed for fuzz testing parameter spaces, matrices are useful anywhere you need to test across multiple configurations (TLS versions, cipher suites, buffer sizes, etc.). Look for tests with manual loops over configurations that could be converted to declarative matrices.


### Performance

-   **C-side Optimizations:** Buffer handling, memory allocation patterns
-   **Janet-side Optimizations:** API layer efficiency improvements
-   **Benchmarking:** Expanding the perf9 test matrix and analysis tools
-   **Profiling:** Identifying bottlenecks under various workloads


### DTLS

-   **Protocol Correctness:** DTLS has known issues and needs attention
-   **Multi-client Server:** Improving the DTLS server implementation
-   **Testing:** Expanding DTLS test coverage


### Documentation & Examples

-   **Tutorials:** Real-world usage guides (mTLS setup, OCSP, etc.)
-   **Examples:** More complete example applications
-   **API Documentation:** Improving clarity and completeness


### Infrastructure

-   **CI/CD:** GitHub Actions improvements, cross-platform testing
-   **Packaging:** Distribution packages, container images
-   **Testing Framework:** Improvements to the [assay](https://github.com/llmII/janet-assay) test framework


## How to Contribute

1.  Check existing issues on GitHub and/or Fossil
2.  For large changes, open an issue first to discuss approach
3.  Follow the coding style (see `jpm run format-janet` and `jpm run format-c`)
4.  Ensure tests pass: `janet test/runner.janet -f '{unit,regression,coverage}'`
5.  Submit a PR on GitHub or patch via Fossil


# License

ISC License. See LICENSE file.


# Credits and Acknowledgments

This project was made possible by studying and learning from:


## Janet Language

-   Authors: Calvin Rose and contributors
-   License: MIT
-   Website: <https://janet-lang.org/>
-   Some test patterns in this library were adapted from Janet's test suite (MIT licensed).


## cqueues

-   Author: William Ahern
-   License: MIT
-   Repository: <https://github.com/wahern/cqueues>
-   The event loop integration patterns, particularly for TLS BIO handling, were informed by studying cqueues' excellent implementation.


## janet-jdn

-   Author: Andrew Chambers
-   License: MIT
-   Repository: <https://github.com/andrewchambers/janet-jdn>
-   The JDN encode/decode pattern in our performance testing framework is based on his work.

If you are an author or contributor to any project that influenced this work and would like explicit acknowledgment, please file a GitHub issue or fossil ticket.

