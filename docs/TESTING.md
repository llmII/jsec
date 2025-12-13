
# Table of Contents

1.  [Overview](#org1fae105)
2.  [Directory Structure](#org31aa475)
3.  [Running Tests](#org1038f7c)
    1.  [Basic Usage](#orge60c0d6)
    2.  [Filter Syntax](#org44c74e5)
    3.  [Verbosity Levels](#org7f8ccc5)
    4.  [Listing Tests](#orgd5138f4)
    5.  [Other Options](#org104c7d5)
4.  [Writing Tests](#org757af6e)
    1.  [Basic Test Suite](#org435b09e)
    2.  [Using Test Helpers](#org299ff7b)
    3.  [Matrix Testing](#orgf981791)
    4.  [Expected Failures](#orgeb2e43c)
5.  [Performance Testing (Experimental)](#orge533e04)
    1.  [Running Performance Tests](#orgecba772)
    2.  [Analyzing Results with perf9-analyze](#org0cd8dfb)
    3.  [Performance Test Matrix](#orge5a7dd8)
6.  [Test Categories](#org3fee46f)
7.  [Naming Conventions](#org9c842e4)
8.  [Environment Variables](#org1103848)



<a id="org1fae105"></a>

# Overview

JSEC uses [assay](https://github.com/llmII/janet-assay) for testing. Tests are organized into suites by
category, with support for matrix testing, timeouts, and parallel execution.

**Note:** `jpm test` is deprecated. Use the runner directly.


<a id="org31aa475"></a>

# Directory Structure

    jsec/
    ├── suites/
    │   ├── helpers/             # Shared test utilities
    │   │   ├── certs.janet      # Certificate generation helpers
    │   │   ├── network.janet    # Port allocation, socket matrices
    │   │   └── init.janet       # Re-exports all helpers
    │   ├── unit/                # Unit tests
    │   ├── integration/         # Integration tests
    │   ├── regression/          # Regression tests
    │   ├── coverage/            # Internal API coverage tests
    │   └── performance/         # Performance tests (perf9)
    └── test/
        └── runner.janet         # Test runner entry point


<a id="org1038f7c"></a>

# Running Tests


<a id="orge60c0d6"></a>

## Basic Usage

    # Run all tests (except performance)
    janet test/runner.janet -f '{unit,regression,coverage}'
    
    # Run with summary output
    janet test/runner.janet -f '{unit,regression,coverage}' --verbosity 1
    
    # Run specific category
    janet test/runner.janet -f 'unit'
    
    # Run specific suite
    janet test/runner.janet -f 'unit/TLS*'
    
    # Run with verbose output
    janet test/runner.janet -f 'unit' --verbosity 5


<a id="org44c74e5"></a>

## Filter Syntax

The `-f` / `--filter` flag uses a unified filter syntax:

    category/suite/test[matrix]<coordinated>

Examples:

    # All unit tests
    -f 'unit'
    
    # TLS and DTLS suites in unit
    -f 'unit/{TLS,DTLS}*'
    
    # Any handshake test in any suite
    -f '*/*/handshake*'
    
    # Matrix test with specific parameters
    -f 'unit/buffer[size=1024]'
    
    # Skip a suite (use --skip flag)
    --skip 'unit/slow*'

Use `--filter-help` for complete syntax documentation.


<a id="org7f8ccc5"></a>

## Verbosity Levels

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-right" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-right">Level</th>
<th scope="col" class="org-left">Shows</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-right">0</td>
<td class="org-left">Summary only (pass/fail totals)</td>
</tr>

<tr>
<td class="org-right">1</td>
<td class="org-left">+ Suite results</td>
</tr>

<tr>
<td class="org-right">2</td>
<td class="org-left">+ Categories, timing, memory stats</td>
</tr>

<tr>
<td class="org-right">4</td>
<td class="org-left">+ Skip/expected-fail reasons</td>
</tr>

<tr>
<td class="org-right">5</td>
<td class="org-left">+ Individual test results</td>
</tr>

<tr>
<td class="org-right">6</td>
<td class="org-left">+ Stack traces, failing assertion forms</td>
</tr>
</tbody>
</table>

    janet test/runner.janet --verbosity 5


<a id="orgd5138f4"></a>

## Listing Tests

    # List suites
    janet test/runner.janet --list suites
    
    # List all tests
    janet test/runner.janet --list all
    
    # List categories
    janet test/runner.janet --list categories


<a id="org104c7d5"></a>

## Other Options

    # Dry run (show what would run)
    janet test/runner.janet --dry-run -f 'unit'
    
    # Set timeout (seconds)
    janet test/runner.janet --timeout 60
    
    # Track memory usage
    janet test/runner.janet --memory
    
    # Run only ensured combos (quick smoke test)
    janet test/runner.janet --ensured-only
    
    # JSON output
    janet test/runner.janet --json results.json
    
    # Run with valgrind wrapper
    janet test/runner.janet --wrapper 'valgrind --leak-check=full'


<a id="org757af6e"></a>

# Writing Tests


<a id="org435b09e"></a>

## Basic Test Suite

    (import assay)
    (use suites/helpers)
    
    (assay/def-suite :name "My Suite" :category :unit)
    
    (assay/def-test "basic addition"
      (assert (= 4 (+ 2 2)) "2+2 should equal 4"))
    
    (assay/def-test "with timeout" :timeout 30
      (do-slow-operation))
    
    (assay/end-suite)


<a id="org299ff7b"></a>

## Using Test Helpers

    (use suites/helpers)
    
    # Generate test certificates
    (def certs (generate-temp-certs))
    # Returns {:cert "PEM..." :key "PEM..."}
    
    # With specific key type
    (def certs (generate-temp-certs {:key-type :ec-p256}))
    
    # Get random port for testing
    (def port (make-random-port))


<a id="orgf981791"></a>

## Matrix Testing

Run tests with multiple parameter combinations:

    (assay/def-matrix "protocol tests"
      :matrix {:protocol [:tcp :tls]
               :verify [true false]}
      (fn [config]
        (test-with-protocol (config :protocol) (config :verify))))


<a id="orgeb2e43c"></a>

## Expected Failures

Mark tests that document known issues:

    (assay/def-test "known issue"
      :expected-fail "Bug #123: fails on large inputs"
      (assert false "This is expected to fail"))


<a id="orge533e04"></a>

# Performance Testing (Experimental)

Performance tests use the perf9 framework and can run for extended periods.
They are excluded from the default test run.

**Warning:** Performance testing is unstable. Output formats, metrics collection,
and implementation details are subject to change as optimizations are made.


<a id="orgecba772"></a>

## Running Performance Tests

    # Run performance tests (can take hours for full matrix)
    janet test/runner.janet -f 'performance'
    
    # Run with limited matrix sampling
    janet test/runner.janet -f 'performance' --matrix-sample 5
    
    # Output results to JSON for analysis
    janet test/runner.janet -f 'performance' --json /tmp/perf-results.json


<a id="org0cd8dfb"></a>

## Analyzing Results with perf9-analyze

The `bin/perf9-analyze` tool processes JSON output from performance tests:

    # Summary with individual test results
    ./bin/perf9-analyze /tmp/perf-results.json
    
    # Summary without individual results (grouped stats only)
    ./bin/perf9-analyze -n /tmp/perf-results.json
    
    # Compare two test runs
    ./bin/perf9-analyze --compare run1.json run2.json
    
    # Detailed output for all tests
    ./bin/perf9-analyze --detail /tmp/perf-results.json

The analyzer provides:

-   Throughput statistics (mean, median, p95) by protocol, TLS version, client count
-   Per-client throughput ranges (slowest/fastest)
-   Handshake timing analysis
-   Comparison between test runs with percentage changes


<a id="orge5a7dd8"></a>

## Performance Test Matrix

The perf9 suite tests combinations of:

-   Protocol: TCP, TLS, Unix sockets
-   TLS versions: 1.2, 1.3
-   Client counts: Various concurrency levels
-   Chunk sizes: Different buffer sizes
-   Worker types: Fibers, threads, subprocesses


<a id="org3fee46f"></a>

# Test Categories

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Category</th>
<th scope="col" class="org-left">Purpose</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left">unit</td>
<td class="org-left">Fast, isolated unit tests</td>
</tr>

<tr>
<td class="org-left">integration</td>
<td class="org-left">Cross-module integration tests</td>
</tr>

<tr>
<td class="org-left">regression</td>
<td class="org-left">Tests for specific fixed bugs</td>
</tr>

<tr>
<td class="org-left">coverage</td>
<td class="org-left">Internal API coverage tests</td>
</tr>

<tr>
<td class="org-left">performance</td>
<td class="org-left">Long-running performance benchmarks</td>
</tr>
</tbody>
</table>


<a id="org9c842e4"></a>

# Naming Conventions

-   Suite files: `suite-*.janet` in category directory
-   Test names: Descriptive, kebab-case
-   Helpers: Shared utilities in `suites/helpers/`


<a id="org1103848"></a>

# Environment Variables

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Variable</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left">JSEC<sub>DEBUG</sub></td>
<td class="org-left">Enable debug output (1=on)</td>
</tr>

<tr>
<td class="org-left">JSEC<sub>VERBOSE</sub></td>
<td class="org-left">Enable verbose output (1=on)</td>
</tr>
</tbody>
</table>

