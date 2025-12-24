
# Table of Contents

1.  [Welcome](#orge452936)
2.  [Code Standards](#org05303c8)
    1.  [Janet Code Style](#orgc39deb7)
    2.  [C Code Style](#org69374ad)
    3.  [Comments](#orga3d9c6e)
3.  [Testing Requirements](#orgb64689f)
    1.  [All Contributions Must Include Tests](#org3ff8997)
    2.  [Running Tests](#orged67658)
    3.  [Test Requirements](#org5536c06)
    4.  [Test Style](#orge9915d4)
    5.  [C Projects: Memory Testing](#orgb8f7d7a)
4.  [Pull Request Process](#org25fb414)
    1.  [Repository Information](#org7d2e69f)
    2.  [Submission Process](#orga69b468)
    3.  [PR Checklist](#orge3b8fe2)
5.  [Documentation](#org779c61a)
6.  [Getting Help](#orgfdb0e4a)
7.  [License](#org8099349)



<a id="orge452936"></a>

# Welcome

Thank you for considering contributing to jsec! This document explains our standards and processes.


<a id="org05303c8"></a>

# Code Standards


<a id="orgc39deb7"></a>

## Janet Code Style

-   Use `let` and `with` macros instead of `def`, `defer`, `var` where sensible
-   Prefer keyword symbols over strings (e.g., `:TLS1_3` instead of `"TLS1.3"`)
-   Follow conventions in [STYLE.org](STYLE.md)
-   Format code with `jfmt`: `jpm run format-janet`
-   Soft limit: 78 columns, hard limit: 80 columns (janet-format won't help with
    this so it's okay sometimes for lines to be longer until a tool exists to
    aid in this)


<a id="org69374ad"></a>

## C Code Style

-   K&R style (see [.astylerc](.astylerc))
-   4-space indentation
-   Pointer alignment: `int *ptr`
-   Format code with `astyle`: `jpm run format-c`
-   Soft limit: 78 columns, hard limit: 80 columns
-   Comment complex logic, not obvious operations
-   Use Janet OS macros for platform guards
-   No compiler warnings allowed


<a id="orga3d9c6e"></a>

## Comments

-   Comment what code does, not implementation history
-   Clarify non-obvious logic
-   Do not comment trivial operations (`2+2=4`)
-   No "we used to do X, now we do Y" comments
-   Focus on "why" rather than "what" for complex sections


<a id="orgb64689f"></a>

# Testing Requirements


<a id="org3ff8997"></a>

## All Contributions Must Include Tests

New functionality or extended functionality **must** be appropriately tested for a contribution to be accepted.


<a id="orged67658"></a>

## Running Tests

jsec uses the [assay](https://github.com/llmII/janet-assay) testing framework.

    # Run unit, regression, and coverage tests (recommended for development)
    janet test/runner.janet -f '{unit,regression,coverage}'
    
    # Run all tests (includes performance - takes hours)
    janet test/runner.janet
    
    # Dry run to see what would execute
    janet test/runner.janet -f '{unit,regression,coverage}' --dry-run
    
    # Run specific suite
    janet test/runner.janet -f 'unit/tls-stream'
    
    # Run specific test within a suite
    janet test/runner.janet -f 'unit/tls-stream/handshake'
    
    # Verbose output
    janet test/runner.janet -f '{unit,regression,coverage}' --verbosity 2
    
    # List all available tests
    janet test/runner.janet --list all

See [docs/TESTING.org](docs/TESTING.md) for comprehensive testing documentation.


<a id="org5536c06"></a>

## Test Requirements

-   All existing tests must pass
-   New features require corresponding test cases
-   Bug fixes should include regression tests
-   Tests should work on Unix sockets as well as TCP (for TLS, for UDP we'll update when DTLS is good)
-   External connections only to example.com (tests should gracefully handle failures)
-   Tests must be concise for valgrind performance (though this obviously won't fix valgrind being too slow presently)
-   No stubbed or incomplete tests accepted


<a id="orge9915d4"></a>

## Test Style

-   Tests are organized into suites in `suites/` directory by category
-   Use assay's `def-test` macro for defining tests
-   Use `(test-setup)` and `(test-teardown)` for fixture management
-   Clean up resources properly
-   Test both function calls and method calls (`(:read stream)` and `(tls/read stream)`)
-   Test error conditions, not just happy paths
-   Use matrix tests for testing across configurations (TLS versions, protocols, etc.)


<a id="orgb8f7d7a"></a>

## C Projects: Memory Testing

For projects with C code, memory checking is mandatory (once developer tooling works appropriately):

    # Check for memory leaks with valgrind
    jpm run leak-check # valgrind is slow, elide this or help fix things to be speedy enough
    
    # Run tests with AddressSanitizer/UndefinedBehaviorSanitizer
    jpm run test-sanitized # Address sanitizer is slow, UBSan is fine though
    
    # Run clang-tidy static analysis
    jpm run tidy


<a id="org25fb414"></a>

# Pull Request Process


<a id="org7d2e69f"></a>

## Repository Information

-   **Primary repository**: `code.amlegion.org/jsec` (Fossil)
-   **Mirror**: `https://github.com/llmII/jsec` (Git)
-   Contributions accepted via Git or Fossil
-   Git contributions will be converted to patches and applied with Fossil
-   We attempt to credit contributor's GitHub/Git name appropriately


<a id="orga69b468"></a>

## Submission Process

1.  Fork the repository (Git) or request commit access (Fossil)
2.  Create a feature branch: `git checkout -b feature/my-feature`
3.  Make your changes following code standards
4.  Add tests for your changes in appropriate suite under `suites/`
5.  Run test suite: `janet test/runner.janet -f '{unit,regression,coverage}'`
6.  Format your code: `jpm run format`
7.  **If C code**: Run memory checks: `jpm run leak-check` and `jpm run test-sanitized` (once tooling for such stabilizes)
8.  Update documentation in `docs/` if needed
9.  Commit with clear, descriptive messages
10. Push to your fork and submit a pull request (Git) or commit (Fossil)


<a id="orge3b8fe2"></a>

## PR Checklist

-   [ ] Code follows style guidelines
-   [ ] All tests pass (`janet test/runner.janet -f '{unit,regression,coverage}'`)
-   [ ] New tests added for new functionality
-   [ ] Documentation updated if needed
-   [ ] Code formatted with `jpm run format`
-   [ ] **If C code**: Memory checks pass (`jpm run leak-check`, `jpm run test-sanitized`) (once tooling for such stabilizes)
-   [ ] **If C code**: No compiler warnings
-   [ ] Commit messages are clear and descriptive


<a id="org779c61a"></a>

# Documentation

-   Use org-mode files (`.org`), not Markdown
-   API documentation goes in `docs/API.org`
-   Guides go in `docs/GUIDE.org`
-   Reference examples in `examples/` directory
-   Generate Markdown with `jpm run release`


<a id="orgfdb0e4a"></a>

# Getting Help

-   Check existing tests for patterns
-   Read [API documentation](docs/API.md)
-   Look at [examples](examples/) directory
-   Review [style guide](STYLE.md)


<a id="org8099349"></a>

# License

By contributing, you agree that your contributions will be licensed under the ISC License.

