# Coverage Tests

This directory contains coverage tests for jsec's **internal/private API**.

## What belongs here

Coverage tests exercise the internal implementation details that users should
NOT rely on but we need to ensure work correctly. These are separate from unit
tests which test the public API.

### Internal API modules:
- `jsec/tls-stream` - Low-level TLS stream implementation
- `jsec/dtls-stream` - Low-level DTLS stream implementation

### Internal functions:
- `tls-stream/set-ocsp-response` - OCSP stapling (not exposed as method)
- Any function that requires importing `*-stream` modules directly

## What does NOT belong here

Public API tests belong in `suites/unit/`:
- `jsec/tls` - Unified TLS API (tls/connect, tls/listen, tls/wrap, etc.)
- `jsec/cert` - Certificate generation
- `jsec/crypto` - Cryptographic operations
- `jsec/bio` - BIO utilities

## Migration from unit tests

Tests in `suites/unit/` that use:
- `jsec/tls-stream` or `jsec/dtls-stream` directly
- Functions not available as methods on public objects
- `net/*` when they should use `tls/*`

Should be migrated here, rewritten to test the same functionality through
the public API, or both (test internal separately from public).