/*
 * internal.h - Internal definitions for CA (Certificate Authority)
 * implementation
 *
 * Architecture Overview:
 * ======================
 * The CA module provides Certificate Authority functionality:
 * - Root and intermediate CA creation
 * - CSR signing and certificate issuance
 * - CRL (Certificate Revocation List) generation
 * - OCSP request parsing and response creation (mechanics only, no networking)
 * - Serial number management with optional persistence
 * - Optional certificate tracking
 *
 * Design Principles:
 * ==================
 * 1. Every operation available as BOTH object method AND standalone function
 *    - :sign-csr method  AND  ca/sign function
 *    - :issue method     AND  ca/issue function
 *    - etc.
 *
 * 2. Simple API for common cases, powerful API for edge cases
 *    - :issue for one-step cert generation (recommended)
 *    - :sign-csr for custom workflows
 *
 * 3. Stateless by default, stateful when needed
 *    - Certificate tracking is OFF by default
 *    - Serial number persistence is opt-in
 *
 * 4. OCSP provides mechanics, not networking
 *    - User implements HTTP server
 *    - We provide crypto operations
 *
 * File Organization:
 * ==================
 * - types.c   - CA type definition, GC, constructors, method table
 * - sign.c    - CSR signing, certificate issuance
 * - crl.c     - CRL generation and revocation tracking
 * - ocsp.c    - OCSP request parsing and response creation
 * - module.c  - Module registration and exports
 *
 * Author: jsec project
 * License: ISC
 */

#ifndef JCA_INTERNAL_H
#define JCA_INTERNAL_H

#include "../jutils.h"
/* Error macros now in jutils.h */
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/*
 * =============================================================================
 * CA Type Definition
 * =============================================================================
 */

typedef struct {
    X509 *cert;              /* CA certificate */
    EVP_PKEY *key;           /* CA private key */
    int64_t serial;          /* Next serial number */
    int track_issued;        /* Whether to track issued certs (default: 0) */
    STACK_OF(X509) * issued; /* Issued certs (only if track_issued) */
    STACK_OF(X509_REVOKED) * revoked; /* Revoked certs (for CRL generation) */
} JanetCA;

/* Abstract type declaration */
extern const JanetAbstractType ca_type;

/*
 * =============================================================================
 * Revocation Reasons (X509v3 standard)
 * =============================================================================
 */

typedef enum {
    CA_REVOKE_UNSPECIFIED = 0,
    CA_REVOKE_KEY_COMPROMISE = 1,
    CA_REVOKE_CA_COMPROMISE = 2,
    CA_REVOKE_AFFILIATION_CHANGED = 3,
    CA_REVOKE_SUPERSEDED = 4,
    CA_REVOKE_CESSATION_OF_OPERATION = 5,
    CA_REVOKE_CERTIFICATE_HOLD = 6,
    CA_REVOKE_REMOVE_FROM_CRL = 8,
    CA_REVOKE_PRIVILEGE_WITHDRAWN = 9,
    CA_REVOKE_AA_COMPROMISE = 10
} CARevocationReason;

/* Convert Janet keyword to revocation reason */
CARevocationReason ca_keyword_to_reason(Janet kw);

/* Convert revocation reason to Janet keyword */
Janet ca_reason_to_keyword(CARevocationReason reason);

/*
 * =============================================================================
 * types.c - Type definition and constructors
 * =============================================================================
 */

/* GC callback */
int ca_gc(void *p, size_t s);

/* Mark callback (for GC tracing) */
int ca_gcmark(void *p, size_t s);

/* Get method callback */
int ca_get(void *p, Janet key, Janet *out);

/* Method table */
extern const JanetMethod ca_methods[];

/* Create CA from existing cert+key PEM */
Janet cfun_ca_create(int32_t argc, Janet *argv);

/* Generate new root CA */
Janet cfun_ca_generate(int32_t argc, Janet *argv);

/* Generate intermediate CA signed by parent */
Janet cfun_ca_generate_intermediate(int32_t argc, Janet *argv);

/*
 * =============================================================================
 * sign.c - CSR signing and certificate issuance
 * =============================================================================
 */

/* Sign a CSR, return certificate PEM
 * Options:
 *   :days-valid 365
 *   :not-before <time>
 *   :not-after <time>
 *   :serial <number>
 *   :extensions [...]
 *   :copy-extensions true
 *   :key-usage "..."
 *   :extended-key-usage "serverAuth,clientAuth"
 *   :san ["DNS:example.com" "IP:1.2.3.4"]
 *   :basic-constraints "CA:FALSE"
 */
Janet cfun_ca_sign_csr(int32_t argc, Janet *argv);

/* Issue certificate (generate key + CSR + sign in one step)
 * Options:
 *   :common-name "server.example.com"
 *   :san ["DNS:server.example.com"]
 *   :days-valid 365
 *   :key-type :ec-p256 | :ec-p384 | :rsa-2048 | :rsa-4096
 *   :key-usage "..."
 *   :extended-key-usage "..."
 * Returns: {:cert <pem> :key <pem>}
 */
Janet cfun_ca_issue(int32_t argc, Janet *argv);

/* Get CA certificate PEM */
Janet cfun_ca_get_cert(int32_t argc, Janet *argv);

/* Get current serial number (for persistence) */
Janet cfun_ca_get_serial(int32_t argc, Janet *argv);

/* Set serial number (for restoring from persistence) */
Janet cfun_ca_set_serial(int32_t argc, Janet *argv);

/* Check if tracking is enabled */
Janet cfun_ca_is_tracking(int32_t argc, Janet *argv);

/* Get list of issued certificates (only if tracking enabled) */
Janet cfun_ca_get_issued(int32_t argc, Janet *argv);

/*
 * =============================================================================
 * crl.c - CRL generation and revocation tracking
 * =============================================================================
 */

/* Revoke a certificate by serial number
 * Works whether tracking is enabled or not
 * If tracking enabled, looks up cert in issued list
 * Otherwise, just adds serial to revocation list
 */
Janet cfun_ca_revoke(int32_t argc, Janet *argv);

/* Generate signed CRL
 * Options:
 *   :days-valid 30
 *   :revoked [{:serial N :date <time> :reason <kw>} ...]  (optional if
 * tracking) Returns: CRL in PEM format
 */
Janet cfun_ca_generate_crl(int32_t argc, Janet *argv);

/* Get list of revoked serials (for inspection/persistence) */
Janet cfun_ca_get_revoked(int32_t argc, Janet *argv);

/*
 * =============================================================================
 * ocsp.c - OCSP request parsing and response creation
 * =============================================================================
 * Provides the CRYPTO MECHANICS for OCSP.
 * User is responsible for HTTP server implementation.
 */

/* Parse OCSP request bytes
 * Returns: {:issuer-name-hash <buffer>
 *           :issuer-key-hash <buffer>
 *           :serial <number>
 *           :nonce <buffer|nil>}
 */
Janet cfun_ca_parse_ocsp_request(int32_t argc, Janet *argv);

/* Create OCSP response
 * Status: :good | :revoked | :unknown
 * Options:
 *   :revocation-time <time>    (if status is :revoked)
 *   :revocation-reason <kw>    (if status is :revoked)
 *   :this-update <time>        (default: now)
 *   :next-update <time>        (default: +1 day)
 *   :include-nonce true        (echo nonce from request)
 * Returns: DER-encoded OCSP response bytes
 */
Janet cfun_ca_create_ocsp_response(int32_t argc, Janet *argv);

/*
 * =============================================================================
 * Helper functions (internal)
 * =============================================================================
 */

/* Add X509v3 extension to certificate */
int ca_add_extension(X509 *cert, X509 *issuer, int nid, const char *value);

/* Generate keypair based on type keyword */
EVP_PKEY *ca_generate_keypair(Janet key_type);

/* Create X509_NAME from Janet table or string */
X509_NAME *ca_create_name(Janet name_spec);

/* Convert X509 to PEM string */
Janet ca_x509_to_pem(X509 *cert);

/* Convert EVP_PKEY to PEM string */
Janet ca_key_to_pem(EVP_PKEY *key);

/* Load X509 from PEM string */
X509 *ca_pem_to_x509(Janet pem);

/* Load EVP_PKEY from PEM string */
EVP_PKEY *ca_pem_to_key(Janet pem);

/* Load X509_REQ (CSR) from PEM string */
X509_REQ *ca_pem_to_csr(Janet pem);

/* Get next serial and increment */
int64_t ca_next_serial(JanetCA *ca);

/*
 * =============================================================================
 * Options Helper - handles both table and struct
 * =============================================================================
 */

/* Get value from options (supports both table and struct) */
static inline Janet ca_opts_get(Janet opts, const char *key) {
    Janet kw = janet_ckeywordv(key);
    if (janet_checktype(opts, JANET_TABLE)) {
        return janet_table_get(janet_unwrap_table(opts), kw);
    } else if (janet_checktype(opts, JANET_STRUCT)) {
        return janet_struct_get(janet_unwrap_struct(opts), kw);
    }
    return janet_wrap_nil();
}

/* Check if opts is valid (table or struct) */
static inline int ca_opts_valid(Janet opts) {
    return janet_checktype(opts, JANET_TABLE) ||
           janet_checktype(opts, JANET_STRUCT);
}

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

void jca_register_types(JanetTable *env);
void jca_register_sign(JanetTable *env);
void jca_register_crl(JanetTable *env);
void jca_register_ocsp(JanetTable *env);

#endif /* JCA_INTERNAL_H */
