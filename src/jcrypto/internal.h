/*
 * internal.h - Internal header for jcrypto module
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#ifndef JCRYPTO_INTERNAL_H
#define JCRYPTO_INTERNAL_H

#include "../compat.h" /* For LibreSSL/OpenSSL detection */
#include "../jutils.h"
/* Error macros now in jutils.h */
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#if JSEC_HAS_OSSL_PARAM
    #include <openssl/core_names.h> /* For OSSL_PKEY_PARAM_* (OpenSSL 3.0+) */
#endif

/*============================================================================
 * Function declarations for separate compilation units
 *============================================================================*/

/* base64.c */
Janet cfun_base64_encode(int32_t argc, Janet *argv);
Janet cfun_base64_decode(int32_t argc, Janet *argv);
Janet cfun_base64url_encode(int32_t argc, Janet *argv);
Janet cfun_base64url_decode(int32_t argc, Janet *argv);

/* cms.c */
Janet cfun_cms_sign(int32_t argc, Janet *argv);
Janet cfun_cms_verify(int32_t argc, Janet *argv);
Janet cfun_cms_encrypt(int32_t argc, Janet *argv);
Janet cfun_cms_decrypt(int32_t argc, Janet *argv);
Janet cfun_cms_certs_only(int32_t argc, Janet *argv);
Janet cfun_cms_get_certs(int32_t argc, Janet *argv);

/* csr.c */
Janet cfun_generate_csr(int32_t argc, Janet *argv);
Janet cfun_parse_csr(int32_t argc, Janet *argv);

/* digest.c */
Janet cfun_digest(int32_t argc, Janet *argv);

/* hmac.c */
Janet cfun_hmac(int32_t argc, Janet *argv);

/* kdf.c */
Janet cfun_hkdf(int32_t argc, Janet *argv);
Janet cfun_pbkdf2(int32_t argc, Janet *argv);
Janet cfun_ecdh_derive(int32_t argc, Janet *argv);

/* keys.c */
Janet cfun_generate_key(int32_t argc, Janet *argv);
Janet cfun_export_public_key(int32_t argc, Janet *argv);
Janet cfun_load_key(int32_t argc, Janet *argv);
Janet cfun_export_key(int32_t argc, Janet *argv);
Janet cfun_key_info(int32_t argc, Janet *argv);

/* random.c */
Janet cfun_random_bytes(int32_t argc, Janet *argv);
Janet cfun_generate_challenge(int32_t argc, Janet *argv);

/* sign.c */
Janet cfun_sign(int32_t argc, Janet *argv);
Janet cfun_verify(int32_t argc, Janet *argv);

/* cipher.c */
Janet cfun_encrypt(int32_t argc, Janet *argv);
Janet cfun_decrypt(int32_t argc, Janet *argv);
Janet cfun_generate_nonce(int32_t argc, Janet *argv);
Janet cfun_cipher_info(int32_t argc, Janet *argv);

/* rsa.c */
Janet cfun_rsa_encrypt(int32_t argc, Janet *argv);
Janet cfun_rsa_decrypt(int32_t argc, Janet *argv);
Janet cfun_rsa_max_plaintext(int32_t argc, Janet *argv);

/* convert.c */
Janet cfun_convert_key(int32_t argc, Janet *argv);
Janet cfun_convert_cert(int32_t argc, Janet *argv);
Janet cfun_detect_format(int32_t argc, Janet *argv);

/* pkcs12.c */
Janet cfun_parse_pkcs12(int32_t argc, Janet *argv);
Janet cfun_create_pkcs12(int32_t argc, Janet *argv);

/* ec.c */
Janet cfun_ec_point_mul(int32_t argc, Janet *argv);
Janet cfun_ec_point_add(int32_t argc, Janet *argv);
Janet cfun_ec_point_to_bytes(int32_t argc, Janet *argv);
Janet cfun_ec_point_from_bytes(int32_t argc, Janet *argv);
Janet cfun_ec_generate_scalar(int32_t argc, Janet *argv);

#endif /* JCRYPTO_INTERNAL_H */
