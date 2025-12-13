/*
 * jcert.c - Certificate generation and management for Janet
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "jutils.h"
#include "jutils/internal.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <time.h>
#include <string.h>

/* Forward declarations for jcert/verify.c functions */
extern Janet cfun_cert_verify_chain(int32_t argc, Janet *argv);
extern Janet cfun_cert_build_chain(int32_t argc, Janet *argv);

/* Generate self-signed certificate
 * Returns a struct {:cert "PEM..." :key "PEM..."}
 * Options:
 *   :common-name "localhost"
 *   :days-valid 365
 *   :bits 2048
 *   :country "US"
 *   :organization "Test"
 */
static Janet cfun_generate_self_signed_cert(int32_t argc, Janet *argv) {
    janet_arity(argc, 0, 1);

    const char *cn = "localhost";
    int days = 365;
    int bits = 2048;
    const char *country = "US";
    const char *org = "Test";
    const char *key_type =
        "rsa";  /* Default to RSA, supports: rsa, ec-p256, ec-p384, ec-p521, ed25519 */

    if (argc > 0) {
        if (!janet_checktype(argv[0], JANET_TABLE) &&
            !janet_checktype(argv[0], JANET_STRUCT)) {
            cert_panic_param("options must be a table or struct");
        }

        Janet val;

        val = janet_get(argv[0], janet_ckeywordv("common-name"));
        if (janet_checktype(val,
                            JANET_STRING)) cn = (const char *)janet_unwrap_string(val);

        val = janet_get(argv[0], janet_ckeywordv("days-valid"));
        if (janet_checktype(val, JANET_NUMBER)) days = (int)janet_unwrap_number(val);

        val = janet_get(argv[0], janet_ckeywordv("bits"));
        if (janet_checktype(val, JANET_NUMBER)) bits = (int)janet_unwrap_number(val);

        val = janet_get(argv[0], janet_ckeywordv("country"));
        if (janet_checktype(val,
                            JANET_STRING)) country = (const char *)janet_unwrap_string(val);

        val = janet_get(argv[0], janet_ckeywordv("organization"));
        if (janet_checktype(val,
                            JANET_STRING)) org = (const char *)janet_unwrap_string(val);

        val = janet_get(argv[0], janet_ckeywordv("key-type"));
        if (janet_checktype(val,
                            JANET_KEYWORD)) key_type = (const char *)janet_unwrap_keyword(val);
        else if (janet_checktype(val,
                                 JANET_STRING)) key_type = (const char *)janet_unwrap_string(val);
    }

    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    BIO *cert_bio = NULL;
    BIO *key_bio = NULL;
    char *cert_buf = NULL;
    char *key_buf = NULL;
    long cert_len = 0;
    long key_len = 0;

    /* Generate Key based on key type */
    EVP_PKEY_CTX *ctx = NULL;
    int pkey_type = EVP_PKEY_RSA;
    int ec_nid = 0;

    if (strcmp(key_type, "rsa") == 0) {
        pkey_type = EVP_PKEY_RSA;
    } else if (strcmp(key_type, "ec-p256") == 0) {
        pkey_type = EVP_PKEY_EC;
        ec_nid = NID_X9_62_prime256v1;
    } else if (strcmp(key_type, "ec-p384") == 0) {
        pkey_type = EVP_PKEY_EC;
        ec_nid = NID_secp384r1;
    } else if (strcmp(key_type, "ec-p521") == 0) {
        pkey_type = EVP_PKEY_EC;
        ec_nid = NID_secp521r1;
    } else if (strcmp(key_type, "ed25519") == 0) {
        pkey_type = EVP_PKEY_ED25519;
    } else {
        cert_panic_param("unsupported key type: %s (supported: rsa, ec-p256, ec-p384, ec-p521, ed25519)",
                         key_type);
    }

    if (pkey_type == EVP_PKEY_EC) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx) goto cleanup;
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            goto cleanup;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ec_nid) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            goto cleanup;
        }
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            goto cleanup;
        }
    } else {
        ctx = EVP_PKEY_CTX_new_id(pkey_type, NULL);
        if (!ctx) goto cleanup;
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            goto cleanup;
        }
        if (pkey_type == EVP_PKEY_RSA) {
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                goto cleanup;
            }
        }
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            goto cleanup;
        }
    }
    EVP_PKEY_CTX_free(ctx);

    /* Generate Certificate */
    x509 = X509_new();
    if (!x509) goto cleanup;

    X509_set_version(x509, 2); /* Version 3 */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); /* Serial 1 */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * days);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, OSSL_STR(country),
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, OSSL_STR(org), -1,
                               -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, OSSL_STR(cn), -1,
                               -1, 0);

    X509_set_issuer_name(x509, name);

    /* Add extensions */
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, x509, x509, NULL, NULL, 0);

    X509_EXTENSION *ext;

    /* Basic Constraints */
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints,
                              "critical,CA:TRUE");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Key Usage */
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_key_usage,
                              "digitalSignature,keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Subject Alternative Name (SAN) - Required for modern TLS hostname verification
     * We add both DNS and IP entries for the common name, as it might be either */
    {
        char san_value[512];
        /* Check if cn looks like an IP address (contains only digits and dots for IPv4) */
        int is_ip = 1;
        for (const char *p = cn; *p; p++) {
            if (*p != '.' && (*p < '0' || *p > '9')) {
                is_ip = 0;
                break;
            }
        }
        /* Also check for IPv6 (contains colons) */
        if (!is_ip) {
            is_ip = (strchr(cn, ':') != NULL);
        }

        if (is_ip) {
            snprintf(san_value, sizeof(san_value), "IP:%s", cn);
        } else {
            snprintf(san_value, sizeof(san_value), "DNS:%s", cn);
        }

        ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_alt_name, san_value);
        if (ext) {
            X509_add_ext(x509, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    /* Subject Key Identifier */
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Ed25519/Ed448 don't use a digest, pass NULL; others use SHA256 */
    const EVP_MD *md = (pkey_type == EVP_PKEY_ED25519) ? NULL : EVP_sha256();
    if (!X509_sign(x509, pkey, md)) goto cleanup;

    /* Write to PEM */
    cert_bio = BIO_new(BIO_s_mem());
    if (!cert_bio) goto cleanup;
    if (!PEM_write_bio_X509(cert_bio, x509)) goto cleanup;

    key_bio = BIO_new(BIO_s_mem());
    if (!key_bio) goto cleanup;
    if (!PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL,
                                  NULL)) goto cleanup;

    cert_len = BIO_get_mem_data(cert_bio, &cert_buf);
    key_len = BIO_get_mem_data(key_bio, &key_buf);

    if (cert_len <= 0 || key_len <= 0) goto cleanup;

    /* Create result struct with data while BIOs are still valid */
    JanetKV *st = janet_struct_begin(2);
    janet_struct_put(st, janet_ckeywordv("cert"),
                     janet_stringv((const uint8_t *)cert_buf, cert_len));
    janet_struct_put(st, janet_ckeywordv("key"),
                     janet_stringv((const uint8_t *)key_buf, key_len));
    Janet result = janet_wrap_struct(janet_struct_end(st));

    /* Clean up OpenSSL resources */
    X509_free(x509);
    EVP_PKEY_free(pkey);
    BIO_free(cert_bio);
    BIO_free(key_bio);

    return result;

cleanup:
    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (cert_bio) BIO_free(cert_bio);
    if (key_bio) BIO_free(key_bio);

    cert_panic_ssl("failed to generate certificate");
}

/* Generate self-signed certificate from an existing private key
 * Returns certificate PEM string
 * Options:
 *   :common-name "localhost"
 *   :days-valid 365
 *   :country "US"
 *   :organization "Test"
 */
static Janet cfun_generate_self_signed_from_key(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    JanetByteView key_pem = janet_getbytes(argv, 0);

    const char *cn = "localhost";
    int days = 365;
    const char *country = "US";
    const char *org = "Test";

    if (argc > 1) {
        if (!janet_checktype(argv[1], JANET_TABLE) &&
            !janet_checktype(argv[1], JANET_STRUCT)) {
            cert_panic_param("options must be a table or struct");
        }

        Janet val;

        val = janet_get(argv[1], janet_ckeywordv("common-name"));
        if (janet_checktype(val,
                            JANET_STRING)) cn = (const char *)janet_unwrap_string(val);

        val = janet_get(argv[1], janet_ckeywordv("days-valid"));
        if (janet_checktype(val, JANET_NUMBER)) days = (int)janet_unwrap_number(val);

        val = janet_get(argv[1], janet_ckeywordv("country"));
        if (janet_checktype(val,
                            JANET_STRING)) country = (const char *)janet_unwrap_string(val);

        val = janet_get(argv[1], janet_ckeywordv("organization"));
        if (janet_checktype(val,
                            JANET_STRING)) org = (const char *)janet_unwrap_string(val);
    }

    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    BIO *cert_bio = NULL;
    char *cert_buf = NULL;
    long cert_len = 0;

    /* Load the private key */
    BIO *key_bio = BIO_new_mem_buf(key_pem.bytes, key_pem.len);
    if (!key_bio) goto cleanup;

    pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    BIO_free(key_bio);
    key_bio = NULL;

    if (!pkey) {
        cert_panic_ssl("failed to load private key");
    }

    /* Generate Certificate */
    x509 = X509_new();
    if (!x509) goto cleanup;

    X509_set_version(x509, 2); /* Version 3 */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); /* Serial 1 */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * days);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, OSSL_STR(country),
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, OSSL_STR(org), -1,
                               -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, OSSL_STR(cn), -1,
                               -1, 0);

    X509_set_issuer_name(x509, name);

    /* Add extensions */
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, x509, x509, NULL, NULL, 0);

    X509_EXTENSION *ext;

    /* Basic Constraints */
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints,
                              "critical,CA:TRUE");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Key Usage */
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_key_usage,
                              "digitalSignature,keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Subject Alternative Name (SAN) */
    {
        char san_value[512];
        int is_ip = 1;
        for (const char *p = cn; *p; p++) {
            if (*p != '.' && (*p < '0' || *p > '9')) {
                is_ip = 0;
                break;
            }
        }
        if (!is_ip) {
            is_ip = (strchr(cn, ':') != NULL);
        }

        if (is_ip) {
            snprintf(san_value, sizeof(san_value), "IP:%s", cn);
        } else {
            snprintf(san_value, sizeof(san_value), "DNS:%s", cn);
        }

        ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_alt_name, san_value);
        if (ext) {
            X509_add_ext(x509, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    /* Subject Key Identifier */
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (!X509_sign(x509, pkey, EVP_sha256())) goto cleanup;

    /* Write to PEM */
    cert_bio = BIO_new(BIO_s_mem());
    if (!cert_bio) goto cleanup;
    if (!PEM_write_bio_X509(cert_bio, x509)) goto cleanup;

    cert_len = BIO_get_mem_data(cert_bio, &cert_buf);

    if (cert_len <= 0) goto cleanup;

    Janet result = janet_stringv((const uint8_t *)cert_buf, cert_len);

    /* Clean up OpenSSL resources */
    X509_free(x509);
    EVP_PKEY_free(pkey);
    BIO_free(cert_bio);

    return result;

cleanup:
    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (cert_bio) BIO_free(cert_bio);
    if (key_bio) BIO_free(key_bio);

    cert_panic_ssl("failed to generate certificate");
}

/*============================================================================
 * Certificate Parsing/Inspection Functions
 *============================================================================*/

/* Helper: Format serial number as hex string with colons */
static Janet format_serial(ASN1_INTEGER *serial) {
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn) return janet_wrap_nil();

    char *hex = BN_bn2hex(bn);
    BN_free(bn);
    if (!hex) return janet_wrap_nil();

    /* Format with colons (AB:CD:EF...) */
    size_t hex_len = strlen(hex);
    size_t result_len = hex_len + (hex_len / 2);  /* Add space for colons */
    char *result = janet_smalloc(result_len + 1);
    if (!result) {
        OPENSSL_free(hex);
        return janet_wrap_nil();
    }

    size_t j = 0;
    for (size_t i = 0; i < hex_len; i++) {
        if (i > 0 && i % 2 == 0) {
            result[j++] = ':';
        }
        result[j++] = hex[i];
    }
    result[j] = '\0';

    Janet ret = janet_cstringv(result);
    janet_sfree(result);
    OPENSSL_free(hex);
    return ret;
}

/* Helper: Extract name fields from X509_NAME */
static Janet extract_name_fields(X509_NAME *name) {
    JanetTable *fields = janet_table(8);

    int idx;
    char buf[256];

    /* Common Name */
    idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (idx >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (data && ASN1_STRING_length(data) > 0) {
            janet_table_put(fields, janet_ckeywordv("cn"),
                            janet_stringv(ASN1_STRING_get0_data(data),
                                          ASN1_STRING_length(data)));
        }
    }

    /* Organization */
    idx = X509_NAME_get_index_by_NID(name, NID_organizationName, -1);
    if (idx >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (data && ASN1_STRING_length(data) > 0) {
            janet_table_put(fields, janet_ckeywordv("o"),
                            janet_stringv(ASN1_STRING_get0_data(data),
                                          ASN1_STRING_length(data)));
        }
    }

    /* Organizational Unit */
    idx = X509_NAME_get_index_by_NID(name, NID_organizationalUnitName, -1);
    if (idx >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (data && ASN1_STRING_length(data) > 0) {
            janet_table_put(fields, janet_ckeywordv("ou"),
                            janet_stringv(ASN1_STRING_get0_data(data),
                                          ASN1_STRING_length(data)));
        }
    }

    /* Country */
    idx = X509_NAME_get_index_by_NID(name, NID_countryName, -1);
    if (idx >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (data && ASN1_STRING_length(data) > 0) {
            janet_table_put(fields, janet_ckeywordv("c"),
                            janet_stringv(ASN1_STRING_get0_data(data),
                                          ASN1_STRING_length(data)));
        }
    }

    /* State/Province */
    idx = X509_NAME_get_index_by_NID(name, NID_stateOrProvinceName, -1);
    if (idx >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (data && ASN1_STRING_length(data) > 0) {
            janet_table_put(fields, janet_ckeywordv("st"),
                            janet_stringv(ASN1_STRING_get0_data(data),
                                          ASN1_STRING_length(data)));
        }
    }

    /* Locality */
    idx = X509_NAME_get_index_by_NID(name, NID_localityName, -1);
    if (idx >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (data && ASN1_STRING_length(data) > 0) {
            janet_table_put(fields, janet_ckeywordv("l"),
                            janet_stringv(ASN1_STRING_get0_data(data),
                                          ASN1_STRING_length(data)));
        }
    }

    /* Email */
    idx = X509_NAME_get_index_by_NID(name, NID_pkcs9_emailAddress, -1);
    if (idx >= 0) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (data && ASN1_STRING_length(data) > 0) {
            janet_table_put(fields, janet_ckeywordv("email"),
                            janet_stringv(ASN1_STRING_get0_data(data),
                                          ASN1_STRING_length(data)));
        }
    }

    /* Full DN string */
    if (X509_NAME_oneline(name, buf, sizeof(buf))) {
        janet_table_put(fields, janet_ckeywordv("dn"), janet_cstringv(buf));
    }

    return janet_wrap_table(fields);
}

/* Helper: Convert ASN1_TIME to Unix timestamp */
static int64_t asn1_time_to_unix(const ASN1_TIME *time) {
    struct tm t;
    memset(&t, 0, sizeof(t));

    if (ASN1_TIME_to_tm(time, &t) != 1) {
        return 0;
    }

    /* Convert to Unix timestamp - portable implementation */
    /* Days from year 0 to 1970 */
    int64_t days = 0;
    int year = t.tm_year + 1900;

    /* Years to days */
    for (int y = 1970; y < year; y++) {
        days += (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
    }
    for (int y = year; y < 1970; y++) {
        days -= (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
    }

    /* Months to days */
    static const int mdays[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    days += mdays[t.tm_mon] + t.tm_mday - 1;

    /* Leap day adjustment */
    if (t.tm_mon > 1 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) {
        days++;
    }

    return days * 86400 + (int64_t)t.tm_hour * 3600 + (int64_t)t.tm_min * 60 +
           t.tm_sec;
}

/* Helper: Extract Subject Alternative Names */
static Janet extract_san(X509 *cert) {
    GENERAL_NAMES *names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL,
                                            NULL);
    if (!names) return janet_wrap_nil();

    int count = sk_GENERAL_NAME_num(names);
    JanetArray *arr = janet_array(count);

    for (int i = 0; i < count; i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(names, i);
        char buf[256];

        switch (gen->type) {
            case GEN_DNS:
                snprintf(buf, sizeof(buf), "DNS:%.*s",
                         ASN1_STRING_length(gen->d.dNSName),
                         ASN1_STRING_get0_data(gen->d.dNSName));
                janet_array_push(arr, janet_cstringv(buf));
                break;
            case GEN_EMAIL:
                snprintf(buf, sizeof(buf), "EMAIL:%.*s",
                         ASN1_STRING_length(gen->d.rfc822Name),
                         ASN1_STRING_get0_data(gen->d.rfc822Name));
                janet_array_push(arr, janet_cstringv(buf));
                break;
            case GEN_URI:
                snprintf(buf, sizeof(buf), "URI:%.*s",
                         ASN1_STRING_length(gen->d.uniformResourceIdentifier),
                         ASN1_STRING_get0_data(gen->d.uniformResourceIdentifier));
                janet_array_push(arr, janet_cstringv(buf));
                break;
            case GEN_IPADD: {
                    ASN1_OCTET_STRING *ip = gen->d.iPAddress;
                    if (ip->length == 4) {
                        snprintf(buf, sizeof(buf), "IP:%d.%d.%d.%d",
                                 ip->data[0], ip->data[1], ip->data[2], ip->data[3]);
                        janet_array_push(arr, janet_cstringv(buf));
                    } else if (ip->length == 16) {
                        /* IPv6 - simplified output */
                        snprintf(buf, sizeof(buf), "IP:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                 ip->data[0], ip->data[1], ip->data[2], ip->data[3],
                                 ip->data[4], ip->data[5], ip->data[6], ip->data[7],
                                 ip->data[8], ip->data[9], ip->data[10], ip->data[11],
                                 ip->data[12], ip->data[13], ip->data[14], ip->data[15]);
                        janet_array_push(arr, janet_cstringv(buf));
                    }
                    break;
                }
            default:
                break;
        }
    }

    GENERAL_NAMES_free(names);
    return janet_wrap_array(arr);
}

/* Helper: Extract key usage bits */
static Janet extract_key_usage(X509 *cert) {
    ASN1_BIT_STRING *usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (!usage) return janet_wrap_nil();

    JanetArray *arr = janet_array(9);

    if (ASN1_BIT_STRING_get_bit(usage, 0))
        janet_array_push(arr, janet_ckeywordv("digital-signature"));
    if (ASN1_BIT_STRING_get_bit(usage, 1))
        janet_array_push(arr, janet_ckeywordv("non-repudiation"));
    if (ASN1_BIT_STRING_get_bit(usage, 2))
        janet_array_push(arr, janet_ckeywordv("key-encipherment"));
    if (ASN1_BIT_STRING_get_bit(usage, 3))
        janet_array_push(arr, janet_ckeywordv("data-encipherment"));
    if (ASN1_BIT_STRING_get_bit(usage, 4))
        janet_array_push(arr, janet_ckeywordv("key-agreement"));
    if (ASN1_BIT_STRING_get_bit(usage, 5))
        janet_array_push(arr, janet_ckeywordv("key-cert-sign"));
    if (ASN1_BIT_STRING_get_bit(usage, 6))
        janet_array_push(arr, janet_ckeywordv("crl-sign"));
    if (ASN1_BIT_STRING_get_bit(usage, 7))
        janet_array_push(arr, janet_ckeywordv("encipher-only"));
    if (ASN1_BIT_STRING_get_bit(usage, 8))
        janet_array_push(arr, janet_ckeywordv("decipher-only"));

    ASN1_BIT_STRING_free(usage);
    return janet_wrap_array(arr);
}

/* Helper: Extract extended key usage */
static Janet extract_ext_key_usage(X509 *cert) {
    EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL,
                              NULL);
    if (!eku) return janet_wrap_nil();

    int count = sk_ASN1_OBJECT_num(eku);
    JanetArray *arr = janet_array(count);

    for (int i = 0; i < count; i++) {
        ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(eku, i);
        int nid = OBJ_obj2nid(obj);

        switch (nid) {
            case NID_server_auth:
                janet_array_push(arr, janet_ckeywordv("server-auth"));
                break;
            case NID_client_auth:
                janet_array_push(arr, janet_ckeywordv("client-auth"));
                break;
            case NID_code_sign:
                janet_array_push(arr, janet_ckeywordv("code-signing"));
                break;
            case NID_email_protect:
                janet_array_push(arr, janet_ckeywordv("email-protection"));
                break;
            case NID_time_stamp:
                janet_array_push(arr, janet_ckeywordv("time-stamping"));
                break;
            case NID_OCSP_sign:
                janet_array_push(arr, janet_ckeywordv("ocsp-signing"));
                break;
            default: {
                    char buf[80];
                    OBJ_obj2txt(buf, sizeof(buf), obj, 1);
                    janet_array_push(arr, janet_cstringv(buf));
                    break;
                }
        }
    }

    EXTENDED_KEY_USAGE_free(eku);
    return janet_wrap_array(arr);
}

/* Helper: Get public key info */
static Janet get_pubkey_info(EVP_PKEY *pkey) {
    JanetTable *info = janet_table(3);

    int type = EVP_PKEY_base_id(pkey);
    int bits = EVP_PKEY_bits(pkey);

    janet_table_put(info, janet_ckeywordv("bits"), janet_wrap_integer(bits));

    switch (type) {
        case EVP_PKEY_RSA:
            janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("rsa"));
            break;
        case EVP_PKEY_EC: {
                janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("ec"));
                /* Use OpenSSL 3.0 API to get curve name */
                char curve_name[80];
                size_t curve_len = sizeof(curve_name);
                if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                                   curve_name, curve_len, &curve_len) == 1) {
                    janet_table_put(info, janet_ckeywordv("curve"), janet_cstringv(curve_name));
                }
                break;
            }
        case EVP_PKEY_ED25519:
            janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("ed25519"));
            break;
        case EVP_PKEY_ED448:
            janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("ed448"));
            break;
        case EVP_PKEY_X25519:
            janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("x25519"));
            break;
        case EVP_PKEY_X448:
            janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("x448"));
            break;
        default:
            janet_table_put(info, janet_ckeywordv("type"), janet_ckeywordv("unknown"));
            break;
    }

    return janet_wrap_table(info);
}

/* Helper: Calculate certificate fingerprint */
static Janet calc_fingerprint(X509 *cert, const EVP_MD *md) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (!X509_digest(cert, md, digest, &digest_len)) {
        return janet_wrap_nil();
    }

    /* Format as hex with colons */
    char *result = janet_smalloc((size_t)digest_len * 3);
    if (!result) return janet_wrap_nil();

    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(result + (size_t)i * 3, "%02X%s", digest[i],
                (i < digest_len - 1) ? ":" : "");
    }

    Janet ret = janet_cstringv(result);
    janet_sfree(result);
    return ret;
}

/*
 * (cert/parse cert-pem)
 *
 * Parse an X.509 certificate and return its details.
 *
 * Returns a table with:
 *   :version      - Certificate version (1, 2, or 3)
 *   :serial       - Serial number as hex string
 *   :subject      - Subject fields {:cn :o :ou :c :st :l :email :dn}
 *   :issuer       - Issuer fields (same structure as subject)
 *   :not-before   - Validity start (Unix timestamp)
 *   :not-after    - Validity end (Unix timestamp)
 *   :public-key   - Key info {:type :bits :curve}
 *   :san          - Subject Alternative Names array
 *   :key-usage    - Key usage array
 *   :ext-key-usage - Extended key usage array
 *   :is-ca        - Boolean indicating if cert is a CA
 *   :fingerprint-sha256 - SHA-256 fingerprint
 *   :fingerprint-sha1   - SHA-1 fingerprint
 *   :signature-algorithm - Signature algorithm name
 *   :pem          - Original PEM data
 */
static Janet cfun_parse_cert(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    JanetByteView pem = janet_getbytes(argv, 0);

    /* Parse certificate */
    BIO *bio = BIO_new_mem_buf(pem.bytes, (int)pem.len);
    if (!bio) {
        cert_panic_resource("failed to create BIO");
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) {
        cert_panic_parse("failed to parse certificate");
    }

    /* Build result table */
    JanetTable *result = janet_table(16);

    /* Version */
    janet_table_put(result, janet_ckeywordv("version"),
                    janet_wrap_integer(X509_get_version(cert) + 1));

    /* Serial */
    janet_table_put(result, janet_ckeywordv("serial"),
                    format_serial(X509_get_serialNumber(cert)));

    /* Subject */
    janet_table_put(result, janet_ckeywordv("subject"),
                    extract_name_fields(X509_get_subject_name(cert)));

    /* Issuer */
    janet_table_put(result, janet_ckeywordv("issuer"),
                    extract_name_fields(X509_get_issuer_name(cert)));

    /* Validity */
    janet_table_put(result, janet_ckeywordv("not-before"),
                    janet_wrap_number((double)asn1_time_to_unix(X509_get0_notBefore(cert))));
    janet_table_put(result, janet_ckeywordv("not-after"),
                    janet_wrap_number((double)asn1_time_to_unix(X509_get0_notAfter(cert))));

    /* Public key info */
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey) {
        janet_table_put(result, janet_ckeywordv("public-key"), get_pubkey_info(pkey));
        EVP_PKEY_free(pkey);
    }

    /* SAN */
    Janet san = extract_san(cert);
    if (!janet_checktype(san, JANET_NIL)) {
        janet_table_put(result, janet_ckeywordv("san"), san);
    }

    /* Key usage */
    Janet ku = extract_key_usage(cert);
    if (!janet_checktype(ku, JANET_NIL)) {
        janet_table_put(result, janet_ckeywordv("key-usage"), ku);
    }

    /* Extended key usage */
    Janet eku = extract_ext_key_usage(cert);
    if (!janet_checktype(eku, JANET_NIL)) {
        janet_table_put(result, janet_ckeywordv("ext-key-usage"), eku);
    }

    /* Basic constraints - is CA */
    BASIC_CONSTRAINTS *bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL,
                            NULL);
    if (bc) {
        janet_table_put(result, janet_ckeywordv("is-ca"), janet_wrap_boolean(bc->ca));
        if (bc->pathlen) {
            janet_table_put(result, janet_ckeywordv("path-length"),
                            janet_wrap_integer(ASN1_INTEGER_get(bc->pathlen)));
        }
        BASIC_CONSTRAINTS_free(bc);
    } else {
        janet_table_put(result, janet_ckeywordv("is-ca"), janet_wrap_boolean(0));
    }

    /* Fingerprints */
    janet_table_put(result, janet_ckeywordv("fingerprint-sha256"),
                    calc_fingerprint(cert, EVP_sha256()));
    janet_table_put(result, janet_ckeywordv("fingerprint-sha1"),
                    calc_fingerprint(cert, EVP_sha1()));

    /* Signature algorithm */
    int sig_nid = X509_get_signature_nid(cert);
    const char *sig_name = OBJ_nid2ln(sig_nid);
    if (sig_name) {
        janet_table_put(result, janet_ckeywordv("signature-algorithm"),
                        janet_cstringv(sig_name));
    }

    /* Original PEM */
    janet_table_put(result, janet_ckeywordv("pem"),
                    janet_stringv(pem.bytes, pem.len));

    X509_free(cert);
    return janet_wrap_table(result);
}

/*
 * (cert/fingerprint cert-pem &opt algorithm)
 *
 * Calculate certificate fingerprint.
 *
 * Parameters:
 *   cert-pem  - Certificate in PEM format
 *   algorithm - Hash algorithm keyword (default :sha256)
 *               Supported: :sha256, :sha384, :sha512, :sha1
 *
 * Returns fingerprint as hex string with colons (e.g., "AB:CD:EF:...")
 */
static Janet cfun_fingerprint(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    JanetByteView pem = janet_getbytes(argv, 0);

    /* Get algorithm */
    const EVP_MD *md = EVP_sha256();
    if (argc > 1 && !janet_checktype(argv[1], JANET_NIL)) {
        const uint8_t *algo = janet_getkeyword(argv, 1);
        if (strcmp((const char *)algo, "sha256") == 0) {
            md = EVP_sha256();
        } else if (strcmp((const char *)algo, "sha384") == 0) {
            md = EVP_sha384();
        } else if (strcmp((const char *)algo, "sha512") == 0) {
            md = EVP_sha512();
        } else if (strcmp((const char *)algo, "sha1") == 0) {
            md = EVP_sha1();
        } else {
            cert_panic_param("unsupported fingerprint algorithm: %s", algo);
        }
    }

    /* Parse certificate */
    BIO *bio = BIO_new_mem_buf(pem.bytes, (int)pem.len);
    if (!bio) {
        cert_panic_resource("failed to create BIO");
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) {
        cert_panic_parse("failed to parse certificate");
    }

    Janet result = calc_fingerprint(cert, md);
    X509_free(cert);

    if (janet_checktype(result, JANET_NIL)) {
        cert_panic_ssl("failed to calculate fingerprint");
    }

    return result;
}

/*
 * (cert/verify-signature cert-pem issuer-cert-pem)
 *
 * Verify that a certificate was signed by the issuer.
 *
 * Parameters:
 *   cert-pem        - Certificate to verify
 *   issuer-cert-pem - Issuer's certificate (contains public key)
 *
 * Returns true if signature is valid, false otherwise.
 */
static Janet cfun_verify_signature(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    JanetByteView cert_pem = janet_getbytes(argv, 0);
    JanetByteView issuer_pem = janet_getbytes(argv, 1);

    /* Parse certificates */
    BIO *bio1 = BIO_new_mem_buf(cert_pem.bytes, (int)cert_pem.len);
    if (!bio1) cert_panic_resource("failed to create BIO");
    X509 *cert = PEM_read_bio_X509(bio1, NULL, NULL, NULL);
    BIO_free(bio1);
    if (!cert) cert_panic_parse("failed to parse certificate");

    BIO *bio2 = BIO_new_mem_buf(issuer_pem.bytes, (int)issuer_pem.len);
    if (!bio2) {
        X509_free(cert);
        cert_panic_resource("failed to create BIO");
    }
    X509 *issuer = PEM_read_bio_X509(bio2, NULL, NULL, NULL);
    BIO_free(bio2);
    if (!issuer) {
        X509_free(cert);
        cert_panic_parse("failed to parse issuer certificate");
    }

    /* Get issuer's public key */
    EVP_PKEY *pkey = X509_get_pubkey(issuer);
    X509_free(issuer);
    if (!pkey) {
        X509_free(cert);
        cert_panic_ssl("failed to get issuer public key");
    }

    /* Verify signature */
    int result = X509_verify(cert, pkey);

    EVP_PKEY_free(pkey);
    X509_free(cert);

    return janet_wrap_boolean(result == 1);
}

JANET_MODULE_ENTRY(JanetTable *env) {
    JanetReg cfuns[] = {
        {
            "generate-self-signed-cert", cfun_generate_self_signed_cert,
            "(jsec/cert/generate-self-signed-cert &opt options)\n\n"
            "Generate a self-signed certificate and private key.\n"
            "Returns a struct {:cert \"PEM...\" :key \"PEM...\"}.\n"
            "Options table keys:\n"
            "  :common-name (default \"localhost\")\n"
            "  :days-valid (default 365)\n"
            "  :bits (default 2048, RSA only)\n"
            "  :key-type - :rsa, :ec-p256, :ec-p384, :ec-p521, :ed25519 (default :rsa)\n"
            "  :country (default \"US\")\n"
            "  :organization (default \"Test\")"
        },
        {
            "generate-self-signed-from-key", cfun_generate_self_signed_from_key,
            "(jsec/cert/generate-self-signed-from-key key-pem &opt options)\n\n"
            "Generate a self-signed certificate from an existing private key.\n"
            "Returns the certificate PEM string.\n"
            "Options table keys:\n"
            "  :common-name (default \"localhost\")\n"
            "  :days-valid (default 365)\n"
            "  :country (default \"US\")\n"
            "  :organization (default \"Test\")"
        },
        {
            "parse", cfun_parse_cert,
            "(jsec/cert/parse cert-pem)\n\n"
            "Parse an X.509 certificate and return its details.\n"
            "Returns a table with:\n"
            "  :version      - Certificate version (1, 2, or 3)\n"
            "  :serial       - Serial number as hex string\n"
            "  :subject      - Subject fields {:cn :o :ou :c :st :l :email :dn}\n"
            "  :issuer       - Issuer fields (same structure as subject)\n"
            "  :not-before   - Validity start (Unix timestamp)\n"
            "  :not-after    - Validity end (Unix timestamp)\n"
            "  :public-key   - Key info {:type :bits :curve}\n"
            "  :san          - Subject Alternative Names array\n"
            "  :key-usage    - Key usage array\n"
            "  :ext-key-usage - Extended key usage array\n"
            "  :is-ca        - Boolean indicating if cert is a CA\n"
            "  :fingerprint-sha256 - SHA-256 fingerprint\n"
            "  :fingerprint-sha1   - SHA-1 fingerprint\n"
            "  :signature-algorithm - Signature algorithm name\n"
            "  :pem          - Original PEM data"
        },
        {
            "fingerprint", cfun_fingerprint,
            "(jsec/cert/fingerprint cert-pem &opt algorithm)\n\n"
            "Calculate certificate fingerprint.\n"
            "algorithm defaults to :sha256.\n"
            "Supported: :sha256, :sha384, :sha512, :sha1\n"
            "Returns fingerprint as hex string with colons."
        },
        {
            "verify-signature", cfun_verify_signature,
            "(jsec/cert/verify-signature cert-pem issuer-cert-pem)\n\n"
            "Verify that a certificate was signed by the issuer.\n"
            "Returns true if signature is valid, false otherwise."
        },
        {
            "verify-chain", cfun_cert_verify_chain,
            "(jsec/cert/verify-chain cert-pem &opt opts)\n\n"
            "Verify a certificate against a trust chain.\n"
            "Options:\n"
            "  :chain [<pem> ...] - Intermediate certificates\n"
            "  :trusted [<pem> ...] - Trusted root certificates\n"
            "  :trusted-dir \"/path\" - Directory of trusted certs (OpenSSL hash format)\n"
            "  :purpose :server-auth - Certificate purpose (:server-auth, :client-auth, :code-signing, :email-protection, :timestamp, :any)\n"
            "  :hostname \"example.com\" - Verify hostname in SAN/CN\n"
            "  :time 1234567890 - Verify at specific Unix timestamp\n"
            "  :check-crl true - Enable CRL checking\n"
            "  :crl <pem> - CRL to check against\n\n"
            "Returns table:\n"
            "  {:valid true :chain [<pem> ...]} on success\n"
            "  {:valid false :error \"message\" :depth N} on failure"
        },
        {
            "build-chain", cfun_cert_build_chain,
            "(jsec/cert/build-chain cert-pem intermediates trusted)\n\n"
            "Build a certificate chain from cert to trusted root.\n"
            "intermediates - array of PEM strings or single PEM with multiple certs\n"
            "trusted - array of trusted root PEM strings or single PEM\n"
            "Returns array of PEM strings from cert to root, or nil if chain can't be built."
        },
        {NULL, NULL, NULL}
    };
    JanetReg *reg = cfuns;
    while (reg->name) {
        janet_def(env, reg->name, janet_wrap_cfunction(reg->cfun),
                  reg->documentation);
        reg++;
    }
}
