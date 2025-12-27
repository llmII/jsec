/*
 * jcrypto/ec.c - Elliptic curve point operations
 *
 * Low-level EC operations for advanced cryptographic protocols.
 * Use cases: Custom key agreement, threshold signatures, ECIES, DKG.
 *
 * WARNING: These are low-level primitives. Misuse can lead to security
 * vulnerabilities. Use higher-level APIs (like crypto/ecdh-derive) when
 * possible.
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#if JSEC_HAS_OSSL_PARAM
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

/*
 * Get NID for curve keyword
 */
static int get_curve_nid(const char *curve) {
    if (strcmp(curve, "p-256") == 0 || strcmp(curve, "prime256v1") == 0) {
        return NID_X9_62_prime256v1;
    }
    if (strcmp(curve, "p-384") == 0 || strcmp(curve, "secp384r1") == 0) {
        return NID_secp384r1;
    }
    if (strcmp(curve, "p-521") == 0 || strcmp(curve, "secp521r1") == 0) {
        return NID_secp521r1;
    }
    if (strcmp(curve, "secp256k1") == 0) {
        return NID_secp256k1;
    }
    return 0; /* Invalid */
}

/*
 * Get field size in bytes for curve
 */
static int get_curve_field_size(int nid) {
    switch (nid) {
        case NID_X9_62_prime256v1:
            return 32;
        case NID_secp384r1:
            return 48;
        case NID_secp521r1:
            return 66; /* 521 bits = 66 bytes */
        case NID_secp256k1:
            return 32;
        default:
            return 0;
    }
}

/*
 * Point multiplication (scalar * G or scalar * point)
 * (crypto/ec-point-mul curve scalar &opt point)
 * If point is nil, multiplies generator G
 * Returns {:x <buffer> :y <buffer>}
 */
Janet cfun_ec_point_mul(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    const uint8_t *curve_kw = janet_getkeyword(argv, 0);
    JanetByteView scalar_bv = janet_getbytes(argv, 1);

    int nid = get_curve_nid((const char *)curve_kw);
    if (nid == 0) {
        crypto_panic_param("unsupported curve: %s (supported: p-256, p-384, "
                           "p-521, secp256k1)",
                           (const char *)curve_kw);
    }

    /* Create EC group */
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        crypto_panic_ssl("failed to create EC group");
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        EC_GROUP_free(group);
        crypto_panic_resource("failed to create BN context");
    }

    /* Convert scalar to BIGNUM */
    BIGNUM *scalar = BN_bin2bn(scalar_bv.bytes, (int)scalar_bv.len, NULL);
    if (!scalar) {
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_ssl("failed to parse scalar");
    }

    /* Get point to multiply (generator or provided point) */
    EC_POINT *base_point = NULL;
    int free_base = 0;

    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        /* Parse provided point */
        JanetTable *point_table = NULL;
        JanetStruct point_struct = NULL;

        if (janet_checktype(argv[2], JANET_TABLE)) {
            point_table = janet_unwrap_table(argv[2]);
        } else if (janet_checktype(argv[2], JANET_STRUCT)) {
            point_struct = janet_unwrap_struct(argv[2]);
        } else {
            BN_free(scalar);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            crypto_panic_param("point must be a table with :x and :y keys");
        }

        Janet x_val =
            point_table
                ? janet_table_get(point_table, janet_ckeywordv("x"))
                : janet_struct_get(point_struct, janet_ckeywordv("x"));
        Janet y_val =
            point_table
                ? janet_table_get(point_table, janet_ckeywordv("y"))
                : janet_struct_get(point_struct, janet_ckeywordv("y"));

        if (janet_checktype(x_val, JANET_NIL) ||
            janet_checktype(y_val, JANET_NIL)) {
            BN_free(scalar);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            crypto_panic_param("point requires both :x and :y coordinates");
        }

        JanetByteView x_bv = janet_getbytes(&x_val, 0);
        JanetByteView y_bv = janet_getbytes(&y_val, 0);

        BIGNUM *x = BN_bin2bn(x_bv.bytes, (int)x_bv.len, NULL);
        BIGNUM *y = BN_bin2bn(y_bv.bytes, (int)y_bv.len, NULL);

        base_point = EC_POINT_new(group);
        if (!base_point || !x || !y) {
            if (x) BN_free(x);
            if (y) BN_free(y);
            if (base_point) EC_POINT_free(base_point);
            BN_free(scalar);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            crypto_panic_resource("failed to allocate point");
        }

        if (!EC_POINT_set_affine_coordinates(group, base_point, x, y, ctx)) {
            BN_free(x);
            BN_free(y);
            EC_POINT_free(base_point);
            BN_free(scalar);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            crypto_panic_ssl(
                "invalid point coordinates (point not on curve?)");
        }

        BN_free(x);
        BN_free(y);
        free_base = 1;
    } else {
        /* Use generator */
        base_point = (EC_POINT *)EC_GROUP_get0_generator(group);
    }

    /* Create result point */
    EC_POINT *result_point = EC_POINT_new(group);
    if (!result_point) {
        if (free_base) EC_POINT_free(base_point);
        BN_free(scalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_resource("failed to allocate result point");
    }

    /* Perform multiplication */
    if (!EC_POINT_mul(group, result_point, NULL, base_point, scalar, ctx)) {
        EC_POINT_free(result_point);
        if (free_base) EC_POINT_free(base_point);
        BN_free(scalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_ssl("point multiplication failed");
    }

    /* Extract coordinates */
    BIGNUM *result_x = BN_new();
    BIGNUM *result_y = BN_new();

    if (!result_x || !result_y ||
        !EC_POINT_get_affine_coordinates(group, result_point, result_x,
                                         result_y, ctx)) {
        if (result_x) BN_free(result_x);
        if (result_y) BN_free(result_y);
        EC_POINT_free(result_point);
        if (free_base) EC_POINT_free(base_point);
        BN_free(scalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_ssl("failed to get result coordinates");
    }

    /* Convert to fixed-size byte arrays */
    int field_size = get_curve_field_size(nid);
    uint8_t *x_bytes = janet_smalloc((size_t)field_size);
    uint8_t *y_bytes = janet_smalloc((size_t)field_size);

    if (!x_bytes || !y_bytes) {
        if (x_bytes) janet_sfree(x_bytes);
        if (y_bytes) janet_sfree(y_bytes);
        BN_free(result_x);
        BN_free(result_y);
        EC_POINT_free(result_point);
        if (free_base) EC_POINT_free(base_point);
        BN_free(scalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_resource("out of memory");
    }

    /* Zero-pad to field size */
    memset(x_bytes, 0, (size_t)field_size);
    memset(y_bytes, 0, (size_t)field_size);
    int x_len = BN_num_bytes(result_x);
    int y_len = BN_num_bytes(result_y);
    BN_bn2bin(result_x, x_bytes + (field_size - x_len));
    BN_bn2bin(result_y, y_bytes + (field_size - y_len));

    /* Build result table */
    JanetTable *result = janet_table(2);
    janet_table_put(result, janet_ckeywordv("x"),
                    janet_stringv(x_bytes, field_size));
    janet_table_put(result, janet_ckeywordv("y"),
                    janet_stringv(y_bytes, field_size));

    /* Cleanup */
    janet_sfree(x_bytes);
    janet_sfree(y_bytes);
    BN_free(result_x);
    BN_free(result_y);
    EC_POINT_free(result_point);
    if (free_base) EC_POINT_free(base_point);
    BN_free(scalar);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return janet_wrap_table(result);
}

/*
 * Point addition
 * (crypto/ec-point-add curve point1 point2)
 * Returns {:x <buffer> :y <buffer>}
 */
Janet cfun_ec_point_add(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    const uint8_t *curve_kw = janet_getkeyword(argv, 0);

    int nid = get_curve_nid((const char *)curve_kw);
    if (nid == 0) {
        crypto_panic_param("unsupported curve: %s", (const char *)curve_kw);
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) crypto_panic_ssl("failed to create EC group");

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        EC_GROUP_free(group);
        crypto_panic_resource("failed to create BN context");
    }

    /* Parse both points */
    EC_POINT *p1 = EC_POINT_new(group);
    EC_POINT *p2 = EC_POINT_new(group);
    EC_POINT *result = EC_POINT_new(group);

    if (!p1 || !p2 || !result) {
        if (p1) EC_POINT_free(p1);
        if (p2) EC_POINT_free(p2);
        if (result) EC_POINT_free(result);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_resource("failed to allocate points");
    }

    /* Helper to parse point from Janet */
    for (int i = 0; i < 2; i++) {
        EC_POINT *target = (i == 0) ? p1 : p2;
        Janet point_val = argv[i + 1];

        JanetTable *pt = NULL;
        JanetStruct ps = NULL;
        if (janet_checktype(point_val, JANET_TABLE)) {
            pt = janet_unwrap_table(point_val);
        } else if (janet_checktype(point_val, JANET_STRUCT)) {
            ps = janet_unwrap_struct(point_val);
        } else {
            EC_POINT_free(p1);
            EC_POINT_free(p2);
            EC_POINT_free(result);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            crypto_panic_param("point %d must be a table with :x and :y",
                               i + 1);
        }

        Janet x_val = pt ? janet_table_get(pt, janet_ckeywordv("x"))
                         : janet_struct_get(ps, janet_ckeywordv("x"));
        Janet y_val = pt ? janet_table_get(pt, janet_ckeywordv("y"))
                         : janet_struct_get(ps, janet_ckeywordv("y"));

        JanetByteView x_bv = janet_getbytes(&x_val, 0);
        JanetByteView y_bv = janet_getbytes(&y_val, 0);

        BIGNUM *x = BN_bin2bn(x_bv.bytes, (int)x_bv.len, NULL);
        BIGNUM *y = BN_bin2bn(y_bv.bytes, (int)y_bv.len, NULL);

        int ok = EC_POINT_set_affine_coordinates(group, target, x, y, ctx);
        BN_free(x);
        BN_free(y);

        if (!ok) {
            EC_POINT_free(p1);
            EC_POINT_free(p2);
            EC_POINT_free(result);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            crypto_panic_param("invalid point %d coordinates (not on curve?)",
                               i + 1);
        }
    }

    /* Add points */
    if (!EC_POINT_add(group, result, p1, p2, ctx)) {
        EC_POINT_free(p1);
        EC_POINT_free(p2);
        EC_POINT_free(result);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_ssl("point addition failed");
    }

    /* Extract result coordinates */
    BIGNUM *rx = BN_new();
    BIGNUM *ry = BN_new();
    EC_POINT_get_affine_coordinates(group, result, rx, ry, ctx);

    int field_size = get_curve_field_size(nid);
    uint8_t *x_bytes = janet_smalloc((size_t)field_size);
    uint8_t *y_bytes = janet_smalloc((size_t)field_size);

    memset(x_bytes, 0, (size_t)field_size);
    memset(y_bytes, 0, (size_t)field_size);
    int rx_len = BN_num_bytes(rx);
    int ry_len = BN_num_bytes(ry);
    BN_bn2bin(rx, x_bytes + (field_size - rx_len));
    BN_bn2bin(ry, y_bytes + (field_size - ry_len));

    JanetTable *ret = janet_table(2);
    janet_table_put(ret, janet_ckeywordv("x"),
                    janet_stringv(x_bytes, field_size));
    janet_table_put(ret, janet_ckeywordv("y"),
                    janet_stringv(y_bytes, field_size));

    janet_sfree(x_bytes);
    janet_sfree(y_bytes);
    BN_free(rx);
    BN_free(ry);
    EC_POINT_free(p1);
    EC_POINT_free(p2);
    EC_POINT_free(result);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return janet_wrap_table(ret);
}

/*
 * Serialize point to bytes
 * (crypto/ec-point-to-bytes curve point &opt opts)
 * opts: {:compressed true}
 * Returns buffer (compressed or uncompressed SEC1 format)
 */
Janet cfun_ec_point_to_bytes(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    const uint8_t *curve_kw = janet_getkeyword(argv, 0);

    int compressed = 0;
    if (argc > 2 && !janet_checktype(argv[2], JANET_NIL)) {
        if (janet_checktype(argv[2], JANET_TABLE)) {
            JanetTable *opts = janet_unwrap_table(argv[2]);
            Janet comp_val =
                janet_table_get(opts, janet_ckeywordv("compressed"));
            compressed = janet_truthy(comp_val);
        } else if (janet_checktype(argv[2], JANET_STRUCT)) {
            JanetStruct opts = janet_unwrap_struct(argv[2]);
            Janet comp_val =
                janet_struct_get(opts, janet_ckeywordv("compressed"));
            compressed = janet_truthy(comp_val);
        }
    }

    int nid = get_curve_nid((const char *)curve_kw);
    if (nid == 0)
        crypto_panic_param("unsupported curve: %s", (const char *)curve_kw);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) crypto_panic_ssl("failed to create EC group");

    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *point = EC_POINT_new(group);

    if (!ctx || !point) {
        if (ctx) BN_CTX_free(ctx);
        if (point) EC_POINT_free(point);
        EC_GROUP_free(group);
        crypto_panic_resource("out of memory");
    }

    /* Parse point */
    JanetTable *pt = NULL;
    JanetStruct ps = NULL;
    if (janet_checktype(argv[1], JANET_TABLE)) {
        pt = janet_unwrap_table(argv[1]);
    } else if (janet_checktype(argv[1], JANET_STRUCT)) {
        ps = janet_unwrap_struct(argv[1]);
    } else {
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_param("point must be a table with :x and :y");
    }

    Janet x_val = pt ? janet_table_get(pt, janet_ckeywordv("x"))
                     : janet_struct_get(ps, janet_ckeywordv("x"));
    Janet y_val = pt ? janet_table_get(pt, janet_ckeywordv("y"))
                     : janet_struct_get(ps, janet_ckeywordv("y"));

    JanetByteView x_bv = janet_getbytes(&x_val, 0);
    JanetByteView y_bv = janet_getbytes(&y_val, 0);

    BIGNUM *x = BN_bin2bn(x_bv.bytes, (int)x_bv.len, NULL);
    BIGNUM *y = BN_bin2bn(y_bv.bytes, (int)y_bv.len, NULL);

    int ok = EC_POINT_set_affine_coordinates(group, point, x, y, ctx);
    BN_free(x);
    BN_free(y);

    if (!ok) {
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_ssl("invalid point coordinates");
    }

    /* Serialize */
    point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED
                                              : POINT_CONVERSION_UNCOMPRESSED;
    size_t len = EC_POINT_point2oct(group, point, form, NULL, 0, ctx);
    if (len == 0) {
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_ssl("failed to determine output size");
    }

    uint8_t *buf = janet_smalloc(len);
    if (!buf) {
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_resource("out of memory");
    }

    EC_POINT_point2oct(group, point, form, buf, len, ctx);
    Janet result = janet_stringv(buf, (int32_t)len);

    janet_sfree(buf);
    EC_POINT_free(point);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return result;
}

/*
 * Deserialize point from bytes
 * (crypto/ec-point-from-bytes curve bytes)
 * Returns {:x <buffer> :y <buffer>}
 */
Janet cfun_ec_point_from_bytes(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    const uint8_t *curve_kw = janet_getkeyword(argv, 0);
    JanetByteView bytes = janet_getbytes(argv, 1);

    int nid = get_curve_nid((const char *)curve_kw);
    if (nid == 0)
        crypto_panic_param("unsupported curve: %s", (const char *)curve_kw);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) crypto_panic_ssl("failed to create EC group");

    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *point = EC_POINT_new(group);

    if (!ctx || !point) {
        if (ctx) BN_CTX_free(ctx);
        if (point) EC_POINT_free(point);
        EC_GROUP_free(group);
        crypto_panic_resource("out of memory");
    }

    if (!EC_POINT_oct2point(group, point, bytes.bytes, bytes.len, ctx)) {
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        crypto_panic_ssl(
            "failed to parse point (invalid encoding or not on curve)");
    }

    /* Extract coordinates */
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates(group, point, x, y, ctx);

    int field_size = get_curve_field_size(nid);
    uint8_t *x_bytes = janet_smalloc((size_t)field_size);
    uint8_t *y_bytes = janet_smalloc((size_t)field_size);

    memset(x_bytes, 0, (size_t)field_size);
    memset(y_bytes, 0, (size_t)field_size);
    int x_len = BN_num_bytes(x);
    int y_len = BN_num_bytes(y);
    BN_bn2bin(x, x_bytes + (field_size - x_len));
    BN_bn2bin(y, y_bytes + (field_size - y_len));

    JanetTable *result = janet_table(2);
    janet_table_put(result, janet_ckeywordv("x"),
                    janet_stringv(x_bytes, field_size));
    janet_table_put(result, janet_ckeywordv("y"),
                    janet_stringv(y_bytes, field_size));

    janet_sfree(x_bytes);
    janet_sfree(y_bytes);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return janet_wrap_table(result);
}

/*
 * Generate random scalar in valid range for curve
 * (crypto/ec-generate-scalar curve)
 * Returns buffer (big-endian integer)
 */
Janet cfun_ec_generate_scalar(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    const uint8_t *curve_kw = janet_getkeyword(argv, 0);

    int nid = get_curve_nid((const char *)curve_kw);
    if (nid == 0)
        crypto_panic_param("unsupported curve: %s", (const char *)curve_kw);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) crypto_panic_ssl("failed to create EC group");

    /* Get the order of the curve */
#if JSEC_OPENSSL
    const BIGNUM *order = EC_GROUP_get0_order(group);
#else
    /* LibreSSL: use EC_GROUP_get_order with output parameter */
    BIGNUM *order_storage = BN_new();
    if (!order_storage) {
        EC_GROUP_free(group);
        crypto_panic_resource("out of memory");
    }
    if (!EC_GROUP_get_order(group, order_storage, NULL)) {
        BN_free(order_storage);
        EC_GROUP_free(group);
        crypto_panic_ssl("failed to get curve order");
    }
    const BIGNUM *order = order_storage;
#endif

    /* Generate random scalar in [1, order-1] */
    BIGNUM *scalar = BN_new();
    if (!scalar) {
#if !JSEC_OPENSSL
        BN_free(order_storage);
#endif
        EC_GROUP_free(group);
        crypto_panic_resource("out of memory");
    }

    /* Generate random < order, then add 1 to ensure non-zero */
    BIGNUM *order_minus_1 = BN_dup(order);
    BN_sub_word(order_minus_1, 1);

    if (!BN_rand_range(scalar, order_minus_1)) {
        BN_free(scalar);
        BN_free(order_minus_1);
#if !JSEC_OPENSSL
        BN_free(order_storage);
#endif
        EC_GROUP_free(group);
        crypto_panic_ssl("failed to generate random scalar");
    }

    BN_add_word(scalar, 1); /* Ensure scalar is at least 1 */
    BN_free(order_minus_1);

    /* Convert to fixed-size bytes */
    int field_size = get_curve_field_size(nid);
    uint8_t *bytes = janet_smalloc((size_t)field_size);
    if (!bytes) {
        BN_free(scalar);
#if !JSEC_OPENSSL
        BN_free(order_storage);
#endif
        EC_GROUP_free(group);
        crypto_panic_resource("out of memory");
    }

    memset(bytes, 0, (size_t)field_size);
    int scalar_len = BN_num_bytes(scalar);
    BN_bn2bin(scalar, bytes + (field_size - scalar_len));

    Janet result = janet_stringv(bytes, field_size);

    janet_sfree(bytes);
    BN_free(scalar);
#if !JSEC_OPENSSL
    BN_free(order_storage);
#endif
    EC_GROUP_free(group);

    return result;
}
