/*
 * jcrypto/base64.c - Base64 encoding/decoding functions
 */

#include "internal.h"

/* Base64 encode */
Janet cfun_base64_encode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView data = janet_getbytes(argv, 0);

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    BIO_write(b64, data.bytes, data.len);
    BIO_flush(b64);

    char *out;
    long out_len = BIO_get_mem_data(mem, &out);

    Janet result = janet_stringv((const uint8_t *)out, out_len);
    BIO_free_all(b64);
    return result;
}

/* Base64 decode */
Janet cfun_base64_decode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView data = janet_getbytes(argv, 0);

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(data.bytes, data.len);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    /* Allocate max possible decoded size */
    size_t max_len = ((size_t)data.len * 3) / 4 + 1;
    unsigned char *buf = janet_malloc(max_len);
    if (!buf) {
        BIO_free_all(b64);
        crypto_panic_resource("failed to allocate decode buffer");
    }

    int len = BIO_read(b64, buf, (int)max_len);
    BIO_free_all(b64);

    if (len < 0) {
        janet_free(buf);
        crypto_panic_ssl("base64 decode failed");
    }

    Janet result = janet_stringv(buf, (int32_t)len);
    janet_free(buf);
    return result;
}

/* Base64url encode (ACME/JWT compatible) */
Janet cfun_base64url_encode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView data = janet_getbytes(argv, 0);

    /* First do regular base64 */
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    BIO_write(b64, data.bytes, data.len);
    BIO_flush(b64);

    char *out;
    long out_len = BIO_get_mem_data(mem, &out);

    /* Convert to URL-safe: + -> -, / -> _, remove padding */
    JanetBuffer *buf = janet_buffer((int32_t)out_len);
    for (long i = 0; i < out_len; i++) {
        if (out[i] == '+') janet_buffer_push_u8(buf, (uint8_t)'-');
        else if (out[i] == '/') janet_buffer_push_u8(buf, (uint8_t)'_');
        else if (out[i] != '=') janet_buffer_push_u8(buf, (uint8_t)out[i]);
    }

    BIO_free_all(b64);
    return janet_stringv(buf->data, buf->count);
}

/* Base64url decode */
Janet cfun_base64url_decode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    JanetByteView data = janet_getbytes(argv, 0);

    /* Convert from URL-safe back to standard base64 */
    JanetBuffer *buf = janet_buffer(data.len + 4);
    for (int32_t i = 0; i < data.len; i++) {
        if (data.bytes[i] == '-') janet_buffer_push_u8(buf, '+');
        else if (data.bytes[i] == '_') janet_buffer_push_u8(buf, '/');
        else janet_buffer_push_u8(buf, data.bytes[i]);
    }
    /* Add padding if needed */
    while (buf->count % 4 != 0) {
        janet_buffer_push_u8(buf, '=');
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(buf->data, buf->count);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    size_t max_len = ((size_t)buf->count * 3) / 4 + 1;
    unsigned char *out = janet_malloc(max_len);
    if (!out) {
        BIO_free_all(b64);
        crypto_panic_resource("failed to allocate decode buffer");
    }

    int len = BIO_read(b64, out, (int)max_len);
    BIO_free_all(b64);

    if (len < 0) {
        janet_free(out);
        crypto_panic_ssl("base64url decode failed");
    }

    Janet result = janet_stringv(out, (int32_t)len);
    janet_free(out);
    return result;
}
