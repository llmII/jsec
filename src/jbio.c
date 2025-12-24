/*
 * jbio.c - OpenSSL BIO wrappers for Janet
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */
#include "jutils.h"
#include <openssl/bio.h>

/* BIO Abstract Type */
static int jbio_gc(void *p, size_t s) {
    (void)s;
    BIO **bio = (BIO **)p;
    if (*bio) {
        BIO_free(*bio);
        *bio = NULL;
    }
    return 0;
}

static int jbio_get(void *p, Janet key, Janet *out);

static const JanetAbstractType jbio_type = {
    "jsec/bio", /* name */
    jbio_gc,    /* gc */
    NULL,       /* gcmark */
    jbio_get,   /* get */
    NULL,       /* put */
    NULL,       /* marshal */
    NULL,       /* unmarshal */
    NULL,       /* tostring */
    NULL,       /* compare */
    NULL,       /* hash */
    NULL,       /* next */
    NULL,       /* call */
    NULL,       /* length */
    NULL,       /* bytes */
    NULL        /* gcperthread */
};

static Janet cfun_bio_new_mem(int32_t argc, Janet *argv) {
    (void)argv; /* Unused */
    janet_fixarity(argc, 0);
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        crypto_panic_ssl("failed to create memory BIO");

    BIO **box = (BIO **)janet_abstract(&jbio_type, sizeof(BIO *));
    *box = bio;
    return janet_wrap_abstract(box);
}

static Janet cfun_bio_write(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    BIO **box = (BIO **)janet_getabstract(argv, 0, &jbio_type);
    BIO *bio = *box;
    if (!bio)
        crypto_panic_config("BIO is closed");

    JanetByteView bytes = janet_getbytes(argv, 1);
    int written = BIO_write(bio, bytes.bytes, bytes.len);
    return janet_wrap_integer(written);
}

static Janet cfun_bio_read(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    BIO **box = (BIO **)janet_getabstract(argv, 0, &jbio_type);
    BIO *bio = *box;
    if (!bio)
        crypto_panic_config("BIO is closed");

    int32_t len = janet_getinteger(argv, 1);
    if (len < 0)
        crypto_panic_param("length must be non-negative");

    uint8_t *buf = janet_malloc(len);
    int read = BIO_read(bio, buf, len);

    if (read <= 0) {
        janet_free(buf);
        return janet_wrap_nil();
    }

    Janet result = janet_stringv(buf, read);
    janet_free(buf);
    return result;
}

static Janet cfun_bio_close(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    BIO **box = (BIO **)janet_getabstract(argv, 0, &jbio_type);
    if (*box) {
        BIO_free(*box);
        *box = NULL;
    }
    return janet_wrap_nil();
}

static Janet cfun_bio_to_string(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    BIO **box = (BIO **)janet_getabstract(argv, 0, &jbio_type);
    BIO *bio = *box;
    if (!bio)
        crypto_panic_config("BIO is closed");

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    return janet_stringv((const uint8_t *)data, len);
}

/* Method table for BIO objects */
static int jbio_get(void *p, Janet key, Janet *out) {
    (void)p;
    if (!janet_checktype(key, JANET_KEYWORD))
        return 0;
    const uint8_t *kw = janet_unwrap_keyword(key);
    if (!janet_cstrcmp(kw, "read")) {
        *out = janet_wrap_cfunction(cfun_bio_read);
        return 1;
    }
    if (!janet_cstrcmp(kw, "write")) {
        *out = janet_wrap_cfunction(cfun_bio_write);
        return 1;
    }
    if (!janet_cstrcmp(kw, "close")) {
        *out = janet_wrap_cfunction(cfun_bio_close);
        return 1;
    }
    return 0;
}

static const JanetReg cfuns[] = {
    {
        "new-mem", cfun_bio_new_mem,
        "(jsec/bio/new-mem)\n\n"
        "Create a new memory BIO.\n"
        "Returns a BIO object that supports :read, :write, and :close methods."
    },

    {
        "write", cfun_bio_write,
        "(jsec/bio/write bio data)\n\n"
        "Write data to BIO. Returns number of bytes written."
    },

    {
        "read", cfun_bio_read,
        "(jsec/bio/read bio len)\n\n"
        "Read up to len bytes from BIO. Returns string or nil if no data."
    },

    {
        "close", cfun_bio_close,
        "(jsec/bio/close bio)\n\n"
        "Close the BIO and free resources. Safe to call multiple times."
    },

    {
        "to-string", cfun_bio_to_string,
        "(jsec/bio/to-string bio)\n\n"
        "Get all data in memory BIO as string without consuming it."
    },

    {NULL, NULL, NULL}
};

JANET_MODULE_ENTRY(JanetTable *env) {
    const JanetReg *reg = cfuns;
    while (reg->name) {
        janet_def(env, reg->name, janet_wrap_cfunction(reg->cfun),
                  reg->documentation);
        reg++;
    }
    janet_register_abstract_type(&jbio_type);
}
