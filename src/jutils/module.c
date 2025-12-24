/*
 * module.c - Module entry point for jsec/utils
 *
 * This module registers shared types (like SSLContext) that are used
 * by multiple jsec modules. It should be imported before tls-stream
 * or dtls-stream to ensure the type is registered only once.
 */

#include "../compat.h"
#include "../jutils.h"
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

/*
 * (utils/ssl-backend)
 * Returns the SSL backend keyword: :openssl or :libressl
 */
static Janet cfun_ssl_backend(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);
#if JSEC_LIBRESSL
    return janet_ckeywordv("libressl");
#else
    return janet_ckeywordv("openssl");
#endif
}

/*
 * (utils/ssl-version)
 * Returns a struct with SSL library version info:
 *   :backend - :openssl or :libressl
 *   :version - version string (e.g., "OpenSSL 3.0.2" or "LibreSSL 4.2.0")
 *   :number  - numeric version for comparison
 */
static Janet cfun_ssl_version(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);

    JanetTable *info = janet_table(3);

#if JSEC_LIBRESSL
    janet_table_put(info, janet_ckeywordv("backend"),
                    janet_ckeywordv("libressl"));
#else
    janet_table_put(info, janet_ckeywordv("backend"), janet_ckeywordv("openssl"));
#endif

    janet_table_put(info, janet_ckeywordv("version"),
                    janet_cstringv(OpenSSL_version(OPENSSL_VERSION)));
    janet_table_put(info, janet_ckeywordv("number"),
                    janet_wrap_number((double)OPENSSL_VERSION_NUMBER));

    return janet_wrap_table(info);
}

static const JanetReg cfuns[] = {
    {
        "ssl-backend", cfun_ssl_backend,
        "(utils/ssl-backend)\n\n"
        "Returns the SSL backend keyword: :openssl or :libressl"
    },
    {
        "ssl-version", cfun_ssl_version,
        "(utils/ssl-version)\n\n"
        "Returns a struct with SSL library version info:\n"
        "  :backend - :openssl or :libressl\n"
        "  :version - version string\n"
        "  :number  - numeric version for comparison"
    },
    {NULL, NULL, NULL}
};

/* Module entry point */
JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "utils", cfuns);
    /* Register shared abstract types */
    jutils_init_context_type();
}
