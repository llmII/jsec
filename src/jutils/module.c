/*
 * module.c - Module entry point for jsec/utils
 *
 * This module registers shared types (like SSLContext) that are used
 * by multiple jsec modules. It should be imported before tls-stream
 * or dtls-stream to ensure the type is registered only once.
 */

#include "../jutils.h"

/* Module entry point */
JANET_MODULE_ENTRY(JanetTable *env) {
    (void)env;
    /* Register shared abstract types */
    jutils_init_context_type();
}
