/*
 * jca/module.c - CA module registration
 *
 * Registers all CA functions and types with Janet.
 *
 * Author: jsec project
 * License: ISC
 */

#include "jca_internal.h"

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

JANET_MODULE_ENTRY(JanetTable *env) {
    /* Register types and constructors */
    jca_register_types(env);

    /* Register signing functions */
    jca_register_sign(env);

    /* Register CRL functions */
    jca_register_crl(env);

    /* Register OCSP functions */
    jca_register_ocsp(env);
}
