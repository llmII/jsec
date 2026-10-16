/*
 * timeout.c - Optional I/O timeout argument parsing
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <math.h>

/*============================================================================
 * CACHED KEYWORDS
 *============================================================================
 * Keywords used in hot paths are cached to avoid repeated interning lookups.
 * Janet keywords are interned (globally unique), so caching the Janet value
 * avoids the hash lookup on every call.
 *
 * Thread safety: Janet guarantees each thread has its own VM state, and
 * keywords are interned per-VM. The init function is called once per module
 * load (which happens once per VM), so this is safe.
 */
static Janet kw_timeout = {0};
static int kw_initialized = 0;

static void ensure_keywords_initialized(void) {
    if (!kw_initialized) {
        kw_timeout = janet_ckeywordv("timeout");
        janet_gcroot(kw_timeout);
        kw_initialized = 1;
    }
}

static JANET_NO_RETURN void timeout_param_error(const char *mod) {
    janet_panicf("[%s:PARAM] timeout must be a non-negative number", mod);
}

/*============================================================================
 * HELPER: Parse timeout from argument
 *============================================================================
 * The optional timeout argument is one of:
 * - absent or nil - no deadline
 * - a number of seconds
 * - a table/struct with a :timeout key (and potentially other options)
 *
 * A value must be non-negative and non-NaN. NaN compares false with
 * everything, so a plain "negative" check would let it sail through to the
 * deadline arming and fire immediately; both are rejected here. Anything
 * else raises the module's timeout parameter error.
 */
double parse_timeout_opt(int32_t argc, Janet *argv, int32_t idx,
                         const char *mod, double no_deadline) {
    if (argc <= idx) {
        return no_deadline;
    }

    Janet arg = argv[idx];

    if (janet_checktype(arg, JANET_NIL)) {
        return no_deadline;
    }

    double timeout;

    if (janet_checktype(arg, JANET_NUMBER)) {
        timeout = janet_unwrap_number(arg);
    } else if (janet_checktype(arg, JANET_TABLE) ||
               janet_checktype(arg, JANET_STRUCT)) {
        ensure_keywords_initialized();
        Janet timeout_val = janet_get(arg, kw_timeout);
        if (janet_checktype(timeout_val, JANET_NIL)) {
            return no_deadline;
        }
        if (!janet_checktype(timeout_val, JANET_NUMBER)) {
            timeout_param_error(mod);
        }
        timeout = janet_unwrap_number(timeout_val);
    } else {
        timeout_param_error(mod);
    }

    if (isnan(timeout) || timeout < 0) {
        timeout_param_error(mod);
    }

    return isinf(timeout) != 0 ? no_deadline : timeout;
}
