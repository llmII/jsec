/*
 * janet_types.c - Janet type conversion utilities
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"

/*
 * Convert Janet string or keyword to C string.
 * Returns NULL if the value is neither a string nor keyword.
 */
const char *janet_to_string_or_keyword(Janet value) {
    if (janet_checktype(value, JANET_STRING)) {
        return (const char *)janet_unwrap_string(value);
    } else if (janet_checktype(value, JANET_KEYWORD)) {
        return (const char *)janet_unwrap_keyword(value);
    }
    return NULL;
}
