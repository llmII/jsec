/*
 * error.c - SSL error handling utilities
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"
#include <string.h>

/*
 * Get human-readable SSL error string.
 *
 * NOTE: Returns pointer to thread-local static buffer. The returned string
 * is only valid until the next call to this function from the same thread.
 * Use immediately or copy if needed across multiple calls.
 */
const char *get_ssl_error_string(void) {
    unsigned long err = ERR_get_error();
    if (err == 0) return "No SSL error";
    static _Thread_local char buf[512];
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}
