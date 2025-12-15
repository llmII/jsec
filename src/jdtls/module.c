/*
 * module.c - DTLS module entry point
 *
 * Registers all DTLS types and functions for the jsec/dtls module.
 *
 * Module API:
 * ===========
 * Context (reusable SSL_CTX):
 *   dtls/new-context - Create reusable context with settings
 *
 * Server-side (UDP-style):
 *   dtls/listen      - Create DTLS server
 *   dtls/recv-from   - Receive from any peer [data addr]
 *   dtls/send-to     - Send to specific peer
 *   dtls/close-server - Close server
 *   dtls/localname   - Get server's bound address
 *
 * Client-side (1:1 connection):
 *   dtls/connect     - Create DTLS client
 *   dtls/read        - Read from client
 *   dtls/write       - Write to client
 *   dtls/close       - Close client
 *
 * Address utilities:
 *   dtls/address     - Create address from host/port
 *   dtls/address-host - Get host from address
 *   dtls/address-port - Get port from address
 *   dtls/address?    - Check if value is address
 */

#include "internal.h"

JANET_MODULE_ENTRY(JanetTable *env) {
    /* Register all components */
    jdtls_register_address(env);
    jdtls_register_context(env);
    jdtls_register_client(env);
    jdtls_register_server(env);
}
