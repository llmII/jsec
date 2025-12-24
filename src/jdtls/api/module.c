/*
 * client/module.c - DTLS client module registration
 *
 * Includes all client components and registers with Janet.
 * Note: Implementation files are compiled separately via project.janet.
 */

#include "../internal.h"

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

static const JanetReg client_cfuns[] = {
    {"connect", cfun_dtls_connect,
     "(dtls/connect host port &opt opts)\n\n"
     "Create a DTLS client connection to the specified host and port.\n"
     "Returns a DTLS client object after handshake completes.\n\n"
     "Options:\n"
     "  :cert - Client certificate for mutual TLS\n"
     "  :key - Client private key\n"
     "  :verify - Verify server certificate (default true)\n"
     "  :ca - CA certificate path\n"
     "  :sni - Server name for SNI (defaults to host)\n"
     "  :session - Session data for resumption\n"
     "  :trusted-cert - Trust specific certificate (for self-signed)"},
    {"upgrade", cfun_dtls_upgrade,
     "(dtls/upgrade transport &opt opts)\n\n"
     "Upgrade an existing connected UDP socket to DTLS.\n"
     "The transport must be a connected UDP socket (from net/connect "
     ":datagram).\n\n"
     "Options:\n"
     "  :cert - Certificate for mutual TLS\n"
     "  :key - Private key\n"
     "  :verify - Verify peer certificate (default true)\n"
     "  :ca - CA certificate path\n"
     "  :sni - Server name for SNI\n"
     "  :session - Session data for resumption\n"
     "  :server - Act as server (default: client)\n"
     "  :trusted-cert - Trust specific certificate"},
    {"read", cfun_dtls_read,
     "(dtls/read client n &opt buf timeout)\n\n"
     "Read up to n bytes from DTLS client.\n"
     "Returns a buffer with the received datagram, or nil on EOF."},
    {"chunk", cfun_dtls_chunk,
     "(dtls/chunk client n &opt buf timeout)\n\n"
     "Read exactly n bytes from DTLS client.\n"
     "Unlike read, will not return early if less than n bytes are "
     "available.\n"
     "Returns buffer with exactly n bytes, or what's available on EOF.\n"
     "Note: For datagrams, each read returns a complete datagram."},
    {"write", cfun_dtls_write,
     "(dtls/write client data &opt timeout)\n\n"
     "Write data to DTLS client.\n"
     "Returns number of bytes written."},
    {"close", cfun_dtls_close,
     "(dtls/close client &opt force)\n\n"
     "Close DTLS client connection.\n"
     "Sends close_notify alert per RFC unless force is true.\n"
     "Async - waits for peer's close_notify response."},
    {"shutdown", cfun_dtls_shutdown,
     "(dtls/shutdown client &opt mode)\n\n"
     "Perform DTLS shutdown without closing the underlying socket.\n"
     "Useful for transitioning back to raw UDP.\n"
     "Mode can be :rd, :wr, or :rdwr (default)."},
    {"version", cfun_dtls_get_version,
     "(:version client)\n\n"
     "Get the DTLS protocol version string (e.g., \"DTLSv1.2\")."},
    {"cipher", cfun_dtls_get_cipher,
     "(:cipher client)\n\n"
     "Get the cipher suite name."},
    {"cipher-bits", cfun_dtls_get_cipher_bits,
     "(:cipher-bits client)\n\n"
     "Get the cipher strength in bits."},
    {"connection-info", cfun_dtls_get_connection_info,
     "(:connection-info client)\n\n"
     "Get all connection info as a struct with keys:\n"
     "  :version - Protocol version string\n"
     "  :cipher - Cipher suite name\n"
     "  :cipher-bits - Cipher strength in bits\n"
     "  :alpn - Negotiated ALPN protocol or nil"},
    {"session-reused?", cfun_dtls_session_reused,
     "(:session-reused? client)\n\n"
     "Check if the session was reused from a previous connection."},
    {"session", cfun_dtls_get_session,
     "(:session client)\n\n"
     "Get the session data for resumption.\n"
     "Returns a buffer containing the serialized session, or nil if not "
     "available."},
    {"set-session", cfun_dtls_set_session,
     "(dtls/set-session client session-data)\n\n"
     "Set session data for resumption.\n"
     "The session-data should be a buffer from a previous dtls/get-session "
     "call.\n"
     "Returns true if session was set successfully, false otherwise."},
    {"trust-cert", cfun_dtls_trust_cert,
     "(dtls/trust-cert client cert-pem)\n\n"
     "Trust a specific certificate for this connection.\n"
     "Useful for self-signed certificates or certificate pinning.\n"
     "The cert-pem should be a string/buffer containing PEM-encoded "
     "certificate."},
    {"localname", cfun_dtls_localname,
     "(dtls/localname client)\n\n"
     "Get the local address as a DTLSAddress."},
    {"peername", cfun_dtls_peername,
     "(dtls/peername client)\n\n"
     "Get the peer's address as a DTLSAddress."},
    {NULL, NULL, NULL}};

void jdtls_register_client(JanetTable *env) {
    janet_register_abstract_type(&dtls_client_type);
    janet_cfuns(env, "jsec/dtls", client_cfuns);
}
