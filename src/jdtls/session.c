/*
 * session.c - DTLS session management
 *
 * Manages per-peer sessions for the DTLS server.
 * Sessions are stored in a hash table keyed by peer address.
 */

#include "internal.h"
#include <string.h>

/*
 * =============================================================================
 * Session Hash Table Helpers
 * =============================================================================
 */

/* Get hash bucket index for an address */
static inline int session_bucket(const DTLSAddress *addr) {
    int32_t h = dtls_address_hash_fn(addr);
    /* Ensure positive index */
    return (int)((uint32_t)h % DTLS_SESSION_TABLE_SIZE);
}

/*
 * =============================================================================
 * Session Lifecycle
 * =============================================================================
 */

/*
 * Create a new DTLS session for a peer.
 * Uses memory BIOs so we control when data goes to/from the network.
 */
DTLSSession *dtls_session_new(SSL_CTX *ctx, const DTLSAddress *peer) {
    DTLSSession *session = janet_malloc(sizeof(DTLSSession));
    if (!session) return NULL;

    memset(session, 0, sizeof(DTLSSession));
    memcpy(&session->peer_addr, peer, sizeof(DTLSAddress));

    /* Create SSL object */
    session->ssl = SSL_new(ctx);
    if (!session->ssl) {
        janet_free(session);
        return NULL;
    }

    /* Create memory BIOs for decoupled I/O
     * - rbio: We write received network data here, SSL reads from it
     * - wbio: SSL writes encrypted data here, we read and send to network
     */
    session->rbio = BIO_new(BIO_s_mem());
    session->wbio = BIO_new(BIO_s_mem());
    if (!session->rbio || !session->wbio) {
        if (session->rbio) BIO_free(session->rbio);
        if (session->wbio) BIO_free(session->wbio);
        SSL_free(session->ssl);
        janet_free(session);
        return NULL;
    }

    /* Set non-blocking mode on BIOs */
    BIO_set_nbio(session->rbio, 1);
    BIO_set_nbio(session->wbio, 1);

    /* Attach BIOs to SSL - SSL takes ownership */
    SSL_set_bio(session->ssl, session->rbio, session->wbio);

    /* Set server mode */
    SSL_set_accept_state(session->ssl);

    session->state = DTLS_STATE_IDLE;
    session->last_activity = get_current_time();
    session->cookie_verified = 0;
    session->next = NULL;

    return session;
}

/*
 * Free a DTLS session.
 * SSL_free also frees the BIOs since they're attached.
 */
void dtls_session_free(DTLSSession *session) {
    if (!session) return;

    if (session->ssl) {
        /* SSL_free frees the attached BIOs too */
        SSL_free(session->ssl);
    }

    janet_free(session);
}

/*
 * =============================================================================
 * Server Session Table Operations
 * =============================================================================
 */

/*
 * Look up a session by peer address.
 * Returns NULL if not found.
 */
DTLSSession *dtls_server_get_session(DTLSServer *server,
                                     const DTLSAddress *addr) {
    int bucket = session_bucket(addr);
    DTLSSession *session = server->sessions[bucket];

    while (session) {
        if (dtls_address_equal(&session->peer_addr, addr)) {
            return session;
        }
        session = session->next;
    }

    return NULL;
}

/*
 * Create a new session and add to server's table.
 * Returns the new session or NULL on failure.
 */
DTLSSession *dtls_server_create_session(DTLSServer *server,
                                        const DTLSAddress *addr) {
    /* Check if session already exists */
    DTLSSession *existing = dtls_server_get_session(server, addr);
    if (existing) {
        existing->last_activity = get_current_time();
        return existing;
    }

    /* Create new session */
    DTLSSession *session = dtls_session_new(server->ctx, addr);
    if (!session) return NULL;

    /* Add to hash table (prepend to bucket) */
    int bucket = session_bucket(addr);
    session->next = server->sessions[bucket];
    server->sessions[bucket] = session;
    server->session_count++;

    return session;
}

/*
 * Remove a session from server's table and free it.
 */
void dtls_server_remove_session(DTLSServer *server, const DTLSAddress *addr) {
    int bucket = session_bucket(addr);
    DTLSSession **pp = &server->sessions[bucket];

    while (*pp) {
        DTLSSession *session = *pp;
        if (dtls_address_equal(&session->peer_addr, addr)) {
            *pp = session->next;
            dtls_session_free(session);
            server->session_count--;
            return;
        }
        pp = &session->next;
    }
}

/*
 * Remove all expired sessions.
 * Called periodically to clean up idle connections.
 */
void dtls_server_cleanup_expired(DTLSServer *server, double now) {
    for (int i = 0; i < DTLS_SESSION_TABLE_SIZE; i++) {
        DTLSSession **pp = &server->sessions[i];

        while (*pp) {
            DTLSSession *session = *pp;
            double age = now - session->last_activity;

            if (age > server->session_timeout) {
                /* Remove expired session */
                *pp = session->next;
                dtls_session_free(session);
                server->session_count--;
            } else {
                pp = &session->next;
            }
        }
    }
}
