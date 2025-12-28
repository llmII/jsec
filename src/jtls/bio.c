/*
 * bio.c - Custom BIO implementation for Janet sockets
 *
 * This provides a custom OpenSSL BIO (Basic I/O) that reads/writes directly
 * to Janet sockets. This avoids the overhead of memory BIO pairs and allows
 * OpenSSL to perform I/O without intermediate buffer copies.
 *
 * How it works:
 * 1. OpenSSL calls our BIO read/write functions when it needs socket I/O
 * 2. We directly call read()/send() on the socket file descriptor
 * 3. If the socket would block (EAGAIN), we set BIO retry flags
 * 4. OpenSSL returns SSL_ERROR_WANT_READ/WANT_WRITE to the caller
 * 5. The caller registers with Janet's event loop and retries later
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"

/*============================================================================
 * BIO READ-AHEAD BUFFER SIZE
 *============================================================================
 * Size of the read-ahead buffer. This should be at least as large as a TLS
 * record (16KB) to allow buffering a full record in one syscall.
 */
#define BIO_AHEAD_SIZE 32768

/*============================================================================
 * BIO READ CALLBACK
 *============================================================================
 * Called by OpenSSL when it needs to read encrypted data from the network.
 *
 * This implementation uses a read-ahead buffer to reduce syscalls:
 * 1. First, serve data from the ahead buffer if available
 * 2. If ahead buffer is empty, read a larger chunk into it
 * 3. Return as much data as requested from the buffer
 *
 * Returns:
 *   > 0: Number of bytes read
 *   0:   EOF (connection closed by peer)
 *   -1:  Error (check BIO_should_retry for EAGAIN)
 */
static int jtls_bio_read(BIO *bio, char *dst, int len) {
    TLSStream *tls = (TLSStream *)BIO_get_data(bio);

    if (!tls || !tls->transport || len <= 0) {
        BIO_clear_retry_flags(bio);
        return -1;
    }

    BIO_clear_retry_flags(bio);

    /* First, check if we have data in the read-ahead buffer */
    if (tls->bio_ahead.p < tls->bio_ahead.pe) {
        size_t avail = (size_t)(tls->bio_ahead.pe - tls->bio_ahead.p);
        size_t count = (size_t)len < avail ? (size_t)len : avail;
        memcpy(dst, tls->bio_ahead.p, count);
        tls->bio_ahead.p += count;
        return (int)count;
    }

    /* Ahead buffer is empty - read from socket */
    jsec_socket_t fd = (jsec_socket_t)tls->transport->handle;

    /* If request is small and we have a buffer, read ahead */
    if (tls->bio_ahead.data && (size_t)len < tls->bio_ahead.capacity) {
        /* Reset buffer pointers */
        tls->bio_ahead.p = tls->bio_ahead.data;
        tls->bio_ahead.pe = tls->bio_ahead.data;

        /* Read as much as we can into the buffer */
#ifdef JANET_WINDOWS
        int n = recv(fd, (char *)tls->bio_ahead.data,
                     (int)tls->bio_ahead.capacity, 0);
#else
        ssize_t n = read(fd, tls->bio_ahead.data, tls->bio_ahead.capacity);
#endif

        if (n > 0) {
            tls->bio_ahead.pe = tls->bio_ahead.data + n;
            /* Return requested amount from buffer */
            size_t count = (size_t)len < (size_t)n ? (size_t)len : (size_t)n;
            memcpy(dst, tls->bio_ahead.p, count);
            tls->bio_ahead.p += count;
            return (int)count;
        } else if (n == 0) {
            return 0; /* EOF */
        } else {
            if (jsec_socket_errno == JSEC_EAGAIN ||
                jsec_socket_errno == JSEC_EWOULDBLOCK) {
                BIO_set_retry_read(bio);
            }
            return -1;
        }
    }

    /* No buffer or large request - read directly */
#ifdef JANET_WINDOWS
    int n = recv(fd, dst, len, 0);
#else
    ssize_t n = read(fd, dst, (size_t)len);
#endif

    if (n > 0) {
        return (int)n;
    } else if (n == 0) {
        /* EOF - peer closed connection */
        return 0;
    } else {
        /* Error - check if it's a retryable error */
        if (jsec_socket_errno == JSEC_EAGAIN ||
            jsec_socket_errno == JSEC_EWOULDBLOCK) {
            BIO_set_retry_read(bio);
        }
        return -1;
    }
}

/*============================================================================
 * BIO WRITE CALLBACK
 *============================================================================
 * Called by OpenSSL when it needs to write encrypted data to the network.
 *
 * Returns:
 *   > 0: Number of bytes written
 *   -1:  Error (check BIO_should_retry for EAGAIN)
 */
static int jtls_bio_write(BIO *bio, const char *src, int len) {
    TLSStream *tls = (TLSStream *)BIO_get_data(bio);

    if (!tls || !tls->transport || len <= 0) {
        BIO_clear_retry_flags(bio);
        return -1;
    }

    BIO_clear_retry_flags(bio);

    jsec_socket_t fd = (jsec_socket_t)tls->transport->handle;
    ssize_t n = send(fd, src, len, MSG_NOSIGNAL);

    if (n > 0) {
        return (int)n;
    } else {
        /* Error - check if it's a retryable error */
        if (jsec_socket_errno == JSEC_EAGAIN ||
            jsec_socket_errno == JSEC_EWOULDBLOCK) {
            BIO_set_retry_write(bio);
        }
        return -1;
    }
}

/*============================================================================
 * BIO PUTS CALLBACK
 *============================================================================
 * Convenience function - just calls bio_write with strlen.
 */
static int jtls_bio_puts(BIO *bio, const char *src) {
    return jtls_bio_write(bio, src, (int)strlen(src));
}

/*============================================================================
 * BIO CONTROL CALLBACK
 *============================================================================
 * Handle BIO control operations. Most are no-ops for socket BIOs.
 */
static long jtls_bio_ctrl(BIO *bio, int cmd, long num, void *ptr) {
    (void)bio;
    (void)num;

    switch (cmd) {
        case BIO_CTRL_FLUSH:
            /* No buffering, so flush is a no-op */
            return 1;

        case BIO_CTRL_DUP:
            /* Allow duplication but don't copy state */
            if (ptr) {
                BIO *new_bio = (BIO *)ptr;
                BIO_set_init(new_bio, 0);
                BIO_set_data(new_bio, NULL);
            }
            return 1;

        default:
            /* Unrecognized command */
            return 0;
    }
}

/*============================================================================
 * BIO CREATE/DESTROY CALLBACKS
 *============================================================================
 * Called when BIO is created or destroyed.
 */
static int jtls_bio_create(BIO *bio) {
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
    return 1;
}

static int jtls_bio_destroy(BIO *bio) {
    if (!bio) return 0;
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    return 1;
}

/*============================================================================
 * GET BIO METHOD
 *============================================================================
 * Returns the singleton BIO_METHOD for Janet socket BIOs.
 *
 * Thread safety: The BIO method must be initialized by calling
 * jtls_init_bio_method() once at module init (before any threads).
 * After initialization, this function is safe to call from any thread.
 *
 * Lifecycle: This BIO_METHOD is intentionally never freed. It is a singleton
 * that persists for the lifetime of the process. This is acceptable because:
 * 1. Only one instance is ever created per process
 * 2. Janet modules don't have a clean unload mechanism
 * 3. The OS will reclaim all memory on process exit
 */
static BIO_METHOD *bio_method = NULL;

void jtls_init_bio_method(void) {
    if (bio_method != NULL) {
        return; /* Already initialized */
    }

    int type = BIO_get_new_index();
    if (type == -1) {
        tls_panic_ssl("failed to get BIO index");
    }

    BIO_METHOD *m = BIO_meth_new(type | BIO_TYPE_SOURCE_SINK, "janet-socket");
    if (m == NULL) {
        tls_panic_ssl("failed to create BIO method");
    }

    BIO_meth_set_write(m, jtls_bio_write);
    BIO_meth_set_read(m, jtls_bio_read);
    BIO_meth_set_puts(m, jtls_bio_puts);
    BIO_meth_set_ctrl(m, jtls_bio_ctrl);
    BIO_meth_set_create(m, jtls_bio_create);
    BIO_meth_set_destroy(m, jtls_bio_destroy);

    bio_method = m;
}

BIO_METHOD *jtls_get_bio_method(void) {
    return bio_method;
}
