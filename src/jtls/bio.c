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

    jsec_socket_t fd = (jsec_socket_t)tls->transport->handle;

#if JSEC_LIBRESSL
    /* First, check if we have data in the read-ahead buffer */
    if (tls->bio_ahead.p < tls->bio_ahead.pe) {
        size_t avail = (size_t)(tls->bio_ahead.pe - tls->bio_ahead.p);
        size_t count = (size_t)len < avail ? (size_t)len : avail;
        memcpy(dst, tls->bio_ahead.p, count);
        tls->bio_ahead.p += count;
        return (int)count;
    }

    /* If request is small and we have a buffer, read ahead */
    if (tls->bio_ahead.data && (size_t)len < tls->bio_ahead.capacity) {
        /* Reset buffer pointers */
        tls->bio_ahead.p = tls->bio_ahead.data;
        tls->bio_ahead.pe = tls->bio_ahead.data;

        /* Read as much as we can into the buffer */
#ifdef JANET_WINDOWS
        int n;
        do {
            n = recv(fd, (char *)tls->bio_ahead.data,
                     (int)tls->bio_ahead.capacity, 0);
        } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#else
        ssize_t n;
        do {
            n = read(fd, tls->bio_ahead.data, tls->bio_ahead.capacity);
        } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
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
#endif

    /* Direct socket read into caller's destination buffer */
#ifdef JANET_WINDOWS
    int n;
    do {
        n = recv(fd, dst, len, 0);
    } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#else
    ssize_t n;
    do {
        n = read(fd, dst, (size_t)len);
    } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
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
 * BIO FLUSH
 *============================================================================
 * Drain the bounded write buffer to the network socket.
 *
 * Tracks head and tail offsets: on partial sends, head advances with zero
 * memmove overhead. When all bytes are transmitted (head == tail), both
 * reset to 0.
 *
 * Returns:
 *   1: All buffered data sent (or nothing buffered / unbuffered)
 *   0: Incomplete flush due to EAGAIN / EWOULDBLOCK (BIO retry flag set)
 *  -1: Socket error (errno preserved)
 */
int jtls_bio_flush(TLSStream *tls) {
    if (!tls || !tls->transport || !tls->write_buffer.data ||
        tls->write_buffer.capacity == 0) {
        return 1;
    }

    if (tls->write_buffer.head == tls->write_buffer.tail) {
        tls->write_buffer.head = 0;
        tls->write_buffer.tail = 0;
        return 1;
    }

    jsec_socket_t fd = (jsec_socket_t)tls->transport->handle;
    while (tls->write_buffer.head < tls->write_buffer.tail) {
        size_t to_send = tls->write_buffer.tail - tls->write_buffer.head;
#ifdef JANET_WINDOWS
        int n;
        do {
            n = send(fd,
                     (const char *)(tls->write_buffer.data +
                                    tls->write_buffer.head),
                     (int)to_send, 0);
        } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#else
        ssize_t n;
        do {
            n = send(fd,
                     (const char *)(tls->write_buffer.data +
                                    tls->write_buffer.head),
                     to_send, MSG_NOSIGNAL);
        } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#endif

        if (n > 0) {
            tls->write_buffer.head += (size_t)n;
            if (tls->write_buffer.head == tls->write_buffer.tail) {
                tls->write_buffer.head = 0;
                tls->write_buffer.tail = 0;
                return 1;
            }
        } else {
            if (jsec_socket_errno == JSEC_EAGAIN ||
                jsec_socket_errno == JSEC_EWOULDBLOCK) {
                if (tls->bio) {
                    BIO_set_retry_write(tls->bio);
                }
                return 0;
            }
            return -1;
        }
    }

    tls->write_buffer.head = 0;
    tls->write_buffer.tail = 0;
    return 1;
}

/*============================================================================
 * BIO WRITE CALLBACK
 *============================================================================
 * Called by OpenSSL when it needs to write encrypted data to the network.
 *
 * Coalesces records into the bounded write buffer. When the buffer fills,
 * it attempts to flush to the socket. If write buffering is disabled, or
 * if a record exceeds the entire buffer capacity, writes go directly to
 * the socket.
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

    /* Unbuffered mode and non-write operations (handshake, shutdown, close):
     * direct socket write without record coalescing */
    if (!tls->write_buffer.data || tls->write_buffer.capacity == 0 ||
        tls->write_state.op != TLS_OP_WRITE) {
        /* If write buffer still holds pending ciphertext from an earlier
         * write, drain it before writing fresh data directly to socket */
        if (tls->write_buffer.head < tls->write_buffer.tail) {
            int flush_res = jtls_bio_flush(tls);
            if (flush_res < 0) {
                return -1;
            }
            if (flush_res == 0) {
                BIO_set_retry_write(bio);
                return -1;
            }
        }

        jsec_socket_t fd = (jsec_socket_t)tls->transport->handle;
#ifdef JANET_WINDOWS
        int n;
        do {
            n = send(fd, src, len, 0);
        } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#else
        ssize_t n;
        do {
            n = send(fd, src, (size_t)len, MSG_NOSIGNAL);
        } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#endif

        if (n > 0) {
            return (int)n;
        } else {
            if (jsec_socket_errno == JSEC_EAGAIN ||
                jsec_socket_errno == JSEC_EWOULDBLOCK) {
                BIO_set_retry_write(bio);
            }
            return -1;
        }
    }

    /* Buffered mode: if record doesn't fit in remaining capacity, flush
     * pending data */
    if (tls->write_buffer.tail + (size_t)len > tls->write_buffer.capacity) {
        int flush_res = jtls_bio_flush(tls);
        if (flush_res < 0) {
            return -1;
        }
        if (flush_res == 0) {
            /* Socket blocked: cannot drain buffer to make room */
            BIO_set_retry_write(bio);
            return -1;
        }
    }

    /* If it fits in write_buffer, copy into buffer (zero memmove, coalescing
     * records) */
    if (tls->write_buffer.tail + (size_t)len <= tls->write_buffer.capacity) {
        memcpy(tls->write_buffer.data + tls->write_buffer.tail, src,
               (size_t)len);
        tls->write_buffer.tail += (size_t)len;
        return len;
    }

    /* Record alone exceeds write buffer capacity: write directly to socket */
    jsec_socket_t fd = (jsec_socket_t)tls->transport->handle;
#ifdef JANET_WINDOWS
    int n;
    do {
        n = send(fd, src, len, 0);
    } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#else
    ssize_t n;
    do {
        n = send(fd, src, (size_t)len, MSG_NOSIGNAL);
    } while (n < 0 && jsec_socket_errno == JSEC_EINTR);
#endif

    if (n > 0) {
        return (int)n;
    } else {
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
    (void)num;
    TLSStream *tls = (TLSStream *)BIO_get_data(bio);

    switch (cmd) {
        case BIO_CTRL_FLUSH:
            if (tls) {
                int res = jtls_bio_flush(tls);
                return res > 0 ? 1 : 0;
            }
            return 1;

        case BIO_CTRL_WPENDING:
            if (tls && tls->write_buffer.data) {
                return (long)(tls->write_buffer.tail -
                              tls->write_buffer.head);
            }
            return 0;

        case BIO_CTRL_PENDING:
#if JSEC_LIBRESSL
            if (tls && tls->bio_ahead.data) {
                return (long)(tls->bio_ahead.pe - tls->bio_ahead.p);
            }
#endif
            return 0;

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
