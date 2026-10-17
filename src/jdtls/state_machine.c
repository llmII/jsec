/*
 * state_machine.c - DTLS async I/O state machine
 *
 * This module implements the async I/O state machine for DTLS.
 * It integrates with Janet's event loop via janet_async_start.
 *
 * DTLS State Machine Flow
 * =======================
 *
 * Unlike TLS which uses a stream socket, DTLS uses datagrams.
 * The state machine handles:
 * 1. Handshake (with retransmission timeouts)
 * 2. Data read/write
 * 3. Shutdown
 *
 * Memory BIO Architecture
 * =======================
 * For the server, we use memory BIOs to decouple SSL from the socket:
 *
 *   Network        rbio (mem)        SSL        wbio (mem)        Network
 *   recvfrom() --> BIO_write() --> SSL_read()
 *                                  SSL_write() --> BIO_read() --> sendto()
 *
 * This allows us to:
 * 1. Demultiplex packets by peer address
 * 2. Route data to correct session
 * 3. Handle timeouts and retransmissions
 *
 * For the client with a connected socket, we can use a dgram BIO directly.
 *
 * Timeout Handling
 * ================
 * DTLS has built-in retransmission: DTLSv1_get_timeout() returns time
 * until next retransmission, DTLSv1_handle_timeout() triggers it. DTLS
 * flight retransmission is driven by a per-handshake DTLSFlightTimer:
 * while a handshake is pending on WANT_READ, the arm schedules a
 * helper fiber on the same event-loop thread (janet_vm.tq) for the
 * exact interval DTLSv1_get_timeout returns. The wake step calls
 * DTLSv1_handle_timeout, flushes the retransmitted flight in wbio
 * when one goes out, re-arms while OpenSSL still schedules a
 * retransmission, and retires otherwise. Arms live on DTLSClient and
 * DTLSSession and are disarmed before the owner is freed; a
 * GC-finalizer disarm only marks the arm canceled and clears the
 * slot, and the wake step retires the arm when it next runs, so
 * teardown never dereferences the helper fiber after the sweep frees
 * it.
 */

#include "internal.h"
#include <errno.h>
#ifndef JANET_WINDOWS
#include <sys/time.h>
#endif

/*
 * =============================================================================
 * SSL Result Translation
 * =============================================================================
 */

DTLSResult dtls_ssl_result(SSL *ssl, int ret) {
    if (ret > 0) {
        return DTLS_RESULT_OK;
    }

    int err = SSL_get_error(ssl, ret);
    switch (err) {
        case SSL_ERROR_NONE:
            return DTLS_RESULT_OK;

        case SSL_ERROR_WANT_READ:
            return DTLS_RESULT_WANT_READ;

        case SSL_ERROR_WANT_WRITE:
            return DTLS_RESULT_WANT_WRITE;

        case SSL_ERROR_ZERO_RETURN:
            /* Peer sent close_notify: the one clean close */
            return DTLS_RESULT_EOF;

        case SSL_ERROR_SYSCALL:
            if (ret == 0 || errno == 0) {
                /* EOF without close_notify: the 1.1.1/LibreSSL surface
                 * of a truncation. Not a clean end of data. */
                return DTLS_RESULT_UNEXPECTED_EOF;
            }
            /* Fall through to error */
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((fallthrough));
#endif

        case SSL_ERROR_SSL:
        default:
            if (jutils_is_unexpected_eof()) {
                /* OpenSSL 3.x surface of the same truncation:
                 * SSL_ERROR_SSL with SSL_R_UNEXPECTED_EOF_WHILE_READING */
                return DTLS_RESULT_UNEXPECTED_EOF;
            }
            return DTLS_RESULT_ERROR;
    }
}

/*
 * =============================================================================
 * Basic SSL Operations
 * =============================================================================
 */

DTLSResult dtls_do_handshake(SSL *ssl) {
    ERR_clear_error();
    int ret = SSL_do_handshake(ssl);
    if (ret == 1) {
        return DTLS_RESULT_OK;
    }
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_write(SSL *ssl, const uint8_t *buf, int32_t len,
                         int32_t *out_len) {
    ERR_clear_error();
    int ret = SSL_write(ssl, buf, len);
    if (ret > 0) {
        *out_len = ret;
        return DTLS_RESULT_OK;
    }
    *out_len = 0;
    return dtls_ssl_result(ssl, ret);
}

DTLSResult dtls_do_shutdown(SSL *ssl) {
    ERR_clear_error();
    int ret = SSL_shutdown(ssl);
    if (ret == 1) {
        /* Bidirectional shutdown complete */
        return DTLS_RESULT_OK;
    }
    if (ret == 0) {
        /* Sent close_notify, waiting for peer's */
        return DTLS_RESULT_WANT_READ;
    }
    return dtls_ssl_result(ssl, ret);
}


/*
 * =============================================================================
 * DTLS Flight Timer (Handshake Retransmission)
 * =============================================================================
 * The Timeout Handling note at the top of this file describes the
 * integration with DTLSv1_get_timeout() and DTLSv1_handle_timeout():
 * while a DTLS handshake is pending on SSL_ERROR_WANT_READ, query the
 * flight timer and, when it fires before a peer datagram arrives, drive
 * the retransmission and flush the flight in wbio to the UDP socket.
 *
 * Each arm runs a helper fiber on the same event-loop thread, sleeping
 * out the exact flight interval as one timeout on the event loop's
 * min-heap - no worker thread and no sleep-polling. The fiber boot
 * body is a Janet source function compiled once at module load and
 * rooted in module-level state: two calls of one step function - the
 * first step suspends on janet_sleep_await, the resume continues in
 * the body and the second step drives the retransmission tick.
 * Disarming wakes the fiber with a zero-duration schedule so it
 * retires the arm immediately; a GC
 * finalizer cannot schedule and may run after the teardown sweep has
 * freed the fiber, so that path only marks the arm canceled and lets
 * the wake step retire it. A canceled arm is released without touching
 * owner state. Retransmission ticks never touch the parked caller
 * fiber, so the caller's overall handshake deadline stays
 * janet_addtimeout's domain and keeps failing the call with "timeout"
 * exactly as before.
 */

#define JDTLS_TIMER_WAKE_PHASE (1u << 0)
#define JDTLS_TIMER_CANCELED (1u << 1)

struct DTLSFlightTimer {
    SSL *ssl;
    void *owner;
    JanetStream *transport;
    DTLSFlightFlushFn flush;
    DTLSFlightTimer **slot; /* owner's arm pointer; NULLed on retire */
    JanetFiber *fiber;      /* two-step helper fiber, one per arm */
    double seconds;         /* flight interval the fiber sleeps out */
    uint8_t flags;          /* Bitmask of JDTLS_TIMER_* */
};

/* Janet core marks a fiber parked on the event loop with
 * JANET_FIBER_EV_FLAG_SUSPENDED (core fiber.h, bit 17), paired with one
 * janet_ev_inc_refcount that the resume path releases. */
#define DTLS_FIBER_EV_SUSPENDED (1 << 17)

/* Pre-marking the helper fiber with JANET_FIBER_FLAG_ROOT (core
 * fiber.h, bit 18) keeps janet_schedule_general from inserting a row
 * in the scheduler task tracking table for this internal fiber. */
#define DTLS_FIBER_EV_ROOT (1 << 18)

/* Helper fiber boot body: (fn [arm step] (step arm) (step arm) nil).
 * The step function is passed in as an argument; the trailing nil
 * keeps both step calls out of tail position, so the body is exactly
 * call, call, return around the sleep: the first call is the sleep
 * step (janet_sleep_await suspends the fiber inside the step call and
 * the resume continues in the body), the second call is the wake
 * step. Compiled once at module load below and rooted in module-level
 * state so the GC can never collect it while arms exist; compiling a
 * Janet source helper instead of hand-packed boot bytecode keeps the
 * body independent of the bytecode format, which a hand-packed body
 * would break against silently the day that format changes. */
#define DTLS_FLIGHT_TIMER_BODY_SOURCE \
    "(fn [arm step] (step arm) (step arm) nil)"

static Janet dtls_flight_timer_step(int32_t argc, Janet *argv);

static JanetFunction *dtls_flight_timer_body = NULL;

void jdtls_flight_timer_init(JanetTable *env) {
    Janet out;
    if (dtls_flight_timer_body) {
        return; /* compiled exactly once; re-entry is a no-op */
    }
    if (janet_dostring(env, DTLS_FLIGHT_TIMER_BODY_SOURCE,
                       "jdtls-flight-timer-body", &out) ||
            !janet_checktype(out, JANET_FUNCTION)) {
        janet_panic("could not compile DTLS flight timer helper body");
    }
    dtls_flight_timer_body = janet_unwrap_function(out);
    janet_gcroot(out);
}

/* Unroot what the arm kept alive and free it. The owner's slot is
 * already clear, so the arm is unreachable from its owner here. */
static void dtls_flight_timer_release(DTLSFlightTimer *arm) {
    janet_gcunroot(janet_wrap_fiber(arm->fiber));
    janet_gcunroot(janet_wrap_abstract(arm->transport));
    janet_free(arm);
}

/* Retire an arm whose helper fiber must never run again: bumping
 * sched_id makes janet_loop1 drop the stale timeout entry and skip a
 * queued resume without waking the fiber, and clearing the suspended
 * flag releases the event-loop refcount the park took. */
static void dtls_flight_timer_retire_in_place(DTLSFlightTimer *arm) {
    JanetFiber *fiber = arm->fiber;
    fiber->sched_id++;
    if (fiber->gc.flags & DTLS_FIBER_EV_SUSPENDED) {
        fiber->gc.flags &= ~DTLS_FIBER_EV_SUSPENDED;
        janet_ev_dec_refcount();
    }
    dtls_flight_timer_release(arm);
}

/* One step of the helper fiber body. The first step sleeps out the
 * flight interval (janet_sleep_await suspends the fiber and never
 * returns here - the resume continues in the body); the second step
 * runs the retransmission tick and retires the arm. When the arm is
 * canceled the tick is skipped entirely - the retire path touches
 * only the arm's own fiber and transport roots, never owner state. */
static Janet dtls_flight_timer_step(int32_t argc, Janet *argv) {
    DTLSFlightTimer *arm;
    janet_fixarity(argc, 1);
    arm = (DTLSFlightTimer *)janet_getpointer(argv, 0);
    if (!(arm->flags & JDTLS_TIMER_WAKE_PHASE)) {
        arm->flags |= JDTLS_TIMER_WAKE_PHASE;
        if (!(arm->flags & JDTLS_TIMER_CANCELED)) {
            janet_sleep_await(arm->seconds);
        }
        return janet_wrap_nil();
    }
    if (!(arm->flags & JDTLS_TIMER_CANCELED) && *arm->slot == arm) {
        struct timeval tv;
        int rc;
        /* Detach first: teardown during the tick must not reach the
         * arm while it is driving the retransmission. */
        *arm->slot = NULL;
        rc = DTLSv1_handle_timeout(arm->ssl);
        if (rc > 0 && arm->flush) {
            arm->flush(arm->owner, arm->transport);
        }
        /* Re-arm while OpenSSL still schedules a retransmission. */
        if (DTLSv1_get_timeout(arm->ssl, &tv) == 1) {
            double seconds =
                (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
            /* A zero remaining interval means handle_timeout did not
             * reset the flight timer; retire instead of spinning on it. */
            if (seconds > 0.0) {
                dtls_flight_timer_arm(arm->slot, arm->ssl, arm->owner,
                                      arm->transport, arm->flush);
            }
        }
    }
    dtls_flight_timer_release(arm);
    return janet_wrap_nil();
}

void dtls_flight_timer_arm(DTLSFlightTimer **slot, SSL *ssl, void *owner,
                           JanetStream *transport, DTLSFlightFlushFn flush) {
    DTLSFlightTimer *arm;
    JanetFiber *fiber;
    Janet fiber_args[2];
    struct timeval tv;
    /* Only a handshake with a retransmission scheduled needs a timer. */
    if (DTLSv1_get_timeout(ssl, &tv) != 1) {
        dtls_flight_timer_disarm(slot, 0);
        return;
    }
    dtls_flight_timer_disarm(slot, 0);
    arm = (DTLSFlightTimer *)janet_malloc(sizeof(DTLSFlightTimer));
    if (!arm) {
        return; /* OOM: handshake continues without retransmission */
    }
    arm->ssl = ssl;
    arm->owner = owner;
    arm->transport = transport;
    arm->flush = flush;
    arm->slot = slot;
    arm->seconds = (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    arm->flags = 0;
    if (!dtls_flight_timer_body) {
        /* Helper body missing (module init never compiled it): keep the
         * handshake running without retransmission, like the OOM case. */
        janet_free(arm);
        return;
    }
    fiber_args[0] = janet_wrap_pointer(arm);
    fiber_args[1] = janet_wrap_cfunction(dtls_flight_timer_step);
    fiber = janet_fiber(dtls_flight_timer_body, 16, 2, fiber_args);
    if (!fiber) {
        janet_free(arm);
        return;
    }
    arm->fiber = fiber;
    janet_gcroot(janet_wrap_fiber(fiber));
    janet_gcroot(janet_wrap_abstract(transport));
    *slot = arm;
    /* Mark the helper fiber as a task fiber before the first
     * schedule: janet_schedule_general only records fibers that are
     * not yet JANET_FIBER_FLAG_ROOT (core fiber flag bit 18), so the
     * scheduler task table never gets a row for this internal fiber
     * and a later in-place cancel cannot leave a stale row behind. */
    fiber->gc.flags |= DTLS_FIBER_EV_ROOT;
    janet_schedule(fiber, janet_wrap_nil());
}

void dtls_flight_timer_disarm(DTLSFlightTimer **slot, int in_gc) {
    DTLSFlightTimer *arm = *slot;
    JanetFiber *fiber;
    if (!arm) {
        return;
    }
    *slot = NULL;
    arm->flags |= JDTLS_TIMER_CANCELED;
    if (in_gc) {
        /* A GC finalizer runs during a sweep, where even janet_schedule
         * is unsafe (it may grow the scheduler spawn queue), and at
         * process teardown the sweep has already freed the helper
         * fiber's GC block. Never touch the fiber here: only mark the
         * arm canceled and clear the slot. The wake step retires the
         * arm at its next run - the arm's gcroot keeps the fiber alive
         * through a normal sweep, and a parked fiber's timeout keeps
         * the event loop running until the wake fires. At real teardown
         * the wake never runs and the arm goes away with the process. */
        return;
    }
    fiber = arm->fiber;
    if (janet_fiber_status(fiber) == JANET_STATUS_ALIVE) {
        /* Mid-tick: the running wake step retires the arm. */
        return;
    }
    if (!janet_fiber_can_resume(fiber)) {
        /* A fiber that cannot resume would never notice a wake: retire
         * in place instead. */
        dtls_flight_timer_retire_in_place(arm);
        return;
    }
    /* Zero-duration wake: the helper fiber retires the arm at once. */
    janet_schedule(fiber, janet_wrap_nil());
}
