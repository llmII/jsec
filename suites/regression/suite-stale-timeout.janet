# Stale timeout regression test
# Ticket 12ec930dcd959cff9f8fb9bf71d800fc991c4e0e
#
# "Stale timeout after synchronous completion cancels a later wait"
#
# jtls/api/io.c arms janet_addtimeout(timeout) BEFORE calling
# jtls_attempt_io(). When the operation completes synchronously (data
# already available - the TLS_IO_COMPLETE path returns 1 without ever
# calling janet_async_start), the fiber's sched_id is not advanced
# (ev.c:534 only advances it in janet_schedule_general), so the armed
# timeout stays live. When it later fires it runs
# janet_cancel(fiber, "timeout") (ev.c:1551-1553) and wrongly aborts an
# unrelated later suspension in the same fiber.
#
# This test demonstrates:
#   (a) a timed TLS read completes synchronously when data is already
#       pending (returns its bytes in far less than the armed timeout),
#   (b) the still-armed timeout then wrongly cancels a later, unrelated
#       wait (a plain ev/sleep) in the same fiber,
#   (c) the failure is exactly the predicted "timeout" error - ev/sleep
#       never arms an error timeout of its own (janet_sleep_await sets
#       is_error = 0), so "timeout" here can only be the stale timer
#       left behind by the synchronous read.
#
# Under fixed code the whole test passes: the sleep runs to completion
# and the server still receives the delayed "world" write.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# Generate certs at suite load time (shared by tests in this module)
(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "Stale Timeout Regression"
  :description "Ticket 12ec930d: stale timeout after synchronous completion cancels a later wait"

  (def-test "stale timeout after synchronous completion cancels a later wait"
    :timeout 15

    (let [[server socket-path] (make-server :tcp)
          addr (get-server-addr server :tcp socket-path)
          ready (ev/chan 1)]

      (defer (do (:close server) (cleanup-socket socket-path))

        # Client fiber: complete the TLS handshake eagerly (tls/wrap),
        # queue "hello", let it reach the server's socket, then send
        # "world" only after the stale deadline has already fired.
        #
        # Terminology, used throughout this file:
        #   "stale timer" - the 0.1s deadline that janet_addtimeout()
        #     arms in cfun_read (jtls/api/io.c:125) BEFORE jtls_attempt_io()
        #     is called. Under the defect that deadline is never disarmed,
        #     because the read completes synchronously and so the fiber's
        #     sched_id is never advanced (only janet_schedule_general does
        #     that, ev.c:534). It stays live and can fire at any later
        #     suspension point in this same fiber.
        #   "stale timer window" - the interval during which that deadline
        #     is pending, i.e. from the moment the server's timed read
        #     returns until the 0.1s deadline elapses. Inside the window
        #     the fiber is holding a deadline it should not have, and any
        #     suspension is at risk of being cancelled by it.
        #
        # The client withholds "world" for 0.6s - comfortably past that
        # 0.1s window - so the outcome is unambiguous either way:
        #   - defective: the stale timer fires inside the window and
        #     cancels the server fiber before "world" is sent at all;
        #   - fixed:     no deadline survives, the server's ev/sleep runs
        #     to completion, and "world" arrives during the second read.
        (ev/go (fn []
                 (try
                   (with [conn (make-client-conn :tcp addr)]
                     (with [c (tls/wrap conn {:verify false})]
                       (:write c "hello")
                       (ev/sleep 0.2)
                       (ev/give ready true)
                       (ev/sleep 0.6)
                       (:write c "world")))
                   ([err] (ev/give ready (string "client error: " err))))))

        (with [conn (:accept server)]
          (with [s (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]

            # Block until "hello" is sitting in the server's socket buffer.
            (def ready-val (ev/take ready))
            (assert (= true ready-val)
                    (string/format "client setup failed: %v" ready-val))

            # (a) Timed read with data already available: must complete
            # synchronously - it returns the pending bytes in far less than
            # the 0.1s timeout it just armed. The elapsed assertion is what
            # makes the proof airtight: a timeout was armed for an operation
            # that never suspended.
            (def t0 (os/clock))
            (def r1 (:read s 5 nil 0.1))
            (def dt0 (- (os/clock) t0))
            (assert r1 "first read should return data")
            (assert (= "hello" (string r1))
                    "first read should return the pending hello bytes")
            (assert (< dt0 0.1)
                    (string/format
                      "first read must complete synchronously before its 0.1s timeout (took %.4fs)"
                      dt0))

            # (b)(c) A later, unrelated suspension in the SAME fiber. The
            # stale 0.1s timeout from the read above is still armed (same
            # sched_id); under the defect it cancels this sleep with
            # "timeout" about 0.1s after the read. ev/sleep's own timer
            # resumes with nil (is_error = 0), so a "timeout" raised here
            # can only be the stale janet_addtimeout deadline.
            (ev/sleep 0.5)

            # Reached only when no stale timer exists (fixed code): the
            # sleep ran to completion and the delayed "world" write is
            # received by a normal read.
            (def r2 (:read s 5 nil 2.0))
            (assert (= "world" (string r2))
                    "second read should receive the delayed world bytes")))))))
