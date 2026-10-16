# Async close returns nil regression test
# Ticket 68c97a6265e5b4c0922758cea21390fd8597685d
#
# "Async (:close s) raises \"Connection closed\" instead of returning nil"
#
# Mechanism (ticket branch ticket-68c97a6265, off 0.2.0):
#   - cfun_close (src/jtls/api/io.c:229-281) returns nil on every
#     completion path (:239, :260, :277, :280). The graceful path
#     (:263-281) arms TLS_OP_CLOSE on the embedded write_state
#     (:269-274) and hands it to jtls_attempt_io at :276.
#   - TLS_OP_CLOSE (src/jtls/state_machine.c:416-469) completes
#     synchronously on every SSL_shutdown outcome except
#     SSL_ERROR_WANT_WRITE (:444-445), the one path that returns
#     TLS_IO_WANT_WRITE and suspends the fiber. A full socket send
#     buffer - the close_notify alert cannot be flushed - is what
#     produces WANT_WRITE: jtls_bio_write reports the would-block as
#     a retryable BIO write (src/jtls/bio.c:140-149).
#   - On resumption the TLS_IO_COMPLETE case closes the transport
#     BEFORE scheduling the caller: "For TLS_OP_CLOSE, close
#     transport in both sync and async cases"
#     (src/jtls/state_machine.c:589-597, janet_stream_close at :594),
#     and only then janet_schedule(fiber, nil) at :627.
#   - janet_stream_close dispatches JANET_ASYNC_EVENT_CLOSE to the
#     transport's registered read and write fibers (janet core
#     core/ev.c:390-402, janet 1.41.1), and the closing fiber is
#     still registered as the transport's write fiber (registration
#     at src/jtls/state_machine.c:530). The CLOSE/ERR case of
#     jtls_async_callback cancels it with "Connection closed"
#     (src/jtls/state_machine.c:924-931, janet_cancel at :928).
#   - The later janet_schedule(fiber, nil) at :627 is silently
#     dropped because the fiber is already flagged canceled
#     (core/ev.c:517-518), so the caller resumes with the cancel
#     error instead of the intended nil.
#
# Saturation vehicle: a Unix socket pair, not TCP loopback. On a
# Unix stream socket the peer's receive buffer is the only sink -
# no ACK or receive-window machinery hands space back while the peer
# is not reading - so once the raw fill loop parks mid-chunk the
# send buffer stays genuinely full until the drain below reads (a
# 1-byte probe write still times out at that point). On TCP loopback
# the same fill parks too, but ACK and receive-window autotuning
# leak free space back within milliseconds, the close_notify alert
# always finds room, and the WANT_WRITE close path is never taken -
# (:close c) then returns nil synchronously and the defect hides.
#
# This test demonstrates:
#   (a) with the client-side send buffer full - a raw fill loop on
#       the underlying connection parks against the pair's socket
#       buffer capacity, with the server side not reading - an async
#       (:close c) suspends on the WANT_WRITE close path
#       (src/jtls/state_machine.c:444-445),
#   (b) when the server side then drains and the close resumes and
#       completes, (:close c) must return nil - under the defect it
#       raises "Connection closed" from the self-cancel, the exact
#       predicted symptom.
#
# Proof contract: the fill fiber is cancelled once the buffer is full
# so it can never resume and refill while the close is in flight -
# the queued bytes keep the buffer full until the drain fiber opens
# the window. The close is then measured to have SUSPENDED (it cannot
# return before the drain), so the async completion path is taken
# every run. It fails on purpose under the defect with exactly the
# predicted symptom and becomes the regression guard after the fix
# lands.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "Async Close Returns Nil Regression"
  :description "Ticket 68c97a6265: async (:close s) must return nil instead of raising Connection closed"

  (def-test "async close returns nil instead of raising Connection closed"
    :timeout 60

    (let [[server socket-path] (make-server :unix)
          addr (get-server-addr server :unix socket-path)
          ready (ev/chan 1)]
      (var mc nil)

      (defer (do (:close server) (cleanup-socket socket-path))

        # Client fiber: connect, complete the TLS handshake (the wrap
        # interleaves with the server-side wrap below), publish the
        # client stream for the closer, then raw-write 64 KiB chunks
        # on the underlying connection in a loop. The loop parks
        # mid-chunk once the socket send buffer is full and stays
        # parked until cancelled below - the fill must never resume
        # and refill while the close is in flight.
        (def fa
          (ev/go (fn []
                   (try
                     (do
                       (def conn (make-client-conn :unix addr))
                       (def c (tls/wrap conn {:verify false}))
                       (set mc c)
                       (ev/give ready :handshake-done)
                       (def chunk (string/repeat "F" (* 64 1024)))
                       (forever (:write conn chunk)))
                     ([err] (ev/give ready (string "client error: " err)))))))

        (def sconn (:accept server))
        (def s (tls/wrap sconn {:cert (certs :cert) :key (certs :key)}))
        (def rv (ev/take ready))
        (unless (= :handshake-done rv)
          (error (string "setup failed: " rv)))
        (def c mc)

        # Let the fill loop park: the Unix pair absorbs only its
        # socket-buffer capacity (a few hundred KiB) against an
        # unbounded fill, and nothing returns space while the peer
        # is not reading. Then cancel the fill fiber so the queued
        # bytes keep the buffer full and nothing refills it later.
        (ev/sleep 1.0)
        (ev/cancel fa "fill done")

        # Drain fiber: waits until the close has had time to suspend
        # on WANT_WRITE (the buffer is still full), then raw-reads the
        # server side to open the window so the close resumes.
        (def fb
          (ev/go (fn []
                   (ev/sleep 1.5)
                   (try
                     (for i 0 12
                       (def chunk (:read sconn (* 512 1024) nil 5))
                       (when (or (not chunk) (empty? chunk)) (break)))
                     ([_] nil)))))

        # The close: suspends on WANT_WRITE while the buffer is full,
        # completes when the drain opens the window. Correct contract:
        # return nil. Defect: raise "Connection closed".
        (var close-result :not-called)
        (var close-dt 0)
        (def t0 (os/clock))
        (try
          (do (:close c) (set close-result :returned-nil))
          ([err] (set close-result (string "raised: " err))))
        (set close-dt (- (os/clock) t0))

        (ev/cancel fb "test done")
        (defer (do (try (:close s) ([_] nil))
                   (try (:close sconn) ([_] nil))
                   (try (:close c) ([_] nil)))

          # Proof precondition: the close must have SUSPENDED (it
          # cannot return before the drain fiber opens the window at
          # +1.5s). A sub-second return means the send buffer was not
          # full and the sync completion path was taken - the async
          # close path was never exercised, so a pass here would prove
          # nothing.
          (assert (> close-dt 1.0)
                  (string/format
                    (string "proof precondition failed: (:close c) returned "
                            "in %.3fs, before the drain fiber could open the "
                            "send-buffer window - the socket send buffer was "
                            "not full and the async close completion path "
                            "(src/jtls/state_machine.c:444-445, :589-597) "
                            "was never taken")
                    close-dt))

          (assert (= :returned-nil close-result)
                  (string/format
                    (string "async (:close s) must return nil instead of "
                            "raising: the TLS_IO_COMPLETE case closes the "
                            "transport before scheduling the caller "
                            "(janet_stream_close at "
                            "src/jtls/state_machine.c:594 before the "
                            "janet_schedule at :627), so the CLOSE event "
                            "self-cancels the closing fiber with "
                            "\"Connection closed\" "
                            "(src/jtls/state_machine.c:928) and the "
                            "schedule is dropped (core/ev.c:517-518); "
                            "got: %s")
                    (string close-result))))))))
