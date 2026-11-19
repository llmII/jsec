# DTLS read n relative regression test
# Ticket 3e3e111f755e13e5690f179eb3b2d81146601e63
#
# "DTLS read accounting is absolute, not relative to call start"
#
# Mechanism (this tree):
#   Janet's ev/read semantics make n relative to the bytes THIS call
#   appends, measured from the buffer count at operation start. The jtls
#   half was fixed by ticket af4355945681dda4d8bba3712682a411a77815da
#   (merged as a177a52abc27cf775a012dcebde0b211ebe6f2aa), which added
#   buf_start (src/jtls/internal.h:199) and converted every comparison to
#   (count - buf_start). The DTLS paths were not touched and still use
#   the buffer's TOTAL count:
#   - src/jdtls/api/async.c:187 - the suspended read's size is
#     (state->nbytes - state->buffer->count): with a pre-filled buffer the
#     request is shrunk by the pre-existing bytes (5 - 3 = 2 here), and
#     with count >= nbytes the length goes to zero or negative.
#   - src/jdtls/api/async.c:197 - EOF is decided by absolute
#     buffer->count > 0, so pre-filled content is returned as if freshly
#     read when this call appended nothing.
#   - src/jdtls/state_machine.c:422 - (data->state.nbytes -
#     data->state.buffer->count), the same absolute accounting on the
#     DTLS_OP_READ continuation of dtls_async_callback; decisions at
#     src/jdtls/state_machine.c:428 and :433 use absolute count > 0.
#   - src/jdtls/api/io.c:54 - the synchronous first attempt's EOF is
#     decided by absolute buf->count > 0 (the read cap at io.c:46 is
#     already per-call).
#
# This test demonstrates:
#   (a) (:read s 5 buf) on a buffer already holding 3 bytes reads 5
#       bytes relative to THIS call - the peer sends one 5-byte datagram
#       and the buffer must end at 8 bytes ("XXX12345") - while under
#       the defect the async continuation reads only 5 - 3 = 2 bytes and
#       the datagram is truncated to "XXX12",
#   (b) EOF is decided by the bytes THIS call read, not the buffer's
#       total: with the buffer pre-filled and 0 bytes appended this call,
#       the read must return nil both on the suspending path
#       (src/jdtls/api/async.c:197) and on the synchronous first attempt
#       (src/jdtls/api/io.c:54), while under the defect both return the
#       stale 3 bytes as if freshly read.
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion - (a) "the DTLS read
# appended 2 of 5 requested bytes to a pre-filled buffer (n compared
# against the buffer's total count of 3, not this call's bytes): expected
# 5 bytes appended this call onto "XXX", buffer is now @"XXX12"" and
# (b) "EOF with a pre-filled buffer and 0 bytes read this call returned
# the stale buffer as freshly read data instead of nil (EOF is decided by
# the bytes this call read, not the buffer's total count; ...): got
# @"XXX"" - and nothing else: no crash, no hang, no unrelated error.
# Under fixed code every test passes.
(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "DTLS Read N Relative Regression"
  :description "Ticket 3e3e111f75: DTLS read n is relative to call start, not the buffer's total count"

  (def-test "read-into-pre-filled-buffer-appends-n-bytes-this-call"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            go-chan (ev/chan 1)
            read-done (ev/chan 2)]

        # Server fiber: handshake plus one priming round ("Ping1" -> "pong"),
        # then wait for the go signal and send exactly one 5-byte datagram.
        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true)
                (ev/take go-chan)
                (when addr1 (:send-to server addr1 "12345")))
              ([err] (ev/give primed (string "server error: " err))))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        (defer (:close conn true)

          # Priming round: completes the handshake and leaves no pending data.
          (:write conn "Ping1")
          (def r1 (:read conn 1024))
          (assert r1 "priming read should return the pong payload")
          (def primed-val (ev/take primed))
          (assert (= true primed-val)
                  (string/format "server setup failed: %v" primed-val))

          # The buffer is pre-filled with 3 bytes; n = 5 is THIS call's
          # request and must be measured from the buffer count at call start
          # (ev/read append semantics, src/jtls/internal.h:199).
          (def buf @"XXX")
          (ev/go
            (fn []
              (try
                (ev/give read-done [:ok (:read conn 5 buf)])
                ([err] (ev/give read-done [:err (string err)])))))

          # Let the read suspend on WANT_READ before the datagram exists,
          # so the completion runs the async continuation
          # (src/jdtls/api/async.c:182-200).
          (ev/sleep 0.3)
          (ev/give go-chan true)

          (def [tag r] (ev/take read-done))
          (assert (= :ok tag)
                  (string/format "read raised instead of returning: %s" r))
          (def new-bytes (- (length buf) 3))

          # (a) n is relative to this call: exactly 5 new bytes land on top
          # of the 3 pre-existing ones. Under the defect the continuation's
          # read size is (5 - 3) = 2 (src/jdtls/api/async.c:187) and this
          # fails with the predicted truncation symptom.
          (assert (= 5 new-bytes)
                  (string/format
                    (string "the DTLS read appended %d of 5 requested bytes "
                            "to a pre-filled buffer (n compared against the "
                            "buffer's total count of 3, not this call's "
                            "bytes): expected 5 bytes appended this call "
                            "onto \"XXX\", buffer is now %s")
                    new-bytes (describe buf)))))))

  (def-test "eof-on-suspended-read-returns-nil-not-pre-filled-bytes"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            read-done (ev/chan 2)]

        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true))
              ([err] (ev/give primed (string "server error: " err))))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        (defer (:close conn true)

          (:write conn "Ping1")
          (def r1 (:read conn 1024))
          (assert r1 "priming read should return the pong payload")
          (def primed-val (ev/take primed))
          (assert (= true primed-val)
                  (string/format "server setup failed: %v" primed-val))

          (def buf @"XXX")
          (ev/go
            (fn []
              (try
                (ev/give read-done [:ok (:read conn 5 buf)])
                ([err] (ev/give read-done [:err (string err)])))))

          # Suspend the read on WANT_READ, then close the server, which
          # sends close_notify to the established session
          # (src/jdtls/server.c:825-845); the completion hits the EOF
          # decision at src/jdtls/api/async.c:197.
          (ev/sleep 0.3)
          (:close server)

          (def [tag r] (ev/take read-done))
          (assert (= :ok tag)
                  (string/format "read raised instead of returning: %s" r))

          # (b) EOF with 0 bytes appended THIS call returns nil: the stale
          # pre-filled bytes must not be reported as freshly read data.
          (assert (nil? r)
                  (string/format
                    (string "EOF with a pre-filled buffer and 0 bytes read "
                            "this call returned the stale buffer as freshly "
                            "read data instead of nil (EOF is decided by the "
                            "bytes this call read, not the buffer's total "
                            "count; absolute buffer->count > 0 at "
                            "src/jdtls/api/async.c:197): got %s")
                    (describe r)))))))

  (def-test "eof-on-synchronous-read-returns-nil-not-pre-filled-bytes"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)]

        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true))
              ([err] (ev/give primed (string "server error: " err))))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        (defer (:close conn true)

          (:write conn "Ping1")
          (def r1 (:read conn 1024))
          (assert r1 "priming read should return the pong payload")
          (def primed-val (ev/take primed))
          (assert (= true primed-val)
                  (string/format "server setup failed: %v" primed-val))

          # Close first so the synchronous first attempt of the next read
          # processes the pending close_notify and takes the EOF branch at
          # src/jdtls/api/io.c:53-55.
          (:close server)
          (ev/sleep 0.3)

          (def buf @"XXX")
          (def r (:read conn 5 buf))

          # (b) Same EOF contract on the synchronous path: 0 bytes this
          # call means nil, not the stale buffer.
          (assert (nil? r)
                  (string/format
                    (string "EOF with a pre-filled buffer and 0 bytes read "
                            "this call returned the stale buffer as freshly "
                            "read data instead of nil (EOF is decided by the "
                            "bytes this call read, not the buffer's total "
                            "count; absolute buf->count > 0 at "
                            "src/jdtls/api/io.c:54): got %s")
                    (describe r))))))))
