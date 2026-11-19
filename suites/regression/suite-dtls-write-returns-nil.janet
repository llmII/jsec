# dtls/write return value regression test
# Ticket 7d86a4df9ebd42ae405ee5479d14d5773e4c83ad
#
# "dtls/write returns integer byte count instead of nil like tls/write
# and ev/write"
#
# Mechanism (this tree):
#   tls/write returns nil on success (src/jtls/module.c:135 documents
#   "Returns nil, or raises an error if write failed") and Janet's
#   ev/write returns nil, so a caller swapping connection initializers
#   between a net stream and a jdtls stream sees a different return
#   shape from the same write. The DTLS write paths return the integer
#   byte count instead:
#   - src/jdtls/api/io.c:183 - the synchronous completion in
#     cfun_dtls_write returns janet_wrap_integer(nwritten) when
#     dtls_do_write completes immediately.
#   - src/jdtls/api/async.c:213 - the async completion for
#     CLIENT_OP_WRITE schedules janet_wrap_integer(nwritten).
#   - src/jdtls/state_machine.c:432 - the DTLS_OP_WRITE completion
#     likewise returns janet_wrap_integer(nwritten).
#   The module docstring at src/jdtls/api/module.c ("Returns number of
#   bytes written") and docs/API.org:472 ("*Returns*: Number of bytes
#   written") advertise that integer shape, while the ruled contract
#   (and tls/write and ev/write) is nil on success.
#
# This test demonstrates:
#   (a) (dtls/write client data) on an established DTLS session
#       returns nil on success, exactly like tls/write and ev/write,
#       while under the defect the call returns the integer byte count
#       of the datagram just written,
#   (b) the same nil contract holds for the (:write client data) JAT
#       method entry, which dispatches to the same cfun_dtls_write.
#
# Predicted symptom: the write returns an integer byte count (the
# datagram length) instead of nil. The async completion sites
# (src/jdtls/api/async.c:213, src/jdtls/state_machine.c:432) share the
# defect; on Linux loopback UDP the send buffer never back-pressures,
# so the guard exercises the synchronous completion path, which is the
# ordinary case and fails with the same predicted symptom.
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion - "the DTLS write
# returned the integer byte count N instead of nil" - and nothing else:
# no crash, no hang, no unrelated error. Under fixed code every test
# passes.
(use assay)
(import jsec/tls :as tls)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "DTLS Write Returns Nil Regression"
  :description "Ticket 7d86a4df9e: dtls/write must return nil on success like tls/write and ev/write"

  (def-test "dtls-write-returns-nil-on-success"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            ready (ev/chan 1)]

        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give ready true))
              ([err] (ev/give ready (string "server error: " err))))))

        (def conn (tls/connect "127.0.0.1" (string port)
                               {:datagram true :verify false}))
        (defer (:close conn true)

          # Priming round completes the handshake and leaves no pending data
          (:write conn "Ping1")
          (def r1 (:read conn 1024))
          (assert r1 "priming read should return the pong payload")
          (def ready-val (ev/take ready))
          (assert (= true ready-val)
                  (string/format "server setup failed: %v" ready-val))

          # The server must keep draining so the writes below cannot
          # back up its receive queue across the pair of datagrams
          (ev/go
            (fn []
              (try
                (do
                  (:recv-from server 1024 (buffer/new 1024))
                  (:recv-from server 1024 (buffer/new 1024)))
                ([_] nil))))

          # (a) the module-fn write returns nil on success. Under the
          # defect it returns the integer byte count and this fails
          # with the predicted symptom.
          (def payload "Ping2")
          (def r (dtls/write conn payload))
          (assert (= nil r)
                  (string/format
                    (string "the DTLS write returned the integer byte "
                            "count %v instead of nil (tls/write and "
                            "ev/write return nil on success and the "
                            "ruled dtls/write contract is nil on "
                            "success)")
                    r))

          # (b) the (:write client data) JAT method carries the same
          # nil-on-success contract
          (def r-method (:write conn "Ping3"))
          (assert (= nil r-method)
                  (string/format
                    (string "the (:write client data) method returned "
                            "the integer byte count %v instead of nil "
                            "(the method entry dispatches to the same "
                            "cfun_dtls_write and shares its nil-on-"
                            "success contract with tls/write)")
                    r-method)))))))
