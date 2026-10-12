# dtls/read and dtls/recv-from datagram sizing regression test
# Ticket c0b609dd3dada7dbc6e32771382465bd2b70a549
#
# "dtls/read and dtls/recv-from mishandle nbytes == 0 and nbytes
# smaller than incoming datagram"
#
# Mechanism (this tree, branch off 0.2.0):
#   Janet's net/read and net/recv-from on :datagram UDP sockets follow
#   one sizing contract: nbytes == 0 appends nothing and returns the
#   buffer immediately without I/O, and nbytes smaller than the
#   incoming datagram copies up to nbytes bytes into the destination
#   buffer and discards the remainder of that datagram so the next read
#   receives the NEXT datagram. The jdtls paths break both halves:
#   - src/jdtls/api/io.c:73-92 (dtls_do_read): with n == 0 the
#     SSL_peek succeeds, to_read evaluates to 0, and SSL_read(ssl, p, 0)
#     returns 0, which dtls_ssl_result (src/jdtls/state_machine.c:48-72)
#     classifies as DTLS_RESULT_EOF; cfun_dtls_read (io.c:105-148) then
#     returns nil - a fake EOF - while the peer's datagram stays unread
#     in OpenSSL's record buffer. The suspension path in
#     src/jdtls/api/async.c:185-204 has the same n == 0 shape.
#   - src/jdtls/api/io.c:81 (dtls_do_read): to_read is clamped to n
#     but the remaining avail - n bytes of the decrypted DTLS record
#     are never drained, so the NEXT read returns the REMAINDER of the
#     same datagram instead of the next datagram.
#   - src/jdtls/server.c:465-535 (process_datagram) always reads the
#     whole record (SSL_pending-sized SSL_read) and never sees the
#     caller's nbytes: cfun_dtls_recv_from (server.c:764-806) parses
#     nbytes at :768 and stores it at :801 but it reaches no read, so
#     a nbytes == 0 call appends the full datagram and a nbytes smaller
#     than the datagram appends the full datagram anyway.
#
# This test demonstrates:
#   (a) (dtls/read client 0) returns the buffer with 0 bytes appended
#       immediately - an empty buffer on an empty target - without
#       consuming the pending datagram, while under the defect the call
#       returns nil (a fake EOF) with the datagram left unread,
#   (b) a read of nbytes smaller than the datagram copies up to nbytes
#       and discards the remainder of that datagram, so the next read
#       receives the NEXT datagram, while under the defect the next
#       read returns the remainder of the SAME datagram,
#   (c) (dtls/recv-from server nbytes buf) copies at most nbytes bytes
#       into buf and discards the rest of the datagram, and with
#       nbytes == 0 appends nothing, while under the defect the full
#       datagram lands in buf regardless of nbytes.
#
# Predicted symptom: (a) the n == 0 read returns nil (fake EOF), (b)
# the next read after a truncated read returns the remainder of the
# same datagram instead of the next datagram, and (c) recv-from puts
# the full datagram in the buffer regardless of nbytes.
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion and nothing else: no
# crash, no hang, no unrelated error. Under fixed code every test
# passes.
(use assay)
(import jsec/tls :as tls)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "DTLS Datagram Sizing Regression"
  :description "Ticket c0b609dd3d: dtls/read and dtls/recv-from honour nbytes == 0 and truncate-and-discard like Janet net"

  (def-test "read-zero-returns-empty-buffer-not-fake-eof"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            go-chan (ev/chan 1)]

        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true)
                (ev/take go-chan)
                (when addr1 (:send-to server addr1 "1234567890")))
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

          (ev/give go-chan true)
          (ev/sleep 0.3)

          # (a) n == 0 returns the buffer with 0 bytes appended without
          # I/O. Under the defect this returns nil (fake EOF) and the
          # assertion fails with the predicted symptom.
          (def r (:read conn 0))
          (assert (and (buffer? r) (empty? r))
                  (string/format
                    (string "the (dtls/read client 0) call returned %s "
                            "instead of an empty buffer with 0 bytes "
                            "appended (net/read on a :datagram socket "
                            "returns the buffer immediately without "
                            "I/O when nbytes is 0; the n == 0 read is "
                            "misclassified as EOF and returns nil - a "
                            "fake EOF)")
                    (string/format "%q" r)))

          # The datagram must not have been consumed by the n == 0 call
          (def r2 (:read conn 1024))
          (assert (= "1234567890" (string r2))
                  (string/format
                    (string "after the n == 0 call the pending datagram "
                            "was not readable intact: got %s")
                    (string/format "%q" r2)))))))

  (def-test "read-n-below-datagram-discards-remainder"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            go-chan (ev/chan 1)]

        (ev/go
          (fn []
            (try
              (do
                (def addr1 (:recv-from server 1024 (buffer/new 1024)))
                (when addr1 (:send-to server addr1 "pong"))
                (ev/give primed true)
                (ev/take go-chan)
                (when addr1
                  (:send-to server addr1 "ABCDEFGHIJ")
                  (:send-to server addr1 "KLMNOPQRST")))
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

          (ev/give go-chan true)
          (ev/sleep 0.3)

          # A 3-byte read of a 10-byte datagram copies 3 bytes and
          # discards the rest of THAT datagram
          (def r-trunc (:read conn 3))
          (assert (= "ABC" (string r-trunc))
                  (string/format
                    (string "the 3-byte read of the 10-byte datagram "
                            "returned %s instead of the first 3 bytes")
                    (string/format "%q" r-trunc)))

          # The next read must receive the NEXT datagram, never the
          # discarded remainder of the previous one. Under the defect
          # this returns "DEFGHIJ" - the tail of the SAME datagram -
          # and the assertion fails with the predicted symptom.
          (def r-next (:read conn 1024))
          (assert (= "KLMNOPQRST" (string r-next))
                  (string/format
                    (string "the read after a 3-byte truncated read "
                            "returned %s - the remainder of the SAME "
                            "datagram - instead of the next datagram "
                            "(net/read on a :datagram socket discards "
                            "the remainder of a partially read "
                            "datagram so the next read receives the "
                            "next datagram)")
                    (string/format "%q" r-next)))))))

  (def-test "recv-from-nbytes-caps-and-discards-remainder"
    :timeout 20

    (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                               :cert (certs :cert)
                                               :key (certs :key)})]
      (let [[_ port] (:localname server)
            primed (ev/chan 1)
            go-chan (ev/chan 1)]

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

          # The client sends the datagrams the server will recv-from
          (:write conn "ABCDEFGHIJ")
          (:write conn "KLMNOPQRST")
          (ev/sleep 0.3)

          # (c) nbytes == 4 must put 4 bytes in the buffer and discard
          # the rest of the datagram. Under the defect the full
          # datagram lands in the buffer and the assertion fails with
          # the predicted symptom.
          (def buf @"")
          (def peer (dtls/recv-from server 4 buf))
          (assert peer "recv-from should return the peer address")
          (assert (= "ABC" (string buf))
                  (string/format
                    (string "dtls/recv-from with nbytes 4 put %s in "
                            "the buffer instead of the first 4 bytes "
                            "of the datagram (net/recv-from on a "
                            ":datagram socket copies up to nbytes and "
                            "discards the remainder)")
                    (string/format "%q" buf)))

          # The remainder of that datagram is discarded, so the next
          # recv-from receives the NEXT datagram in full
          (def buf2 @"")
          (def peer2 (dtls/recv-from server 1024 buf2))
          (assert peer2 "recv-from should return the peer address")
          (assert (= "KLMNOPQRST" (string buf2))
                  (string/format
                    (string "the recv-from after a 4-byte truncated "
                            "recv-from returned %s instead of the "
                            "next datagram")
                    (string/format "%q" buf2)))

          # nbytes == 0 appends nothing (after the peer's datagram
          # arrives). Under the defect the full datagram is appended
          # regardless of nbytes.
          (:write conn "0123456789")
          (ev/sleep 0.3)
          # the recv-from below must not consume the datagram's bytes
          (def buf0 @"")
          (def peer0 (dtls/recv-from server 0 buf0))
          (assert (= 0 (length buf0))
                  (string/format
                    (string "dtls/recv-from with nbytes 0 appended %s "
                            "to the target buffer instead of 0 bytes "
                            "(net/recv-from with nbytes 0 appends "
                            "nothing and discards the datagram)")
                    (string/format "%q" buf0))))))))
