# OpenSSL error-queue contamination regression test
# Ticket 1b2ba3616ea88a56bdb112393cacccb74e34666f
#
# "OpenSSL error-queue contamination makes SSL_get_error lie"
#
# OpenSSL's SSL_get_error contract (man SSL_get_error):
#   "The current thread's error queue must be empty before the TLS/SSL
#   I/O operation is attempted, or SSL_get_error() will not work
#   reliably. Emptying the current thread's error queue is done with
#   ERR_clear_error(3)."
# ossl_ssl_get_error honors this by peeking ERR_peek_error() BEFORE it
# consults the BIO retry flags: a non-empty queue forces SSL_ERROR_SSL
# even when the operation merely wants to read.
#
# jsec never calls ERR_clear_error() before SSL_read/SSL_write/
# SSL_shutdown. In this tree the I/O call sites are:
#   src/jtls/state_machine.c:217  SSL_accept/SSL_connect (TLS_OP_HANDSHAKE)
#   src/jtls/state_machine.c:269  SSL_read  (TLS_OP_READ)
#   src/jtls/state_machine.c:316  SSL_read  (TLS_OP_CHUNK)
#   src/jtls/state_machine.c:377  SSL_write (TLS_OP_WRITE)
#   src/jtls/state_machine.c:415  SSL_shutdown (TLS_OP_SHUTDOWN/CLOSE)
#   src/jtls/state_machine.c:855  SSL_read  (hangup drain path)
#   src/jdtls/state_machine.c:91  SSL_do_handshake (dtls_do_handshake)
#   src/jdtls/state_machine.c:100 SSL_read  (dtls_do_read)
#   src/jdtls/state_machine.c:111 SSL_write (dtls_do_write)
#   src/jdtls/state_machine.c:121 SSL_shutdown (dtls_do_shutdown)
# None is preceded by ERR_clear_error(); each feeds SSL_get_error
# (jtls/state_machine.c:228,285,331,390,432,873 and
# jdtls/state_machine.c:53) which then reports the LEFTOVER error as if
# it belonged to the I/O call. handle_ssl_error's default case
# (jtls/state_machine.c:173-176) formats it into "Read error: <leftover>"
# and the read panics.
#
# Contaminant used here: (crypto/key-info non-key). cfun_key_info
# (src/jcrypto/keys.c:295) probes the input with PEM_read_bio_PrivateKey
# (keys.c:322) and PEM_read_bio_PUBKEY (keys.c:328); on a non-key both
# probes fail and the function RETURNS NORMALLY with {:type :unknown}
# without ever draining the queue. Each failed probe leaves one
# "DECODER routines::unsupported" error on the thread's queue, so the
# call is a quiet contaminant: it succeeds at the Janet level while
# leaving the OpenSSL error queue non-empty. The error queue is
# per-thread and Janet fibers share the thread, so one fiber's
# crypto/key-info poisons the next TLS I/O of ANY fiber - the exact
# cross-fiber hazard this ticket reports.
#
# Why the observING read is the SECOND read on the connection: OpenSSL
# 3.x runs the handshake state machine once on the first read after
# handshake (post-handshake message processing), and state_machine()
# (ssl/statem/statem.c) calls ERR_clear_error() on entry. That one-shot
# incidental clear hides pre-handshake leftovers (e.g. the PEM_R_
# NO_START_LINE that tls/accept's cert-chain loading leaves behind) but
# only for the FIRST read. Every later read on a quiescent connection
# takes the plain record-layer retry path with no clear at all, so a
# queue dirtied after the first read is seen in full by SSL_get_error.
#
# This test demonstrates:
#   (a) contamination: fiber A invokes crypto/key-info on a non-key and
#       the call returns {:type :unknown} normally - its two failed PEM
#       probes are left on the thread's error queue,
#   (b) on a HEALTHY TLS connection (handshake complete, first read
#       already delivered data), a second read that would legitimately
#       SSL_ERROR_WANT_READ - the peer has not sent its next payload yet
#       - instead raises a spurious error naming the leftover, e.g.
#       "Read error: error:1E08010C:DECODER routines::unsupported",
#   (c) under fixed code (ERR_clear_error at the jtls/jdtls I/O
#       boundary) the same read suspends cleanly and delivers the
#       delayed "world" payload when the peer sends it at +0.6s, and
#       the test passes.
#
# Under the defect the second read raises immediately (no hang, no
# crash) and the test fails with exactly that spurious error message.

(use assay)
(import jsec/tls :as tls)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "Error Queue Contamination Regression"
  :description "Ticket 1b2ba3616e: leftover OpenSSL errors make SSL_get_error report SSL_ERROR_SSL on a healthy WANT_READ"

  (def-test "contaminated error queue makes healthy TLS read raise instead of suspend"
    :timeout 10

    (with [server (tls/listen "127.0.0.1" "0")]
      (let [[_ port] (net/localname server)
            contaminated (ev/chan 1)
            server-done (ev/chan 1)]

        # Server fiber: complete the handshake, deliver "hello"
        # immediately, withhold "world" until +0.6s so the observING read
        # below is issued while the peer has nothing more to send.
        (ev/go (fn []
                 (try
                   (with [client (tls/accept server
                                             {:cert (certs :cert)
                                              :key (certs :key)})]
                     (:write client "hello")
                     (ev/sleep 0.6)
                     (:write client "world")
                     (ev/take server-done))
                   ([err] (ev/give server-done (string "server error: " err))))))

        (with [conn (tls/connect "127.0.0.1" (string port) {:verify false})]

          # Prime the connection past its first-read phase: this read
          # delivers the pending "hello" and also consumes the one-shot
          # state-machine entry whose ERR_clear_error() would otherwise
          # mask leftovers for us. The connection is healthy from here.
          (def r1 (:read conn 5 nil 2.0))
          (assert r1 "first read should return the pending hello bytes")
          (assert (= "hello" (string r1))
                  "first read should receive the hello payload")

          # (a) Contamination in a SEPARATE fiber, matching the ticket's
          # cross-fiber scenario. ev/give/ev/take order the two fibers
          # deterministically: the queue is dirty before fiber B reads.
          (ev/go (fn []
                   (try
                     (ev/give contaminated
                              [:ok (crypto/key-info "THIS IS NOT A KEY")])
                     ([err] (ev/give contaminated [:err err])))))
          (def [status info] (ev/take contaminated))
          (assert (= :ok status)
                  (string/format "contaminating key-info call failed: %q %q"
                                 status info))
          (assert (= :unknown (info :type))
                  (string/format
                    (string "key-info on a non-key should report :unknown "
                            "(both PEM probes failed, queue left dirty), got %q")
                    info))

          # (b) The observING read. "world" is not on the wire yet, so a
          # correct SSL_get_error reports WANT_READ and this read
          # suspends until the peer sends at +0.6s. Under the defect the
          # queue still holds key-info's "DECODER routines::unsupported"
          # leftovers, SSL_get_error peeks them and lies SSL_ERROR_SSL,
          # and handle_ssl_error panics "Read error: <leftover>" naming
          # an error that has nothing to do with this connection. The
          # raise is the proof; let it propagate so the test fails with
          # that exact message.
          (def r2 (:read conn 5 nil 2.0))

          # (c) Reached only under fixed code: the read suspended cleanly
          # and the delayed payload arrived when the peer sent it.
          (assert r2 "second read should return the delayed payload")
          (assert (= "world" (string r2))
                  "second read should receive the delayed world bytes")

          (ev/give server-done true))))))
