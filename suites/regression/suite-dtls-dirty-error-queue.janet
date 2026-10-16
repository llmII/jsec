# DTLS handshake failures leave the OpenSSL error queue dirty test
# Ticket 6ac49861814fcdb31bc4905aa47874301f3dab06
#
# "Check OpenSSL and allocation return values in jdtls session
# creation, handshake processing, and connection-info queries"
#
# Mechanism (this tree): process_datagram (src/jdtls/server.c:465-548)
# feeds each datagram to SSL_do_handshake and, when the outcome is
# neither SSL_ERROR_WANT_READ nor SSL_ERROR_WANT_WRITE, treats the
# handshake as failed - a handled, transient peer failure - drops the
# session, and returns nil (src/jdtls/server.c:497-500) without
# draining the OpenSSL error queue. The create-failure return at
# :472-475 and the BIO_write failure return at :479-481 are the same
# shape, and dtls_session_new (src/jdtls/session.c:34-76) leaves the
# same residue when SSL_new (:42-46) or BIO_new (:52-59) fails and
# ignores the BIO_set_nbio results at :63-64; the established read
# path is the only place that clears, before SSL_peek (:520) and
# SSL_read (:526). The queue is per-thread and all fibers share it, so
# a stale handshake error misleads the next OpenSSL operation that
# consults the queue: get_ssl_error_string (src/jutils/error.c:19-27)
# pops the EARLIEST queued error and clears the rest, so the
# cfun_load_key panic path (src/jcrypto/keys.c:146-157) reports the
# leftover instead of its own parse error.
#
# This test demonstrates:
#   (a) on a clean queue crypto/load-key on garbage raises its own
#       "DECODER routines::unsupported",
#   (b) a transient peer handshake failure on the DTLS server - a
#       hello_request handshake message (a client may not send one),
#       which fails SSL_do_handshake and takes the handled cleanup
#       path - leaves "SSL routines::unexpected message" behind,
#   (c) the same crypto/load-key run afterwards raises the LEFTOVER
#       "SSL routines::unexpected message" instead of its own error:
#       an unrelated operation reporting a stale handshake error.
#
# Proof contract: under the defect the test fails with exactly the
# predicted symptom (a later operation raises the leftover error from
# the earlier handled handshake failure); under fixed code the whole
# test passes.

(use assay)
(import jsec/dtls-stream :as dtls)
(import jsec/crypto :as crypto)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- load-key-own-error
  ``Run crypto/load-key on garbage; return the raised error text (nil
   if it did not raise). The failure's own parse error is
   "DECODER routines::unsupported"; on a dirty queue the raise names
   whatever the queue held instead.``
  []
  (try
    (do (crypto/load-key "not a PEM key at all") nil)
    ([err] (string err))))

# A DTLS handshake record (type 22, DTLS 1.2, epoch 0, seq 0, length
# 12) holding a complete hello_request message (msg_type 0, zero
# length). HelloRequest is server-to-client; a server receiving one
# from a peer fails the handshake with "unexpected message" and takes
# the handled cleanup path in process_datagram.
(def handshake-failure-datagram
  (string
    "\x16\xFE\xFD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0C"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))

(def-suite :name "DTLS Dirty Error Queue Regression"
  :description "Ticket 6ac4986181: handled DTLS handshake failures must leave the OpenSSL error queue empty"

  (def-test "handshake-failure-misleads-a-later-operations-raise"
    :timeout 15

    # Control: the failing load's own error text on a clean queue.
    (def clean-err (load-key-own-error))
    (assert clean-err "control: crypto/load-key on garbage must raise")

    (def server (dtls/listen "127.0.0.1" "0"
                             {:cert (certs :cert) :key (certs :key)}))
    (def [_ port] (dtls/localname server))
    (defer (:close server)
      (def peer (net/connect "127.0.0.1" (string port)
                             :datagram "127.0.0.1" "0"))
      (defer (:close peer)
        (:write peer handshake-failure-datagram)

        # Synchronize on the processing of the datagram: dtls/recv-from
        # drains it (handshake fails, session dropped) and then holds
        # out for application data until the timeout cancels the call.
        # The timeout path makes no OpenSSL calls, so nothing touches
        # the error queue between the handshake failure and the probe.
        (def sync
          (try
            (do (dtls/recv-from server 4096 (buffer/new 4096) 1.0)
                :returned)
            ([err] err)))
        (assert (= "timeout" sync)
                (string/format
                  (string "setup: dtls/recv-from must drain the queued "
                          "handshake-failure datagram and then time out "
                          "waiting for application data (the timeout "
                          "path touches no OpenSSL calls), but it ended "
                          "with %q")
                  sync))

        # The queue now holds the handshake leftover. A later
        # operation that consults the queue must still report ITS OWN
        # error: crypto/load-key on garbage must raise exactly what
        # the control did. Under the defect get_ssl_error_string pops
        # the earlier leftover first and the raise becomes
        # "SSL routines::unexpected message" - a stale error from a
        # handled handshake failure, raised by an unrelated operation.
        (def dirty-err (load-key-own-error))
        (assert (= clean-err dirty-err)
                (string/format
                  (string "the OpenSSL error queue must be empty after a "
                          "handled DTLS handshake failure, so an "
                          "unrelated later operation raises its own "
                          "error instead of the leftover from the "
                          "earlier failure (the failed-handshake path "
                          "of process_datagram at "
                          "src/jdtls/server.c:497-500 drops the session "
                          "and returns nil without ERR_clear_error, and "
                          "get_ssl_error_string at "
                          "src/jutils/error.c:19-27 pops the earliest "
                          "queued error): got (clean-raise=%q "
                          "contaminated-raise=%q)")
                  clean-err dirty-err))))))
