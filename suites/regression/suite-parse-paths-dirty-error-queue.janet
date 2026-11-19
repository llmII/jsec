# Parse paths leave the OpenSSL error queue dirty regression test
# Ticket 7a8824c6f5fecd77593cfb11dddb4e8f162c8f8e
#
# "Parse paths leave the OpenSSL error queue dirty"
#
# The cert/key/CMS parse paths push errors onto the thread's OpenSSL
# error queue and never drain it. Sites re-derived against this tree:
# the SAN extension builder in cert/generate-self-signed-cert feeds
# "IP:<cn>" to X509V3_EXT_conf_nid (src/jcert/jcert.c:214, again at
# :398) and ignores failure - a common name that looks like a malformed
# IP ("1.2.3.4.5") makes the call fail and leave
# "X509 V3 routines::bad ip address" on the queue while the function
# RETURNS NORMALLY. Same shape elsewhere: PEM loops terminate with
# PEM_R_NO_START_LINE left behind (src/jutils/cert_loading.c:71,
# :124, src/jcrypto/cms.c:92-96), cfun_key_info's probes fail quietly
# and return {:type :unknown} (src/jcrypto/keys.c:322, :328), and
# cfun_load_key's panic path pops only one error through
# get_ssl_error_string (src/jcrypto/keys.c:144-153 ->
# src/jutils/error.c:23-27). The correct drain pattern is already
# in-tree at src/jcert/verify.c:47-52.
#
# The queue is per-thread and fibers share it, so a quiet parse in one
# fiber poisons every later OpenSSL call that consults the queue.
# get_ssl_error_string (src/jutils/error.c:23-27) pops the EARLIEST
# queued error, so after a quiet parse the next operation's raise names
# the LEFTOVER - the exact misdirection the ticket reports ("any code
# that mixes parsing with OpenSSL calls that consult the queue can
# still be misled").
#
# Tree/platform note: the TLS/DTLS I/O boundary now calls
# ERR_clear_error() before every SSL call (src/jtls/state_machine.c:202
# and src/jdtls/state_machine.c:91,101,113,124 - ticket 1b2ba3616e),
# so on this tree a healthy TLS read no longer raises the leftover; the
# residue is exhibited through the get_ssl_error_string panic surface
# the fix shape names (drain-and-return-first-error), which still
# consults the dirty queue unprotected.
#
# This test demonstrates:
#   (a) contamination: cert generation with a malformed-IP common name
#       exercises the failing X509V3_EXT_conf_nid at
#       src/jcert/jcert.c:214 and RETURNS NORMALLY while leaving
#       "X509 V3 routines::bad ip address" on the thread's error queue
#       (run in a separate fiber: the queue is per-thread and fibers
#       share it),
#   (b) misdirection: the next operation that consults the queue -
#       crypto/load-key on garbage, whose own parse error is
#       "DECODER routines::unsupported" - raises the LEFTOVER
#       "X509 V3 routines::bad ip address" instead, because
#       get_ssl_error_string (src/jutils/error.c:23-27) pops the
#       earliest queued error,
#   (c) under fixed code the queue is empty after every parse, the
#       later raise names the failing load's own error, and the healthy
#       second TLS read on the primed connection still suspends and
#       delivers the delayed "world" payload when the peer sends it at
#       +0.6s.
#
# Proof contract: under the defect the test fails with exactly the
# predicted symptom (a subsequent operation raises the leftover error
# from the earlier parse); under fixed code the whole test passes.

(use assay)
(import jsec/tls :as tls)
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- load-key-own-error
  ``Run crypto/load-key on garbage; return the raised error text (nil if
   it did not raise). The failure's own parse error is
   "DECODER routines::unsupported"; on a dirty queue the raise names
   whatever the queue held instead.``
  []
  (try
    (do (crypto/load-key "not a PEM key at all") nil)
    ([err] (string err))))

(def-suite :name "Parse Paths Dirty Error Queue Regression"
  :description "Ticket 7a8824c6f5: parse paths must leave the OpenSSL error queue empty so later operations are not misled by leftovers"

  (def-test "parse-contaminant-misleads-a-later-operations-raise"
    :timeout 15

    # Control: the failing load's own error text on a clean queue.
    (def clean-err (load-key-own-error))
    (assert clean-err "control: crypto/load-key on garbage must raise")

    (with [server (tls/listen "127.0.0.1" "0")]
      (let [[_ port] (net/localname server)
            contaminated (ev/chan 1)
            server-done (ev/chan 1)]

        # Server fiber: complete the handshake, deliver "hello"
        # immediately, withhold "world" until +0.6s so the observING
        # read below is issued while the peer has nothing more to send.
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
          # delivers the pending "hello" and consumes the one-shot
          # state-machine entry whose incidental ERR_clear_error() would
          # otherwise mask leftovers. The connection is healthy from here.
          (def r1 (:read conn 5 nil 2.0))
          (assert r1 "first read should return the pending hello bytes")
          (assert (= "hello" (string r1))
                  "first read should receive the hello payload")

          # (a) Contamination in a SEPARATE fiber, matching the
          # ticket's cross-fiber scenario: the per-thread queue is
          # shared by all fibers. ev/give/ev/take order the two fibers
          # deterministically: the queue is dirty before the probe
          # below runs.
          (ev/go (fn []
                   (try
                     (ev/give contaminated
                              [:ok (cert/generate-self-signed-cert
                                     {:common-name "1.2.3.4.5"
                                      :key-type :ec-p256
                                      :days-valid 1})])
                     ([err] (ev/give contaminated [:err err])))))
          (def [status info] (ev/take contaminated))
          (assert (= :ok status)
                  (string/format "contaminating parse failed: %q %q"
                                 status info))

          # (b) The queue now holds the parse leftover. A later
          # operation that consults the queue must still report ITS
          # OWN error: crypto/load-key on garbage must raise its own
          # "DECODER routines::unsupported" exactly as the control did.
          # Under the defect get_ssl_error_string pops the earlier
          # leftover first and the raise becomes
          # "X509 V3 routines::bad ip address" - a leftover error
          # raised by an unrelated operation.
          (def dirty-err (load-key-own-error))
          (assert (= clean-err dirty-err)
                  (string/format
                    (string "the OpenSSL error queue must be empty after a parse "
                            "operation, so a subsequent operation raises its own "
                            "error instead of a leftover from the earlier parse: "
                            "got (clean-raise=%q contaminated-raise=%q)")
                    clean-err dirty-err))

          # (c) Reached under fixed code: the healthy second read
          # suspends cleanly and the delayed payload arrives when the
          # peer sends it.
          (def r2 (:read conn 5 nil 2.0))
          (assert r2 "second read should return the delayed payload")
          (assert (= "world" (string r2))
                  "second read should receive the delayed world bytes")

          (ev/give server-done true))))))
