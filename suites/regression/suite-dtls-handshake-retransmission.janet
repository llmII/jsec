# DTLS handshake flight retransmission regression test
# Ticket 5689f2ba70f1c6936e4b003ddf3719df55a2b3a8
#
# "Drive DTLSv1_get_timeout and DTLSv1_handle_timeout for DTLS handshake
#  retransmission"
#
# Mechanism (this tree, branch ticket-5689f2ba70... off 0.2.0 at
# 2eef29afaf): the architecture note in src/jdtls/state_machine.c:30-37
# says DTLS integrates DTLSv1_get_timeout() and DTLSv1_handle_timeout()
# with Janet's event loop, but no call site of either exists anywhere in
# src/ - the only matches are that comment (state_machine.c:34-35).
# Neither the client connect/handshake machinery (src/jdtls/api/async.c)
# nor the DTLS server datagram path (src/jdtls/server.c) ever queries
# the DTLS flight timer or triggers a retransmission, and nothing
# schedules a timer while SSL_ERROR_WANT_READ is pending on a handshake.
# Over UDP, a single dropped or reordered handshake flight datagram
# therefore stalls the handshake indefinitely until the caller's outer
# operation timeout expires: the flight in the wbio is never resent.
# The ruled fix (2026-10-11, INDEX.org Ruling 2.6a) queries
# DTLSv1_get_timeout while a DTLS handshake is in progress, schedules
# retransmission timers on Janet's event loop, calls DTLSv1_handle_timeout
# when the flight timer fires before a peer datagram arrives, and flushes
# the retransmitted flight in wbio to the UDP socket - while
# distinguishing retransmission timer ticks from the caller's overall
# handshake deadline.
#
# This test demonstrates: a DTLS client whose FIRST handshake flight
# datagram is dropped by a one-shot lossy UDP relay must still complete
# the handshake - the client retransmits its flight after the DTLS
# flight timer, the relay forwards the retransmission, and the server
# answers it. The scenario runs in a subprocess whose independent
# watchdog observes the stall from the outside (the pattern of
# suites/regression/suite-dtls-timed-read-hangs.janet).
#
# Proof contract: under the defect the test fails with exactly the
# predicted symptom - "the DTLS handshake stalled: the dropped first
# flight datagram was never retransmitted ... the handshake stalls
# indefinitely until the caller's outer operation timeout expires" -
# and nothing else: no crash, no unrelated error. Under fixed code the
# handshake completes and every test passes.

(use assay)
(import ../helpers :prefix "")

# =============================================================================
# Child program: jsec DTLS server, one-shot lossy relay, jsec DTLS client
# =============================================================================

(def- child-program
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(defn finish [tag msg dropped forwarded]
  (print "RESULT:" tag ":" msg)
  (print "RELAY:dropped=" (string dropped) " forwarded=" (string forwarded))
  (flush))

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))

# The real peer: a jsec DTLS server. recv-from drives the handshake
# transparently and only returns on application data; answer every
# application datagram with PONG.
(def server (tls/listen "127.0.0.1" "0"
                         {:datagram true :cert (certs :cert) :key (certs :key)}))
(def [_ server-port] (:localname server))

(ev/go
  (fn []
    (try
      (do
        (while (def addr (:recv-from server 2048 (buffer/new 2048)))
          (:send-to server addr "PONG")))
      ([_] nil))))

# One-shot lossy relay: one UDP socket in the middle, forwarding both
# directions, dropping the FIRST client-side datagram - the initial
# handshake flight - exactly once.
(def relay (net/listen "127.0.0.1" "0" :datagram))
(def [_ relay-port] (net/localname relay))
(def server-addr (net/address "127.0.0.1" (string server-port)))
(var client-addr nil)
(var dropped 0)
(var forwarded 0)

(defn same-peer? [a b]
  (and a b (deep= (net/address-unpack a) (net/address-unpack b))))

(ev/go
  (fn []
    (try
      (do
        (forever
          (def buf (buffer/new 2048))
          (def src (net/recv-from relay 2048 buf))
          (cond
            (same-peer? src client-addr)
            (do (net/send-to relay client-addr buf) (++ forwarded))

            (and client-addr (= (last (net/address-unpack src)) server-port))
            (do (net/send-to relay client-addr buf) (++ forwarded))

            (do
              (unless client-addr (set client-addr src))
              (if (= dropped 0)
                (++ dropped)
                (do (net/send-to relay server-addr buf) (++ forwarded)))))))
      ([_] nil))))

# The client under test: a full DTLS connect through the relay. With the
# first flight dropped, only a retransmission can move the handshake.
(ev/go
  (fn []
    (try
      (do
        (def client (tls/connect "127.0.0.1" (string relay-port)
                                 {:datagram true :verify false}))
        (:write client "probe")
        (def pong (:read client 2048))
        (finish "ok" "handshake-completed-despite-dropped-first-flight"
                dropped forwarded)
        (os/exit 0))
      ([err]
        (finish "error" (string err) dropped forwarded)
        (os/exit 0)))))

# Watchdog: the handshake must complete in well under this budget once
# the flight is retransmitted (OpenSSL's first DTLS flight timer is 1s).
# The watchdog fires only when nothing retransmits and the handshake
# stalls - the predicted symptom.
(ev/go
  (fn []
    (ev/sleep 10)
    (finish "hang"
            "no-retransmission-of-the-dropped-handshake-flight"
            dropped forwarded)
    (os/exit 3)))
```)

(defn- run-retransmission-child
  "Spawn the lossy-relay handshake scenario under the janet interpreter.
   Returns {:exit n :out stdout :err stderr}."
  []
  (def proc (os/spawn ["janet" "-e" child-program] :p {:out :pipe :err :pipe}))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

(def-suite :name "DTLS Handshake Retransmission Regression"
  :description "Ticket 5689f2ba70: a dropped DTLS handshake flight datagram is retransmitted and the handshake completes"

  (def-test "dropped-first-flight-datagram-is-retransmitted-and-handshake-completes"
    :timeout 30

    (def child (run-retransmission-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # The relay must actually have dropped exactly one client datagram -
    # otherwise this run proved nothing.
    (assert (string/find "RELAY:dropped=1" out)
            (string/format
              (string "the lossy relay did not drop exactly one "
                      "client-side datagram (child stdout: %s; child "
                      "stderr: %s)")
              (string/trim out) (string/trim err)))

    # The handshake must complete despite the dropped flight: the client
    # retransmits after DTLSv1_get_timeout and the relay forwards the
    # retransmission. Under the defect nothing ever calls
    # DTLSv1_handle_timeout, no retransmission leaves the wbio, and the
    # watchdog observes the stall - the predicted symptom.
    (assert (string/find "RESULT:ok:handshake-completed" out)
            (string/format
              (string "the DTLS handshake stalled: the dropped first "
                      "flight datagram was never retransmitted (the "
                      "handshake stalls indefinitely until the caller's "
                      "outer operation timeout expires - neither the "
                      "client machinery in src/jdtls/api/async.c nor the "
                      "server datagram path in src/jdtls/server.c ever "
                      "calls DTLSv1_get_timeout or "
                      "DTLSv1_handle_timeout, so the flight in wbio is "
                      "never resent). Child exit status %d; child "
                      "stdout: %s; child stderr: %s")
              exit (string/trim out) (string/trim err)))))
