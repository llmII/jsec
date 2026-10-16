# DTLS close and synchronous IO error regression test
# Ticket 89968f746e92f38b0fe73dd6cf566c61938a5d94
#
# "Make dtls/close non-blocking after sending close_notify and raise on
# synchronous DTLS_RESULT_ERROR in dtls/read, dtls/chunk, and dtls/write"
#
# Mechanism (this tree):
#   - cfun_dtls_close (src/jdtls/api/close.c:49-90) sends close_notify
#     through dtls_do_shutdown (close.c:73) and then, with the code
#     comment "RFC-compliant: Send close_notify and wait for peer's"
#     (close.c:69), waits for the peer's close_notify: whenever the
#     shutdown returns WANT_READ it parks the fiber through
#     dtls_client_start_async_close (close.c:85-88,
#     src/jdtls/api/async.c:374-382) with no deadline, so a UDP peer
#     that never answers leaves (:close client) hanging indefinitely.
#     The healthy exchange is mis-ordered too: the CLIENT_OP_CLOSE arm
#     (src/jdtls/api/async.c:218-232) closes the transport with
#     janet_stream_close (async.c:226) BEFORE scheduling the nil result
#     and ending the async op (async.c:240-241), so the close event
#     reaches the still-registered listener and the CLOSE/ERR/HUP arm
#     (async.c:112-120) cancels the completing fiber with "stream
#     error" (async.c:118).
#   - cfun_dtls_read (src/jdtls/api/io.c:105-147) and cfun_dtls_write
#     (io.c:161-191) fall through every non-growth, non-EOF result -
#     DTLS_RESULT_ERROR included - into dtls_client_start_async_read /
#     dtls_client_start_async_write (io.c:142-146, io.c:186-190),
#     parking the fiber on a socket event that may never arrive instead
#     of raising; cfun_dtls_chunk (io.c:210-213) delegates to
#     cfun_dtls_read and inherits the same fall-through.
#   - dtls_do_write returning DTLS_RESULT_EOF (SSL_ERROR_ZERO_RETURN /
#     peer closed, src/jdtls/state_machine.c:63-71) currently completes
#     a dtls/write with nil at both Decision 3b arms: cfun_dtls_write
#     (src/jdtls/api/io.c:177-189) falls the outcome through into
#     dtls_client_start_async_write instead of raising [DTLS:IO], and
#     the parked CLIENT_OP_WRITE completion (src/jdtls/api/async.c:
#     265-267) schedules nil on the same EOF outcome instead of
#     raising [DTLS:IO].
#
# This test demonstrates:
#   (a) (:close client) against a silent peer - one that never answers
#       close_notify - returns nil without waiting,
#   (b) (:close client) against a peer that does answer close_notify
#       returns nil like (:close tls-stream), not the catchable "stream
#       error",
#   (c) dtls/read raises on a synchronous DTLS_RESULT_ERROR instead of
#       parking the fiber,
#   (d) dtls/chunk raises on a synchronous DTLS_RESULT_ERROR instead of
#       parking the fiber,
#   (e) dtls/write raises on a synchronous DTLS_RESULT_ERROR instead of
#       parking the fiber,
#   (f) dtls/write on a peer-closed session with unwritten bytes raises
#       [DTLS:IO] instead of returning nil (ruling Decision 3b: the
#       synchronous cfun_dtls_write fall-through at
#       src/jdtls/api/io.c:177-189 and the parked CLIENT_OP_WRITE
#       completion at src/jdtls/api/async.c:265-267 must both raise
#       [DTLS:IO] when dtls_do_write returns DTLS_RESULT_EOF).
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion - (a) the close hangs
# indefinitely against the silent peer, (b) the close raises the
# catchable "stream error" against the live peer, (c)(d)(e) the
# synchronous error is not raised and the fiber parks waiting for a
# socket event that may never arrive, and (f) the write completes with
# nil where [DTLS:IO] must be raised - and nothing else: no crash, no
# unrelated error. Under fixed code every test passes.

(use assay)
(import ../helpers :prefix "")

# ---------------------------------------------------------------------------
# Shared child plumbing
# ---------------------------------------------------------------------------

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- run-child
  "Spawn a child program under the janet interpreter, sharing this test's
   generated certificates through the environment. Returns
   {:exit n :out stdout :err stderr}."
  [prog]
  (def proc
    (os/spawn ["janet" "-e" prog] :pe
              (merge (os/environ)
                     {"JSEC_TEST_CERT" (certs :cert)
                      "JSEC_TEST_KEY" (certs :key)
                      :out :pipe :err :pipe})))
  (def out-buf @"")
  (def err-buf @"")
  (ev/go (fn [] (when-let [b (:read (proc :out) :all)] (buffer/push out-buf b))))
  (ev/go (fn [] (when-let [b (:read (proc :err) :all)] (buffer/push err-buf b))))
  (def exit (os/proc-wait proc))
  (:close (proc :out))
  (:close (proc :err))
  {:exit exit :out (string out-buf) :err (string err-buf)})

(defn- signal-death-note
  "Human-readable note when the child died by signal (POSIX shell exit
   semantics: status = signal + 128)."
  [exit]
  (case exit
    134 " (died by signal 6 SIGABRT)"
    139 " (died by signal 11 SIGSEGV)"
    ""))

(defn- result-line
  "The child's RESULT line, or a note that none was printed."
  [out]
  (if-let [idx (string/find "RESULT:" out)]
    (string/trim (string/slice out idx))
    (string "(no RESULT line; child stdout: " (string/trim out) ")")))

(defn- parse-elapsed
  "Elapsed seconds from the child's RESULT line, or nil."
  [out]
  (when-let [idx (string/find ":elapsed=" out)]
    (scan-number (string/trim (string/slice out (+ idx 9))))))

# ---------------------------------------------------------------------------
# Child programs
# ---------------------------------------------------------------------------

(def- child-header
  ```
(import jsec/tls :as tls)

(def CERT (os/getenv "JSEC_TEST_CERT"))
(def KEY (os/getenv "JSEC_TEST_KEY"))

(def server (tls/listen "127.0.0.1" "0"
                        {:datagram true :cert CERT :key KEY}))
(def [_ port] (:localname server))
```)

(def- child-prime
  ```
(def client (tls/connect "127.0.0.1" (string port)
                         {:datagram true :verify false}))
(:write client "probe")
(unless (:read client 1024)
  (print "RESULT:setup-failed:no-pong")
  (os/exit 2))
```)

(def- child-outcome
  ```
(def outcome (ev/chan 2))
(ev/go
  (fn []
    (def t0 (os/clock))
    (try
      (do
        (def r OP)
        (ev/give outcome [:returned (describe r) (- (os/clock) t0)]))
      ([err]
        (ev/give outcome [:raised (string err) (- (os/clock) t0)])))))
(ev/go
  (fn []
    (ev/sleep 5)
    (ev/give outcome [:hang "still-suspended-after-5s-watchdog" 0])))
(def [tag a elapsed] (ev/take outcome))
(print "RESULT:"
       (if (= tag :returned) "returned:" (if (= tag :raised) "raised:" "hang:"))
       a ":elapsed=" (string elapsed))
(os/exit 0)
```)

(defn- child-close-program
  "Close scenario: live-peer keeps answering; silent-peer lets the recv
   loop die and stays bound but unprocessed, so close_notify is never
   answered."
  [live-peer]
  (string
    child-header
    (if live-peer
      ``
# The peer keeps answering for the whole scenario.
(ev/go
  (fn []
    (try
      (while (def addr (:recv-from server 1024 (buffer/new 1024)))
        (:send-to server addr "PONG"))
      ([_] nil))))
``
      ``
# The peer answers the handshake and the priming round, then goes silent:
# the recv loop dies at its next deadline (recv-from cancels the fiber with
# its timeout) while the server socket stays bound and unprocessed, so the
# client's close_notify is never answered.
(var serving true)
(ev/go
  (fn []
    (try
      (while serving
        (when (def addr (:recv-from server 1024 (buffer/new 1024) 0.2))
          (:send-to server addr "PONG")))
      ([_] nil))))
``)
    child-prime
    (if live-peer
      "(ev/sleep 0.3)\n"
      "(set serving false)\n(ev/sleep 0.6)\n")
    (string/replace "OP" "(:close client)" child-outcome)))

(defn- child-io-program
  "Synchronous-error scenario for the given operation form: the peer's
   socket is taken out of service, one datagram is written to provoke the
   ICMP port-unreachable answer (a pending ECONNREFUSED on the client's
   connected socket), then the operation under test runs. Its synchronous
   SSL call surfaces SSL_ERROR_SYSCALL, which maps to DTLS_RESULT_ERROR."
  [op]
  (string
    child-header
    ``
# The peer keeps answering through the priming round.
(ev/go
  (fn []
    (try
      (while (def addr (:recv-from server 1024 (buffer/new 1024)))
        (:send-to server addr "PONG"))
      ([_] nil))))
``
    child-prime
    ``
# Take the peer's socket out of service and make the client datagram hit
# the dead port, so the ICMP answer leaves ECONNREFUSED pending on the
# client socket for the operation under test.
(:close server true)
(ev/sleep 0.2)
(:write client "trigger-icmp")
(ev/sleep 0.6)
``
    (string/replace "OP" op child-outcome)))

(defn- child-write-eof-program
  "Peer-closed EOF write scenario (ruling Decision 3b): the peer answers
   through the priming round, then closes cleanly (non-forced close-server
   sends close_notify to the established session and closes the socket);
   the client's read consumes the close_notify so the session is
   peer-closed with the write's bytes still unwritten. The write under
   test runs next; once it has parked, one datagram to the peer's dead
   socket provokes the ICMP answer whose edge resumes the parked write
   completion - the wake a completion observes in production."
  []
  (string
    child-header
    ``
# The peer keeps answering through the priming round.
(ev/go
  (fn []
    (try
      (while (def addr (:recv-from server 1024 (buffer/new 1024)))
        (:send-to server addr "PONG"))
      ([_] nil))))
``
    child-prime
    ``
# Peer close: non-forced close-server sends close_notify to the
# established session and closes the socket. The read consumes the
# close_notify (returns nil) - the session is peer-closed and the
# write's bytes remain unwritten.
(:close server)
(ev/sleep 0.5)
(try (:read client 2048 {:timeout 2}) ([_] nil))
``
    ``
(def outcome (ev/chan 2))
(ev/go
  (fn []
    (def t0 (os/clock))
    (try
      (do
        (def r (:write client ""))
        (ev/give outcome [:returned (describe r) (- (os/clock) t0)]))
      ([err]
        (ev/give outcome [:raised (string err) (- (os/clock) t0)])))))
(ev/go
  (fn []
    (ev/sleep 5)
    (ev/give outcome [:hang "still-suspended-after-5s-watchdog" 0])))
# Once the write under test has parked, one datagram to the peer's dead
# socket provokes the ICMP answer whose EPOLLOUT|EPOLLERR edge resumes
# the parked write completion - the wake a live completion observes.
(ev/sleep 0.3)
(try (:write client "wake-edge") ([_] nil))
(def [tag a elapsed] (ev/take outcome))
(print "RESULT:"
       (if (= tag :returned) "returned:" (if (= tag :raised) "raised:" "hang:"))
       a ":elapsed=" (string elapsed))
(os/exit 0)
``))

# ---------------------------------------------------------------------------
# Suite
# ---------------------------------------------------------------------------

(def-suite :name "DTLS Close And Sync IO Error Regression"
  :description "Ticket 89968f746e: dtls/close returns nil without waiting for the peer, synchronous DTLS_RESULT_ERROR raises in dtls/read, dtls/chunk, and dtls/write, and dtls/write raises [DTLS:IO] on a peer-closed session (Decision 3b)"

  (def-test "dtls-close-against-silent-peer-returns-nil-without-hanging"
    :timeout 30

    (def child (run-child (child-close-program false)))
    (def out (child :out))
    (def res (result-line out))
    (def exit (child :exit))
    (assert (string/find "RESULT:returned:nil" res)
            (string/format
              (string "(:close client) against a silent peer must return "
                      "nil without waiting for the peer's close_notify, "
                      "but the child reported %s - cfun_dtls_close "
                      "(src/jdtls/api/close.c:49-90) sends close_notify "
                      "and then waits for the peer's (the comment at "
                      "close.c:69): whenever dtls_do_shutdown returns "
                      "WANT_READ the fiber is parked through "
                      "dtls_client_start_async_close (close.c:85-88, "
                      "src/jdtls/api/async.c:374-382) with no deadline, "
                      "so against a peer that never answers the close "
                      "hangs indefinitely - the predicted symptom; child "
                      "exit status %d%s; child stdout: %s; child stderr: "
                      "%s")
              res exit (signal-death-note exit) (string/trim out)
              (string/trim (child :err))))

    (def elapsed (parse-elapsed res))
    (assert (and elapsed (<= elapsed 2.0))
            (string/format
              (string "the close took %s s: it must return without "
                      "waiting on the wire (non-blocking unidirectional "
                      "shutdown), not linger toward a peer close_notify "
                      "that never arrives; child stdout: %s")
              (describe elapsed) (string/trim out))))

  (def-test "dtls-close-against-live-peer-returns-nil-not-stream-error"
    :timeout 30

    (def child (run-child (child-close-program true)))
    (def out (child :out))
    (def res (result-line out))
    (def exit (child :exit))
    (assert (string/find "RESULT:returned:nil" res)
            (string/format
              (string "(:close client) against a peer that answers "
                      "close_notify must return nil like "
                      "(:close tls-stream), but the child reported %s - "
                      "the CLIENT_OP_CLOSE completion arm "
                      "(src/jdtls/api/async.c:218-232) closes the "
                      "transport with janet_stream_close (async.c:226) "
                      "BEFORE scheduling the nil result and ending the "
                      "async op (async.c:240-241), so the close event "
                      "reaches the still-registered listener and the "
                      "CLOSE/ERR/HUP arm (async.c:112-120) cancels the "
                      "completing fiber with \"stream error\" "
                      "(async.c:118) - the predicted symptom; child "
                      "exit status %d%s; child stdout: %s; child stderr: "
                      "%s")
              res exit (signal-death-note exit) (string/trim out)
              (string/trim (child :err))))

    (def elapsed (parse-elapsed res))
    (assert (and elapsed (<= elapsed 2.0))
            (string/format
              (string "the close took %s s: it must return without "
                      "waiting on the wire (non-blocking unidirectional "
                      "shutdown); child stdout: %s")
              (describe elapsed) (string/trim out))))

  (def-test "dtls-read-raises-on-synchronous-error-instead-of-parking"
    :timeout 30

    (def child (run-child (child-io-program "(:read client 2048)")))
    (def out (child :out))
    (def res (result-line out))
    (def exit (child :exit))
    (assert (string/find "RESULT:raised:" res)
            (string/format
              (string "(dtls/read client n) must raise on a synchronous "
                      "DTLS_RESULT_ERROR instead of parking the fiber, "
                      "but the child reported %s - cfun_dtls_read "
                      "(src/jdtls/api/io.c:105-147) falls through every "
                      "non-growth, non-EOF result - DTLS_RESULT_ERROR "
                      "included - into dtls_client_start_async_read "
                      "(io.c:142-146): with the peer's socket gone the "
                      "read surfaces SSL_ERROR_SYSCALL, which maps to "
                      "DTLS_RESULT_ERROR (src/jdtls/state_machine.c:"
                      "48-81), yet the fiber parks waiting for a socket "
                      "event that may never arrive - the predicted "
                      "symptom; child exit status %d%s; child stdout: "
                      "%s; child stderr: %s")
              res exit (signal-death-note exit) (string/trim out)
              (string/trim (child :err))))

    (def elapsed (parse-elapsed res))
    (assert (and elapsed (<= elapsed 2.0))
            (string/format
              (string "the operation resolved in %s s: the raise must be "
                      "the synchronous result, not a later completion; "
                      "child stdout: %s")
              (describe elapsed) (string/trim out))))

  (def-test "dtls-chunk-raises-on-synchronous-error-instead-of-parking"
    :timeout 30

    (def child (run-child (child-io-program "(:chunk client 2048)")))
    (def out (child :out))
    (def res (result-line out))
    (def exit (child :exit))
    (assert (string/find "RESULT:raised:" res)
            (string/format
              (string "(dtls/chunk client n) must raise on a synchronous "
                      "DTLS_RESULT_ERROR instead of parking the fiber, "
                      "but the child reported %s - cfun_dtls_chunk "
                      "(src/jdtls/api/io.c:210-213) delegates to "
                      "cfun_dtls_read (io.c:105-147) and inherits its "
                      "fall-through of every non-growth, non-EOF result "
                      "- DTLS_RESULT_ERROR included - into "
                      "dtls_client_start_async_read (io.c:142-146): with "
                      "the peer's socket gone the chunk surfaces "
                      "SSL_ERROR_SYSCALL, which maps to DTLS_RESULT_ERROR "
                      "(src/jdtls/state_machine.c:48-81), yet the fiber "
                      "parks waiting for a socket event that may never "
                      "arrive - the predicted symptom; child exit status "
                      "%d%s; child stdout: %s; child stderr: %s")
              res exit (signal-death-note exit) (string/trim out)
              (string/trim (child :err))))

    (def elapsed (parse-elapsed res))
    (assert (and elapsed (<= elapsed 2.0))
            (string/format
              (string "the operation resolved in %s s: the raise must be "
                      "the synchronous result, not a later completion; "
                      "child stdout: %s")
              (describe elapsed) (string/trim out))))

  (def-test "dtls-write-raises-on-synchronous-error-instead-of-parking"
    :timeout 30

    (def child (run-child (child-io-program "(:write client \"second-datagram\")")))
    (def out (child :out))
    (def res (result-line out))
    (def exit (child :exit))
    (assert (string/find "RESULT:raised:" res)
            (string/format
              (string "(dtls/write client data) must raise on a "
                      "synchronous DTLS_RESULT_ERROR instead of parking "
                      "the fiber, but the child reported %s - "
                      "cfun_dtls_write (src/jdtls/api/io.c:161-191) "
                      "falls through every non-OK result - "
                      "DTLS_RESULT_ERROR included - into "
                      "dtls_client_start_async_write (io.c:186-190): "
                      "with the peer's socket gone the write surfaces "
                      "SSL_ERROR_SYSCALL, which maps to DTLS_RESULT_ERROR "
                      "(src/jdtls/state_machine.c:48-81), yet the fiber "
                      "parks waiting for a socket event that may never "
                      "arrive - the predicted symptom; child exit status "
                      "%d%s; child stdout: %s; child stderr: %s")
              res exit (signal-death-note exit) (string/trim out)
              (string/trim (child :err))))

    (def elapsed (parse-elapsed res))
    (assert (and elapsed (<= elapsed 2.0))
            (string/format
              (string "the operation resolved in %s s: the raise must be "
                      "the synchronous result, not a later completion; "
                      "child stdout: %s")
              (describe elapsed) (string/trim out))))

  (def-test "dtls-write-raises-dtls-io-on-peer-closed-session-with-unwritten-bytes"
    :timeout 30

    (def child (run-child (child-write-eof-program)))
    (def out (child :out))
    (def res (result-line out))
    (def exit (child :exit))
    (assert (string/find "RESULT:raised:[DTLS:IO]" res)
            (string/format
              (string "a dtls/write against a peer-closed session with "
                      "unwritten bytes must raise [DTLS:IO] instead of "
                      "returning nil (ruling Decision 3b), but the child "
                      "reported %s - both arms currently complete the "
                      "write with nil: cfun_dtls_write "
                      "(src/jdtls/api/io.c:177-189) falls the synchronous "
                      "DTLS_RESULT_EOF outcome (SSL_ERROR_ZERO_RETURN or "
                      "SSL_ERROR_SYSCALL with the write returning 0, "
                      "src/jdtls/state_machine.c:63-71) through into "
                      "dtls_client_start_async_write instead of raising, "
                      "and the parked CLIENT_OP_WRITE completion "
                      "(src/jdtls/api/async.c:265-267) schedules nil on "
                      "the same EOF outcome instead of raising [DTLS:IO] "
                      "- the predicted symptom; child exit status %d%s; "
                      "child stdout: %s; child stderr: %s")
              res exit (signal-death-note exit) (string/trim out)
              (string/trim (child :err))))

    (def elapsed (parse-elapsed res))
    (assert (and elapsed (<= elapsed 2.0))
            (string/format
              (string "the write resolved in %s s: the [DTLS:IO] raise "
                      "must decide the write's unwritten bytes at the "
                      "call, not linger toward a completion; child "
                      "stdout: %s")
              (describe elapsed) (string/trim out)))))
