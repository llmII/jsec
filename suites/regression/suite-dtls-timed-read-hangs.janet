# Timed DTLS read timeout regression test
# Ticket 683cb79c3b1d8445856a705697cf4ca7f472283f
#
# "Timed DTLS reads ignore their timeout and hang forever"
#
# Mechanism (this tree):
#   The documented deadline is decorative on every client I/O path - it
#   is stored (sometimes) and never armed, and the documented &opt
#   timeout arguments are never read:
#   - src/jdtls/api/io.c:15 documents (dtls/read client n &opt buf
#     timeout) and cfun_dtls_read (io.c:20-62) accepts argc 2..4
#     (io.c:21) but reads only the buffer at argv[2] (io.c:36); argv[3],
#     the timeout, is never inspected anywhere in io.c:20-62.
#   - src/jdtls/api/io.c:65 documents (dtls/write client data &opt
#     timeout) and cfun_dtls_write (io.c:70-98) accepts argc 2..3
#     (io.c:71) and never reads argv[2] at all.
#   - The live client continuations take no deadline: the read's
#     suspension is started by dtls_client_start_async_read
#     (src/jdtls/api/async.c:331-343, janet_async_start at :341-342) and
#     the write's by dtls_client_start_async_write
#     (src/jdtls/api/async.c:345-356, janet_async_start at :354-355);
#     neither ever calls janet_addtimeout, and their WANT_READ/WANT_WRITE
#     re-arms at src/jdtls/api/async.c:245-260 do not either.
#   - The DTLS_OP_* starters store a deadline they never arm:
#     dtls_async_read writes data->state.timeout at
#     src/jdtls/state_machine.c:569 (:561-569) and dtls_async_write at
#     src/jdtls/state_machine.c:603 (:596-603); both currently have no
#     callers, so on the live paths the deadline is not even stored.
#   - The only janet_addtimeout in src/jdtls is src/jdtls/server.c:757,
#     on the recv-from path - the pattern exists and is simply not
#     applied to client I/O.
#   jtls does this correctly: parse_timeout_opt reads the argv timeout
#   (src/jtls/api/io.c:52-82, negative timeouts raise at :76-79) and the
#   deadline is armed with janet_addtimeout at first suspension
#   (src/jtls/state_machine.c:526-531), which cancels the fiber with
#   "timeout" on expiry - the ev/read contract this test asserts.
#
# This test demonstrates:
#   (a) (dtls/read client 5 buf 0.2) with no application data ever
#       arriving must return or raise at the 0.2s deadline; under the
#       defect the deadline is never armed and the read hangs forever -
#       the scenario runs in a subprocess whose independent 5s watchdog
#       observes the hang from the outside (mirroring
#       suite-timed-read-timeout-crash.janet's subprocess shape),
#   (b) the documented &opt timeout arguments of dtls/read and dtls/write
#       are actually read and validated: a negative timeout must be
#       rejected the way jtls parse_timeout_opt rejects it
#       (src/jtls/api/io.c:76-79), not silently accepted. The write-side
#       DEADLINE cannot be exercised on this Linux platform - a UDP send
#       never suspends on loopback (300 x 8 KiB writes produced 0
#       suspensions), so the arg-consumption surface is the exhibitable
#       half for dtls/write; the deadline itself is proved on the read
#       side in (a).
#
# Proof contract: under the defect each test fails with exactly the
# predicted symptom named in its final assertion - (a) "the timed DTLS
# read never returned at its 0.2s deadline: the 5s watchdog found it
# still suspended (the &opt timeout is dropped unread and the operation
# never arms janet_addtimeout, so the read hangs forever)" and (b)
# "dtls/read (or dtls/write) dropped its &opt timeout argument unread: a
# negative timeout was silently accepted" - and nothing else: no crash,
# no unrelated error. Under fixed code every test passes.
(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

# =============================================================================
# Child program for (a): the timed read with no data, plus a watchdog
# =============================================================================

(def- child-program
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))
(def server (tls/listen "127.0.0.1" "0"
                         {:datagram true :cert (certs :cert) :key (certs :key)}))
(def [_ port] (:localname server))

# Server fiber: recv-from handles the handshake transparently and only
# returns on application data; answer the priming round with PONG, then
# stay silent so the timed read below has no data to wake it.
(ev/go
  (fn []
    (try
      (do
        (while (def addr (:recv-from server 1024 (buffer/new 1024)))
          (:send-to server addr "PONG")))
      ([_] nil))))

(def client (tls/connect "127.0.0.1" (string port)
                          {:datagram true :verify false}))

# Priming round: complete the handshake and prove the session is live.
(:write client "probe")
(def pong (:read client 1024))

(def outcome (ev/chan 2))

# The timed read under the test: the documented &opt timeout must bound
# the wait. No application data will ever arrive.
(ev/go
  (fn []
    (def t0 (os/clock))
    (try
      (do
        (def r (:read client 5 nil 0.2))
        (ev/give outcome [:returned (describe r) (- (os/clock) t0)]))
      ([err]
        (ev/give outcome [:raised (string err) (- (os/clock) t0)])))))

# Watchdog, independent of the read. A read that honors its deadline
# completes in well under a second; the watchdog only fires when the
# deadline is decorative and the read is still suspended.
(ev/go
  (fn []
    (ev/sleep 5)
    (ev/give outcome [:hang nil 0])))

(def [tag a b] (ev/take outcome))
(when (= tag :hang)
  (print "RESULT:hang:read-still-suspended-after-5s")
  (os/exit 3))
(print "RESULT:" (if (= tag :returned) "returned:" "error:") a
       ":elapsed=" (string b))
(os/exit 0)
```)

(defn- run-timed-read-child
  "Spawn the timed-read scenario under the janet interpreter. Returns
   {:exit n :out stdout :err stderr}."
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

(defn- signal-death-note
  "Human-readable note when the child died by signal (POSIX shell exit
   semantics: status = signal + 128)."
  [exit]
  (case exit
    134 " (died by signal 6 SIGABRT)"
    139 " (died by signal 11 SIGSEGV)"
    ""))

(defn- parse-elapsed
  "Elapsed seconds from the child's RESULT line, or nil."
  [out]
  (when-let [idx (string/find ":elapsed=" out)]
    (scan-number (string/trim (string/slice out (+ idx 9))))))

# =============================================================================
# Shared loopback for the arg-consumption tests (b)
# =============================================================================

(defn- with-pong-loopback
  "Run body with conn bound to a live DTLS client whose server answers
   every application datagram with PONG. body is a function of conn."
  [body]
  (with [server (tls/listen "127.0.0.1" "0" {:datagram true
                                             :cert (certs :cert)
                                             :key (certs :key)})]
    (let [[_ port] (:localname server)]
      (ev/go
        (fn []
          (try
            (do
              (while (def addr (:recv-from server 1024 (buffer/new 1024)))
                (:send-to server addr "PONG")))
            ([_] nil))))
      (def conn (tls/connect "127.0.0.1" (string port)
                             {:datagram true :verify false}))
      (defer (:close conn true)
        # Priming round: complete the handshake and prove the session is live.
        (:write conn "probe")
        (def pong (:read conn 1024))
        (assert pong "priming read should return the PONG payload")
        (body conn)))))

(def-suite :name "DTLS Timed Read Timeout Regression"
  :description "Ticket 683cb79c3b: timed DTLS reads honor their &opt timeout deadline instead of hanging forever"

  (def-test "timed-read-with-no-data-returns-or-raises-at-deadline"
    :timeout 30

    (def child (run-timed-read-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The read must complete at its deadline - return or raise - not
    # hang. Under the defect the 0.2s timeout is dropped unread, the
    # suspension never arms janet_addtimeout, and only the watchdog ends
    # the scenario.
    (assert (or (string/find "RESULT:returned:" out)
                (string/find "RESULT:error:" out))
            (string/format
              (string "the timed DTLS read never returned at its 0.2s "
                      "deadline: the 5s watchdog found it still suspended "
                      "(the &opt timeout is dropped unread at "
                      "src/jdtls/api/io.c:20-62 and the operation never "
                      "arms janet_addtimeout, so the read hangs forever); "
                      "child exit status %d%s; child stdout: %s; "
                      "child stderr: %s")
              exit (signal-death-note exit) (string/trim out)
              (string/trim err)))

    # The completion must sit AT the deadline: a premature return would
    # be a false EOF, a late one is not the deadline contract.
    (def elapsed (parse-elapsed out))
    (assert (and elapsed (>= elapsed 0.15) (<= elapsed 2.0))
            (string/format
              (string "the timed DTLS read completed in %s s: it must "
                      "return or raise AT its 0.2s deadline (ev/read "
                      "timeout semantics), neither before waiting for "
                      "data nor long after; child stdout: %s")
              (describe elapsed) (string/trim out))))

  (def-test "read-timeout-argument-is-read-and-validated"
    :timeout 20

    (with-pong-loopback
      (fn [conn]
        # A finite timeout on a completing read is accepted and the data
        # is delivered.
        (:write conn "ping")
        (def r (:read conn 1024 @"" 0.2))
        (assert r "a timed read with data available must deliver it")

        # The argument must be consumed and validated like jtls
        # parse_timeout_opt (src/jtls/api/io.c:52-82): a negative
        # deadline is a parameter error, not a silently ignored value.
        (:write conn "ping2")
        (var outcome :no-call)
        (try
          (set outcome (:read conn 1024 @"" -1))
          ([e] (set outcome [:raised (string e)])))
        (assert (and (tuple? outcome) (= :raised (get outcome 0)))
                (string/format
                  (string "dtls/read dropped its &opt timeout argument "
                          "unread: a negative timeout was silently "
                          "accepted and the read completed (callers who "
                          "pass a timeout get no deadline; the argv "
                          "timeout is never read at "
                          "src/jdtls/api/io.c:20-62). Expected a "
                          "parameter error like jtls parse_timeout_opt "
                          "(src/jtls/api/io.c:76-79); got %s")
                  (describe outcome))))))

  (def-test "write-timeout-argument-is-read-and-validated"
    :timeout 20

    (with-pong-loopback
      (fn [conn]
        # A finite timeout on a completing write is accepted and the
        # write reports its byte count.
        (def n (:write conn "hello" 0.2))
        (assert (and (number? n) (pos? n))
                "a timed write with a live connection must return the byte count")

        # The argument must be consumed and validated like jtls
        # parse_timeout_opt (src/jtls/api/io.c:52-82): a negative
        # deadline is a parameter error, not a silently ignored value.
        (var outcome :no-call)
        (try
          (set outcome (:write conn "hello2" -1))
          ([e] (set outcome [:raised (string e)])))
        (assert (and (tuple? outcome) (= :raised (get outcome 0)))
                (string/format
                  (string "dtls/write dropped its &opt timeout argument "
                          "unread: a negative timeout was silently "
                          "accepted and the write completed (callers who "
                          "pass a timeout get no deadline; the argv "
                          "timeout is never read at "
                          "src/jdtls/api/io.c:70-98). Expected a "
                          "parameter error like jtls parse_timeout_opt "
                          "(src/jtls/api/io.c:76-79); got %s")
                  (describe outcome)))))))
