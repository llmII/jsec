# Stale pending_read/pending_write after external cancellation regression test
# Ticket c7dd939d28592faaea4b36489c10c88414a93113
#
# "pending_read/pending_write go stale after cancellation causing hot spin"
#
# Mechanism (this tree, 0.2.0 basis, src/jtls/state_machine.c):
#   - jtls_attempt_io records the op's fiber in tls->pending_read
#     (state_machine.c:553) or tls->pending_write (:555) and clears the
#     slot only on COMPLETE (:582/:584) or ERROR (:688/:690).
#   - External cancellation of a suspended op (timed read expiry,
#     ev/with-deadline, ev/cancel) takes janet_cancel -> resume ->
#     janet_fiber_did_resume -> janet_async_end (core/ev.c:327, 274-291).
#     jtls_async_callback's JANET_ASYNC_EVENT_DEINIT case is a bare no-op
#     here (state_machine.c:795-797), so the slot is never cleared: the
#     fiber pointer in tls->pending_read outlives the operation.
#   - The stale slot then drives the cooperative-mode decision in
#     jtls_attempt_io: a WRITE that needs READ keeps its WRITE-only
#     registration (state_machine.c:646-651) because a reader "appears"
#     to exist, instead of registering for READ (:651) and consuming the
#     peer's handshake bytes.
#   - The HUP/CLOSE/ERR completion paths in jtls_async_callback have the
#     same gap for the opposite reason: they NULL the fiber ev_state
#     field before janet_async_end (so the DEINIT callback cannot clear
#     on their behalf) and never touch the slot.
#
# Expected contract after the fix:
#   (a) an externally cancelled TLS op leaves no pending slot behind
#       (DEINIT clears the matching slot when the operation state is
#       still reachable; HUP/CLOSE/ERR completion paths clear it too),
#   (b) the subsequent write that needs READ suspends cleanly and either
#       completes once the peer supplies handshake data, or raises at
#       its own deadline,
#   (c) CPU stays near idle over the wait (no busy re-entry loop).
#
# Shape: the scenario runs in a SUBPROCESS and the parent asserts from
# the outside (same idiom as suites/regression/suite-timed-read-timeout-crash.janet).
# The child measures CPU vs wall over the write window and prints
# RESULT:cpu:N wall:M plus the read/write outcomes; a watchdog bounds the
# run so a busy loop cannot starve the harness.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def- child-program
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(defn cpu [] (os/clock :cputime))
(defn wall [] (os/clock :monotonic))

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))
(def listener (tls/listen "127.0.0.1" "0" {:cert (certs :cert) :key (certs :key)}))
(def [host port] (net/localname listener))
(def ready (ev/chan 1))
(def hold (ev/chan 1))
(def cconn (net/connect host (string port)))

# Raw client: stays silent until told, then runs a real TLS handshake so a
# healthy write has everything it needs to complete.
(ev/go (fn []
         (try
           (do
             (ev/take ready)
             (ev/take hold)
             (with [tc (tls/wrap cconn "127.0.0.1" {:verify false})]
               (ev/sleep 5)))
           ([err] nil))))

(def c (tls/accept listener {:cert (certs :cert) :key (certs :key)}))
(ev/give ready true)

# Watchdog: bound the whole run; report CPU vs wall of the write window.
(def cpu0 (cpu))
(def wall0 (wall))
(ev/go (fn []
         (ev/sleep 4.5)
         (print (string/format "RESULT:cpu:%.3f wall:%.3f"
                               (- (cpu) cpu0) (- (wall) wall0)))
         (flush)
         (os/exit 0)))

# Canonical staleness trigger: timed read expires with no peer data.
(def read-outcome
  (try
    (do (def r (:read c 1024 nil 0.4)) (string "returned:" (describe r)))
    ([err] (string "error:" err))))
(print "READ:" read-outcome)

# Subsequent write that needs READ (lazy handshake, ClientHello not sent).
# Under the defect the stale tls pending_read slot keeps this registered
# for WRITE only. Let the peer speak a little after the write suspends so
# a healthy registration can make progress.
(def wdone (ev/chan 1))
(ev/go (fn []
         (def wo (try (do (:write c "bye" 2.0) "returned:nil")
                   ([err] (string "error:" err))))
         (ev/give wdone wo)))
(ev/sleep 0.3)
(ev/give hold true)
(def write-outcome (ev/take wdone))
(print "WRITE:" write-outcome)
(print (string/format "RESULT:cpu:%.3f wall:%.3f"
                      (- (cpu) cpu0) (- (wall) wall0)))
(flush)
(os/exit 0)
```)

(defn- run-child
  "Spawn the scenario under the janet interpreter. Returns
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
  [exit]
  (case exit
    134 " (died by signal 6 SIGABRT: glibc abort after free(): invalid pointer)"
    139 " (died by signal 11 SIGSEGV)"
    ""))

(defn- parse-cpu-wall
  [out]
  (when-let [m (string/find "RESULT:cpu:" out)]
    (def line (string/trim (string (string/slice out m))))
    (def parts (string/split " " (first (string/split "\n" line))))
    (def cpu-val (scan-number (string/trim (string/slice (parts 0) (length "RESULT:cpu:")))))
    (def wall-val (scan-number (string/trim (string/slice (parts 1) (length "wall:")))))
    [cpu-val wall-val]))

(def-suite :name "Pending Slot Stale After Cancel Regression"
  :description "Ticket c7dd939d28: a cancelled TLS op must not leave a stale pending slot that hijacks a later write's registration"

  (def-test "write after an expired timed read suspends cleanly instead of burning CPU or dying"
    :timeout 60

    (def child (run-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The cancelled read must expire as a plain Janet error. On this
    # branch the process dies first with the embedded-state free crash
    # (ticket 6e1a853d70), which is reported verbatim below.
    (assert (= 0 exit)
            (string/format
              (string "child died during the scenario instead of finishing: "
                      "exit status %d%s; child stdout: %s; child stderr: %s")
              exit (signal-death-note exit) (string/trim out) (string/trim err)))

    (assert (string/find "READ:error:timeout" out)
            (string/format
              (string "the timed read must expire with the \"timeout\" error "
                      "(ev/read contract); child stdout: %s; child stderr: %s")
              (string/trim out) (string/trim err)))

    # (b) The follow-up write must terminate cleanly: either complete once
    # the peer handshakes, or raise at its own deadline. Getting stuck in a
    # busy re-entry loop shows up as CPU ~= wall below.
    (assert (or (string/find "WRITE:returned:nil" out)
                (string/find "WRITE:error:timeout" out))
            (string/format
              (string "the write after the cancelled read must complete or "
                      "raise at its own deadline; child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err)))

    # (c) CPU must stay near idle across the scenario. A stale slot that
    # drives the cooperative-mode loop burns CPU; the numbers are printed
    # by the child as RESULT:cpu:N wall:M.
    (def cw (parse-cpu-wall out))
    (assert cw
            (string/format "child did not report RESULT:cpu:N wall:M; child stdout: %s"
                           (string/trim out)))
    (def [cpu-val wall-val] cw)
    (assert (< cpu-val (* 0.25 wall-val))
            (string/format
              (string "the write after the cancelled read burned CPU instead of "
                      "suspending cleanly: cpu %.3fs over wall %.3fs; "
                      "child stdout: %s")
              cpu-val wall-val (string/trim out)))))
