# Timed TLS read expiry crash regression test
# Ticket 6e1a853d702ec10d7f173a7ce819dba3fef008f2
#
# "Timed TLS read that expires with no data crashes (SIGSEGV)"
#
# A timed TLS read whose deadline expires with no data from the peer
# kills the process: glibc prints "free(): invalid pointer" and aborts
# (SIGABRT; on libcs without the header check the same invalid free
# surfaces as SIGSEGV).
#
# Mechanism (this tree, 0.2.0 basis):
#   - cfun_read/cfun_chunk/cfun_write store the operation state in the
#     TLSState EMBEDDED in TLSStream (src/jtls/api/io.c:113,
#     src/jtls/internal.h:247-248) and jtls_schedule_async passes that
#     interior pointer to janet_async_start as fiber->ev_state
#     (src/jtls/state_machine.c:528). No heap allocation is involved -
#     see the comment at state_machine.c:515-517.
#   - Every jsec-side janet_async_end call NULLs fiber->ev_state first
#     ("Clear ev_state before janet_async_end to prevent double-free
#     (state is embedded in TLSStream, not heap-allocated)"),
#     state_machine.c:507,629,698,714,782,837,868,881,892,899,906,923.
#   - The one path jsec does not drive is external cancellation. When
#     the deadline fires, Janet cancels the fiber ("timeout",
#     core/ev.c:1553), and on resume calls janet_fiber_did_resume ->
#     janet_async_end (core/ev.c:327). janet_async_end invokes the
#     async callback with JANET_ASYNC_EVENT_DEINIT and then
#     janet_free(fiber->ev_state) (core/ev.c:287). jtls_async_callback's
#     DEINIT case is a no-op (src/jtls/state_machine.c:795-796), so
#     ev_state still points at the embedded TLSState and janet_free
#     frees an interior pointer -> "free(): invalid pointer" -> abort.
#
# Observed failure (defect): the process dies with
#   free(): invalid pointer
#   exit status 134 (SIGABRT + 128)
# and the read never returns or raises anything.
#
# Correct expiry contract (Janet ev/read / net/read semantics):
# (net/read stream nbytes &opt buf timeout) documents "Takes an
# optional timeout in seconds, after which will raise an error", and
# the timed-read deadline arms janet_addtimeout, which on expiry runs
# janet_cancel(fiber, "timeout") (core/ev.c:1553). So under fixed code
# (:read s n buf timeout) with no peer data must RAISE the Janet error
# "timeout", catchable in a try like any other error - exactly what a
# plain (net/read s n buf timeout) does on a bare TCP stream. It must
# not return, not hang, and not kill the process.
#
# Shape: the crash kills the process, so the scenario runs in a
# SUBPROCESS (os/spawn of the janet interpreter on a child program) and
# the parent test asserts from the outside:
#   (a) the child exits 0 instead of dying by signal (exit 134 = SIGABRT
#       or 139 = SIGSEGV under the defect),
#   (b) the child reports that the timed read raised the "timeout"
#       error (RESULT:error:timeout on its stdout).
# The failure message embeds the child's exit status and stderr so the
# defect's crash text is visible in the failing output.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# Child program: TLS loopback, client completes the handshake and never
# sends application data, server performs a timed read with a short
# deadline. Prints RESULT:error:<err> if the read raises (expected under
# the fix: "timeout"), RESULT:returned:<value> if it somehow returns,
# then exits 0. Under the defect the process dies before any RESULT
# line: glibc's "free(): invalid pointer" goes to stderr and the exit
# status is 128+signal.
(def- child-program
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))
(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))
(def addr {:host host :port (string port)})
(def ready (ev/chan 1))

(ev/go (fn []
         (try
           (with [conn (net/connect (addr :host) (addr :port))]
             (with [c (tls/wrap conn {:verify false})]
               (ev/give ready true)
               (ev/sleep 5)))
           ([err] (ev/give ready (string "client error: " err))))))

(with [conn (:accept server)]
  (with [s (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
    (def rv (ev/take ready))
    (unless (= true rv)
      (print "SETUP-FAILED:" rv)
      (os/exit 2))
    (try
      (do
        (def r (:read s 5 nil 0.2))
        (print "RESULT:returned:" (describe r)))
      ([err]
        (print "RESULT:error:" err)))))
(os/exit 0)
```)

(defn- run-timed-read-child
  "Spawn the crash scenario under the janet interpreter. Returns
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
    134 " (died by signal 6 SIGABRT: glibc abort after free(): invalid pointer)"
    139 " (died by signal 11 SIGSEGV)"
    ""))

(def-suite :name "Timed Read Timeout Crash Regression"
  :description "Ticket 6e1a853d70: timed TLS read expiry with no peer data must raise timeout, not kill the process"

  (def-test "timed TLS read expiring with no data raises timeout instead of crashing"
    :timeout 30

    (def child (run-timed-read-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The child must survive: a timed read that expires with no data
    # is a normal error condition, not a process-fatal one. Under the
    # defect this fails with exit 134/139 and the crash text below.
    (assert (= 0 exit)
            (string/format
              (string "timed TLS read expiry killed the process instead of "
                      "raising a Janet error: child exit status %d%s; "
                      "child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))

    # (b) The failure mode under the fix must be exactly the expiry
    # contract of (ev/read stream n buf timeout) / (net/read ...):
    # the read raises "timeout".
    (assert (string/find "RESULT:error:timeout" out)
            (string/format
              (string "timed TLS read must raise the \"timeout\" error on "
                      "expiry (ev/read contract); child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err)))))
