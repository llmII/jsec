# Fiber GC frees embedded TLSState ev_state regression test
# Ticket 1377def05cbc5c1fd3de4ff928323a20efaf5f8e
#
# "Fiber GC frees the embedded TLSState ev_state as if heap-allocated"
#
# Mechanism (this tree, ticket branch off 0.2.0):
#   - The per-operation states are EMBEDDED in TLSStream: struct TLSState
#     at src/jtls/internal.h:177-210, read_state and write_state at
#     src/jtls/internal.h:247-248 inside struct TLSStream at
#     src/jtls/internal.h:233. No heap allocation is involved.
#   - jtls_schedule_async hands that interior pointer to
#     janet_async_start (src/jtls/state_machine.c:530), which registers
#     janet_vm.root_fiber (core/ev.c:312-313) and stores the pointer in
#     fiber->ev_state (core/ev.c:308).
#   - Every jsec-driven janet_async_end clears ev_state first - the
#     JANET_ASYNC_EVENT_DEINIT case nulls it (src/jtls/state_machine.c:
#     797-803, the 6e1a853d70 fix) and the completion and error paths
#     clear before ending.
#   - The path jsec does not drive is the fiber deinit free: when a fiber
#     is freed while a registration is still live, the
#     JANET_MEMORY_FIBER case of janet_deinit_block frees ev_state as if
#     it were heap-allocated - janet_free(f->ev_state) at core/gc.c:338
#     (case at core/gc.c:333-341). That is an interior pointer into the
#     TLSStream block, so glibc aborts with "free(): invalid pointer".
#   - Nothing at teardown ends the registration first: the transport's
#     own GC only runs janet_stream_close_impl (core/ev.c:405-409), which
#     closes the handle WITHOUT dispatching CLOSE to listeners, and
#     jtls_stream_gc (src/jtls/types.c:62-84) frees SSL state but never
#     clears a parked fiber's ev_state or the pending slots
#     (src/jtls/internal.h:244-245). os/exit runs janet_deinit
#     (core/os.c:287) into janet_clear_memory (core/gc.c:668-689), which
#     frees every GC block in list order - the fiber block frees the
#     interior pointer whether the TLSStream block is freed before or
#     after it.
#
# This test demonstrates:
#   (a) a fiber parked on a suspended TLS read (the peer never sends) is
#       still registered with ev_state pointing into the embedded
#       TLSState when the process begins teardown - the child reaches
#       os/exit with the read still parked (RESULT: line),
#   (b) that teardown must exit cleanly (status 0) - under the defect
#       the process dies instead: glibc "free(): invalid pointer" and
#       exit 134 (SIGABRT), or SIGSEGV / exit 139 on libcs without the
#       chunk-header check.
#
# Proof contract: the scenario is deterministic (subprocess isolation,
# the read is parked synchronously before teardown, and no path can end
# the registration once parked). It fails on purpose under the defect
# with exactly the predicted abort and becomes the regression guard
# after the fix lands.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# Child program: TLS loopback, handshake completes, then a fiber parks
# on a blocking TLS read that can never complete (the peer sends no
# application data and keeps the connection open). The main fiber waits
# long enough for the read to suspend and register, prints RESULT, and
# calls os/exit while the read fiber is still parked - the teardown
# free path under test. Under the defect the process dies inside
# janet_deinit before any exit status is reported to the shell.
(def- parked-fiber-child-program
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

(def conn (:accept server))
(def s (tls/wrap conn {:cert (certs :cert) :key (certs :key)}))
(def rv (ev/take ready))
(unless (= true rv)
  (print "SETUP-FAILED:" rv)
  (os/exit 2))

# Park a fiber on a suspended TLS read: the peer never sends, so this
# fiber stays registered (ev_state -> the embedded TLSState) forever.
(ev/go (fn []
         (try
           (do (def _ (:read s 5)) (print "READ-RETURNED"))
           ([err] (print "READ-ERROR:" err)))))
(ev/sleep 0.3)
(print "RESULT:teardown-with-parked-fiber")
(file/flush stdout)
(os/exit 0)
```)

(defn- run-parked-fiber-teardown-child
  "Spawn the teardown scenario under the janet interpreter. Returns
   {:exit n :out stdout :err stderr}."
  []
  (def proc (os/spawn ["janet" "-e" parked-fiber-child-program] :p {:out :pipe :err :pipe}))
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

# ===========================================================================
# Second named guard: teardown-after-failed-certificate-verify-exits-cleanly
# ===========================================================================
# Fiber teardown frees embedded TLSState after failed verify regression test
# Ticket d4cd1f7993bdcabbb053a0d10817680edd997135
#
# "Fiber teardown frees embedded TLSState after a failed verify"
#
# Mechanism (this tree, ticket branch off 0.2.0):
#   - The per-operation states are EMBEDDED in TLSStream: struct TLSState
#     at src/jtls/internal.h:177-210, read_state and write_state at
#     src/jtls/internal.h:247-248 inside struct TLSStream at
#     src/jtls/internal.h:233. No heap allocation is involved.
#   - jtls_schedule_async hands that interior pointer to
#     janet_async_start as the fiber ev_state field
#     (src/jtls/state_machine.c:495-531, registration at :530), and
#     janet_async_start registers janet_vm.root_fiber rather than the
#     executing fiber (core/ev.c:312-313).
#   - The 6e1a853d70 fix clears ev_state in the DEINIT case
#     (src/jtls/state_machine.c:797-802) and before every jsec-driven
#     janet_async_end (:628-632, :697-701, :713-717).
#   - On the failed-verify exchange those paths do not all run: a jtls
#     registration reaches process teardown with ev_state still set -
#     no janet_async_end after its last re-registration, no
#     janet_cancel, and the transport never closed, so the CLOSE/ERR
#     teardown (src/jtls/state_machine.c:924-931) never runs either.
#   - Janet core then frees the interior pointer in the
#     JANET_MEMORY_FIBER case of janet_deinit_block (core/gc.c:333-341,
#     janet_free(f->ev_state) at :338) via janet_clear_memory /
#     janet_deinit at process teardown - os/exit runs janet_deinit
#     (core/os.c:287).
#
# This test demonstrates:
#   (a) a client TLS handshake that fails certificate verification
#       surfaces the failure as a catchable Janet error
#       ("Read error: error:0A000086:SSL routines::certificate verify
#       failed") and the child reaches process teardown with the
#       failed-verify exchange complete and the client transport left
#       unclosed (the ticket's trigger shape),
#   (b) that teardown must exit cleanly (status 0) - under the defect
#       the process dies instead: glibc "free(): invalid pointer" and
#       exit 134 (SIGABRT), or SIGSEGV / exit 139 on libcs without the
#       chunk-header check.
#
# Proof contract: the scenario is deterministic (subprocess isolation;
# the verify failure is forced by :verify-hostname and raises on the
# first read; nothing ends the registration before teardown). It fails
# on purpose under the defect with exactly the predicted abort and
# becomes the regression guard after the fix lands.


# Child program: TLS loopback. The server presents a self-signed
# certificate for 127.0.0.1; the client connects with
# :verify-hostname "wrong.example" so certificate verification MUST
# fail. tls/connect returns the stream before the handshake completes
# (src/jtls/api/connect.c:593), so the first read drives the handshake
# and raises the verify failure. The child reports that error, reaches
# teardown WITHOUT closing the client transport (the ticket's trigger),
# and calls os/exit - the teardown free path under test. Every line is
# flushed because under the defect the abort inside janet_deinit
# discards unflushed stdio buffers. Under the defect the process dies
# before the shell sees exit status 0: glibc's "free(): invalid
# pointer" goes to stderr and the exit status is 128+signal.
(def- child-program
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(defn say [& xs]
  (print ;xs)
  (file/flush stdout))

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))
(def server (net/listen "127.0.0.1" "0"))
(def [host port] (net/localname server))

(ev/go (fn []
         (try
           (with [conn (:accept server)]
             (with [c (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]
               (ev/sleep 3)))
           ([err] (say "SERVER-ERR:" err)))))

(try
  (do
    (def c (tls/connect host (string port)
                        {:verify-hostname "wrong.example"}))
    (try
      (do (def r (:read c 1 nil 5)) (say "RESULT:read:" (describe r)))
      ([e] (say "RESULT:verify-error:" e))))
  ([err]
    (say "RESULT:error:" err)))
(say "RESULT:teardown-after-failed-verify")
(os/exit 0)
```)

(defn- run-failed-verify-teardown-child
  "Spawn the failed-verify teardown scenario under the janet
   interpreter. Returns {:exit n :out stdout :err stderr}."
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

(def-suite :name "Fiber GC Ev State Free Regression"
  :description "Tickets 1377def05c d4cd1f7993: process teardown must not free the embedded TLSState ev_state as heap memory"

  (def-test "process-teardown-with-fiber-parked-on-suspended-tls-read-exits-cleanly"
    :timeout 30

    (def child (run-parked-fiber-teardown-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The scenario must actually reach teardown with the read fiber
    # still parked - otherwise the test would prove nothing about the
    # fiber-deinit free path (core/gc.c:338).
    (assert (string/find "RESULT:teardown-with-parked-fiber" out)
            (string/format
              (string "the child must reach os/exit with the read fiber "
                      "still parked on the suspended TLS read; child "
                      "stdout: %s; child stderr: %s")
              (string/trim out) (string/trim err)))

    # (b) Teardown with a parked registration must not free the embedded
    # TLSState as if heap-allocated. Under the defect this fails with
    # exit 134/139 and the crash text below.
    (assert (= 0 exit)
            (string/format
              (string "process teardown freed the embedded TLSState "
                      "ev_state as if heap-allocated (janet_free at "
                      "core/gc.c:338) instead of exiting cleanly: child "
                      "exit status %d%s; child stderr: %s")
              exit (signal-death-note exit) (string/trim err))))

  (def-test "teardown-after-failed-certificate-verify-exits-cleanly"
    :timeout 30

    (def child (run-failed-verify-teardown-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The failed-verify exchange must actually run and fail
    # certificate verification - the catchable Janet error is the
    # correct behaviour and the scenario validity condition: without it
    # the teardown would prove nothing about the failed-verify path.
    (assert (string/find "certificate verify failed" out)
            (string/format
              (string "the client handshake must fail certificate "
                      "verification with the OpenSSL verify error "
                      "(caught and reported by the child); child "
                      "stdout: %s; child stderr: %s")
              (string/trim out) (string/trim err)))

    # (a) The child must reach process teardown with the failed-verify
    # exchange complete and the client transport left unclosed - the
    # exact trigger shape of the ticket (no CLOSE/ERR teardown runs).
    (assert (string/find "RESULT:teardown-after-failed-verify" out)
            (string/format
              (string "the child must reach os/exit after the failed "
                      "verify exchange with the transport unclosed; "
                      "child stdout: %s; child stderr: %s")
              (string/trim out) (string/trim err)))

    # (b) Teardown after the failed verify must not free the embedded
    # TLSState as if heap-allocated. Under the defect this fails with
    # exit 134/139 and the crash text below.
    (assert (= 0 exit)
            (string/format
              (string "process teardown after a failed certificate "
                      "verify freed the embedded TLSState ev_state as "
                      "if heap-allocated (janet_free at core/gc.c:338) "
                      "instead of exiting cleanly: child exit status "
                      "%d%s; child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))))
