# SNI map non-bytes key regression test
# Ticket c85647d95ad351a5773af03cb24a25815d4966ac
#
# "janet_unwrap_string on table keys in new-context SNI map"
#
# Mechanism (this tree, branch ticket-c85647d95ad351a5773af03cb24a25815d4966ac
# off 0.2.0 at 599e82e288): cfun_new_context walks the :sni map with
# janet_dictionary_view (src/jtls/api/context.c:73) and at
# src/jtls/api/context.c:84-85 casts every key with
# janet_unwrap_string(kvs[i].key). The only guard on the key is
# !janet_checktype(kvs[i].key, JANET_NIL) at src/jtls/api/context.c:83 -
# there is no bytes-type check. janet_unwrap_string is
# janet_nanbox_to_pointer on the raw value bits (janet.h:837, janet 1.40.1),
# so a non-bytes key (e.g. a number) is reinterpreted as a pointer and the
# subsequent jsec_strdup (src/jtls/api/context.c:113) dereferences it:
# the process dies on SIGSEGV. String/keyword/symbol keys are safe
# (janet_string bytes are NUL-terminated) - only non-bytes keys crash.
# The fix is to type-check each key with janet_checktype(key,
# JANET_STRING|JANET_KEYWORD|JANET_SYMBOL) and raise a Janet type error.
#
# This test demonstrates:
#   (a) an SNI map with a numeric key must make new-context raise a
#       catchable Janet error (the fix's contract),
#   (b) under the defect the same call raises nothing at all - it kills
#       the process with SIGSEGV before any error can be caught, and the
#       parent observes a signal death (exit status 139) with no RESULT
#       line on stdout.
#
# Shape: the crash kills the process, so the scenario runs in a
# SUBPROCESS (os/spawn of the janet interpreter on a child program,
# the pattern of suites/regression/suite-timed-read-timeout-crash.janet)
# and the parent test asserts from the outside:
#   (i) the child exits 0 instead of dying by signal (139 = SIGSEGV
#       under the defect),
#   (ii) the child prints RESULT:error:<err> (any Janet error - the
#       fix's message is not prescribed) rather than RESULT:ok.
#
# Under the defect the test fails with exactly the predicted symptom -
# the child's SIGSEGV exit status where a Janet error was required (no
# crash of the test process, no hang, no unrelated error); under fixed
# code the whole test passes.

(use assay)
(import ../helpers :prefix "")

# Child program: build a server context whose :sni map has a numeric key.
# Prints RESULT:ok if new-context somehow accepts the map, RESULT:error:<err>
# if it raises a Janet error (expected under the fix), then exits 0. Under
# the defect the process dies inside janet_unwrap_string before any RESULT
# line: SIGSEGV, no stderr text.
(def- child-program
  ```
(import jsec/tls :as tls)
(import jsec/cert :as cert)

(def certs (cert/generate-self-signed-cert
             {:common-name "127.0.0.1" :key-type :rsa :bits 2048 :days-valid 1}))
(try
  (do
    (tls/new-context {:cert (certs :cert)
                      :key (certs :key)
                      :sni {1 {:cert (certs :cert) :key (certs :key)}}})
    (print "RESULT:ok"))
  ([err]
    (print "RESULT:error:" err)))
(os/exit 0)
```)

(defn- run-sni-child
  "Spawn the numeric-SNI-key scenario under the janet interpreter.
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

(defn- signal-death-note
  "Human-readable note when the child died by signal (POSIX shell exit
   semantics: status = signal + 128)."
  [exit]
  (case exit
    134 " (died by signal 6 SIGABRT)"
    139 " (died by signal 11 SIGSEGV)"
    ""))

(def-suite :name "SNI Map Non-Bytes Key Regression"
  :description "Ticket c85647d95a: numeric SNI map key must raise a Janet type error, not crash new-context"

  (def-test "numeric sni map key raises a janet error instead of crashing"
    :timeout 30

    (def child (run-sni-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a)(b) The child must survive: a non-bytes SNI key is a caller
    # error, not a process-fatal one. Under the defect this fails with
    # exit 139 and the crash text in the message.
    (assert (= 0 exit)
            (string/format
              (string "new-context with a non-bytes SNI map key must raise a "
                      "Janet type error instead of crashing: child exit "
                      "status %d%s; child stdout: %s; child stderr: %s")
              exit (signal-death-note exit) (string/trim out) (string/trim err)))

    # Reached only when the process survived: it must report a Janet
    # error (the fix raises a type error; the message is not prescribed),
    # not a successful context build.
    (assert (string/find "RESULT:error:" out)
            (string/format
              (string "new-context must raise a Janet type error for a "
                      "non-bytes SNI map key; child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err)))))
