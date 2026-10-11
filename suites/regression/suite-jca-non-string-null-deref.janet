# JCA non-string option NULL dereference regression test
# Ticket 93efd533e591a7c07045120bb64a7e2affb24319
#
# "NULL dereference on non-string option values throughout jca"
#
# Mechanism (this tree, 0.2.0 basis):
#   janet_to_string_or_keyword (src/jutils/janet_types.c:14-21) returns
#   NULL for any Janet value that is neither string nor keyword. The jca
#   call sites store that return without a NULL check and pass it on to
#   a C string sink that dereferences it:
#     - ca_generate_keypair: the NULL is stored at
#       src/jca/types.c:198 and reaches the strcmp at
#       src/jca/types.c:201 (:key-type option of ca/generate,
#       ca/generate-intermediate, :issue).
#     - add_san_entries: each SAN entry is stored at
#       src/jca/sign.c:53 and the janet_buffer_push_cstring call at
#       src/jca/sign.c:54 strlen's it. Reached from ca/sign
#       (src/jca/sign.c:232) and :issue (src/jca/sign.c:414).
#     - ca_sign_csr :basic-constraints: the NULL is stored at
#       src/jca/sign.c:145 and handed to ca_add_extension at
#       src/jca/sign.c:209, whose X509V3_EXT_conf_nid call at
#       src/jca/types.c:258 dereferences it.
#     - ca_keyword_to_reason: the NULL is stored at src/jca/crl.c:26
#       and the strcmp chain at src/jca/crl.c:28 dereferences it
#       (:revoke reason, generate-crl :revoked reason).
#     - ca_create_ocsp_response: the NULL is stored at
#       src/jca/ocsp.c:183 and the strcmp chain at src/jca/ocsp.c:185
#       dereferences it (status argument).
#   The same unchecked store sits at src/jca/types.c:372,397,402,513,
#   543,548 and src/jca/sign.c:122,127,301,328,333,338,343; those
#   feed X509_NAME entry helpers or fall through to option defaults and
#   fail soft on this OpenSSL instead of crashing. The correct pattern
#   is the NULL check plus janet_panicf type error, as at
#   src/jutils/security.c:68-71.
#
# This test demonstrates:
#   (a) a non-string, non-keyword option value (a number) passed to the
#       jca APIs kills the process with SIGSEGV - exit status 139, no
#       Janet error is raised - because the NULL from
#       janet_to_string_or_keyword reaches strcmp/strlen/X509V3
#       unchecked,
#   (b) under the fixed shape (NULL check plus Janet type error at each
#       of those sites) the same calls raise catchable Janet errors,
#       each child reports RESULT:error: and exits 0, and every guard
#       here passes.
#
# Proof contract: under the defect each scenario child dies before any
# RESULT line and the guard fails with the child exit status and crash
# text; under the fix each child catches a Janet type error, the guards
# see RESULT:error: and exit status 0, and this whole suite is green.
#
# Shape: the crash kills the process, so every scenario runs in a
# SUBPROCESS (os/spawn of the janet interpreter on a child program) and
# the parent test asserts from the outside:
#   (a) the child exits 0 instead of dying by signal (exit 139 = SIGSEGV
#       under the defect),
#   (b) the child reports that the call raised (RESULT:error:... on its
#       stdout).
# The failure message embeds the child exit status and stderr so the
# defect crash text is visible in the failing output.

(use assay)
(import ../helpers :prefix "")

# Child programs. Each performs one defective call inside try so that
# under the fixed shape the Janet error is caught and reported as
# RESULT:error:<err>; if the call returns normally the child reports
# RESULT:returned:<value>; under the defect the process dies before any
# RESULT line. Setup failures report SETUP-FAILED and exit 2 so they
# cannot be mistaken for the defect.

(def- child-key-type
  ```
(import jsec/ca)
(try
  (do
    (ca/generate {:key-type 5})
    (print "RESULT:returned:ok"))
  ([err] (print "RESULT:error:" err)))
(os/exit 0)
```)

(def- child-san-entry
  ```
(import jsec/ca)
(def ca-obj
  (try (ca/generate)
       ([err] (do (print "SETUP-FAILED:" err) (os/exit 2)))))
(try
  (do
    (:issue ca-obj {:common-name "x" :san [5]})
    (print "RESULT:returned:ok"))
  ([err] (print "RESULT:error:" err)))
(os/exit 0)
```)

(def- child-basic-constraints
  ```
(import jsec/ca :as ca)
(import jsec/crypto :as crypto)
(def ca-obj
  (try (ca/generate)
       ([err] (do (print "SETUP-FAILED:" err) (os/exit 2)))))
(def key
  (try (crypto/generate-key :ec-p256)
       ([err] (do (print "SETUP-FAILED:" err) (os/exit 2)))))
(def csr
  (try (crypto/generate-csr key {:common-name "t"})
       ([err] (do (print "SETUP-FAILED:" err) (os/exit 2)))))
(try
  (do
    (ca/sign ca-obj csr {:basic-constraints 5})
    (print "RESULT:returned:ok"))
  ([err] (print "RESULT:error:" err)))
(os/exit 0)
```)

(def- child-revoke-reason
  ```
(import jsec/ca)
(def ca-obj
  (try (ca/generate)
       ([err] (do (print "SETUP-FAILED:" err) (os/exit 2)))))
(try
  (do
    (:revoke ca-obj 123 5)
    (print "RESULT:returned:ok"))
  ([err] (print "RESULT:error:" err)))
(os/exit 0)
```)

(def- child-ocsp-status
  ```
(import jsec/ca)
(def ca-obj
  (try (ca/generate)
       ([err] (do (print "SETUP-FAILED:" err) (os/exit 2)))))
(try
  (do
    (ca/create-ocsp-response ca-obj @{} 5)
    (print "RESULT:returned:ok"))
  ([err] (print "RESULT:error:" err)))
(os/exit 0)
```)

(defn- run-scenario
  "Spawn one crash scenario under the janet interpreter. Returns
   {:exit n :out stdout :err stderr}."
  [program]
  (def proc (os/spawn ["janet" "-e" program] :p {:out :pipe :err :pipe}))
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
    138 " (died by signal 10 SIGBUS)"
    139 " (died by signal 11 SIGSEGV: NULL dereference of the janet_to_string_or_keyword return)"
    ""))

(def-suite :name "JCA Non-String Option Null Deref Regression"
  :description "Ticket 93efd533e5: non-string jca option values must raise a Janet error, not dereference NULL"

  (def-test "ca-generate-non-string-key-type-raises-error-not-null-deref"
    :timeout 30

    (def child (run-scenario child-key-type))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The child must survive: a non-string option value is a normal
    # type error condition, not a process-fatal one. Under the defect
    # this fails with exit 139 and the crash text below.
    (assert (= 0 exit)
            (string/format
              (string "ca/generate with non-string :key-type killed the "
                      "process instead of raising a Janet error: child "
                      "exit status %d%s; child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))

    # (b) The failure mode under the fix must be exactly a Janet error:
    # janet_to_string_or_keyword (src/jutils/janet_types.c:14-21) returns
    # NULL for a number and the return must be checked before the
    # strcmp at src/jca/types.c:201.
    (assert (string/find "RESULT:error:" out)
            (string/format
              (string "ca/generate with non-string :key-type must raise a "
                      "Janet error (check the janet_to_string_or_keyword "
                      "return at src/jca/types.c:198 before the strcmp at "
                      "src/jca/types.c:201); child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err))))

  (def-test "issue-non-string-san-entry-raises-error-not-null-deref"
    :timeout 30

    (def child (run-scenario child-san-entry))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    (assert (= 0 exit)
            (string/format
              (string ":issue with a non-string :san entry killed the "
                      "process instead of raising a Janet error: child "
                      "exit status %d%s; child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))

    (assert (string/find "RESULT:error:" out)
            (string/format
              (string ":issue with a non-string :san entry must raise a "
                      "Janet error (check the janet_to_string_or_keyword "
                      "return at src/jca/sign.c:53 before "
                      "janet_buffer_push_cstring); child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err))))

  (def-test "sign-csr-non-string-basic-constraints-raises-error-not-null-deref"
    :timeout 30

    (def child (run-scenario child-basic-constraints))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    (assert (= 0 exit)
            (string/format
              (string "ca/sign with non-string :basic-constraints killed "
                      "the process instead of raising a Janet error: "
                      "child exit status %d%s; child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))

    (assert (string/find "RESULT:error:" out)
            (string/format
              (string "ca/sign with non-string :basic-constraints must "
                      "raise a Janet error (check the "
                      "janet_to_string_or_keyword return at "
                      "src/jca/sign.c:145 before the ca_add_extension "
                      "call at src/jca/sign.c:209); child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err))))

  (def-test "revoke-non-string-reason-raises-error-not-null-deref"
    :timeout 30

    (def child (run-scenario child-revoke-reason))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    (assert (= 0 exit)
            (string/format
              (string ":revoke with a non-string reason killed the "
                      "process instead of raising a Janet error: child "
                      "exit status %d%s; child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))

    (assert (string/find "RESULT:error:" out)
            (string/format
              (string ":revoke with a non-string reason must raise a "
                      "Janet error (check the janet_to_string_or_keyword "
                      "return at src/jca/crl.c:26 before the strcmp at "
                      "src/jca/crl.c:28); child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err))))

  (def-test "create-ocsp-response-non-string-status-raises-error-not-null-deref"
    :timeout 30

    (def child (run-scenario child-ocsp-status))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    (assert (= 0 exit)
            (string/format
              (string "ca/create-ocsp-response with non-string status "
                      "killed the process instead of raising a Janet "
                      "error: child exit status %d%s; child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))

    (assert (string/find "RESULT:error:" out)
            (string/format
              (string "ca/create-ocsp-response with non-string status "
                      "must raise a Janet error (check the "
                      "janet_to_string_or_keyword return at "
                      "src/jca/ocsp.c:183 before the strcmp at "
                      "src/jca/ocsp.c:185); child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err)))))
