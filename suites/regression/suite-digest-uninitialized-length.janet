# crypto/digest uninitialized length regression test
# Ticket d807bc397b29b7da79560bcebd14ab816c5aa31f
#
# "crypto/digest uses an uninitialized length on failure"
#
# cfun_digest (src/jcrypto/digest.c:52-73) never checks the return of
# EVP_DigestInit_ex (digest.c:67), EVP_DigestUpdate (digest.c:68), or
# EVP_DigestFinal_ex (digest.c:69). md_len (digest.c:62) is only ever
# written by a successful EVP_DigestFinal_ex, so when init fails -
# :md4 (also :mdc2, :whirlpool) resolves to a legacy EVP_MD that
# EVP_get_digestbyname reports non-NULL while EVP_DigestInit_ex fails
# because the OpenSSL 3 legacy provider is not loaded - the call falls
# through to janet_stringv(md_value, md_len) (digest.c:72) with md_len
# still uninitialized. The correct checked pattern is already in-tree in
# cfun_digest_begin (digest.c:86-88) and cfun_digest_finish
# (digest.c:122-124).
#
# This test demonstrates:
#   (a) crypto/digest on an algorithm whose provider is not loaded
#       (here :md4) must raise a Janet error - the same failure class
#       cfun_digest_begin already raises - and must never build a
#       string with an uninitialized length,
#   (b) under the defect the call does not raise: with this toolchain
#       the garbage md_len is large enough that janet_string (Janet
#       core string.c:48-56) copies md_len bytes out of the 64-byte
#       md_value stack buffer and the process dies with SIGSEGV (exit
#       139) inside janet_string, called from cfun_digest - the
#       "garbage-length result or abort" outcome the ticket predicts.
#
# Shape: the abort kills the process, so the scenario runs in a
# SUBPROCESS (os/spawn of the janet interpreter on a child program,
# the same shape as suites/regression/suite-timed-read-timeout-crash.
# janet) and the parent asserts from the outside:
#   (a) the child exits 0 instead of dying by signal (139 SIGSEGV or
#       134 SIGABRT under the defect),
#   (b) the child reports that the digest call raised a Janet error
#       (RESULT:error: on its stdout) and did not return a result.
#
# Proof contract: under the defect the test fails with exactly the
# predicted symptom (the child dies by SIGSEGV in janet_string from the
# garbage md_len, or returns a garbage-length result); under fixed code
# the whole test passes.

(use assay)
(import ../helpers :prefix "")

(def- child-program
  ```
(import jsec/crypto :as crypto)
(try
  (do
    (def r (crypto/digest :md4 @"abc"))
    (print "RESULT:returned-len:" (length r)))
  ([err]
    (print "RESULT:error:" err)))
(os/exit 0)
```)

(defn- run-digest-child
  ``Spawn the digest scenario under the janet interpreter. Returns
   {:exit n :out stdout :err stderr}.``
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
  ``Human-readable note when the child died by signal (POSIX shell exit
   semantics: status = signal + 128).``
  [exit]
  (case exit
    134 " (died by signal 6 SIGABRT)"
    139 " (died by signal 11 SIGSEGV: janet_string copied the garbage md_len bytes out of the md_value stack buffer)"
    ""))

(def-suite :name "Digest Uninitialized Length Regression"
  :description "Ticket d807bc397b: crypto/digest must raise on an uninitializable algorithm, never build a string with an uninitialized length"

  (def-test "digest on unavailable algorithm raises instead of using uninitialized length"
    :timeout 30

    (def child (run-digest-child))
    (def exit (child :exit))
    (def out (child :out))
    (def err (child :err))

    # (a) The child must survive: a digest algorithm whose provider is
    # not loaded is an ordinary error condition, not a process-fatal
    # one. Under the defect this fails with exit 139/134 and the crash
    # text below - janet_string(md_value, md_len) with md_len still
    # uninitialized at digest.c:72.
    (assert (= 0 exit)
            (string/format
              (string "crypto/digest on :md4 must raise a Janet error, "
                      "not kill the process with an out-of-bounds read "
                      "driven by the uninitialized md_len (digest.c:62, "
                      "used at digest.c:72): child exit status %d%s; "
                      "child stderr: %s")
              exit (signal-death-note exit) (string/trim err)))

    # (b) The failure mode under the fix must be exactly what
    # cfun_digest_begin already does for a failed init (digest.c:86-88):
    # raise a Janet error. A returned result of any length is the
    # defect's garbage-length outcome.
    (assert (string/find "RESULT:error:" out)
            (string/format
              (string "crypto/digest must raise a Janet error when "
                      "EVP_DigestInit_ex fails (never return a "
                      "garbage-length result); child stdout: %s; "
                      "child stderr: %s")
              (string/trim out) (string/trim err)))))
