# CA error paths leak the OpenSSL objects they already hold
#
# Mechanism (this tree):
#   (1) (:generate-crl ca ...) raises on a bad :revoked entry while the
#       CRL object allocated at src/jca/crl.c:202 is still held. A
#       non-string :reason (for example {:serial 1 :reason 123}) raises
#       "revocation reason must be a string or keyword" from inside the
#       reason converter (src/jca/crl.c:29), so the free-and-raise shape
#       its sibling failures use (src/jca/crl.c:240, :260, :267) never
#       runs. A non-integer :serial (for example {:serial "x"}) raises
#       from the serial parse (src/jca/crl.c:264) with the CRL still
#       held. Each raise leaves the X509_CRL and its attachments
#       unfreed. The per-entry revocation object is created only after
#       these checks (src/jca/crl.c:272), so the CRL is what leaks.
#   (2) (ca/create cert-pem key) raises on a non-byte key value in the
#       key loader (src/jca/types.c:134) after the certificate has been
#       parsed and allocated by the caller (src/jca/types.c:312); the
#       raise unwinds past the caller and the X509 stays unfreed. The
#       neighbouring garbage-PEM case is already clean - the loader
#       reports a parse failure by returning and the caller frees the
#       certificate first (src/jca/types.c:313-317) - only the
#       pre-parse type raise skips that free.
#   Each raise leaves its earlier allocations unfreed.
#
# This test demonstrates:
#   (a) each bad-input raise produces its named error and the process
#       survives: the :reason raise, the :serial raise, and the
#       non-byte key raise are normal error conditions, not
#       process-fatal ones,
#   (b) each raise path leaks its earlier allocations: forcing the same
#       raise 50000 times in a fresh subprocess grows the process by
#       the unfreed objects - measured on this host at 50000 forced
#       raises: the bad-reason path grew about 53000 kB (X509_CRL), the
#       bad-serial path about 43000 kB (X509_CRL), the non-byte-key
#       path about 218000 kB (parsed X509),
#   (c) under fixed code each raise frees its earlier allocations before
#       unwinding, forcing it 50000 times leaves the process memory
#       flat (the same-size alloc/free cycle reuses its chunks), and the
#       raise still happens.
#
# Shape: leak-class, driven like crash-class - each scenario runs in a
# SUBPROCESS child (janet -e) that self-measures its virtual size with
# assay/memory around the forced-raise loop and reports
# RESULT:<raised>:<growth-kb> and ERR:<first error>. The parent asserts
# the child survived with exit 0, every forced raise produced the named
# error, and the growth stays under the leak-freedom bound. The
# subprocess shape keeps the measurement clean: the worker process
# itself never holds the leaks and concurrent tests cannot pollute the
# sample.
#
# Proof contract: plain tests asserting the correct behaviour - each
# bad-input raise raises AND its earlier allocations are freed. Under
# the defect the leak-freedom assertions fail on purpose with the
# predicted growth (the raise leaves its earlier allocations unfreed)
# and they become the regression guard once the fix lands. Leak freedom
# is additionally verified under the instrumented build in
# sanitizers/run-with-lsan.sh.

(use assay)
(import assay/memory)
(import jsec/ca)
(import ../helpers :prefix "")

# Forced raises per child run. The leak is small per raise (about 1.1 kB
# for a CRL and 4.4 kB for a parsed certificate on this host's OpenSSL),
# so the proof amplifies it: 50000 forced raises leak hundreds of MB
# under the defect while the fixed path reuses its chunks and stays
# flat.
(def- forced-raises 50000)

# Leak-freedom bound in kB for the whole forced-raise loop. The defect
# side grows by tens to hundreds of MB (measured); the fixed side stays
# in the low kB (chunk reuse after the per-raise free).
(def- leak-bound-kb 4096)

(defn- run-leak-child
  "Spawn the leak scenario under the janet interpreter. Returns
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

(defn- result-fields
  "Parse the child's RESULT:<raised>:<growth-kb> line into [raised growth]
   or nil when absent."
  [out]
  (when-let [idx (string/find "RESULT:" out)]
    (def start (+ idx (length "RESULT:")))
    (def stop (or (string/find "\n" out start) (length out)))
    (def parts (string/split ":" (string/slice out start stop)))
    (when (= 2 (length parts))
      (def raised (scan-number (parts 0)))
      (def growth (scan-number (parts 1)))
      (when (and raised growth) [raised growth]))))

(def- crl-bad-reason-child
  ```
(import jsec/ca)
(import assay/memory)

(def ca (ca/generate {:common-name "Leak Root"}))

(defn force-once
  "Force the generate-crl non-string :reason raise once. Returns the
   error raised, or nil when the call did not raise."
  []
  (try (do (:generate-crl ca {:revoked @[{:serial 1 :reason 123}]}) nil)
       ([e] e)))

# Warm the allocator first so the growth sample is not arena slop.
(for i 0 200 (force-once))

(def v0 (get (memory/info) :vsize))
(var raised 0)
(var first-err nil)
(for i 0 50000
  (def e (force-once))
  (if (nil? e)
    (error "scenario did not raise")
    (do (++ raised) (unless first-err (set first-err e)))))
(def v1 (get (memory/info) :vsize))

(print "RESULT:" raised ":" (div (- v1 v0) 1024))
(print "ERR:" (string first-err))
(os/exit 0)
```)

(def- crl-bad-serial-child
  ```
(import jsec/ca)
(import assay/memory)

(def ca (ca/generate {:common-name "Leak Root"}))

(defn force-once
  "Force the generate-crl non-integer :serial raise once. Returns the
   error raised, or nil when the call did not raise."
  []
  (try (do (:generate-crl ca {:revoked @[{:serial "x"}]}) nil)
       ([e] e)))

(for i 0 200 (force-once))

(def v0 (get (memory/info) :vsize))
(var raised 0)
(var first-err nil)
(for i 0 50000
  (def e (force-once))
  (if (nil? e)
    (error "scenario did not raise")
    (do (++ raised) (unless first-err (set first-err e)))))
(def v1 (get (memory/info) :vsize))

(print "RESULT:" raised ":" (div (- v1 v0) 1024))
(print "ERR:" (string first-err))
(os/exit 0)
```)

(def- ca-create-non-byte-key-child
  ```
(import jsec/ca)
(import assay/memory)

(def ca (ca/generate {:common-name "Leak Root"}))
(def cert-pem (:get-cert ca))

(defn force-once
  "Force the ca/create non-byte :key raise once. Returns the error
   raised, or nil when the call did not raise."
  []
  (try (do (ca/create cert-pem 123) nil) ([e] e)))

(for i 0 200 (force-once))

(def v0 (get (memory/info) :vsize))
(var raised 0)
(var first-err nil)
(for i 0 50000
  (def e (force-once))
  (if (nil? e)
    (error "scenario did not raise")
    (do (++ raised) (unless first-err (set first-err e)))))
(def v1 (get (memory/info) :vsize))

(print "RESULT:" raised ":" (div (- v1 v0) 1024))
(print "ERR:" (string first-err))
(os/exit 0)
```)

(defn- assert-leak-freedom
  "Shared parent-side contract for one raise path: the child survives,
   every forced raise produced the named error, and the process growth
   stays under the leak-freedom bound."
  [child error-fragment alloc-note raise-note]
  (def exit (child :exit))
  (def out (child :out))
  (def err (child :err))
  (assert (= 0 exit)
          (string/format
            (string "the forced-raise child must survive (the bad input is "
                    "a normal error condition, not a process-fatal one); "
                    "child exit status %d; child stdout: %s; child "
                    "stderr: %s")
            exit (string/trim out) (string/trim err)))
  (assert (string/find error-fragment out)
          (string/format
            (string "every forced raise must produce the named error %q "
                    "(the raise contract the fix must keep); child "
                    "stdout: %s; child stderr: %s")
            error-fragment (string/trim out) (string/trim err)))
  (def fields (result-fields out))
  (assert (not (nil? fields))
          (string/format
            (string "the child must report RESULT:<raised>:<growth-kb>; "
                    "child stdout: %s; child stderr: %s")
            (string/trim out) (string/trim err)))
  (def [raised growth] fields)
  (assert (= raised forced-raises)
          (string/format
            (string "the child must force the raise on every one of the %d "
                    "iterations (raise contract); it reported %d raises; "
                    "child stdout: %s")
            forced-raises raised (string/trim out)))
  (assert (<= growth leak-bound-kb)
          (string/format
            (string "each raise must free its earlier allocations: forcing "
                    "this raise %d times must stay under %d kB of process "
                    "growth, but the process grew by %d kB - the raise "
                    "leaves its earlier allocations unfreed (%s; %s)")
            raised leak-bound-kb growth alloc-note raise-note)))

(def-suite :name "CA Error Path Object Leak Regression"
  :description "CA raise paths must free the OpenSSL objects they already hold"

  (def-test "generate-crl-bad-revoked-reason-must-free-the-crl"
    :timeout 120

    (def child (run-leak-child crl-bad-reason-child))
    (assert-leak-freedom
      child "revocation reason must be a string or keyword"
      "the X509_CRL allocated at src/jca/crl.c:202"
      "the reason converter raises at src/jca/crl.c:29 before the free-and-raise shape at src/jca/crl.c:267"))

  (def-test "generate-crl-bad-revoked-serial-must-free-the-crl"
    :timeout 120

    (def child (run-leak-child crl-bad-serial-child))
    (assert-leak-freedom
      child "64 bit signed integer"
      "the X509_CRL allocated at src/jca/crl.c:202"
      "the serial parse raises at src/jca/crl.c:264 with the CRL held"))

  (def-test "ca-create-non-byte-key-must-free-the-loaded-certificate"
    :timeout 120

    (def child (run-leak-child ca-create-non-byte-key-child))
    (assert-leak-freedom
      child "expected string, symbol, keyword or buffer"
      "the X509 allocated at src/jca/types.c:312"
      "the key loader raises at src/jca/types.c:134 before any free")))
