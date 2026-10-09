# CA helpers leak OpenSSL objects on their panic paths regression test
# Ticket 7fba14b72c5c5c496d05cf5924bfbd92557b5f84
#
# "CA helpers leak OpenSSL objects on their panic paths"
#
# Mechanism (this tree):
#   (1) The CA construction path loads the certificate and then the key
#       (src/jca/types.c:313-314): ca_pem_to_x509 returns the parsed
#       X509 (src/jca/types.c:115-130), then ca_pem_to_key panics on
#       garbage (src/jca/types.c:133-148, "failed to parse private key
#       PEM") and the already-loaded certificate is never freed.
#   (2) The CRL builder allocates the CRL (X509_CRL_new,
#       src/jca/crl.c:179) and then converts the reason keyword
#       (src/jca/crl.c:242); a bad keyword panics inside
#       ca_keyword_to_reason (src/jca/crl.c:21-43, "unknown revocation
#       reason") with the CRL object already allocated. The neighbouring
#       panics in the same loop free the CRL first (src/jca/crl.c:218
#       and :238) - the reason-conversion panic does not.
#   (3) The OCSP response builder panics on a bad revocation-time
#       (src/jca/ocsp.c:279-288, "invalid revocation-time format") with
#       the basic response (OCSP_BASICRESP_new, src/jca/ocsp.c:221) and
#       the cert id (OCSP_cert_id_new, src/jca/ocsp.c:241) already
#       allocated; the later error paths in the same function free both
#       (src/jca/ocsp.c:316-318, :340-342, :355-357, :369-372) but the
#       revocation-time panics free only the ASN1_TIME.
#   Each panic leaves its earlier allocations unfreed.
#
# This test demonstrates:
#   (a) each bad-input panic raises its named error and the process
#       survives: (1) ca/create with a garbage key raises "failed to
#       parse private key PEM", (2) :generate-crl with a bad :reason
#       raises "unknown revocation reason", (3) :create-ocsp-response
#       with a bad :revocation-time raises "invalid revocation-time
#       format" - the raise contract the fix must keep,
#   (b) each panic path leaks its earlier allocations: forcing the same
#       panic 50000 times in a fresh subprocess grows the process by the
#       unfreed objects - measured on this host at 50000 forced panics
#       (OpenSSL 3.6.5): site 1 grew 222216 kB (parsed X509), site 2
#       grew 45672 kB (X509_CRL), site 3 grew 24552 kB
#       (OCSP_BASICRESP plus OCSP_CERTID),
#   (c) under fixed code each panic frees its earlier allocations before
#       unwinding, forcing it 50000 times leaves the process memory flat
#       (the same-size alloc/free cycle reuses its chunks), and the
#       raise still happens.
#
# Shape: leak-class, driven like crash-class - each scenario runs in a
# SUBPROCESS child (janet -e) that self-measures its virtual size with
# assay/memory around the forced-panic loop and reports
# RESULT:<raised>:<growth-kb> and ERR:<first error>. The parent asserts
# the child survived with exit 0, every forced panic raised the named
# error, and the growth stays under the leak-freedom bound. The
# subprocess shape keeps the measurement clean: the worker process
# itself never holds the leaks and concurrent tests cannot pollute the
# sample.
#
# Proof contract: plain tests asserting the correct behaviour - each
# bad-input panic raises AND its earlier allocations are freed. Under
# the defect the leak-freedom assertions fail on purpose with the
# predicted growth (the panic leaves its earlier allocations unfreed)
# and they become the regression guard once the fix lands. Leak freedom
# is additionally verified under the sanitizer build; see the ticket
# ledger for that run and for the note on the stock LSan suppressions.

(use assay)
(import assay/memory)
(import jsec/ca)
(import ../helpers :prefix "")

# Forced panics per child run. The leak is small per panic (about 4.6 kB
# for site 1, 1.0 kB for site 2, 0.5 kB for site 3 on this host's
# OpenSSL 3.6.5), so the proof amplifies it: 50000 forced panics leak
# hundreds of MB under the defect while the fixed path reuses its
# chunks and stays flat.
(def- forced-panics 50000)

# Leak-freedom bound in kB for the whole forced-panic loop. The defect
# side grows by tens to hundreds of MB (measured); the fixed side stays
# in the low kB (chunk reuse after the per-panic free).
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

(def- ca-create-leak-child
  ```
(import jsec/ca)
(import assay/memory)

(def ca (ca/generate {:common-name "Leak Root"}))
(def cert-pem (:get-cert ca))

(defn force-once
  "Force the ca/create key-load panic once. Returns the error raised,
   or nil when the call did not raise."
  []
  (try (do (ca/create cert-pem "THIS IS NOT A KEY") nil) ([e] e)))

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

(def- crl-leak-child
  ```
(import jsec/ca)
(import assay/memory)

(def ca (ca/generate {:common-name "Leak Root"}))

(defn force-once
  "Force the CRL bad-reason panic once. Returns the error raised, or
   nil when the call did not raise."
  []
  (try (do (:generate-crl ca {:revoked @[{:serial 1 :reason :bogus-reason}]})
           nil)
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

(def- ocsp-leak-child
  ```
(import jsec/ca)
(import assay/memory)

(def ca (ca/generate {:common-name "Leak Root"}))
(def request-info @{:serial (int/s64 7)})

(defn force-once
  "Force the OCSP bad-revocation-time panic once. Returns the error
   raised, or nil when the call did not raise."
  []
  (try (do (:create-ocsp-response ca request-info :revoked
                                  {:revocation-time "not-a-time"})
           nil)
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

(defn- assert-leak-freedom
  "Shared parent-side contract for one panic path: the child survives,
   every forced panic raised the named error, and the process growth
   stays under the leak-freedom bound."
  [child error-fragment alloc-note panic-note]
  (def exit (child :exit))
  (def out (child :out))
  (def err (child :err))
  (assert (= 0 exit)
          (string/format
            (string "the forced-panic child must survive (the bad input is "
                    "a normal error condition, not a process-fatal one); "
                    "child exit status %d; child stdout: %s; child "
                    "stderr: %s")
            exit (string/trim out) (string/trim err)))
  (assert (string/find error-fragment out)
          (string/format
            (string "every forced panic must raise the named error %q "
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
  (assert (= raised forced-panics)
          (string/format
            (string "the child must force the panic on every one of the %d "
                    "iterations (raise contract); it reported %d raises; "
                    "child stdout: %s")
            forced-panics raised (string/trim out)))
  (assert (<= growth leak-bound-kb)
          (string/format
            (string "each panic must free its earlier allocations: forcing "
                    "this panic %d times must stay under %d kB of process "
                    "growth, but the process grew by %d kB - the panic "
                    "leaves its earlier allocations unfreed (%s; %s)")
            raised leak-bound-kb growth alloc-note panic-note)))

(def-suite :name "CA Panic Path Leak Regression"
  :description "Ticket 7fba14b72c: CA panic paths must free their earlier OpenSSL allocations"

  (def-test "ca-create-key-load-panic-must-free-the-loaded-certificate"
    :timeout 120

    (def child (run-leak-child ca-create-leak-child))
    (assert-leak-freedom
      child "failed to parse private key PEM"
      "the X509 loaded at src/jca/types.c:313"
      "ca_pem_to_key panics at src/jca/types.c:144-145"))

  (def-test "crl-bad-reason-panic-must-free-the-crl-object"
    :timeout 120

    (def child (run-leak-child crl-leak-child))
    (assert-leak-freedom
      child "unknown revocation reason"
      "the X509_CRL allocated at src/jca/crl.c:179"
      "ca_keyword_to_reason panics at src/jca/crl.c:242 via src/jca/crl.c:43"))

  (def-test "ocsp-bad-revocation-time-panic-must-free-basic-response-and-cert-id"
    :timeout 120

    (def child (run-leak-child ocsp-leak-child))
    (assert-leak-freedom
      child "invalid revocation-time format"
      "the OCSP_BASICRESP at src/jca/ocsp.c:221 and OCSP_CERTID at src/jca/ocsp.c:241"
      "the revocation-time panics at src/jca/ocsp.c:279-288")))
