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
(import ../helpers :prefix "")

(def- crl-bad-reason-child
  (make-plateau-leak-child
    ```
(import jsec/ca)

(def ca (ca/generate {:common-name "Leak Root"}))

(defn force-once
  "Force the generate-crl non-string :reason raise once. Returns the
   error raised, or nil when the call did not raise."
  []
  (try (do (:generate-crl ca {:revoked @[{:serial 1 :reason 123}]}) nil)
       ([e] e)))
```))

(def- crl-bad-serial-child
  (make-plateau-leak-child
    ```
(import jsec/ca)

(def ca (ca/generate {:common-name "Leak Root"}))

(defn force-once
  "Force the generate-crl non-integer :serial raise once. Returns the
   error raised, or nil when the call did not raise."
  []
  (try (do (:generate-crl ca {:revoked @[{:serial "x"}]}) nil)
       ([e] e)))
```))

(def- ca-create-non-byte-key-child
  (make-plateau-leak-child
    ```
(import jsec/ca)

(def ca (ca/generate {:common-name "Leak Root"}))
(def cert-pem (:get-cert ca))

(defn force-once
  "Force the ca/create non-byte :key raise once. Returns the error
   raised, or nil when the call did not raise."
  []
  (try (do (ca/create cert-pem 123) nil) ([e] e)))
```))

(def- ca-sign-csr-bad-san-child
  (make-plateau-leak-child
    ```
(import jsec/ca)
(import jsec/crypto)

(def ca (ca/generate {:common-name "Leak Root"}))
(def key (crypto/generate-key :ec-p256))
(def csr (crypto/generate-csr key {:common-name "san-leak.test"}))

(defn force-once
  "Force the ca/sign-csr non-string :san entry raise once. Returns the
   error raised, or nil when the call did not raise."
  []
  (try (do (:sign-csr ca csr {:san [123]}) nil) ([e] e)))
```))

(def-suite :name "CA Error Path Object Leak Regression"
  :description "CA raise paths must free the OpenSSL objects they already hold"

  (def-test "generate-crl-bad-revoked-reason-must-free-the-crl"
    :timeout 120

    (def child (run-leak-child crl-bad-reason-child))
    (assert-plateau-leak-freedom
      child "revocation reason must be a string or keyword"
      "the X509_CRL allocated at src/jca/crl.c:202"
      "the reason converter raises at src/jca/crl.c:29 before the free-and-raise shape at src/jca/crl.c:267"))

  (def-test "generate-crl-bad-revoked-serial-must-free-the-crl"
    :timeout 120

    (def child (run-leak-child crl-bad-serial-child))
    (assert-plateau-leak-freedom
      child "64 bit signed integer"
      "the X509_CRL allocated at src/jca/crl.c:202"
      "the serial parse raises at src/jca/crl.c:264 with the CRL held"))

  (def-test "ca-create-non-byte-key-must-free-the-loaded-certificate"
    :timeout 120

    (def child (run-leak-child ca-create-non-byte-key-child))
    (assert-plateau-leak-freedom
      child "expected string, symbol, keyword or buffer"
      "the X509 allocated at src/jca/types.c:312"
      "the key loader raises at src/jca/types.c:134 before any free"))

  (def-test "ca-sign-csr-bad-san-entry-must-free-cert-key-and-csr"
    :timeout 120

    (def child (run-leak-child ca-sign-csr-bad-san-child))
    (assert-plateau-leak-freedom
      child ":san entry must be a string or keyword"
      "the X509, EVP_PKEY, and X509_REQ allocated in src/jca/sign.c"
      "add_san_entries previously panicked at src/jca/sign.c:55 with objects held")))
